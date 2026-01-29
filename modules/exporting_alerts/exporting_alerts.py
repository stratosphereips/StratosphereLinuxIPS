# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import os
import sqlite3
import threading
import time
from typing import Optional, Tuple

from modules.exporting_alerts.slack_exporter import SlackExporter
from modules.exporting_alerts.stix_exporter import StixExporter
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.imodule import IModule


class ExportingAlerts(IModule):
    """
    Module to export alerts to slack and/or STIX
    You need to have the token in your environment
    variables to use this module
    """

    name = "Exporting Alerts"
    description = "Export alerts to slack or STIX format"
    authors = ["Alya Gomaa"]

    def init(self):
        self.slack = SlackExporter(self.logger, self.db)
        self.stix = StixExporter(self.logger, self.db)
        self.c1 = self.db.subscribe("export_evidence")
        self.channels = {"export_evidence": self.c1}
        self.print("Subscribed to export_evidence channel.", 2, 0)
        self.direct_export_stop = None
        self.direct_export_workers = []
        self.direct_export_start_lock = threading.Lock()
        self.queue_db = None
        self.queue_lock = threading.Lock()
        self.queue_db_path = None

    def _init_direct_export_queue(self):
        if self.queue_db:
            return
        self.queue_db_path = os.path.join(
            self.output_dir, "stix_export_queue.sqlite"
        )
        self.queue_db = sqlite3.connect(
            self.queue_db_path, check_same_thread=False
        )
        self.queue_db.execute("PRAGMA journal_mode=WAL;")
        self.queue_db.execute("PRAGMA synchronous=NORMAL;")
        self.queue_db.execute(
            """
            CREATE TABLE IF NOT EXISTS export_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id TEXT,
                evidence_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                next_retry_at REAL NOT NULL DEFAULT 0,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
            """
        )
        self.queue_db.execute(
            "CREATE INDEX IF NOT EXISTS export_queue_status_idx "
            "ON export_queue(status, next_retry_at)"
        )
        self.queue_db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS export_queue_evidence_id_idx "
            "ON export_queue(evidence_id)"
        )
        self.queue_db.commit()
        self.stix._log_export(
            f"Direct export queue initialized db={self.queue_db_path}"
        )

    def _queue_counts(self) -> Tuple[int, str]:
        if not self.queue_db:
            return 0, "queue=uninitialized"
        counts = {"pending": 0, "retry": 0, "in_progress": 0, "failed": 0}
        with self.queue_lock:
            rows = self.queue_db.execute(
                "SELECT status, COUNT(*) FROM export_queue GROUP BY status"
            ).fetchall()
        for status, count in rows:
            counts[status] = count
        total = sum(counts.values())
        summary = (
            f"queue_total={total} "
            f"pending={counts['pending']} "
            f"retry={counts['retry']} "
            f"in_progress={counts['in_progress']} "
            f"failed={counts['failed']}"
        )
        return total, summary

    def _enqueue_evidence(self, evidence: dict) -> Optional[int]:
        if not self.queue_db:
            self._init_direct_export_queue()
        evidence_id = evidence.get("id")
        now = time.time()
        payload = json.dumps(evidence)
        with self.queue_lock:
            cur = self.queue_db.cursor()
            cur.execute(
                """
                INSERT OR IGNORE INTO export_queue
                (evidence_id, evidence_json, status, attempts, last_error,
                 next_retry_at, created_at, updated_at)
                VALUES (?, ?, 'pending', 0, NULL, 0, ?, ?)
                """,
                (evidence_id, payload, now, now),
            )
            self.queue_db.commit()
            row_id = cur.lastrowid
        total, summary = self._queue_counts()
        self._ensure_direct_export_workers(total)
        self.stix._log_export(
            f"Direct export enqueued id={evidence_id} "
            f"db_id={row_id} {summary}"
        )
        return row_id

    def _requeue_stuck_items(self, stuck_after: float = 300.0) -> int:
        if not self.queue_db:
            return 0
        cutoff = time.time() - stuck_after
        with self.queue_lock:
            cur = self.queue_db.cursor()
            cur.execute(
                """
                UPDATE export_queue
                SET status='retry', updated_at=?
                WHERE status='in_progress' AND updated_at < ?
                """,
                (time.time(), cutoff),
            )
            requeued = cur.rowcount
            self.queue_db.commit()
        if requeued:
            self.stix._log_export(
                f"Direct export requeued stuck_items={requeued} "
                f"stuck_after={stuck_after}s"
            )
        return requeued

    def _has_pending_items(self) -> bool:
        if not self.queue_db:
            return False
        with self.queue_lock:
            row = self.queue_db.execute(
                """
                SELECT COUNT(*)
                FROM export_queue
                WHERE status IN ('pending', 'retry')
                """
            ).fetchone()
        return bool(row and row[0] > 0)

    def _claim_next_item(self) -> Optional[Tuple[int, dict, int, float]]:
        if not self.queue_db:
            return None
        self._requeue_stuck_items()
        now = time.time()
        with self.queue_lock:
            cur = self.queue_db.cursor()
            cur.execute("BEGIN IMMEDIATE")
            row = cur.execute(
                """
                SELECT id, evidence_json, attempts, created_at
                FROM export_queue
                WHERE status IN ('pending', 'retry')
                  AND next_retry_at <= ?
                ORDER BY id
                LIMIT 1
                """,
                (now,),
            ).fetchone()
            if not row:
                cur.execute("COMMIT")
                return None
            item_id, evidence_json, attempts, created_at = row
            attempts += 1
            cur.execute(
                """
                UPDATE export_queue
                SET status='in_progress', attempts=?, updated_at=?
                WHERE id=?
                """,
                (attempts, now, item_id),
            )
            cur.execute("COMMIT")
        try:
            evidence = json.loads(evidence_json)
        except Exception:
            evidence = {}
        return item_id, evidence, attempts, created_at

    def _start_direct_export_workers(self, count: int):
        self._init_direct_export_queue()
        if not self.direct_export_stop:
            self.direct_export_stop = threading.Event()
        start_idx = len(self.direct_export_workers)
        for idx in range(start_idx, start_idx + count):
            worker = threading.Thread(
                target=self._direct_export_worker,
                name=f"stix_direct_export_worker_{idx}",
                daemon=True,
            )
            worker.start()
            self.direct_export_workers.append(worker)
        self.stix._log_export(
            f"Direct export workers started count={len(self.direct_export_workers)}"
        )

    def _ensure_direct_export_workers(self, queue_size: int):
        with self.direct_export_start_lock:
            # prune dead workers
            alive_workers = []
            for worker in self.direct_export_workers:
                if worker.is_alive():
                    alive_workers.append(worker)
                else:
                    self.stix._log_export(
                        f"Direct export worker died name={worker.name}"
                    )
            if len(alive_workers) != len(self.direct_export_workers):
                self.direct_export_workers = alive_workers

            if not self.direct_export_workers:
                self._start_direct_export_workers(
                    self.stix.direct_export_workers
                )
                return

            max_workers = max(
                self.stix.direct_export_workers,
                self.stix.direct_export_max_workers,
            )
            target = len(self.direct_export_workers)
            if queue_size > target * 2 and target < max_workers:
                target = min(max_workers, target + 1)

            if target > len(self.direct_export_workers):
                self._start_direct_export_workers(
                    target - len(self.direct_export_workers)
                )

    def _direct_export_worker(self):
        while True:
            if self.direct_export_stop and self.direct_export_stop.is_set():
                if not self._has_pending_items():
                    return
            try:
                claimed = self._claim_next_item()
            except Exception as err:
                self.stix._log_export(f"Direct export worker error: {err}")
                time.sleep(0.5)
                continue
            try:
                if not claimed:
                    time.sleep(0.5)
                    continue
                item_id, evidence, attempt, created_at = claimed
                evidence_id = (
                    evidence.get("id") if isinstance(evidence, dict) else None
                )
                queue_delay = time.time() - created_at
                self.stix._log_export(
                    f"Direct export dequeue id={evidence_id} "
                    f"attempt={attempt} "
                    f"queue_delay_seconds={queue_delay}"
                )
                exported = self.stix.export_evidence_direct(evidence)
                if exported:
                    with self.queue_lock:
                        self.queue_db.execute(
                            "DELETE FROM export_queue WHERE id=?",
                            (item_id,),
                        )
                        self.queue_db.commit()
                    continue

                retry_max = self.stix.direct_export_retry_max
                backoff = self.stix.direct_export_retry_backoff * (
                    2 ** (attempt - 1)
                )
                if backoff > self.stix.direct_export_retry_max_delay:
                    backoff = self.stix.direct_export_retry_max_delay
                self.stix._log_export(
                    f"Direct export retry scheduled id={evidence_id} "
                    f"attempt={attempt} backoff_seconds={backoff}"
                )
                next_retry_at = time.time() + backoff
                status = "retry"
                if retry_max > 0 and attempt >= retry_max:
                    status = "failed"
                with self.queue_lock:
                    self.queue_db.execute(
                        """
                        UPDATE export_queue
                        SET status=?, next_retry_at=?, updated_at=?, last_error=?
                        WHERE id=?
                        """,
                        (
                            status,
                            next_retry_at,
                            time.time(),
                            "export_failed",
                            item_id,
                        ),
                    )
                    self.queue_db.commit()
            except Exception as err:
                self.stix._log_export(f"Direct export worker error: {err}")

    def shutdown_gracefully(self):
        self.slack.shutdown_gracefully()
        if self.direct_export_stop:
            self.direct_export_stop.set()
            for worker in self.direct_export_workers:
                worker.join(timeout=5)
        if self.queue_db:
            self.queue_db.close()
        self.stix.shutdown_gracefully()

    def pre_main(self):
        utils.drop_root_privs_permanently()

        export_to_slack = self.slack.should_export()
        export_to_stix = self.stix.should_export()

        if not export_to_slack and not export_to_stix:
            self.print(
                "Exporting Alerts module disabled (no export targets configured).",
                0,
                2,
            )
            return 1

        if export_to_slack:
            self.slack.send_init_msg()

        if export_to_stix and self.stix.direct_export:
            self._start_direct_export_workers(self.stix.direct_export_workers)
        elif export_to_stix and self.stix.is_running_non_stop:
            # This thread is responsible for waiting n seconds before
            # each push to the stix server
            # it starts the timer when the first alert happens
            self.stix.start_exporting_thread()

    def remove_sensitive_info(self, evidence: dict) -> str:
        """
        removes the leaked location co-ords from the evidence
        description before exporting
        returns the description without sensitive info
        """
        if "NETWORK_GPS_LOCATION_LEAKED" not in evidence["evidence_type"]:
            return evidence["description"]

        description = evidence["description"]
        return description[: description.index("Leaked location")]

    def main(self):
        # a msg is sent here for each evidence that was part of an alert
        if msg := self.get_msg("export_evidence"):
            evidence = json.loads(msg["data"])
            self.print(
                f"[ExportingAlerts] Evidence {evidence.get('id')} "
                f"type={evidence.get('evidence_type')} received.",
                2,
                0,
            )
            description = self.remove_sensitive_info(evidence)
            if self.slack.should_export():
                srcip = evidence["profile"]["ip"]
                msg_to_send = f"Src IP {srcip} Detected {description}"
                self.slack.export(msg_to_send)

            if self.stix.should_export():
                if self.stix.direct_export:
                    if not self.direct_export_workers:
                        self._start_direct_export_workers(
                            self.stix.direct_export_workers
                        )
                    self._enqueue_evidence(evidence)
                else:
                    added_to_stix: bool = self.stix.add_to_stix_file(evidence)
                    if added_to_stix:
                        # now export to taxii
                        self.stix.export()
                    else:
                        self.print("Problem in add_to_stix_file()", 0, 3)
