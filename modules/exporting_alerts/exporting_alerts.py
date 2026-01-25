# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import queue
import threading
import time

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
        self.print("Subscribed to export_evidence channel.", 1, 0)
        self.direct_export_q = None
        self.direct_export_stop = None
        self.direct_export_workers = []
        self.direct_export_start_lock = threading.Lock()

    def _start_direct_export_workers(self, count: int):
        if not self.direct_export_q:
            self.direct_export_q = queue.Queue()
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
                if self.direct_export_q and self.direct_export_q.empty():
                    return
            try:
                item = self.direct_export_q.get(timeout=1)
            except queue.Empty:
                continue
            try:
                evidence = item.get("evidence")
                enqueued_at = item.get("enqueued_at")
                attempt = item.get("attempt", 1)
                evidence_id = (
                    evidence.get("id") if isinstance(evidence, dict) else None
                )
                queue_delay = (
                    time.time() - enqueued_at
                    if isinstance(enqueued_at, (int, float))
                    else None
                )
                self.stix._log_export(
                    f"Direct export dequeue id={evidence_id} "
                    f"attempt={attempt} "
                    f"queue_delay_seconds={queue_delay}"
                )
                exported = self.stix.export_evidence_direct(evidence)
                if not exported:
                    retry_max = self.stix.direct_export_retry_max
                    if attempt <= retry_max:
                        backoff = self.stix.direct_export_retry_backoff * (
                            2 ** (attempt - 1)
                        )
                        if backoff > self.stix.direct_export_retry_max_delay:
                            backoff = self.stix.direct_export_retry_max_delay
                        self.stix._log_export(
                            f"Direct export retry scheduled id={evidence_id} "
                            f"attempt={attempt} backoff_seconds={backoff}"
                        )
                        time.sleep(backoff)
                        self.direct_export_q.put(
                            {
                                "evidence": evidence,
                                "enqueued_at": enqueued_at,
                                "attempt": attempt + 1,
                            }
                        )
                        qsize = self.direct_export_q.qsize()
                        self._ensure_direct_export_workers(qsize)
                    else:
                        self.stix._log_export(
                            f"Direct export dropped id={evidence_id} "
                            f"attempts={attempt}"
                        )
            except Exception as err:
                self.stix._log_export(
                    f"Direct export worker error: {err}"
                )
            finally:
                self.direct_export_q.task_done()

    def shutdown_gracefully(self):
        self.slack.shutdown_gracefully()
        if self.direct_export_stop:
            self.direct_export_stop.set()
            for worker in self.direct_export_workers:
                worker.join(timeout=5)
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
                    if not self.direct_export_q:
                        self._start_direct_export_workers(
                            self.stix.direct_export_workers
                        )
                    self.direct_export_q.put(
                        {
                            "evidence": evidence,
                            "enqueued_at": time.time(),
                            "attempt": 1,
                        }
                    )
                    qsize = self.direct_export_q.qsize()
                    self._ensure_direct_export_workers(qsize)
                    self.stix._log_export(
                        f"Direct export queued id={evidence.get('id')} "
                        f"queue_size={qsize}"
                    )
                else:
                    added_to_stix: bool = self.stix.add_to_stix_file(
                        evidence
                    )
                    if added_to_stix:
                        # now export to taxii
                        self.stix.export()
                    else:
                        self.print("Problem in add_to_stix_file()", 0, 3)
