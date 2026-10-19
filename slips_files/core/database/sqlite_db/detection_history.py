"""Maintain bounded detection history, hourly summaries and monthly archives."""

import json
import shutil
import re
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ENTITIES = {
    "evidence": (
        "evidence_id",
        "evidence_time",
        "evidence_flows",
        "uid",
        "evidence_reviews",
    ),
    "alerts": (
        "alert_id",
        "alert_time",
        "alert_evidence",
        "evidence_id",
        "alert_reviews",
    ),
}
ARCHIVE_TABLES = (
    "evidence",
    "alerts",
    "evidence_flows",
    "alert_evidence",
    "evidence_reviews",
    "alert_reviews",
    "flows",
    "altflows",
)
ARCHIVE_GLOB = "detections-*.sqlite"
ARCHIVE_NAME = re.compile(r"detections-\d{4}-\d{2}(?:-\d{4,10})?\.sqlite")
SUMMARY_COLUMNS = (
    "hour,profile_ip,evidence_type,threat_level,source_module,whitelisted,"
    "record_count,first_time,last_time,max_atl,max_ratl,alert_count"
)


def initialize_detection_history(connection: sqlite3.Connection) -> None:
    """Install counters, change tracking and restartable maintenance state.

    Parameters:
        connection: Run database connection under its writer locks.
    """
    connection.executescript(
        "CREATE TABLE IF NOT EXISTS history_totals(entity TEXT PRIMARY KEY, count INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS history_state(key TEXT PRIMARY KEY,value TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS history_dirty_hours(hour INTEGER PRIMARY KEY,generation INTEGER NOT NULL DEFAULT 1);"
        "CREATE TABLE IF NOT EXISTS history_summary_jobs(hour INTEGER PRIMARY KEY,generation INTEGER NOT NULL,"
        "cursor_time REAL NOT NULL,cursor_id TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS evidence_hourly(hour INTEGER NOT NULL,profile_ip TEXT,"
        "evidence_type TEXT,threat_level TEXT,source_module TEXT,"
        "whitelisted INTEGER NOT NULL,record_count INTEGER NOT NULL,first_time REAL NOT NULL,last_time REAL NOT NULL,"
        "max_atl REAL,max_ratl REAL,alert_count INTEGER NOT NULL,"
        "PRIMARY KEY(hour,profile_ip,evidence_type,threat_level,source_module,whitelisted));"
        "CREATE UNIQUE INDEX IF NOT EXISTS evidence_hourly_key_idx ON evidence_hourly("
        "hour,json_array(profile_ip,evidence_type,threat_level,source_module,whitelisted));"
        "CREATE TABLE IF NOT EXISTS history_archive_queue(entity TEXT PRIMARY KEY,record_id TEXT NOT NULL,"
        "filename TEXT NOT NULL,phase TEXT NOT NULL DEFAULT 'copy',cursor TEXT NOT NULL DEFAULT '',"
        "restart INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS history_archived_ids(entity TEXT NOT NULL,record_id TEXT NOT NULL,"
        "archived_at REAL NOT NULL,PRIMARY KEY(entity,record_id));"
        "CREATE INDEX IF NOT EXISTS history_archived_age_idx ON history_archived_ids(archived_at);"
        "CREATE INDEX IF NOT EXISTS evidence_time_cover_idx ON evidence(evidence_time,evidence_id,"
        "profile_ip,evidence_type,threat_level,source_module,whitelisted,accumulated_threat_level,accumulated_ratl);"
        "CREATE INDEX IF NOT EXISTS alert_evidence_lookup_idx ON alert_evidence(evidence_id,alert_id);"
    )
    for table, (key, timestamp, child, child_key, _) in ENTITIES.items():
        if (
            connection.execute(
                "SELECT 1 FROM history_totals WHERE entity=?", (table,)
            ).fetchone()
            is None
        ):
            count = connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO history_totals VALUES (?,?)", (table, count)
            )
        for operation, sign in (("INSERT", "+1"), ("DELETE", "-1")):
            connection.execute(
                f"CREATE TRIGGER IF NOT EXISTS history_{table}_{operation.lower()} AFTER {operation} ON {table} "
                f"BEGIN UPDATE history_totals SET count=count{sign} WHERE entity='{table}'; END"
            )
        for operation in ("INSERT", "UPDATE", "DELETE"):
            connection.execute(
                f"CREATE TRIGGER IF NOT EXISTS archive_{child}_{operation.lower()} AFTER {operation} ON {child} "
                "BEGIN UPDATE history_archive_queue SET restart=1 WHERE "
                f"entity='{table}' AND record_id={'OLD' if operation == 'DELETE' else 'NEW'}.{key} "
                "AND phase='copy'; END"
            )
    for operation in ("INSERT", "UPDATE", "DELETE"):
        rows = (
            ("OLD", "NEW")
            if operation == "UPDATE"
            else ("OLD" if operation == "DELETE" else "NEW",)
        )
        dirty = "".join(
            "INSERT INTO history_dirty_hours(hour) SELECT CAST("
            f"{row}.evidence_time/3600 AS INTEGER)*3600 WHERE {row}.evidence_time IS NOT NULL "
            "ON CONFLICT(hour) DO UPDATE SET generation=generation+1;"
            for row in rows
        )
        connection.execute(
            f"CREATE TRIGGER IF NOT EXISTS summary_evidence_{operation.lower()} AFTER {operation} ON evidence "
            f"BEGIN {dirty} END"
        )
        dirty_links = "".join(
            "INSERT INTO history_dirty_hours(hour) SELECT CAST(evidence_time/3600 AS INTEGER)*3600 "
            f"FROM evidence WHERE evidence_id={row}.evidence_id AND evidence_time IS NOT NULL "
            "ON CONFLICT(hour) DO UPDATE SET generation=generation+1;"
            for row in rows
        )
        connection.execute(
            f"CREATE TRIGGER IF NOT EXISTS summary_links_{operation.lower()} AFTER {operation} ON alert_evidence "
            f"BEGIN {dirty_links} END"
        )
    connection.commit()


class DetectionHistory:
    """Move expired detections only after their archive has durably committed."""

    def __init__(
        self, connection: sqlite3.Connection, output_dir: str
    ) -> None:
        """Bind maintenance to one run database.

        Parameters:
            connection: Run connection protected by its process and thread locks.
            output_dir: Relative run output directory.
        """
        self.connection = connection
        self.directory = Path(output_dir) / "databases" / "archives"

    def _state(self, key: str, default: str = "0") -> str:
        """Read a persistent maintenance checkpoint.

        Parameters:
            key: Checkpoint name.
            default: Value returned before the first checkpoint.

        Returns:
            Stored checkpoint text.
        """
        row = self.connection.execute(
            "SELECT value FROM history_state WHERE key=?", (key,)
        ).fetchone()
        return str(row[0]) if row else default

    def _set_state(self, key: str, value: Any) -> None:
        """Write a maintenance checkpoint in the current transaction.

        Parameters:
            key: Checkpoint name.
            value: JSON-compatible checkpoint value.
        """
        self.connection.execute(
            "INSERT INTO history_state VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )

    def summary_step(self, batch_size: int) -> int:
        """Backfill or rebuild a bounded piece of one dirty hourly summary.

        Parameters:
            batch_size: Maximum evidence records examined in this step.

        Returns:
            Number of records processed, or zero when summaries are current.
        """
        connection = self.connection
        connection.execute("BEGIN IMMEDIATE")
        if self._state("summary_complete") != "1":
            cursor = int(self._state("summary_cursor"))
            rows = connection.execute(
                "SELECT rowid,evidence_time FROM evidence WHERE rowid>? ORDER BY rowid LIMIT ?",
                (cursor, batch_size),
            ).fetchall()
            if rows:
                connection.executemany(
                    "INSERT OR IGNORE INTO history_dirty_hours(hour) VALUES (?)",
                    [
                        (int(row[1] // 3600) * 3600,)
                        for row in rows
                        if row[1] is not None
                    ],
                )
                self._set_state("summary_cursor", rows[-1][0])
                connection.commit()
                return len(rows)
            self._set_state("summary_complete", 1)
        dirty = connection.execute(
            "SELECT hour,generation FROM history_dirty_hours ORDER BY hour LIMIT 1"
        ).fetchone()
        if dirty is None:
            connection.commit()
            return 0
        hour, generation = dirty
        job = connection.execute(
            "SELECT generation,cursor_time,cursor_id FROM history_summary_jobs WHERE hour=?",
            (hour,),
        ).fetchone()
        if job is None or job[0] != generation:
            connection.execute(
                "DELETE FROM evidence_hourly WHERE hour=?", (hour,)
            )
            connection.execute(
                "INSERT OR REPLACE INTO history_summary_jobs VALUES (?,?,?,?)",
                (hour, generation, hour, ""),
            )
            cursor_time, cursor_id = hour, ""
        else:
            _, cursor_time, cursor_id = job
        rows = connection.execute(
            "SELECT evidence_id,evidence_time,profile_ip,evidence_type,"
            "threat_level,source_module,COALESCE(whitelisted,0),"
            "accumulated_threat_level,accumulated_ratl,"
            "(SELECT COUNT(*) FROM alert_evidence ae WHERE ae.evidence_id=e.evidence_id) "
            "FROM evidence e INDEXED BY evidence_time_cover_idx WHERE evidence_time>=? AND evidence_time<? "
            "AND (evidence_time,evidence_id)>(?,?) ORDER BY evidence_time,evidence_id LIMIT ?",
            (hour, hour + 3600, cursor_time, cursor_id, batch_size),
        ).fetchall()
        for (
            identifier,
            timestamp,
            ip,
            kind,
            threat,
            module,
            excluded,
            atl,
            ratl,
            alerts,
        ) in rows:
            connection.execute(
                f"INSERT INTO evidence_hourly({SUMMARY_COLUMNS}) VALUES (?,?,?,?,?,?,1,?,?,?,?,?) "
                "ON CONFLICT DO UPDATE SET "
                "record_count=record_count+1,first_time=MIN(first_time,excluded.first_time),"
                "last_time=MAX(last_time,excluded.last_time),max_atl=MAX(COALESCE(max_atl,0),COALESCE(excluded.max_atl,0)),"
                "max_ratl=MAX(COALESCE(max_ratl,0),COALESCE(excluded.max_ratl,0)),alert_count=alert_count+excluded.alert_count",
                (
                    hour,
                    ip,
                    kind,
                    threat,
                    module,
                    excluded,
                    timestamp,
                    timestamp,
                    atl,
                    ratl,
                    alerts,
                ),
            )
        if rows:
            connection.execute(
                "UPDATE history_summary_jobs SET cursor_time=?,cursor_id=? WHERE hour=?",
                (rows[-1][1], rows[-1][0], hour),
            )
        if len(rows) < batch_size:
            connection.execute(
                "DELETE FROM history_dirty_hours WHERE hour=?", (hour,)
            )
            connection.execute(
                "DELETE FROM history_summary_jobs WHERE hour=?", (hour,)
            )
        connection.commit()
        return max(len(rows), 1)

    def _open_archive(self, filename: str) -> sqlite3.Connection:
        """Open a monthly archive with durable commits and compatible tables.

        Parameters:
            filename: Internally generated monthly archive filename.

        Returns:
            Writable archive connection with no pending transaction.
        """
        self.directory.mkdir(parents=True, exist_ok=True)
        if (self.directory / filename).is_symlink():
            raise OSError("Archive destination must not be a symbolic link")
        archive = sqlite3.connect(self.directory / filename, timeout=0.1)
        try:
            archive.execute("PRAGMA synchronous=FULL")
            for table in ARCHIVE_TABLES:
                row = self.connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                    (table,),
                ).fetchone()
                if row:
                    archive.execute(
                        row[0].replace(
                            "CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1
                        )
                    )
            archive.executescript(
                "CREATE TABLE IF NOT EXISTS archive_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);"
                "CREATE INDEX IF NOT EXISTS evidence_time_cover_idx ON evidence(evidence_time,evidence_id,"
                "profile_ip,evidence_type,threat_level,source_module,whitelisted,accumulated_threat_level,accumulated_ratl);"
                "CREATE INDEX IF NOT EXISTS archive_alert_time_idx ON alerts(alert_time,alert_id);"
                "CREATE INDEX IF NOT EXISTS alert_evidence_lookup_idx ON alert_evidence(evidence_id,alert_id);"
                "CREATE INDEX IF NOT EXISTS evidence_flows_uid_idx ON evidence_flows(uid);"
            )
            return archive
        except Exception:
            archive.close()
            raise

    def _copy_row(
        self,
        archive: sqlite3.Connection,
        table: str,
        key: str,
        identifier: str,
    ) -> bool:
        """Replace one archive row with its current source value.

        Parameters:
            archive: Destination connection.
            table: Internal table name.
            key: Internal identifier column.
            identifier: Detection identifier.

        Returns:
            Whether the source row exists.
        """
        cursor = self.connection.execute(
            f"SELECT * FROM {table} WHERE {key}=?", (identifier,)
        )
        row = cursor.fetchone()
        if row is None:
            return False
        columns = ",".join(column[0] for column in cursor.description)
        marks = ",".join("?" for _ in row)
        archive.execute(
            f"INSERT OR REPLACE INTO {table}({columns}) VALUES ({marks})",
            tuple(row),
        )
        return True

    def archive_step(
        self,
        entity: str,
        cutoff: float,
        batch_size: int,
        now: float,
        file_size_mb: int = 256,
    ) -> int:
        """Copy or purge one restartable, bounded relationship batch.

        Parameters:
            entity: Internal evidence or alerts table name.
            cutoff: Oldest timestamp retained in the active database.
            batch_size: Maximum relationships transferred or removed.
            now: Current Unix time used for the rotation month.
            file_size_mb: Target size of a completed monthly segment.

        Returns:
            Number of maintenance units completed.
        """
        connection = self.connection
        key, timestamp, child, child_key, reviews = ENTITIES[entity]
        connection.execute("BEGIN IMMEDIATE")
        queue = connection.execute(
            "SELECT record_id,filename,phase,cursor,restart FROM history_archive_queue WHERE entity=?",
            (entity,),
        ).fetchone()
        if queue is None:
            protected = (
                " AND NOT EXISTS (SELECT 1 FROM alert_evidence ae JOIN alerts a ON a.alert_id=ae.alert_id "
                "WHERE ae.evidence_id=evidence.evidence_id AND a.alert_time>=?)"
                if entity == "evidence"
                else ""
            )
            candidate = connection.execute(
                f"SELECT {key} FROM {entity} WHERE {timestamp}<?{protected} ORDER BY {timestamp},{key} LIMIT 1",
                (cutoff, cutoff) if protected else (cutoff,),
            ).fetchone()
            if candidate is None:
                connection.commit()
                return 0
            identifier = candidate[0]
            prefix = datetime.fromtimestamp(now, timezone.utc).strftime(
                "detections-%Y-%m"
            )
            files = sorted(
                (
                    path
                    for path in self.directory.glob(f"{prefix}-*.sqlite")
                    if ARCHIVE_NAME.fullmatch(path.name)
                ),
                key=lambda path: int(path.stem.rsplit("-", 1)[1]),
            )
            previous = self._state("archive_filename", "")
            part = int(files[-1].stem.rsplit("-", 1)[1]) if files else 1
            if previous.startswith(prefix + "-"):
                part = max(
                    part,
                    int(Path(previous).stem.rsplit("-", 1)[1])
                    + (0 if (self.directory / previous).exists() else 1),
                )
            selected = self.directory / f"{prefix}-{part:04d}.sqlite"
            if (
                selected.exists()
                and selected.stat().st_size >= file_size_mb * 1024 * 1024
            ):
                part += 1
            filename = f"{prefix}-{part:04d}.sqlite"
            self._set_state("archive_filename", filename)
            connection.execute(
                "INSERT INTO history_archive_queue(entity,record_id,filename) VALUES (?,?,?)",
                (entity, identifier, filename),
            )
            phase, cursor, restart = "copy", "", 0
        else:
            identifier, filename, phase, cursor, restart = queue
        with closing(self._open_archive(filename)) as archive:
            try:
                if phase == "purge":
                    if connection.execute(
                        f"SELECT 1 FROM {entity} WHERE {key}=?", (identifier,)
                    ).fetchone():
                        connection.execute(
                            "DELETE FROM history_archive_queue WHERE entity=?",
                            (entity,),
                        )
                        connection.commit()
                        return 1
                    rows = connection.execute(
                        f"SELECT {child_key} FROM {child} WHERE {key}=? ORDER BY {child_key} LIMIT ?",
                        (identifier, batch_size),
                    ).fetchall()
                    # Also preserve links that arrived after the parent was archived.
                    archive.executemany(
                        f"INSERT OR IGNORE INTO {child}({key},{child_key}) VALUES (?,?)",
                        [(identifier, row[0]) for row in rows],
                    )
                    archive.execute(
                        "INSERT OR REPLACE INTO archive_metadata VALUES ('updated_at',?)",
                        (str(now),),
                    )
                    archive.commit()
                    connection.executemany(
                        f"DELETE FROM {child} WHERE {key}=? AND {child_key}=?",
                        [(identifier, row[0]) for row in rows],
                    )
                    if len(rows) < batch_size:
                        connection.execute(
                            "DELETE FROM history_archive_queue WHERE entity=?",
                            (entity,),
                        )
                elif restart:
                    rows = archive.execute(
                        f"SELECT {child_key} FROM {child} WHERE {key}=? ORDER BY {child_key} LIMIT ?",
                        (identifier, batch_size),
                    ).fetchall()
                    archive.executemany(
                        f"DELETE FROM {child} WHERE {key}=? AND {child_key}=?",
                        [(identifier, row[0]) for row in rows],
                    )
                    archive.execute(
                        "INSERT OR REPLACE INTO archive_metadata VALUES ('updated_at',?)",
                        (str(now),),
                    )
                    archive.commit()
                    if len(rows) < batch_size:
                        connection.execute(
                            "UPDATE history_archive_queue SET restart=0,cursor='' WHERE entity=?",
                            (entity,),
                        )
                else:
                    parent = connection.execute(
                        f"SELECT {timestamp} FROM {entity} WHERE {key}=?",
                        (identifier,),
                    ).fetchone()
                    protected = (
                        entity == "evidence"
                        and connection.execute(
                            "SELECT 1 FROM alert_evidence ae JOIN alerts a ON a.alert_id=ae.alert_id "
                            "WHERE ae.evidence_id=? AND a.alert_time>=? LIMIT 1",
                            (identifier, cutoff),
                        ).fetchone()
                    )
                    if (
                        parent is None
                        or parent[0] is None
                        or float(parent[0]) >= cutoff
                        or protected
                    ):
                        connection.execute(
                            "DELETE FROM history_archive_queue WHERE entity=?",
                            (entity,),
                        )
                        connection.commit()
                        return 1
                    rows = connection.execute(
                        f"SELECT {child_key} FROM {child} WHERE {key}=? AND {child_key}>? "
                        f"ORDER BY {child_key} LIMIT ?",
                        (identifier, cursor, batch_size),
                    ).fetchall()
                    archive.executemany(
                        f"INSERT OR IGNORE INTO {child}({key},{child_key}) VALUES (?,?)",
                        [(identifier, row[0]) for row in rows],
                    )
                    finished = len(rows) < batch_size
                    if finished:
                        self._copy_row(archive, entity, key, identifier)
                        self._copy_row(archive, reviews, key, identifier)
                        archive.execute(
                            "INSERT OR REPLACE INTO archive_metadata VALUES ('ready','1')"
                        )
                    archive.execute(
                        "INSERT OR REPLACE INTO archive_metadata VALUES ('updated_at',?)",
                        (str(now),),
                    )
                    archive.commit()
                    if finished:
                        connection.execute(
                            "INSERT OR REPLACE INTO history_archived_ids VALUES (?,?,?)",
                            (entity, identifier, now),
                        )
                        connection.execute(
                            f"DELETE FROM {entity} WHERE {key}=?",
                            (identifier,),
                        )
                        connection.execute(
                            f"DELETE FROM {reviews} WHERE {key}=?",
                            (identifier,),
                        )
                        connection.execute(
                            "UPDATE history_archive_queue SET phase='purge',cursor='' WHERE entity=?",
                            (entity,),
                        )
                    elif rows:
                        connection.execute(
                            "UPDATE history_archive_queue SET cursor=? WHERE entity=?",
                            (rows[-1][0], entity),
                        )
                connection.commit()
            finally:
                archive.rollback()
        return 1

    def expire_archives(
        self, now: float, retention_days: int, max_size_mb: int = 0
    ) -> int:
        """Remove at most one expired, unused monthly archive per pass.

        Parameters:
            now: Current Unix time.
            retention_days: Days to retain an archive after its last write.
            max_size_mb: Optional cap for completed archive storage.

        Returns:
            Number of removed archive files.
        """
        queued = {
            str(row[0])
            for row in self.connection.execute(
                "SELECT filename FROM history_archive_queue"
            )
        }
        paths = sorted(
            (
                path
                for path in self.directory.glob(ARCHIVE_GLOB)
                if ARCHIVE_NAME.fullmatch(path.name) and not path.is_symlink()
            ),
            key=lambda path: path.stat().st_mtime,
        )
        size = sum(path.stat().st_size for path in paths)
        for path in paths:
            over_size = bool(max_size_mb and size > max_size_mb * 1024 * 1024)
            updated = path.stat().st_mtime
            try:
                with sqlite3.connect(
                    f"file:{path}?mode=ro", uri=True, timeout=0.1
                ) as archive:
                    row = archive.execute(
                        "SELECT value FROM archive_metadata WHERE key='updated_at'"
                    ).fetchone()
                    if row:
                        updated = float(row[0])
            except sqlite3.OperationalError:
                pass
            if path.name in queued or (
                not over_size and updated >= now - retention_days * 86400
            ):
                continue
            path.unlink()
            return 1
        return 0

    def maintain(
        self, policy: dict[str, int | bool], now: float
    ) -> dict[str, Any]:
        """Share a short work budget between rollups, archives and expiration.

        Parameters:
            policy: Validated detection_history configuration.
            now: Current Unix time.

        Returns:
            Persistent maintenance health and progress statistics.
        """
        started = time.monotonic()
        deadline = started + int(policy["work_budget_ms"]) / 1000
        batch = int(policy["batch_size"])
        status: dict[str, Any] = {
            "last_run": now,
            "units": 0,
            "interrupted": False,
        }
        status["expired_archives"] = self.expire_archives(
            now,
            int(policy["archive_retention_days"]),
            int(policy.get("max_archive_size_mb", 4096)),
        )
        self.connection.execute(
            "DELETE FROM history_archived_ids WHERE rowid IN "
            "(SELECT rowid FROM history_archived_ids WHERE archived_at<? LIMIT ?)",
            (now - int(policy["active_days"]) * 86400, batch),
        )
        self.connection.commit()
        free = shutil.disk_usage(self.directory.parent).free
        status["disk_pressure"] = (
            free < int(policy["min_free_disk_mb"]) * 1024 * 1024
        )
        page_size = self.connection.execute("PRAGMA page_size").fetchone()[0]
        pages = self.connection.execute("PRAGMA page_count").fetchone()[0]
        free_pages = self.connection.execute(
            "PRAGMA freelist_count"
        ).fetchone()[0]
        target = int(policy.get("max_active_size_mb", 2048)) * 1024 * 1024
        status["active_size_bytes"] = (pages - free_pages) * page_size
        status["size_pressure"] = bool(
            target and status["active_size_bytes"] > target
        )
        age_seconds = int(policy["active_days"]) * 86400
        if status["size_pressure"]:
            age_seconds = min(
                age_seconds, int(policy.get("min_active_hours", 24)) * 3600
            )
        self.connection.set_progress_handler(
            lambda: int(time.monotonic() >= deadline), 1000
        )
        try:
            while time.monotonic() < deadline:
                units = self.summary_step(batch)
                if not status["disk_pressure"]:
                    for entity in ENTITIES:
                        if time.monotonic() >= deadline:
                            break
                        units += self.archive_step(
                            entity,
                            now - age_seconds,
                            batch,
                            now,
                            int(policy.get("archive_file_size_mb", 256)),
                        )
                status["units"] += units
                if not units:
                    break
        except sqlite3.OperationalError as error:
            if (
                "interrupt" not in str(error).lower()
                and "locked" not in str(error).lower()
            ):
                raise
            status["interrupted"] = True
        finally:
            self.connection.set_progress_handler(None, 0)
            self.connection.rollback()
        status["elapsed_ms"] = round((time.monotonic() - started) * 1000, 1)
        status["pending_hours"] = self.connection.execute(
            "SELECT COUNT(*) FROM history_dirty_hours"
        ).fetchone()[0]
        status["pending_archives"] = self.connection.execute(
            "SELECT COUNT(*) FROM history_archive_queue"
        ).fetchone()[0]
        status["oldest_detection_at"] = self.connection.execute(
            "SELECT MIN(evidence_time) FROM evidence"
        ).fetchone()[0]
        status["active_target_bytes"] = target
        status["archive_target_bytes"] = (
            int(policy.get("max_archive_size_mb", 4096)) * 1024 * 1024
        )
        self._set_state("maintenance", json.dumps(status))
        self.connection.commit()
        return status
