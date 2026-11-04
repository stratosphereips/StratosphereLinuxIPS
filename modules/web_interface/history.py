# SPDX-License-Identifier: GPL-2.0-only
"""Collect bounded, indexed history for the local web interface."""

import ipaddress
import json
import math
import re
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import redis
from modules.supported_module_names import Modules
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.sqlite_flock import SQLiteFlock
from slips_files.core.database.sqlite_db.host_profiles import HostProfileStore

ERROR_LINE = re.compile(
    r"^(?P<date>\d{4}[/-]\d{2}[/-]\d{2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+"
    r"\[(?P<module>[^]]+)]\s+(?P<message>.*)$"
)
MODULE_LINE = re.compile(r"^\[(?P<module>[^]]+)]\s+(?P<message>.*)$")
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SLIPS_LOG_NOISE = re.compile(
    r"^(?:Total\s+)?analyzed IPs\b|\[\s*\d+/\d+]\s*\[PID\s+\d+]"
    r"|^Starting (?:the\s+)?(?:modules?|process(?:es)?)\b"
    r"|detected as malicious.*following evidence"
    r"|^\s*- Detected\b|^\s*Weighted Threat Level:"
    r"|^\[EvidenceHandler] Export(?:ing evidence| streaming)\b",
    re.IGNORECASE,
)
MAX_ERROR_EVENT_CHARS = 256 * 1024
RAW_METRIC_RETENTION_SECONDS = 24 * 60 * 60
FLOW_INDEX_BATCH_SIZE = 5000
FLOW_RECONCILE_BATCH_SIZE = 500
HOST_SNAPSHOT_INTERVAL_SECONDS = 60
BACKEND_HEARTBEAT_KEY = "backend_heartbeat_at"
BACKEND_DISCONNECTED_KEY = "backend_disconnected_at"
NETWORK_SCOPES_KEY = "current_network_scopes"
RUNTIME_RESOURCES_KEY = "runtime_resources"
REDIS_PROCESS_CHECK_SECONDS = 30


def network_connection_scope(
    state: Dict[str, Any],
    saved: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Find a connection boundary, joining restarts on the same router.

    Parameters:
        state: Current interface snapshot, including recent changes.
        saved: Last connection boundary retained in this output folder.

    Returns:
        Bounded connection checkpoint with an optional start timestamp.
    """
    try:
        changed_at = float(state["changed_at"])
    except (KeyError, TypeError, ValueError):
        return {}
    if not math.isfinite(changed_at):
        return {}
    gateway = str(state.get("gateway_mac") or "").lower()
    result = {
        "connected": bool(state.get("connected")),
        "gateway_mac": gateway,
        "changed_at": changed_at,
        "start": None,
    }
    if not result["connected"]:
        return result
    start = changed_at
    barrier = False
    history = state.get("history", [])
    for previous in reversed(
        history[-10:] if isinstance(history, list) and gateway else []
    ):
        if (
            not isinstance(previous, dict)
            or not previous.get("connected")
            or str(previous.get("gateway_mac") or "").lower() != gateway
        ):
            barrier = True
            break
        try:
            previous_start = float(previous["changed_at"])
        except (KeyError, TypeError, ValueError):
            barrier = True
            break
        if not math.isfinite(previous_start) or previous_start > start:
            barrier = True
            break
        start = previous_start
    if (
        gateway
        and isinstance(saved, dict)
        and saved.get("connected")
        and saved.get("gateway_mac") == gateway
    ):
        try:
            saved_start = float(saved["start"])
            saved_change = float(saved["changed_at"])
            if (
                math.isfinite(saved_start)
                and math.isfinite(saved_change)
                and saved_start <= saved_change <= changed_at
                and (not barrier or saved_change >= start)
            ):
                start = min(start, saved_start)
        except (KeyError, TypeError, ValueError):
            pass
    result["start"] = start
    return result


def connect_history(path: Path, read_only: bool = False) -> sqlite3.Connection:
    """
    Open the web history database.

    Parameters:
        path: Module-specific SQLite path.
        read_only: Open without write access when true.

    Returns:
        Configured SQLite connection.
    """
    if read_only:
        connection = sqlite3.connect(
            f"file:{path}?mode=ro", uri=True, timeout=5
        )
    else:
        connection = sqlite3.connect(path, timeout=20)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
    connection.row_factory = sqlite3.Row
    return connection


def initialize_history(path: Path) -> None:
    """
    Create the web history schema and indexes.

    Parameters:
        path: Module-specific SQLite path.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    statements = (
        "CREATE TABLE IF NOT EXISTS metadata ("
        "key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS flow_index ("
        "uid TEXT PRIMARY KEY, flow_rowid INTEGER NOT NULL, "
        "event_time REAL NOT NULL, src_ip TEXT NOT NULL, "
        "dst_ip TEXT NOT NULL, proto TEXT, app_proto TEXT, "
        "bytes INTEGER NOT NULL, packets INTEGER NOT NULL, "
        "source_packets INTEGER NOT NULL DEFAULT 0, label TEXT)",
        "CREATE INDEX IF NOT EXISTS flow_src_time_idx "
        "ON flow_index(src_ip, event_time DESC, uid)",
        "CREATE INDEX IF NOT EXISTS flow_dst_time_idx "
        "ON flow_index(dst_ip, event_time DESC, uid)",
        "CREATE INDEX IF NOT EXISTS flow_time_idx ON flow_index(event_time DESC, uid)",
        "CREATE TABLE IF NOT EXISTS host_snapshots ("
        "ip TEXT PRIMARY KEY, observed_at REAL NOT NULL, data TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS host_seen_idx "
        "ON host_snapshots(observed_at DESC, ip)",
        "CREATE TABLE IF NOT EXISTS error_events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, event_time REAL NOT NULL, "
        "module TEXT NOT NULL, message TEXT NOT NULL, line TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS error_time_idx "
        "ON error_events(event_time DESC, id)",
        "CREATE INDEX IF NOT EXISTS error_module_time_idx "
        "ON error_events(module, event_time DESC)",
        "CREATE TABLE IF NOT EXISTS runtime_metrics_1s ("
        "ts REAL PRIMARY KEY, cpu_percent REAL NOT NULL, "
        "memory_mb REAL NOT NULL, flows_per_second REAL NOT NULL, "
        "flow_delta REAL NOT NULL DEFAULT 0)",
        "CREATE INDEX IF NOT EXISTS metrics_1s_time_idx ON runtime_metrics_1s(ts)",
        "CREATE TABLE IF NOT EXISTS runtime_metrics_1m ("
        "bucket_ts REAL PRIMARY KEY, cpu_avg REAL NOT NULL, "
        "cpu_max REAL NOT NULL, memory_avg REAL NOT NULL, "
        "memory_max REAL NOT NULL, fps_avg REAL NOT NULL, "
        "fps_max REAL NOT NULL, flow_total REAL NOT NULL, "
        "samples INTEGER NOT NULL)",
        "CREATE INDEX IF NOT EXISTS metrics_1m_time_idx "
        "ON runtime_metrics_1m(bucket_ts)",
    )
    with connect_history(path) as connection:
        for statement in statements:
            connection.execute(statement)
        metric_columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(runtime_metrics_1s)"
            ).fetchall()
        }
        if "flow_delta" not in metric_columns:
            connection.execute(
                "ALTER TABLE runtime_metrics_1s "
                "ADD COLUMN flow_delta REAL NOT NULL DEFAULT 0"
            )
        flow_columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(flow_index)"
            ).fetchall()
        }
        if "source_packets" not in flow_columns:
            connection.execute(
                "ALTER TABLE flow_index ADD COLUMN source_packets "
                "INTEGER NOT NULL DEFAULT 0"
            )
            connection.execute(
                "UPDATE flow_index SET source_packets = packets"
            )
        log_columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(error_events)")
        }
        if "source" not in log_columns:
            connection.execute(
                "ALTER TABLE error_events ADD COLUMN source TEXT NOT NULL DEFAULT 'errors.log'"
            )
            connection.execute(
                "UPDATE error_events SET source='error.log' WHERE EXISTS "
                "(SELECT 1 FROM metadata WHERE key='error_log_name' AND value='error.log')"
            )
        if "time_source" not in log_columns:
            connection.execute(
                "ALTER TABLE error_events ADD COLUMN time_source TEXT NOT NULL DEFAULT 'logged'"
            )
        connection.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
            ("schema_version", "3"),
        )


class HistoryCollector:
    """Incrementally archive web indexes and operational measurements."""

    def __init__(
        self,
        output_dir: str,
        history_path: Path,
        redis_client: redis.Redis,
        root_pid: int,
        host_profiles_path: Optional[Path] = None,
    ) -> None:
        """
        Initialize collector state.

        Parameters:
            output_dir: Current run output directory.
            history_path: Module-specific history database.
            redis_client: Current run Redis client.
            root_pid: Main Slips process identifier.
            host_profiles_path: Shared permanent identity store.
        """
        self.output_dir = Path(output_dir)
        self.flows_path = self.output_dir / "databases" / "flows.sqlite"
        self.history_path = history_path
        self.redis = redis_client
        self.root_pid = root_pid
        self.host_profiles_path = (
            host_profiles_path
            or Path(ConfigParser().permanent_dir())
            / "host_profiles"
            / "hosts.sqlite"
        )
        self._processes: Dict[int, psutil.Process] = {}
        try:
            self._root_process = psutil.Process(root_pid)
        except psutil.Error:
            self._root_process = None
        self._redis_process: Optional[psutil.Process] = None
        self._last_redis_process_check = -float("inf")
        self._process_scope_complete = False
        self._last_flow_count: Optional[int] = None
        self._last_flow_check = time.monotonic()
        self._last_rollup = 0.0
        self._last_flow_reconcile = 0.0
        self._last_host_snapshot = 0.0
        self._detection_schema_ready = False
        self._redis_detection_backfill_complete = False
        initialize_history(self.history_path)

    @staticmethod
    def _metadata_get(
        connection: sqlite3.Connection, key: str, default: str = "0"
    ) -> str:
        """Read a collector checkpoint."""
        row = connection.execute(
            "SELECT value FROM metadata WHERE key = ?", (key,)
        ).fetchone()
        return str(row["value"]) if row else default

    @staticmethod
    def _metadata_set(
        connection: sqlite3.Connection, key: str, value: Any
    ) -> None:
        """Store a collector checkpoint."""
        connection.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
            (key, str(value)),
        )

    def record_backend_heartbeat(self, now: Optional[float] = None) -> float:
        """
        Record that the Slips-owned web collector is still alive.

        Parameters:
            now: Explicit Unix timestamp, or the current time when omitted.

        Returns:
            The heartbeat timestamp written to history.
        """
        heartbeat = time.time() if now is None else float(now)
        try:
            states = self.redis.hgetall("network_states")
        except redis.RedisError:
            states = None
        visits_changed = not getattr(
            self, "_network_visits_initialized", False
        )
        with connect_history(self.history_path) as connection:
            self._metadata_set(connection, BACKEND_HEARTBEAT_KEY, heartbeat)
            self._metadata_set(connection, BACKEND_DISCONNECTED_KEY, 0)
            if isinstance(states, dict) and states:
                old = self._metadata_get(connection, NETWORK_SCOPES_KEY, "{}")
                saved = self._json_value(old, {})
                saved = saved if isinstance(saved, dict) else {}
                scopes = {}
                for interface, raw in states.items():
                    state = self._json_value(raw, {})
                    if isinstance(state, dict):
                        scopes[interface] = network_connection_scope(
                            state, saved.get(interface)
                        )
                serialized = json.dumps(scopes, sort_keys=True)
                if serialized != old:
                    visits_changed = True
                    self._metadata_set(
                        connection, NETWORK_SCOPES_KEY, serialized
                    )
        if visits_changed and isinstance(states, dict) and states:
            from modules.web_interface.network_scope import (
                record_network_visits,
            )

            for interface, raw in states.items():
                state = self._json_value(raw, {})
                if isinstance(state, dict):
                    record_network_visits(
                        self.history_path,
                        interface,
                        state,
                        f"{self.output_dir}:{self.root_pid}",
                        saved.get(interface),
                    )
            self._network_visits_initialized = True
        return heartbeat

    def mark_backend_disconnected(self, now: Optional[float] = None) -> float:
        """
        Mark a clean separation between the retained page and Slips backend.

        Parameters:
            now: Explicit Unix timestamp, or the current time when omitted.

        Returns:
            The disconnection timestamp written to history.
        """
        disconnected_at = time.time() if now is None else float(now)
        with connect_history(self.history_path) as connection:
            self._metadata_set(
                connection, BACKEND_DISCONNECTED_KEY, disconnected_at
            )
        return disconnected_at

    def index_new_flows(self) -> int:
        """
        Index one bounded batch of raw flows.

        Returns:
            Number of indexed rows.
        """
        if not self.flows_path.exists():
            return 0
        with connect_history(self.history_path) as history:
            last_rowid = int(
                self._metadata_get(history, "flow_last_rowid", "0")
            )
            last_uid = self._metadata_get(history, "flow_last_uid", "")
            try:
                source = sqlite3.connect(
                    f"file:{self.flows_path}?mode=ro",
                    uri=True,
                    timeout=5,
                )
                source.row_factory = sqlite3.Row
                if last_rowid:
                    checkpoint = source.execute(
                        "SELECT uid FROM flows WHERE rowid = ?",
                        (last_rowid,),
                    ).fetchone()
                    if checkpoint is None:
                        # Deleting the tail permits SQLite to reuse rowids.
                        last_rowid = 0
                    elif not last_uid:
                        # Upgrade a pre-retention checkpoint in place.
                        self._metadata_set(
                            history, "flow_last_uid", checkpoint["uid"]
                        )
                    elif checkpoint["uid"] != last_uid:
                        last_rowid = 0
                rows = source.execute(
                    "SELECT rowid, uid, flow, label FROM flows "
                    "WHERE rowid > ? ORDER BY rowid LIMIT ?",
                    (last_rowid, FLOW_INDEX_BATCH_SIZE),
                ).fetchall()
                source.close()
            except sqlite3.Error:
                return 0
            indexed: List[tuple[Any, ...]] = []
            for row in rows:
                try:
                    flow = json.loads(row["flow"])
                except (TypeError, ValueError):
                    continue
                indexed.append(
                    (
                        str(row["uid"]),
                        int(row["rowid"]),
                        float(flow.get("starttime") or 0),
                        str(flow.get("saddr") or ""),
                        str(flow.get("daddr") or ""),
                        str(flow.get("proto") or ""),
                        str(flow.get("appproto") or ""),
                        int(flow.get("bytes") or 0),
                        int(flow.get("pkts") or 0),
                        int(flow.get("spkts") or flow.get("pkts") or 0),
                        str(row["label"] or ""),
                    )
                )
            if indexed:
                history.executemany(
                    "INSERT OR REPLACE INTO flow_index "
                    "(uid, flow_rowid, event_time, src_ip, dst_ip, proto, "
                    "app_proto, bytes, packets, source_packets, label) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    indexed,
                )
            if rows:
                self._metadata_set(
                    history, "flow_last_rowid", rows[-1]["rowid"]
                )
                self._metadata_set(history, "flow_last_uid", rows[-1]["uid"])
            self._metadata_set(history, "flow_index_updated_at", time.time())
            return len(indexed)

    def reconcile_flow_index(self) -> int:
        """Remove a bounded batch of indexes whose raw flows expired.

        Returns:
            Number of orphaned index rows removed in this pass.
        """
        if not self.flows_path.exists():
            return 0
        with connect_history(self.history_path) as history:
            last_uid = self._metadata_get(
                history, "flow_reconcile_last_uid", ""
            )
            rows = history.execute(
                "SELECT uid FROM flow_index WHERE uid > ? "
                "ORDER BY uid LIMIT ?",
                (last_uid, FLOW_RECONCILE_BATCH_SIZE),
            ).fetchall()
            if not rows:
                self._metadata_set(history, "flow_reconcile_last_uid", "")
                return 0
            uids = [str(row["uid"]) for row in rows]
            placeholders = ",".join("?" for _ in uids)
            try:
                with sqlite3.connect(
                    f"file:{self.flows_path}?mode=ro",
                    uri=True,
                    timeout=5,
                ) as source:
                    present = {
                        str(row[0])
                        for row in source.execute(
                            f"SELECT uid FROM flows WHERE uid IN "
                            f"({placeholders})",
                            uids,
                        ).fetchall()
                    }
            except sqlite3.Error:
                return 0
            missing = [uid for uid in uids if uid not in present]
            if missing:
                missing_placeholders = ",".join("?" for _ in missing)
                history.execute(
                    f"DELETE FROM flow_index WHERE uid IN "
                    f"({missing_placeholders})",
                    missing,
                )
            self._metadata_set(history, "flow_reconcile_last_uid", uids[-1])
            return len(missing)

    def _live_processes(self) -> List[psutil.Process]:
        """Resolve this run's Slips and Redis process trees, including Zeek.

        Returns:
            Unique live processes; inaccessible trees mark the sample partial.
        """
        self._process_scope_complete = True
        root = self._root_process
        try:
            running = root is not None and root.is_running()
        except psutil.Error:
            running = False
        if not running:
            self._process_scope_complete = False
            return []
        now = time.monotonic()
        if now - self._last_redis_process_check >= REDIS_PROCESS_CHECK_SECONDS:
            self._last_redis_process_check = now
            try:
                server = self.redis.info("server")
                pid = int(server["process_id"])
                self._redis_process = psutil.Process(pid) if pid > 0 else None
            except (
                redis.RedisError,
                psutil.Error,
                KeyError,
                TypeError,
                ValueError,
            ):
                self._redis_process = None
        roots = [root]
        if self._redis_process is not None:
            roots.append(self._redis_process)
        else:
            self._process_scope_complete = False
        unique: Dict[int, psutil.Process] = {}
        for owner in roots:
            try:
                if (
                    not owner.is_running()
                    or owner.status() == psutil.STATUS_ZOMBIE
                ):
                    self._process_scope_complete = False
                    continue
                unique[owner.pid] = owner
                descendants = owner.children(recursive=True)
            except psutil.Error:
                self._process_scope_complete = False
                continue
            for process in descendants:
                try:
                    if (
                        process.is_running()
                        and process.status() != psutil.STATUS_ZOMBIE
                    ):
                        unique[process.pid] = process
                except psutil.AccessDenied:
                    self._process_scope_complete = False
                except psutil.Error:
                    continue
        return list(unique.values())

    def sample_metrics(self) -> None:
        """Persist one CPU, memory, and profiler throughput sample."""
        cpu_total = 0.0
        memory_bytes = 0
        live_pids = set()
        for process in self._live_processes():
            live_pids.add(process.pid)
            cached = self._processes.get(process.pid)
            if cached is None or cached != process:
                cached = process
                self._processes[process.pid] = process
            try:
                with cached.oneshot():
                    cpu_total += cached.cpu_percent(interval=None)
                    memory_bytes += cached.memory_info().rss
            except psutil.AccessDenied:
                self._process_scope_complete = False
            except psutil.Error:
                continue
        self._processes = {
            pid: process
            for pid, process in self._processes.items()
            if pid in live_pids
        }
        cpu_count = max(psutil.cpu_count() or 1, 1)
        cpu_percent = cpu_total / cpu_count
        total_memory = max(psutil.virtual_memory().total, 1)
        try:
            current_count = int(
                self.redis.get("processed_flows_by_profiler_so_far") or 0
            )
        except (redis.RedisError, TypeError, ValueError):
            current_count = self._last_flow_count or 0
        now_monotonic = time.monotonic()
        elapsed = max(now_monotonic - self._last_flow_check, 0.001)
        flow_delta = 0.0
        flows_per_second = 0.0
        if self._last_flow_count is not None:
            flow_delta = max(current_count - self._last_flow_count, 0)
            flows_per_second = flow_delta / elapsed
        self._last_flow_count = current_count
        self._last_flow_check = now_monotonic
        with connect_history(self.history_path) as connection:
            self._metadata_set(
                connection,
                RUNTIME_RESOURCES_KEY,
                json.dumps(
                    {
                        "sampled_at": time.time(),
                        "root_pid": self.root_pid,
                        "cpu_percent": cpu_percent,
                        "memory_percent": memory_bytes / total_memory * 100,
                        "memory_bytes": memory_bytes,
                        "total_memory_bytes": total_memory,
                        "cpu_count": cpu_count,
                        "process_count": len(live_pids),
                        "complete": self._process_scope_complete,
                    }
                ),
            )
            connection.execute(
                "INSERT OR REPLACE INTO runtime_metrics_1s "
                "(ts, cpu_percent, memory_mb, flows_per_second, flow_delta) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    time.time(),
                    cpu_percent,
                    memory_bytes / 1024 / 1024,
                    flows_per_second,
                    flow_delta,
                ),
            )

    @staticmethod
    def _error_timestamp(date: str, clock: str) -> float:
        """Convert a Slips log timestamp to Unix time."""
        try:
            return datetime.fromisoformat(
                f"{date.replace('/', '-')} {clock}"
            ).timestamp()
        except ValueError:
            return 0.0

    @staticmethod
    def _store_error_event(
        connection: sqlite3.Connection,
        event_id: Optional[int],
        event_time: float,
        module: str,
        message: str,
        raw_text: str,
        source: str = "errors.log",
        time_source: str = "logged",
    ) -> int:
        """Insert a log event or extend its raw multiline source.

        Parameters:
            connection: Writable history database connection.
            event_id: Existing event ID when extending an earlier block.
            event_time: Timestamp from the event header.
            module: Module in the event header.
            message: Summary from the event header.
            raw_text: Header and retained continuation lines.
            source: Original log filename.
            time_source: Logged, observed, or unavailable timestamp.

        Returns:
            Stored event ID.
        """
        if event_id is not None:
            connection.execute(
                "UPDATE error_events SET line = ? WHERE id = ?",
                (raw_text, event_id),
            )
            return event_id
        cursor = connection.execute(
            "INSERT INTO error_events "
            "(event_time, module, message, line, source, time_source) VALUES (?, ?, ?, ?, ?, ?)",
            (event_time, module, message, raw_text, source, time_source),
        )
        return int(cursor.lastrowid)

    @staticmethod
    def _backfill_error_continuations(
        connection: sqlite3.Connection, error_path: Path
    ) -> int:
        """Attach existing traceback lines to imported header-only events.

        Parameters:
            connection: Writable history database connection.
            error_path: Current Slips error log.

        Returns:
            Number of existing events repaired.
        """
        matching_ids: dict[str, deque[Optional[int]]] = defaultdict(deque)
        for row in connection.execute(
            "SELECT id, line FROM error_events WHERE source=? ORDER BY id",
            (error_path.name,),
        ):
            raw_text = str(row["line"])
            header = raw_text.split("\n", 1)[0]
            matching_ids[header].append(
                int(row["id"]) if "\n" not in raw_text else None
            )
        if not matching_ids:
            return 0

        repaired = 0
        current_id: Optional[int] = None
        current_lines: list[str] = []
        current_size = 0
        try:
            with error_path.open(
                "r", encoding="utf-8", errors="replace"
            ) as handle:
                for line in handle:
                    header = line.rstrip()
                    if ERROR_LINE.match(header):
                        if current_id is not None and len(current_lines) > 1:
                            connection.execute(
                                "UPDATE error_events SET line = ? WHERE id = ?",
                                ("\n".join(current_lines), current_id),
                            )
                            repaired += 1
                        ids = matching_ids.get(header)
                        current_id = ids.popleft() if ids else None
                        current_lines = (
                            [header] if current_id is not None else []
                        )
                        current_size = len(header)
                    elif (
                        current_id is not None
                        and current_size < MAX_ERROR_EVENT_CHARS
                    ):
                        continuation = line.rstrip("\r\n")
                        current_lines.append(continuation)
                        current_size += len(continuation) + 1
        except OSError:
            return repaired
        if current_id is not None and len(current_lines) > 1:
            connection.execute(
                "UPDATE error_events SET line = ? WHERE id = ?",
                ("\n".join(current_lines), current_id),
            )
            repaired += 1
        return repaired

    def tail_errors(self) -> int:
        """
        Archive newly appended module log events.

        Returns:
            Number of archived events.
        """
        canonical = self.output_dir / "errors.log"
        legacy = self.output_dir / "error.log"
        error_path = canonical if canonical.exists() else legacy
        return self._tail_log(error_path)

    def tail_slips(self) -> int:
        """Archive useful slips.log messages without detection or startup noise.

        Returns:
            Number of newly archived events.
        """
        return self._tail_log(self.output_dir / "slips.log")

    def _tail_log(self, error_path: Path) -> int:
        """Read one bounded log batch with independent rotation checkpoints.

        Parameters:
            error_path: Runtime or error log in this run's output directory.

        Returns:
            Number of newly archived events.
        """
        if not error_path.exists():
            return 0
        runtime = error_path.name == "slips.log"
        offset_key = f"error_offset:{error_path.name}"
        last_event_key = f"error_last_event_id:{error_path.name}"
        with connect_history(self.history_path) as connection:
            backfill_key = f"error_multiline_backfilled:{error_path.name}"
            if (
                not runtime
                and self._metadata_get(connection, backfill_key, "0") != "1"
            ):
                self._backfill_error_continuations(connection, error_path)
                self._metadata_set(connection, backfill_key, 1)
            offset = int(self._metadata_get(connection, offset_key, "0"))
            try:
                stat = error_path.stat()
                inode_key = f"error_inode:{error_path.name}"
                inode = f"{stat.st_dev}:{stat.st_ino}"
                if (
                    stat.st_size < offset
                    or self._metadata_get(connection, inode_key, inode)
                    != inode
                ):
                    offset = 0
                    self._metadata_set(
                        connection, f"log_initial_size:{error_path.name}", 0
                    )
                self._metadata_set(connection, inode_key, inode)
                initial_size_key = f"log_initial_size:{error_path.name}"
                initial_size = int(
                    self._metadata_get(
                        connection, initial_size_key, str(stat.st_size)
                    )
                )
                self._metadata_set(connection, initial_size_key, initial_size)
            except OSError:
                return 0
            active_id: Optional[int] = None
            active_event: Optional[tuple[float, str, str]] = None
            active_lines: list[str] = []
            active_size = 0
            active_time_source = "logged"
            dirty = False
            if offset:
                checkpoint = self._metadata_get(connection, last_event_key, "")
                previous_id = int(checkpoint or 0)
                if not checkpoint:
                    latest = connection.execute(
                        "SELECT id FROM error_events WHERE source=? ORDER BY id DESC LIMIT 1",
                        (error_path.name,),
                    ).fetchone()
                    previous_id = int(latest["id"]) if latest else 0
                previous = connection.execute(
                    "SELECT id, event_time, module, message, line, time_source "
                    "FROM error_events WHERE id = ? AND source = ?",
                    (previous_id, error_path.name),
                ).fetchone()
                if previous is not None:
                    active_id = int(previous["id"])
                    active_event = (
                        float(previous["event_time"]),
                        str(previous["module"]),
                        str(previous["message"]),
                    )
                    active_lines = str(previous["line"]).split("\n")
                    active_size = len(str(previous["line"]))
                    active_time_source = str(previous["time_source"])
            event_count = 0
            new_offset = offset
            try:
                with error_path.open(
                    "r", encoding="utf-8", errors="replace"
                ) as handle:
                    handle.seek(offset)
                    for _ in range(FLOW_INDEX_BATCH_SIZE):
                        line_start = handle.tell()
                        line = handle.readline()
                        if not line:
                            break
                        if not line.endswith("\n"):
                            new_offset = line_start
                            break
                        new_offset = handle.tell()
                        header = (
                            ANSI_ESCAPE.sub("", line.rstrip())
                            if runtime
                            else line.rstrip()
                        )
                        match = ERROR_LINE.match(header)
                        daemon_match = (
                            MODULE_LINE.match(header)
                            if runtime and not match
                            else None
                        )
                        if (
                            runtime
                            and not match
                            and not daemon_match
                            and re.match(
                                r"^(?:Warning|Error|Traceback)\b", header
                            )
                        ):
                            daemon_match = MODULE_LINE.match(
                                f"[{Modules.MAIN.value}] {header}"
                            )
                        if match or daemon_match:
                            if active_event is not None and dirty:
                                active_id = self._store_error_event(
                                    connection,
                                    active_id,
                                    *active_event,
                                    "\n".join(active_lines),
                                    error_path.name,
                                    active_time_source,
                                )
                            parsed = match or daemon_match
                            if runtime and SLIPS_LOG_NOISE.search(
                                parsed.group("message")
                            ):
                                active_id = None
                                active_event = None
                                active_lines = []
                                dirty = False
                                continue
                            if match:
                                event_time = self._error_timestamp(
                                    match.group("date"), match.group("clock")
                                )
                                active_time_source = (
                                    "logged" if event_time else "unknown"
                                )
                                event_time = event_time or time.time()
                            else:
                                event_time = time.time()
                                active_time_source = (
                                    "unknown"
                                    if line_start < initial_size
                                    else "observed"
                                )
                            active_event = (
                                event_time,
                                parsed.group("module"),
                                parsed.group("message"),
                            )
                            active_id = None
                            active_lines = [line.rstrip()]
                            active_size = len(header)
                            dirty = True
                            event_count += 1
                        elif (
                            active_event is not None
                            and active_size < MAX_ERROR_EVENT_CHARS
                            and not (
                                runtime and SLIPS_LOG_NOISE.search(header)
                            )
                        ):
                            continuation = line.rstrip("\r\n")
                            active_lines.append(continuation)
                            active_size += len(continuation) + 1
                            dirty = True
            except OSError:
                return 0
            if active_event is not None and dirty:
                active_id = self._store_error_event(
                    connection,
                    active_id,
                    *active_event,
                    "\n".join(active_lines),
                    error_path.name,
                    active_time_source,
                )
            self._metadata_set(connection, last_event_key, active_id or 0)
            self._metadata_set(connection, offset_key, new_offset)
            if not runtime:
                self._metadata_set(
                    connection, "error_log_name", error_path.name
                )
            return event_count

    def snapshot_hosts(self) -> int:
        """
        Persist last-known Redis identity data for active profiles.

        Returns:
            Number of host snapshots written.
        """
        try:
            profiles = self.redis.zrange("profiles", 0, -1)
            identity_pipeline = self.redis.pipeline(transaction=False)
            for profile_id in profiles:
                ip = str(profile_id).removeprefix("profile_")
                identity_pipeline.hgetall(profile_id)
                identity_pipeline.hget("DNSresolution", ip)
                identity_pipeline.zrange(f"tws{profile_id}", -1, -1)
            identity_values = identity_pipeline.execute() if profiles else []
        except redis.RedisError:
            return 0

        profile_data: List[tuple[str, Dict[str, Any], Any, str]] = []
        for index, profile_id in enumerate(profiles):
            ip = str(profile_id).removeprefix("profile_")
            fields = identity_values[index * 3] or {}
            if not isinstance(fields, dict):
                fields = {}
            dns = identity_values[index * 3 + 1]
            tw_values = identity_values[index * 3 + 2] or []
            twid = str(tw_values[0]) if tw_values else ""
            profile_data.append((ip, fields, dns, twid))

        accumulated_scores: Dict[str, float] = {}
        risk_weight = 0.32
        try:
            score_pipeline = self.redis.pipeline(transaction=False)
            for ip, _, _, twid in profile_data:
                score_pipeline.zscore(
                    "accumulated_threat_levels", f"profile_{ip}_{twid}"
                )
            score_values = score_pipeline.execute()
            accumulated_scores = {
                ip: float(value or 0)
                for (ip, _, _, _), value in zip(profile_data, score_values)
            }
            risk_weight = float(
                self.redis.hget(
                    "max_risk_weight_of_all_profiles", "risk_weight"
                )
                or risk_weight
            )
        except (redis.RedisError, TypeError, ValueError):
            pass

        try:
            raw_states = self.redis.hgetall("network_states")
        except redis.RedisError:
            raw_states = {}
        states = []
        for raw in raw_states.values() if isinstance(raw_states, dict) else []:
            state = self._json_value(raw, {})
            if isinstance(state, dict):
                states.append(state)
        run_name = f"{self.output_dir}:{self.root_pid}"
        networks = [
            HostProfileStore.network_id_for_state(state, run_name)
            for state in states
        ]
        networks.append(f"run:{run_name}")
        try:
            durable = HostProfileStore.identities_for_ips(
                self.host_profiles_path,
                [ip for ip, _, _, _ in profile_data],
                networks,
                {
                    ip: fields.get("MAC", "")
                    for ip, fields, _, _ in profile_data
                },
            )
        except (OSError, sqlite3.Error):
            durable = {}

        rows: List[tuple[Any, ...]] = []
        observed_at = time.time()
        for ip, fields, dns, twid in profile_data:
            try:
                scope = (
                    "local"
                    if ipaddress.ip_address(ip).is_private
                    else "public"
                )
            except ValueError:
                scope = "special"
            data = {
                "ip": ip,
                "scope": scope,
                "hostname": durable.get(ip, {}).get("name")
                or (
                    ""
                    if durable.get(ip, {}).get("identity_changed")
                    else fields.get("host_name", "")
                ),
                "hostname_source": durable.get(ip, {}).get("source", ""),
                "mac": durable.get(ip, {}).get("mac") or fields.get("MAC", ""),
                "mac_vendor": fields.get("MAC_vendor", ""),
                "threat_level": fields.get("threat_level", "info"),
                "max_threat_level": fields.get("max_threat_level", "info"),
                # An observed L2 MAC can be a router/next-hop MAC for many
                # unrelated remote addresses. Host workspaces are therefore
                # deliberately profile-IP-specific.
                "all_ips": [ip],
                "dns": self._json_value(dns, {}),
                "alert_score_twid": twid,
                "accumulated_threat_level": accumulated_scores.get(ip, 0),
                "accumulated_ratl": accumulated_scores.get(ip, 0)
                * risk_weight,
                "risk_weight": risk_weight,
            }
            rows.append((ip, observed_at, json.dumps(data)))
        if rows:
            with connect_history(self.history_path) as connection:
                connection.executemany(
                    "INSERT OR REPLACE INTO host_snapshots "
                    "(ip, observed_at, data) VALUES (?, ?, ?)",
                    rows,
                )
        self._last_host_snapshot = observed_at
        return len(rows)

    @staticmethod
    def _json_value(value: Any, default: Any) -> Any:
        """Decode a JSON value with a fallback."""
        if value is None:
            return default
        if isinstance(value, (dict, list)):
            return value
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _event_timestamp(value: Any) -> float:
        """
        Normalize numeric, ISO, and Slips timestamps.

        Parameters:
            value: Timestamp value from Redis or alerts.json.

        Returns:
            Unix timestamp, or zero when the value is invalid.
        """
        try:
            return float(value)
        except (TypeError, ValueError):
            pass
        try:
            return datetime.fromisoformat(
                str(value).replace("Z", "+00:00")
            ).timestamp()
        except ValueError:
            pass
        for date_format in (
            "%Y/%m/%d %H:%M:%S.%f%z",
            "%Y/%m/%d %H:%M:%S.%f",
        ):
            try:
                return datetime.strptime(str(value), date_format).timestamp()
            except ValueError:
                continue
        return 0.0

    @staticmethod
    def _list_value(value: Any) -> List[str]:
        """
        Normalize one serialized identifier collection.

        Parameters:
            value: JSON string, collection, or scalar identifier.

        Returns:
            List of string identifiers.
        """
        decoded = HistoryCollector._json_value(value, value)
        if decoded is None:
            return []
        if isinstance(decoded, (list, tuple, set)):
            return [str(item) for item in decoded]
        return [str(decoded)]

    @staticmethod
    def _detection_schema(connection: sqlite3.Connection) -> bool:
        """
        Add durable detection tables to an older flow database.

        Parameters:
            connection: Writable flows.sqlite connection.

        Returns:
            True when durable detection columns were added.
        """
        statements = (
            "CREATE INDEX IF NOT EXISTS alerts_time_idx "
            "ON alerts(alert_time DESC, alert_id)",
            "CREATE INDEX IF NOT EXISTS alerts_ip_time_idx "
            "ON alerts(ip_alerted, alert_time DESC, alert_id)",
            "CREATE TABLE IF NOT EXISTS evidence ("
            "evidence_id TEXT PRIMARY KEY, evidence_time REAL, "
            "profile_ip TEXT, timewindow TEXT, threat_level TEXT, "
            "evidence_type TEXT, source_module TEXT, description TEXT, "
            "confidence REAL, data TEXT, "
            "accumulated_threat_level REAL, accumulated_ratl REAL, "
            "whitelisted INTEGER DEFAULT 0)",
            "CREATE TABLE IF NOT EXISTS evidence_flows ("
            "evidence_id TEXT, uid TEXT, PRIMARY KEY (evidence_id, uid))",
            "CREATE TABLE IF NOT EXISTS alert_evidence ("
            "alert_id TEXT, evidence_id TEXT, PRIMARY KEY (alert_id, evidence_id))",
            "CREATE INDEX IF NOT EXISTS evidence_time_idx "
            "ON evidence(evidence_time DESC, evidence_id)",
            "CREATE INDEX IF NOT EXISTS evidence_profile_time_idx "
            "ON evidence(profile_ip, evidence_time DESC, evidence_id)",
            "CREATE INDEX IF NOT EXISTS evidence_type_idx "
            "ON evidence(evidence_type, evidence_time DESC)",
            "CREATE INDEX IF NOT EXISTS evidence_threat_idx "
            "ON evidence(threat_level, evidence_time DESC)",
            "CREATE INDEX IF NOT EXISTS evidence_flows_uid_idx ON evidence_flows(uid)",
            "CREATE INDEX IF NOT EXISTS alert_evidence_evidence_idx "
            "ON alert_evidence(evidence_id)",
        )
        for statement in statements:
            connection.execute(statement)
        additions = {
            "alerts": {
                "accumulated_threat_level": "REAL",
                "accumulated_ratl": "REAL",
                "risk_weight": "REAL",
            },
            "evidence": {
                "accumulated_threat_level": "REAL",
                "accumulated_ratl": "REAL",
                "whitelisted": "INTEGER DEFAULT 0",
                "source_module": "TEXT",
            },
        }
        upgraded = False
        for table_name, columns in additions.items():
            existing = {
                str(row[1])
                for row in connection.execute(
                    f"PRAGMA table_info({table_name})"
                ).fetchall()
            }
            for column_name, column_type in columns.items():
                if column_name not in existing:
                    connection.execute(
                        f"ALTER TABLE {table_name} "
                        f"ADD COLUMN {column_name} {column_type}"
                    )
                    upgraded = True
        return upgraded

    def _redis_belongs_to_run(self) -> bool:
        """
        Check whether Redis advertises this collector's output directory.

        Returns:
            True only when Redis belongs to the configured run.
        """
        try:
            redis_output_dir = self.redis.hget("analysis", "output_dir")
        except redis.RedisError:
            return False
        if not redis_output_dir:
            return False
        if isinstance(redis_output_dir, bytes):
            redis_output_dir = redis_output_dir.decode(errors="replace")
        expected = self.output_dir.as_posix().rstrip("/")
        actual = Path(str(redis_output_dir)).as_posix().rstrip("/")
        return actual == expected

    def _backfill_redis_evidence(self, connection: sqlite3.Connection) -> int:
        """
        Copy currently retained Redis evidence and relationships.

        Parameters:
            connection: Writable flows.sqlite connection.

        Returns:
            Number of evidence records observed.
        """
        count = 0
        deleted = self._deleted_record_ids(connection)
        try:
            evidence_keys = list(
                self.redis.scan_iter(match="profile_*_timewindow*_evidence")
            )
        except redis.RedisError:
            return 0
        for key in evidence_keys:
            profile_window = str(key)[: -len("_evidence")]
            profile_id, separator, window_number = profile_window.rpartition(
                "_timewindow"
            )
            if not separator:
                continue
            try:
                records = self.redis.hgetall(key)
            except redis.RedisError:
                continue
            for evidence_id, raw in records.items():
                evidence = self._json_value(raw, {})
                if not isinstance(evidence, dict):
                    continue
                canonical_id = str(evidence.get("id") or evidence_id)
                if (
                    getattr(self, "_archive_tombstones_available", False)
                    and connection.execute(
                        "SELECT 1 FROM history_archived_ids WHERE entity='evidence' AND record_id=?",
                        (canonical_id,),
                    ).fetchone()
                ):
                    continue
                cutoff = getattr(self, "_active_history_cutoff", None)
                if (
                    cutoff is not None
                    and self._event_timestamp(evidence.get("timestamp"))
                    < cutoff
                ):
                    continue
                if ("evidence", canonical_id) in deleted:
                    continue
                profile = evidence.get("profile", {})
                profile_ip = (
                    str(profile.get("ip", ""))
                    if isinstance(profile, dict)
                    else str(profile).removeprefix("profile_")
                )
                uids = self._list_value(evidence.get("uid", []))
                if not uids:
                    try:
                        uids = self._list_value(
                            self.redis.hget(
                                "flows_causing_evidence", canonical_id
                            )
                        )
                    except redis.RedisError:
                        pass
                connection.execute(
                    "INSERT OR IGNORE INTO evidence "
                    "(evidence_id, evidence_time, profile_ip, timewindow, "
                    "threat_level, evidence_type, source_module, description, "
                    "confidence, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        canonical_id,
                        self._event_timestamp(evidence.get("timestamp")),
                        profile_ip or profile_id.removeprefix("profile_"),
                        f"timewindow{window_number}",
                        str(evidence.get("threat_level", "info")).lower(),
                        str(evidence.get("evidence_type", "unknown")),
                        str(evidence.get("source_module", "")),
                        str(evidence.get("description", "")),
                        float(evidence.get("confidence") or 0),
                        json.dumps(evidence),
                    ),
                )
                connection.executemany(
                    "INSERT OR IGNORE INTO evidence_flows "
                    "(evidence_id, uid) VALUES (?, ?)",
                    [(canonical_id, uid) for uid in uids],
                )
                count += 1
        try:
            alert_keys = self.redis.scan_iter(match="profile_*_timewindow*")
            for key in alert_keys:
                if (
                    str(key).endswith("_evidence")
                    or self.redis.type(key) != "hash"
                ):
                    continue
                alerts = self._json_value(self.redis.hget(key, "alerts"), {})
                if not isinstance(alerts, dict):
                    continue
                for alert_id, evidence_ids in alerts.items():
                    if ("alert", str(alert_id)) in deleted:
                        continue
                    connection.executemany(
                        "INSERT OR IGNORE INTO alert_evidence "
                        "(alert_id, evidence_id) VALUES (?, ?)",
                        [
                            (str(alert_id), evidence_id)
                            for evidence_id in self._list_value(evidence_ids)
                            if ("evidence", evidence_id) not in deleted
                        ],
                    )
        except redis.RedisError:
            pass
        return count

    @staticmethod
    def _deleted_record_ids(
        connection: sqlite3.Connection,
    ) -> set[tuple[str, str]]:
        """Read deletion tombstones before importing older detection sources.

        Parameters:
            connection: Current run flow database.

        Returns:
            Deleted entity and record ID pairs.
        """
        if not connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' "
            "AND name = 'review_deletions'"
        ).fetchone():
            return set()
        return {
            (str(row[0]), str(row[1]))
            for row in connection.execute(
                "SELECT entity, record_id FROM review_deletions"
            ).fetchall()
        }

    def _backfill_alert_record(
        self,
        connection: sqlite3.Connection,
        record: Dict[str, Any],
        deleted: Optional[set[tuple[str, str]]] = None,
    ) -> None:
        """
        Copy one IDMEF event or incident into durable detection tables.

        Parameters:
            connection: Writable flows.sqlite connection.
            record: Parsed alerts.json line.
            deleted: Tombstones already loaded for this backfill batch.
        """
        record_id = str(record.get("ID", ""))
        if not record_id:
            return
        if deleted is None:
            deleted = self._deleted_record_ids(connection)
        entity = "alert" if record.get("Status") == "Incident" else "evidence"
        if (
            getattr(self, "_archive_tombstones_available", False)
            and connection.execute(
                "SELECT 1 FROM history_archived_ids WHERE entity=? AND record_id=?",
                ("alerts" if entity == "alert" else "evidence", record_id),
            ).fetchone()
        ):
            return
        cutoff = getattr(self, "_active_history_cutoff", None)
        if (
            cutoff is not None
            and self._event_timestamp(record.get("CreateTime")) < cutoff
        ):
            return
        if (entity, record_id) in deleted:
            return
        note = self._json_value(record.get("Note"), {})
        source = record.get("Source") or [{}]
        profile_ip = str(source[0].get("IP", "")) if source else ""
        if record.get("Status") == "Incident":
            accumulated_threat_level = note.get("accumulated_threat_level")
            accumulated_ratl = note.get("accumulated_ratl")
            risk_weight = None
            try:
                if float(accumulated_threat_level):
                    risk_weight = float(accumulated_ratl) / float(
                        accumulated_threat_level
                    )
            except (TypeError, ValueError):
                pass
            connection.execute(
                "INSERT INTO alerts "
                "(alert_id, alert_time, ip_alerted, timewindow, "
                "tw_start, tw_end, label, accumulated_threat_level, "
                "accumulated_ratl, risk_weight) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(alert_id) DO UPDATE SET "
                "accumulated_threat_level = COALESCE(alerts.accumulated_threat_level, "
                "excluded.accumulated_threat_level), "
                "accumulated_ratl = COALESCE(alerts.accumulated_ratl, excluded.accumulated_ratl), "
                "risk_weight = COALESCE(alerts.risk_weight, excluded.risk_weight)",
                (
                    record_id,
                    self._event_timestamp(record.get("CreateTime")),
                    profile_ip,
                    f"timewindow{note.get('timewindow', '')}",
                    record.get("StartTime", ""),
                    note.get("EndTime", ""),
                    "malicious",
                    accumulated_threat_level,
                    accumulated_ratl,
                    risk_weight,
                ),
            )
            connection.executemany(
                "INSERT OR IGNORE INTO alert_evidence "
                "(alert_id, evidence_id) VALUES (?, ?)",
                [
                    (record_id, evidence_id)
                    for evidence_id in self._list_value(record.get("CorrelID"))
                    if ("evidence", evidence_id) not in deleted
                ],
            )
            return
        if record.get("Status") != "Event":
            return
        threat_level = str(
            note.get("threat_level") or record.get("Priority") or "info"
        ).lower()
        evidence_type = str(note.get("evidence_type") or "IDMEF_EVENT")
        connection.execute(
            "INSERT INTO evidence "
            "(evidence_id, evidence_time, profile_ip, timewindow, "
            "threat_level, evidence_type, description, confidence, data, "
            "source_module, accumulated_threat_level, accumulated_ratl) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(evidence_id) DO UPDATE SET "
            "source_module = COALESCE(NULLIF(excluded.source_module, ''), "
            "evidence.source_module), "
            "accumulated_threat_level = COALESCE(evidence.accumulated_threat_level, "
            "excluded.accumulated_threat_level), "
            "accumulated_ratl = COALESCE(evidence.accumulated_ratl, excluded.accumulated_ratl)",
            (
                record_id,
                self._event_timestamp(record.get("StartTime")),
                profile_ip,
                f"timewindow{note.get('timewindow', '')}",
                threat_level,
                evidence_type,
                str(record.get("Description", "")),
                float(record.get("Confidence") or 0),
                json.dumps(record),
                str(note.get("source_module", "")),
                note.get("accumulated_threat_level"),
                note.get("risk_accumulated_threat_level"),
            ),
        )
        connection.executemany(
            "INSERT OR IGNORE INTO evidence_flows (evidence_id, uid) VALUES (?, ?)",
            [
                (record_id, uid)
                for uid in self._list_value(note.get("uids", []))
            ],
        )

    def _backfill_alert_file(
        self, connection: sqlite3.Connection, maximum: int = 5000
    ) -> int:
        """
        Copy one bounded alerts.json batch after Redis expiry.

        Parameters:
            connection: Writable flows.sqlite connection.
            maximum: Maximum complete JSON lines to process.

        Returns:
            Number of parsed records.
        """
        alerts_path = self.output_dir / "alerts" / "alerts.json"
        if not alerts_path.exists():
            return 0
        with connect_history(self.history_path) as history:
            offset = int(
                self._metadata_get(history, "alerts_json_offset", "0")
            )
            stat = alerts_path.stat()
            inode = f"{stat.st_dev}:{stat.st_ino}"
            if (
                self._metadata_get(history, "alerts_json_inode", inode)
                != inode
            ):
                offset = 0
            self._metadata_set(history, "alerts_json_inode", inode)
        deleted = self._deleted_record_ids(connection)
        try:
            if alerts_path.stat().st_size < offset:
                offset = 0
        except OSError:
            return 0
        count = 0
        new_offset = offset
        deadline = time.monotonic() + 0.05
        try:
            with alerts_path.open(
                "r", encoding="utf-8", errors="replace"
            ) as handle:
                handle.seek(offset)
                while count < maximum and time.monotonic() < deadline:
                    line_start = handle.tell()
                    line = handle.readline()
                    if not line:
                        break
                    if not line.endswith("\n"):
                        new_offset = line_start
                        break
                    new_offset = handle.tell()
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(record, dict):
                        self._backfill_alert_record(
                            connection, record, deleted
                        )
                        count += 1
        except OSError:
            return 0
        connection.commit()
        with connect_history(self.history_path) as history:
            self._metadata_set(history, "alerts_json_offset", new_offset)
        return count

    def backfill_detections(self) -> int:
        """
        Upgrade an active or completed run with durable detections.

        Returns:
            Number of Redis and alerts.json records examined.
        """
        if not self.flows_path.exists():
            return 0
        policy = ConfigParser().detection_history_policy()
        live = self.redis.hget("analysis", "input_type") in {
            "interface",
            "stdin",
            "cyst",
        }
        self._active_history_cutoff = (
            time.time() - int(policy["active_days"]) * 86400
            if live and policy["enabled"]
            else None
        )
        try:
            with (
                SQLiteFlock("sqlite_db", self.root_pid).acquire(),
                sqlite3.connect(self.flows_path, timeout=0) as connection,
            ):
                self._archive_tombstones_available = bool(
                    connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE name='history_archived_ids'"
                    ).fetchone()
                )
                schema_upgraded = False
                if not self._detection_schema_ready:
                    schema_upgraded = self._detection_schema(connection)
                    self._detection_schema_ready = True
                if schema_upgraded:
                    with connect_history(self.history_path) as history:
                        self._metadata_set(history, "alerts_json_offset", 0)
                redis_count = 0
                if not self._redis_detection_backfill_complete:
                    with connect_history(self.history_path) as history:
                        checkpoint = self._metadata_get(
                            history,
                            "redis_detection_backfill_complete",
                            "0",
                        )
                    if checkpoint != "0":
                        self._redis_detection_backfill_complete = True
                    else:
                        durable_evidence = int(
                            connection.execute(
                                "SELECT EXISTS(SELECT 1 FROM evidence LIMIT 1)"
                            ).fetchone()[0]
                        )
                        redis_available = self._redis_belongs_to_run()
                        if not durable_evidence and redis_available:
                            redis_count = self._backfill_redis_evidence(
                                connection
                            )
                        if durable_evidence or redis_available:
                            with connect_history(self.history_path) as history:
                                self._metadata_set(
                                    history,
                                    "redis_detection_backfill_complete",
                                    time.time(),
                                )
                            self._redis_detection_backfill_complete = True
                file_count = self._backfill_alert_file(connection)
            return redis_count + file_count
        except sqlite3.Error:
            return 0

    def sample_storage(self) -> None:
        """Record database size and recent growth without deleting data."""
        try:
            size = self.flows_path.stat().st_size
        except OSError:
            size = 0
        now = time.time()
        with connect_history(self.history_path) as connection:
            old_size = int(
                self._metadata_get(connection, "storage_size", str(size))
            )
            old_time = float(
                self._metadata_get(connection, "storage_checked_at", str(now))
            )
            elapsed = max(now - old_time, 1.0)
            growth = max((size - old_size) / elapsed, 0.0)
            self._metadata_set(connection, "storage_size", size)
            self._metadata_set(connection, "storage_growth_bps", growth)
            self._metadata_set(connection, "storage_checked_at", now)

    def rollup_metrics(self) -> int:
        """
        Roll one-second samples older than 24 hours into minute buckets.

        Returns:
            Number of minute buckets written.
        """
        cutoff = time.time() - RAW_METRIC_RETENTION_SECONDS
        complete_minute_cutoff = int(cutoff // 60) * 60
        with connect_history(self.history_path) as connection:
            rows = connection.execute(
                "SELECT CAST(ts / 60 AS INTEGER) * 60 AS bucket, "
                "AVG(cpu_percent), MAX(cpu_percent), "
                "AVG(memory_mb), MAX(memory_mb), "
                "AVG(flows_per_second), MAX(flows_per_second), "
                "SUM(flow_delta), COUNT(*) "
                "FROM runtime_metrics_1s WHERE ts < ? GROUP BY bucket",
                (complete_minute_cutoff,),
            ).fetchall()
            if rows:
                connection.executemany(
                    "INSERT OR REPLACE INTO runtime_metrics_1m "
                    "(bucket_ts, cpu_avg, cpu_max, memory_avg, memory_max, "
                    "fps_avg, fps_max, flow_total, samples) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [tuple(row) for row in rows],
                )
                connection.execute(
                    "DELETE FROM runtime_metrics_1s WHERE ts < ?",
                    (complete_minute_cutoff,),
                )

        return len(rows)

    def prune_operational_history(self, now: float) -> int:
        """Expire bounded batches of old live-run operational records.

        Parameters:
            now: Current Unix timestamp.

        Returns:
            Number of deleted records.
        """
        policy = ConfigParser().detection_history_policy()
        if not policy["enabled"] or self.redis.hget(
            "analysis", "input_type"
        ) not in {"interface", "stdin", "cyst"}:
            return 0
        cutoff = now - int(policy["active_days"]) * 86400
        count = 0
        with connect_history(self.history_path) as connection:
            for table, timestamp in (
                ("error_events", "event_time"),
                ("runtime_metrics_1m", "bucket_ts"),
                ("host_snapshots", "observed_at"),
            ):
                count += connection.execute(
                    f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} "
                    f"WHERE {timestamp}<? ORDER BY {timestamp} LIMIT ?)",
                    (cutoff, FLOW_INDEX_BATCH_SIZE),
                ).rowcount
        return count

    def collect_once(self) -> None:
        """Run one bounded collector iteration."""
        now = time.time()
        self.record_backend_heartbeat(now)
        if now - self._last_host_snapshot >= HOST_SNAPSHOT_INTERVAL_SECONDS:
            self.snapshot_hosts()
            self.sample_storage()
            self._last_host_snapshot = now
        self.index_new_flows()
        if now - self._last_flow_reconcile >= 60:
            self.reconcile_flow_index()
            self._last_flow_reconcile = now
        self.sample_metrics()
        self.tail_errors()
        self.tail_slips()
        if now - self._last_rollup >= 60:
            self.rollup_metrics()
            self.prune_operational_history(now)
            self._last_rollup = now
