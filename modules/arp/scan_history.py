"""Private single-writer checkpoints for bounded ARP contact history."""

import fcntl
import json
import sqlite3
from pathlib import Path

from .scan_detector import ARPScanDetector


class ARPHistoryStore:
    """Keep successful relationships across live capture restarts."""

    def __init__(self, path: Path) -> None:
        """Open an independent database without competing for detection history.

        Parameters:
            path: Module-private checkpoint filename.
        """
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock = path.with_suffix(path.suffix + ".lock").open("a")
        self.connection: sqlite3.Connection | None = None
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.connection = sqlite3.connect(path, timeout=0)
            path.chmod(0o600)
            version = self.connection.execute(
                "PRAGMA user_version"
            ).fetchone()[0]
            if version not in (0, 1):
                raise ValueError("Unsupported ARP contact history version")
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA synchronous=NORMAL")
            self.connection.execute("PRAGMA wal_autocheckpoint=256")
            self.connection.execute("PRAGMA journal_size_limit=2097152")
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS contacts (id INTEGER PRIMARY KEY, updated REAL NOT NULL, data TEXT NOT NULL)"
            )
            self.connection.execute(
                "CREATE INDEX IF NOT EXISTS contact_age ON contacts(updated)"
            )
            self.connection.execute("PRAGMA user_version=1")
            self.connection.commit()
        except BaseException:
            self.close()
            raise

    def load(self, detector: ARPScanDetector, timestamp: float) -> None:
        """Restore at most the configured number of recent contacts.

        Parameters:
            detector: In-memory detector receiving validated history.
            timestamp: Live wall clock used to expire old records.
        """
        records = []
        for (data,) in self.connection.execute(
            "SELECT data FROM contacts WHERE updated >= ? AND updated <= ? ORDER BY updated DESC LIMIT ?",
            (
                timestamp
                - detector.settings.scan_familiar_retention_days * 86400,
                timestamp,
                detector.settings.scan_max_relationships,
            ),
        ):
            try:
                value = json.loads(data)
                if isinstance(value, dict):
                    records.append(value)
            except (ValueError, TypeError):
                continue
        detector.restore(list(reversed(records)), timestamp)
        total = self.connection.execute(
            "SELECT COUNT(*) FROM contacts"
        ).fetchone()[0]
        detector.dirty = total != len(detector.contacts)

    def save(self, detector: ARPScanDetector, timestamp: float) -> None:
        """Replace one bounded snapshot atomically, leaving dirty state on failure.

        Parameters:
            detector: Learned contacts, with no transient request state.
            timestamp: Clock used for retention cleanup.
        """
        records = detector.history(timestamp)
        if not detector.dirty:
            return
        rows = [
            (
                item["seen"],
                json.dumps(item, separators=(",", ":"), allow_nan=False),
            )
            for item in records
        ]
        with self.connection:
            self.connection.execute("DELETE FROM contacts")
            self.connection.executemany(
                "INSERT INTO contacts(updated,data) VALUES (?,?)", rows
            )
        detector.dirty = False

    def close(self) -> None:
        """Release database and writer lock descriptors."""
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if not self.lock.closed:
            self.lock.close()
