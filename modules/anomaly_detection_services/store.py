"""Independent, single-writer SQLite checkpoints for service baselines."""

import fcntl
import json
import sqlite3
from pathlib import Path

from .baseline import ServiceBaseline, ServiceDetector
from .models import Settings


class BaselineStore:
    """Persist bounded models without sharing the detection database writer."""

    def __init__(self, path: Path, settings: Settings) -> None:
        """Open a private baseline database and acquire its writer ownership.

        Parameters:
            path: Module database filename.
            settings: Maximum restored service/client state.
        """
        self.path = path
        self.settings = settings
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
                raise ValueError(
                    "Unsupported service baseline database version"
                )
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA synchronous=NORMAL")
            self.connection.execute("PRAGMA wal_autocheckpoint=256")
            self.connection.execute("PRAGMA journal_size_limit=2097152")
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS services ("
                "key TEXT PRIMARY KEY, updated REAL NOT NULL, data TEXT NOT NULL)"
            )
            self.connection.execute(
                "CREATE INDEX IF NOT EXISTS service_age ON services(updated)"
            )
            self.connection.execute("PRAGMA user_version=1")
            self.connection.commit()
        except BaseException:
            self.close()
            raise

    def load(self) -> dict[str, ServiceBaseline]:
        """Read only as many service records as the configured cap permits.

        Returns:
            Most recently active service models.
        """
        rows = self.connection.execute(
            "SELECT key, data FROM services ORDER BY updated DESC LIMIT ?",
            (self.settings.max_services,),
        )
        return {
            key: ServiceBaseline.from_dict(json.loads(data), self.settings)
            for key, data in rows
        }

    def save(self, detector: ServiceDetector) -> None:
        """Commit dirty models and expire old records in one transaction.

        Parameters:
            detector: Incremental model state with pending changes.
        """
        if not detector.dirty and not detector.deleted:
            return
        rows = [
            (
                key,
                detector.services[key].last_seen,
                json.dumps(
                    detector.services[key].to_dict(),
                    allow_nan=False,
                    separators=(",", ":"),
                ),
            )
            for key in detector.dirty
            if key in detector.services
        ]
        with self.connection:
            self.connection.executemany(
                "INSERT INTO services VALUES (?, ?, ?) ON CONFLICT(key) "
                "DO UPDATE SET updated=excluded.updated, data=excluded.data",
                rows,
            )
            self.connection.executemany(
                "DELETE FROM services WHERE key=?",
                ((key,) for key in detector.deleted),
            )
            self.connection.execute(
                "DELETE FROM services WHERE updated < ?",
                (detector.watermark - self.settings.retention_days * 86400,),
            )
            self.connection.execute(
                "DELETE FROM services WHERE key NOT IN "
                "(SELECT key FROM services ORDER BY updated DESC LIMIT ?)",
                (self.settings.max_services,),
            )
        detector.dirty.clear()
        detector.deleted.clear()

    def close(self) -> None:
        """Release database and writer-lock descriptors."""
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if not self.lock.closed:
            self.lock.close()
