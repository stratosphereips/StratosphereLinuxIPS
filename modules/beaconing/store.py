"""Private nonblocking SQLite checkpoints for bounded connection histories."""

import fcntl
import json
import sqlite3
from pathlib import Path

from .detector import Detector


class Store:
    """Maintain one writer per capture state directory, separate from evidence DB."""

    def __init__(self, path: Path) -> None:
        """Acquire writer ownership and open a bounded WAL checkpoint.

        Parameters:
            path: Private state filename.
        """
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = path.with_suffix(".lock").open("a")
        self.connection: sqlite3.Connection | None = None
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.connection = sqlite3.connect(path, timeout=0)
            path.chmod(0o600)
            if self.connection.execute("PRAGMA user_version").fetchone()[
                0
            ] not in (0, 1):
                raise ValueError("Unsupported beaconing checkpoint version")
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA synchronous=NORMAL")
            self.connection.execute("PRAGMA wal_autocheckpoint=256")
            self.connection.execute("PRAGMA journal_size_limit=2097152")
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS channels (key TEXT PRIMARY KEY, updated REAL NOT NULL, data TEXT NOT NULL)"
            )
            self.connection.execute(
                "CREATE INDEX IF NOT EXISTS channels_age ON channels(updated)"
            )
            self.connection.execute("PRAGMA user_version=1")
            self.connection.commit()
        except BaseException:
            self.close()
            raise

    def load(self, detector: Detector, now: float) -> None:
        """Restore capped recent records for this run's observation clock.

        Parameters:
            detector: Empty detector receiving state.
            now: Wall clock for live input or zero for an offline run.
        """
        rows = self.connection.execute(
            "SELECT key, data FROM channels WHERE updated >= ? ORDER BY updated DESC LIMIT ?",
            (
                now - detector.settings.retention_hours * 3600,
                detector.settings.max_channels,
            ),
        )
        detector.restore([(key, json.loads(data)) for key, data in rows])

    def save(self, detector: Detector) -> None:
        """Commit changed windows and expire/cap saved and in-memory records.

        Parameters:
            detector: State and pending dirty keys; retained on write failure.
        """
        cutoff = detector.watermark - detector.settings.retention_hours * 3600
        for key, channel in list(detector.channels.items()):
            if channel.last_seen < cutoff:
                del detector.channels[key]
                detector.dirty.discard(key)
                detector.deleted.add(key)
            else:
                trimmed = False
                while channel.events and channel.events[0].timestamp < cutoff:
                    channel.events.popleft()
                    trimmed = True
                if trimmed:
                    detector.dirty.add(key)
        rows = [
            (
                key,
                detector.channels[key].last_seen,
                json.dumps(
                    detector.snapshot(key),
                    separators=(",", ":"),
                    allow_nan=False,
                ),
            )
            for key in detector.dirty
            if key in detector.channels
        ]
        with self.connection:
            self.connection.executemany(
                "INSERT INTO channels VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET updated=excluded.updated, data=excluded.data",
                rows,
            )
            self.connection.executemany(
                "DELETE FROM channels WHERE key=?",
                ((key,) for key in detector.deleted),
            )
            self.connection.execute(
                "DELETE FROM channels WHERE updated < ?", (cutoff,)
            )
            self.connection.execute(
                "DELETE FROM channels WHERE key NOT IN (SELECT key FROM channels ORDER BY updated DESC LIMIT ?)",
                (detector.settings.max_channels,),
            )
        detector.dirty.clear()
        detector.deleted.clear()

    def close(self) -> None:
        """Release the checkpoint and exclusive writer lock."""
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if not self.lock.closed:
            self.lock.close()
