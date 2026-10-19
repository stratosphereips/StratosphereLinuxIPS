"""Rotate append-only Slips logs with configurable age and file-count limits."""

import time
import io
import threading
from datetime import datetime, timezone
from pathlib import Path


def rotate_log(
    path: Path, policy: dict[str, int | bool], now: float | None = None
) -> bool:
    """Rename a full log and expire old segments while its writer holds a lock.

    Parameters:
        path: Active log path.
        policy: Validated detection_history rotation settings.
        now: Optional Unix time for naming and expiration.

    Returns:
        Whether the active file was rotated.
    """
    if (
        not policy.get("enabled", True)
        or not path.is_file()
        or path.is_symlink()
    ):
        return False
    now = time.time() if now is None else now
    stat = path.stat()
    if stat.st_size < int(policy["log_max_size_mb"]) * 1024 * 1024:
        return False
    directory = path.parent / "rotated"
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.fromtimestamp(now, timezone.utc).strftime("%Y%m%dT%H%M%S")
    destination = directory / f"{path.name}.{stamp}.{time.time_ns()}"
    path.rename(destination)
    path.touch(mode=stat.st_mode & 0o777)
    path.chmod(stat.st_mode & 0o777)
    cutoff = now - int(policy["archive_retention_days"]) * 86400
    segments = sorted(
        directory.glob(f"{path.name}.*"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    for index, segment in enumerate(segments):
        if (
            segment.is_file()
            and not segment.is_symlink()
            and (
                index >= int(policy.get("log_backup_count", 30))
                or segment.stat().st_mtime < cutoff
            )
        ):
            segment.unlink()
    return True


def expire_rotated_logs(
    output_dir: Path, policy: dict[str, int | bool], now: float | None = None
) -> int:
    """Expire quiet rotated logs even when their active file has not filled again.

    Parameters:
        output_dir: Run output directory.
        policy: Validated rotation ages and maximum segment count.
        now: Optional current Unix time.

    Returns:
        Number of expired log segments removed.
    """
    if not policy.get("enabled", True):
        return 0
    now = time.time() if now is None else now
    removed = 0
    for directory, filenames in (
        (output_dir, ("slips.log", "errors.log")),
        (output_dir / "alerts", ("alerts.log", "alerts.json")),
        (output_dir / "web_interface", ("server.log",)),
    ):
        for filename in filenames:
            paths = sorted(
                (directory / "rotated").glob(f"{filename}.*"),
                key=lambda item: item.stat().st_mtime,
                reverse=True,
            )
            for index, path in enumerate(paths):
                if (
                    path.is_file()
                    and not path.is_symlink()
                    and (
                        index >= int(policy.get("log_backup_count", 30))
                        or path.stat().st_mtime
                        < now - int(policy["archive_retention_days"]) * 86400
                    )
                ):
                    path.unlink()
                    removed += 1
    return removed


class RotatingTextLog(io.TextIOBase):
    """Provide a rotating text stream for the web server's output and tracebacks."""

    def __init__(self, path: Path, policy: dict[str, int | bool]) -> None:
        """Bind the stream to one run-owned log.

        Parameters:
            path: Active log file.
            policy: Rotation size and retention configuration.
        """
        self.path = path
        self.policy = policy
        self.lock = threading.RLock()
        path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, value: str) -> int:
        """Append a text fragment under the stream's shared writer lock.

        Parameters:
            value: Text to append.

        Returns:
            Number of characters written.
        """
        with self.lock:
            rotate_log(self.path, self.policy)
            with self.path.open("a", encoding="utf-8") as handle:
                return handle.write(value)

    def writable(self) -> bool:
        """Report that this text stream accepts writes.

        Returns:
            True for logging and traceback writers.
        """
        return True
