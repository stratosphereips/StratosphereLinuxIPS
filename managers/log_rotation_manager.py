# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Keep the size of the logs written by Slips bounded."""

import time
from pathlib import Path
from typing import Any, Optional

from slips_files.common.log_rotation import rotate_log
from slips_files.common.output_paths import get_alerts_path_inside_output_dir
from slips_files.core.output import Output

# Internal tuning values, intentionally not user-configurable.
# Seconds between passes that rotate the logs that got too big.
LOG_ROTATION_INTERVAL_SECONDS = 30
# Seconds to wait for a log's writers before skipping it for this pass.
LOCK_ACQUIRE_TIMEOUT_SECONDS = 2
DAEMONIZED_MODE = "daemonized"


class LogRotationManager:
    """
    Rotates slips.log, errors.log, alerts.log and alerts.json once they
    reach the size limit of detection_history.
    Why here and not in the writers? so no writer checks the size of its
    log on every line it writes.
    Why no thread? the checks are a few cheap stat() calls, so the main
    loop of Slips calls rotate_logs_if_due() itself.
    """

    def __init__(self, main: Any) -> None:
        """
        :param main: Main Slips instance.
        """
        self.main = main
        self.read_configuration()
        self.is_running = False
        self.last_rotation_time = 0.0

    def read_configuration(self) -> None:
        """Reads the log size and retention limits."""
        self.detection_history_policy = (
            self.main.conf.detection_history_policy()
        )

    def start(self) -> bool:
        """
        Enables the rotation passes if detection_history is enabled.

        Returns:
            True when the logs of this run will be rotated.
        """
        self.is_running = bool(self.detection_history_policy.get("enabled"))
        return self.is_running

    def shutdown(self) -> None:
        """
        Stops rotating, so no log is renamed while Slips is writing its
        last lines.
        """
        self.is_running = False

    def _get_logs_to_rotate(self) -> list[tuple[Path, Optional[Any]]]:
        """
        Lists every log this manager owns with the lock its writers hold.
        slips.log is skipped in daemon mode because the daemon's stdout
        stays attached to it, a renamed file would keep receiving the
        output.

        Returns:
            (log path, writers' lock or None) pairs.
        """
        alerts_dir = Path(
            get_alerts_path_inside_output_dir(self.main.args.output)
        )
        logs: list[tuple[Path, Optional[Any]]] = [
            (
                Path(self.main.logger.errors_logfile),
                Output.errors_logfile_lock,
            ),
            # the evidence logger reopens these two once they're rotated
            (alerts_dir / "alerts.log", None),
            (alerts_dir / "alerts.json", None),
        ]
        if self.main.mode != DAEMONIZED_MODE:
            logs.append(
                (
                    Path(self.main.logger.slips_logfile),
                    Output.slips_logfile_lock,
                )
            )
        return logs

    def _rotate_log(self, path: Path, lock: Optional[Any], now: float) -> bool:
        """
        Rotates one log while holding its writers' lock. A lock that can't
        be acquired is skipped, a process may have died holding it and the
        main loop should never wait for it.

        Parameters:
            path: Active log path.
            lock: Lock shared by the log's writers, if any.
            now: Unix time of the current rotation pass.

        Returns:
            True when the log was rotated.
        """
        if lock is None:
            return rotate_log(path, self.detection_history_policy, now)

        if not lock.acquire(timeout=LOCK_ACQUIRE_TIMEOUT_SECONDS):
            return False
        try:
            return rotate_log(path, self.detection_history_policy, now)
        finally:
            lock.release()

    def rotate_logs_if_due(self, now: Optional[float] = None) -> int:
        """
        Rotates the logs that reached the size limit once every
        LOG_ROTATION_INTERVAL_SECONDS. A log that fails to rotate is
        reported and never stops the rest of the pass.

        Parameters:
            now: Optional Unix time of the current pass.

        Returns:
            Number of logs rotated in this pass.
        """
        if not self.is_running:
            return 0
        now = time.time() if now is None else now
        if now - self.last_rotation_time < LOG_ROTATION_INTERVAL_SECONDS:
            return 0
        self.last_rotation_time = now

        rotated_logs = 0
        for path, lock in self._get_logs_to_rotate():
            try:
                rotated = self._rotate_log(path, lock, now)
                rotated_logs += int(rotated)
                if rotated:
                    self.main.print(
                        f"Rotated {path.name} because it reached "
                        f"log_max_size_mb="
                        f"{self.detection_history_policy['log_max_size_mb']}."
                        f" Old copies are kept in {path.parent / 'rotated'}.",
                        0,
                        1,
                    )
            except Exception as error:
                self.main.print(
                    f"Failed to rotate {path}: {error}",
                    0,
                    1,
                )
        return rotated_logs
