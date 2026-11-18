# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Keep the disk usage of long live captures bounded."""

import threading
import time
from pathlib import Path
from typing import Any, Optional

from slips_files.common.log_rotation import expire_rotated_logs
from slips_files.common.slips_utils import utils
from slips_files.core.database.sqlite_db.detection_history import (
    MAINTENANCE_INTERVAL_SECONDS,
)

# Internal tuning values, intentionally not user-configurable.
# Flows deleted per cleanup pass.
FLOW_RETENTION_BATCH_SIZE = 500
# Seconds between flow cleanup passes.
FLOW_RETENTION_INTERVAL_SECONDS = 60
# Seconds between passes that delete expired rotated logs.
ROTATED_LOGS_EXPIRY_INTERVAL_SECONDS = 60
# Seconds to wait for a running cleanup pass to finish on shutdown.
CLEANUP_THREAD_JOIN_TIMEOUT_SECONDS = 5


class FlowCleanupManager:
    """
    Owns the background thread that deletes old flows, maintains the
    detection history and expires rotated logs.
    Why here and not in the profiler? so the flow processing path never
    waits for cleanup work.
    """

    def __init__(self, main: Any) -> None:
        """
        :param main: Main Slips instance.
        """
        self.main = main
        self.read_configuration()
        # is set on shutdown to stop the cleanup thread
        self.stop_event = threading.Event()
        self.cleanup_thread = threading.Thread(
            target=self._run_cleanup_loop,
            name="flow_cleanup_thread",
            daemon=True,
        )
        self.last_flow_cleanup_time = 0.0
        self.last_rotated_logs_expiry_time = 0.0
        self.history_deferred_since: Optional[float] = None
        self.history_last_success_time: Optional[float] = None
        self.history_last_warning_time = 0.0
        self.history_deferrals = 0
        self.history_warning_interval = max(
            60, MAINTENANCE_INTERVAL_SECONDS * 6
        )

    def read_configuration(self) -> None:
        """Reads the flow retention and the detection history settings."""
        self.flow_retention_policy = self.main.conf.flow_retention_policy()
        self.detection_history_policy = (
            self.main.conf.detection_history_policy()
        )

    def _is_cleanup_needed(self) -> bool:
        """
        Cleanup only runs on interfaces. files and pcaps are finite, so
        their flows are never deleted.

        Returns:
            True when Slips is monitoring an interface and at least one
            cleanup policy is enabled.
        """
        return bool(
            self.main.args.interface
            and (
                self.flow_retention_policy["enabled"]
                or self.detection_history_policy["enabled"]
            )
        )

    def start(self) -> bool:
        """
        Starts the cleanup thread if this run needs it.

        Returns:
            True when the thread was started.
        """
        if not self._is_cleanup_needed():
            return False
        utils.start_thread(self.cleanup_thread, self.main.db)
        return True

    def shutdown(self) -> None:
        """
        Stops the cleanup thread and waits for its running pass to finish,
        so no pass is using the database when Slips closes it.
        """
        self.stop_event.set()
        if self.cleanup_thread.is_alive():
            self.cleanup_thread.join(
                timeout=CLEANUP_THREAD_JOIN_TIMEOUT_SECONDS
            )

    def _expire_rotated_logs_if_due(self, now: float) -> None:
        """
        Deletes expired rotated logs once every
        ROTATED_LOGS_EXPIRY_INTERVAL_SECONDS.

        Parameters:
            now: Unix time of the current cleanup pass.
        """
        if (
            now - self.last_rotated_logs_expiry_time
            < ROTATED_LOGS_EXPIRY_INTERVAL_SECONDS
        ):
            return
        expire_rotated_logs(
            Path(self.main.args.output), self.detection_history_policy, now
        )
        self.last_rotated_logs_expiry_time = now

    def _warn_if_history_keeps_getting_deferred(
        self, status: dict, now: float
    ) -> None:
        """
        A deferred pass is normal when the db is busy, so this only warns
        when the passes keep getting deferred for too long.

        Parameters:
            status: Result of the deferred history maintenance pass.
            now: Unix time of the current cleanup pass.
        """
        self.history_deferrals += 1
        if self.history_deferred_since is None:
            self.history_deferred_since = now
        deferred_for_too_long = (
            now - self.history_deferred_since >= self.history_warning_interval
        )
        warned_recently = (
            now - self.history_last_warning_time
            < self.history_warning_interval
        )
        if not deferred_for_too_long or warned_recently:
            return

        last_success = (
            f"{now - self.history_last_success_time:.0f}s ago"
            if self.history_last_success_time is not None
            else "not yet completed"
        )
        self.main.print(
            "Warning: History maintenance is waiting for database writers: "
            f"{self.history_deferrals} deferred passes, "
            f"phase={status.get('phase', 'unknown')}, "
            f"SQLite={status.get('sqlite_errorname', 'not acquired')}, "
            f"last successful pass {last_success}.",
            1,
            0,
        )
        self.history_last_warning_time = now

    def _maintain_detection_history(self, now: float) -> None:
        """
        Runs one detection history maintenance pass. A failure here is
        reported and never stops the flow cleanup of the same pass.

        Parameters:
            now: Unix time of the current cleanup pass.
        """
        try:
            status = self.main.db.maintain_detection_history(
                self.detection_history_policy, now=now
            )
        except Exception as error:
            self.main.print(
                f"Detection history maintenance failed: {error} "
                f"(phase={getattr(error, 'history_phase', 'unknown')}, "
                f"SQLite={getattr(error, 'sqlite_errorname', 'unknown')})",
                0,
                1,
            )
            return

        if isinstance(status, dict) and status.get("deferred"):
            self._warn_if_history_keeps_getting_deferred(status, now)
            return

        self.history_last_success_time = now
        self.history_deferred_since = None
        self.history_deferrals = 0

    def _delete_old_flows_if_due(self, now: float) -> None:
        """
        Deletes a small batch of expired flows once every
        FLOW_RETENTION_INTERVAL_SECONDS, and removes them from the web
        interface's flow index.

        Parameters:
            now: Unix time of the current cleanup pass.
        """
        if now - self.last_flow_cleanup_time < FLOW_RETENTION_INTERVAL_SECONDS:
            return
        policy = self.flow_retention_policy
        ordinary_age = int(policy["ordinary_hours"]) * 3600
        size_min_age = int(policy.get("size_min_age_minutes", 60)) * 60
        linked_age = int(policy["linked_days"]) * 86400
        removed_uids = self.main.db.maintain_flow_retention(
            now - ordinary_age,
            now - linked_age,
            batch_size=FLOW_RETENTION_BATCH_SIZE,
            max_size_bytes=int(policy["max_size_mb"]) * 1024 * 1024,
            unlinked_size_cutoff=now - min(ordinary_age, size_min_age),
        )
        if removed_uids:
            self.main.db.remove_flow_index_uids(removed_uids)
        self.last_flow_cleanup_time = now

    def _run_cleanup_pass(self, now: float) -> None:
        """
        Runs every cleanup task that is enabled and due.

        Parameters:
            now: Unix time of the current cleanup pass.
        """
        try:
            if self.detection_history_policy.get("enabled"):
                self._expire_rotated_logs_if_due(now)
                self._maintain_detection_history(now)

            if self.flow_retention_policy["enabled"]:
                self._delete_old_flows_if_due(now)
        except Exception as error:
            self.main.print(
                f"Flow retention maintenance failed: {error}",
                0,
                1,
            )

    def _run_cleanup_loop(self) -> None:
        """runs in a thread
        Runs cleanup passes until Slips starts shutting down."""
        if not self.main.args.interface:
            return
        seconds_between_passes = min(
            FLOW_RETENTION_INTERVAL_SECONDS, MAINTENANCE_INTERVAL_SECONDS
        )
        while not self.stop_event.wait(seconds_between_passes):
            self._run_cleanup_pass(time.time())
