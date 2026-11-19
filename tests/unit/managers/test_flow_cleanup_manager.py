# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for the flow cleanup manager."""

from pathlib import Path
from unittest.mock import patch

import pytest

from managers.flow_cleanup_manager import CLEANUP_PASS_INTERVAL_SECONDS
from tests.module_factory import ModuleFactory

MANAGER = "managers.flow_cleanup_manager"


def full_history_policy() -> dict:
    """Return an enabled detection history policy with every limit set."""
    return {
        "enabled": True,
        "active_days": 90,
        "max_active_size_mb": 2048,
        "min_active_hours": 24,
        "archive_retention_days": 30,
        "archive_file_size_mb": 256,
        "max_archive_size_mb": 4096,
        "min_free_disk_mb": 1024,
        "log_max_size_mb": 64,
        "log_backup_count": 30,
    }


def test_init_reads_the_cleanup_policies() -> None:
    """Read both policies and stay idle until start() is called."""
    manager = ModuleFactory().create_flow_cleanup_manager_obj()

    assert manager.flow_retention_policy["enabled"] is True
    assert manager.detection_history_policy == {"enabled": False}
    assert manager.is_running is False
    assert manager.last_cleanup_pass_time == 0.0


@pytest.mark.parametrize(
    "interface, flow_retention_enabled, history_enabled, expected",
    [
        ("eth0", True, True, True),
        ("eth0", True, False, True),
        ("eth0", False, True, True),
        ("eth0", False, False, False),
        (False, True, True, False),
        (None, True, True, False),
    ],
)
def test_start_only_enables_cleanup_when_it_is_needed(
    interface: str | bool | None,
    flow_retention_enabled: bool,
    history_enabled: bool,
    expected: bool,
) -> None:
    """Enable the passes on interfaces with at least one enabled policy.

    Parameters:
        interface: Interface given to Slips, if any.
        flow_retention_enabled: Whether flow retention is enabled.
        history_enabled: Whether detection history is enabled.
        expected: Whether the cleanup passes should be enabled.
    """
    manager = ModuleFactory().create_flow_cleanup_manager_obj()
    manager.main.args.interface = interface
    manager.flow_retention_policy["enabled"] = flow_retention_enabled
    manager.detection_history_policy["enabled"] = history_enabled

    assert manager.start() is expected
    assert manager.is_running is expected


def test_shutdown_stops_the_cleanup_passes() -> None:
    """Never touch the database after shutdown."""
    manager = ModuleFactory().create_flow_cleanup_manager_obj()
    manager.start()

    manager.shutdown()

    assert manager.run_cleanup_if_due(10000000) is False
    manager.main.db.maintain_flow_retention.assert_not_called()


@pytest.mark.parametrize(
    "seconds_since_last_pass, is_pass_expected",
    [
        (CLEANUP_PASS_INTERVAL_SECONDS - 1, False),
        (CLEANUP_PASS_INTERVAL_SECONDS, True),
        (CLEANUP_PASS_INTERVAL_SECONDS + 1, True),
    ],
)
def test_run_cleanup_if_due_respects_the_interval(
    seconds_since_last_pass: int, is_pass_expected: bool
) -> None:
    """Run a pass only once every CLEANUP_PASS_INTERVAL_SECONDS.

    Parameters:
        seconds_since_last_pass: Seconds since the previous pass.
        is_pass_expected: Whether a pass should run now.
    """
    manager = ModuleFactory().create_flow_cleanup_manager_obj()
    manager.start()
    now = 10000000.0
    manager.last_cleanup_pass_time = now - seconds_since_last_pass

    with patch.object(manager, "_run_cleanup_pass") as run_cleanup_pass:
        assert manager.run_cleanup_if_due(now) is is_pass_expected

    if is_pass_expected:
        run_cleanup_pass.assert_called_once_with(now)
        assert manager.last_cleanup_pass_time == now
    else:
        run_cleanup_pass.assert_not_called()


def test_flow_cleanup_runs_in_bounded_pass() -> None:
    """Delete old flows in small batches and clean the web flow index."""
    manager = ModuleFactory().create_flow_cleanup_manager_obj()
    manager.start()
    manager.main.db.maintain_flow_retention.return_value = ["old-flow"]

    with patch(f"{MANAGER}.time.time", return_value=10000000):
        assert manager.run_cleanup_if_due() is True

    manager.main.db.maintain_flow_retention.assert_called_once_with(
        9913600,
        7408000,
        batch_size=500,
        max_size_bytes=512 * 1024 * 1024,
        unlinked_size_cutoff=9996400,
    )
    manager.main.db.remove_flow_index_uids.assert_called_once_with(
        ["old-flow"]
    )
    manager.main.db.maintain_detection_history.assert_not_called()


def test_offline_analysis_never_runs_cleanup_work() -> None:
    """Preserve old PCAP flows even if the main loop asks for a pass."""
    manager = ModuleFactory().create_flow_cleanup_manager_obj()
    manager.main.args.interface = False
    manager.start()

    assert manager.run_cleanup_if_due(10000000) is False

    manager.main.db.maintain_flow_retention.assert_not_called()
    manager.main.db.maintain_detection_history.assert_not_called()


@pytest.mark.parametrize(
    "seconds_since_last_cleanup, removed_uids, expected_cleanups",
    [
        (59, [], 0),
        (60, [], 1),
        (61, ["uid1", "uid2"], 1),
    ],
)
def test_delete_old_flows_if_due(
    seconds_since_last_cleanup: int,
    removed_uids: list[str],
    expected_cleanups: int,
) -> None:
    """Skip passes that are not due and only clean the index when needed.

    Parameters:
        seconds_since_last_cleanup: Age of the previous flow cleanup.
        removed_uids: Flow UIDs deleted by this pass.
        expected_cleanups: Expected number of flow cleanup calls.
    """
    manager = ModuleFactory().create_flow_cleanup_manager_obj()
    manager.last_flow_cleanup_time = 1000
    manager.main.db.maintain_flow_retention.return_value = removed_uids
    now = 1000 + seconds_since_last_cleanup

    manager._delete_old_flows_if_due(now)

    assert (
        manager.main.db.maintain_flow_retention.call_count == expected_cleanups
    )
    assert manager.main.db.remove_flow_index_uids.call_count == int(
        bool(removed_uids)
    )
    assert manager.last_flow_cleanup_time == (
        now if expected_cleanups else 1000
    )


@pytest.mark.parametrize(
    "seconds_since_last_expiry, expected_calls",
    [
        (59, 0),
        (60, 1),
    ],
)
def test_expire_rotated_logs_if_due(
    seconds_since_last_expiry: int, expected_calls: int
) -> None:
    """Expire the rotated logs of this run at most once a minute.

    Parameters:
        seconds_since_last_expiry: Age of the previous expiry pass.
        expected_calls: Expected number of expiry calls.
    """
    manager = ModuleFactory().create_flow_cleanup_manager_obj()
    manager.last_rotated_logs_expiry_time = 1000
    now = 1000 + seconds_since_last_expiry

    with patch(f"{MANAGER}.expire_rotated_logs", return_value=0) as expire_rotated_logs:
        manager._expire_rotated_logs_if_due(now)

    assert expire_rotated_logs.call_count == expected_calls
    if expected_calls:
        expire_rotated_logs.assert_called_once_with(
            Path("output"), manager.detection_history_policy, now
        )


@pytest.mark.parametrize("persistent", [False, True])
def test_deferred_history_does_not_interrupt_flow_cleanup(
    persistent: bool,
) -> None:
    """Keep capture cleanup running and report only persistent contention.

    Parameters:
        persistent: Whether every pass remains busy beyond a minute.
    """
    manager = ModuleFactory().create_flow_cleanup_manager_obj()
    manager.detection_history_policy = full_history_policy()
    manager.start()
    manager.main.db.maintain_detection_history.side_effect = [
        {
            "deferred": persistent or index == 0,
            "phase": "cleanup",
            "sqlite_errorname": "SQLITE_BUSY",
        }
        for index in range(9)
    ]
    manager.main.db.maintain_flow_retention.return_value = []

    with patch(f"{MANAGER}.expire_rotated_logs", return_value=0):
        for index in range(9):
            manager.run_cleanup_if_due(1000 + index * 10)

    # flows are only cleaned once a minute: at 1000 and at 1060
    assert manager.main.db.maintain_flow_retention.call_count == 2
    assert manager.main.db.maintain_detection_history.call_count == 9
    assert manager.main.print.call_count == int(persistent)
    if persistent:
        message, verbosity, debug = manager.main.print.call_args.args
        assert "phase=cleanup" in message
        assert "SQLITE_BUSY" in message
        assert verbosity == 1
        assert debug == 0


def test_successful_history_pass_resets_the_deferral_state() -> None:
    """Forget earlier deferrals once a maintenance pass completes."""
    manager = ModuleFactory().create_flow_cleanup_manager_obj()
    manager.detection_history_policy = full_history_policy()
    manager.history_deferrals = 4
    manager.history_deferred_since = 900.0
    manager.main.db.maintain_detection_history.return_value = {
        "deferred": False
    }

    manager._maintain_detection_history(1000.0)

    assert manager.history_deferrals == 0
    assert manager.history_deferred_since is None
    assert manager.history_last_success_time == 1000.0
    manager.main.print.assert_not_called()


def test_failed_history_pass_is_reported_and_flows_still_cleaned() -> None:
    """Report a history failure without skipping the flow cleanup."""
    manager = ModuleFactory().create_flow_cleanup_manager_obj()
    manager.detection_history_policy = full_history_policy()
    manager.main.db.maintain_detection_history.side_effect = RuntimeError(
        "boom"
    )
    manager.main.db.maintain_flow_retention.return_value = []

    with patch(f"{MANAGER}.expire_rotated_logs", return_value=0):
        manager._run_cleanup_pass(10000000)

    message, verbosity, debug = manager.main.print.call_args.args
    assert "Detection history maintenance failed: boom" in message
    assert (verbosity, debug) == (0, 1)
    manager.main.db.maintain_flow_retention.assert_called_once()


def test_failed_flow_cleanup_never_reaches_the_main_loop() -> None:
    """Report a flow cleanup failure instead of raising it."""
    manager = ModuleFactory().create_flow_cleanup_manager_obj()
    manager.main.db.maintain_flow_retention.side_effect = RuntimeError("boom")

    manager._run_cleanup_pass(10000000)

    manager.main.print.assert_called_once_with(
        "Flow retention maintenance failed: boom", 0, 1
    )


def test_expired_rotated_logs_are_reported_with_the_reason() -> None:
    """Tell the user how many rotated logs were deleted and why."""
    manager = ModuleFactory().create_flow_cleanup_manager_obj()
    manager.detection_history_policy = full_history_policy()
    manager.last_rotated_logs_expiry_time = 0

    with patch(f"{MANAGER}.expire_rotated_logs", return_value=2):
        manager._expire_rotated_logs_if_due(1000)

    message, verbosity, debug = manager.main.print.call_args.args
    assert "Deleted 2 expired rotated log file(s)" in message
    assert "archive_retention_days=30" in message
    assert (verbosity, debug) == (0, 1)


def test_history_maintenance_result_is_reported_with_the_reason() -> None:
    """Tell the user which history work ran and which limit triggered it."""
    manager = ModuleFactory().create_flow_cleanup_manager_obj()
    manager.detection_history_policy = full_history_policy()

    manager._print_history_maintenance_result(
        {"units": 3, "size_pressure": True, "active_size_bytes": 3 * 1024**3}
    )

    message = manager.main.print.call_args.args[0]
    assert "did 3 step(s)" in message
    assert "max_active_size_mb=2048" in message


def test_history_maintenance_result_stays_silent_without_work() -> None:
    """Print nothing when the history pass archived or deleted nothing."""
    manager = ModuleFactory().create_flow_cleanup_manager_obj()
    manager.detection_history_policy = full_history_policy()

    manager._print_history_maintenance_result({"deferred": False})

    manager.main.print.assert_not_called()
