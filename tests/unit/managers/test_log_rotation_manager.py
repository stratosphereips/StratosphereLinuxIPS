# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for the log rotation manager."""

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from managers.log_rotation_manager import (
    LOCK_ACQUIRE_TIMEOUT_SECONDS,
    LOG_ROTATION_INTERVAL_SECONDS,
)
from tests.module_factory import ModuleFactory

MANAGER = "managers.log_rotation_manager"


@pytest.mark.parametrize("is_history_enabled", [True, False])
def test_start_follows_the_detection_history_policy(
    is_history_enabled: bool,
) -> None:
    """Enable the rotation passes only when detection_history is enabled.

    Parameters:
        is_history_enabled: Whether detection_history is enabled.
    """
    manager = ModuleFactory().create_log_rotation_manager_obj()
    manager.detection_history_policy["enabled"] = is_history_enabled

    assert manager.start() is is_history_enabled
    assert manager.is_running is is_history_enabled


def test_shutdown_stops_the_rotation_passes() -> None:
    """Never rotate a log after shutdown."""
    manager = ModuleFactory().create_log_rotation_manager_obj()
    manager.start()

    manager.shutdown()

    with patch(f"{MANAGER}.rotate_log") as rotate_log:
        assert manager.rotate_logs_if_due(1000.0) == 0
    rotate_log.assert_not_called()


@pytest.mark.parametrize(
    "mode, is_slips_log_rotated",
    [
        ("interactive", True),
        ("daemonized", False),
    ],
)
def test_get_logs_to_rotate(mode: str, is_slips_log_rotated: bool) -> None:
    """List every owned log with its lock, and skip slips.log in daemon mode.

    Parameters:
        mode: Mode Slips is running in.
        is_slips_log_rotated: Whether slips.log should be listed.
    """
    manager = ModuleFactory().create_log_rotation_manager_obj()
    manager.main.mode = mode

    with patch(
        f"{MANAGER}.get_alerts_path_inside_output_dir",
        return_value="output/alerts",
    ):
        logs = dict(manager._get_logs_to_rotate())

    expected = {
        Path("output/errors.log"): manager.main.logger.errors_logfile_lock,
        Path("output/alerts/alerts.log"): None,
        Path("output/alerts/alerts.json"): None,
    }
    if is_slips_log_rotated:
        expected[Path("output/slips.log")] = (
            manager.main.logger.slips_logfile_lock
        )
    assert logs == expected


@pytest.mark.parametrize(
    "has_lock, is_lock_acquired, expected_rotate_calls",
    [
        (False, False, 1),
        (True, True, 1),
        (True, False, 0),
    ],
)
def test_rotate_log_holds_the_writers_lock(
    has_lock: bool, is_lock_acquired: bool, expected_rotate_calls: int
) -> None:
    """Rotate under the writers' lock and skip a log whose lock is stuck.

    Parameters:
        has_lock: Whether the log has a writers' lock.
        is_lock_acquired: Whether the lock is acquired before the timeout.
        expected_rotate_calls: Expected calls to rotate_log.
    """
    manager = ModuleFactory().create_log_rotation_manager_obj()
    lock = Mock()
    lock.acquire.return_value = is_lock_acquired
    path = Path("output/errors.log")

    with patch(f"{MANAGER}.rotate_log", return_value=True) as rotate_log:
        is_rotated = manager._rotate_log(
            path, lock if has_lock else None, 1000.0
        )

    assert is_rotated is bool(expected_rotate_calls)
    assert rotate_log.call_count == expected_rotate_calls
    if expected_rotate_calls:
        rotate_log.assert_called_once_with(
            path, manager.detection_history_policy, 1000.0
        )
    if has_lock:
        lock.acquire.assert_called_once_with(
            timeout=LOCK_ACQUIRE_TIMEOUT_SECONDS
        )
        assert lock.release.call_count == int(is_lock_acquired)


def test_rotate_log_releases_the_lock_when_rotation_fails() -> None:
    """A failed rotation must not leave the writers locked out."""
    manager = ModuleFactory().create_log_rotation_manager_obj()
    lock = Mock()
    lock.acquire.return_value = True

    with (
        patch(f"{MANAGER}.rotate_log", side_effect=OSError("disk")),
        pytest.raises(OSError),
    ):
        manager._rotate_log(Path("output/errors.log"), lock, 1000.0)

    lock.release.assert_called_once_with()


@pytest.mark.parametrize(
    "seconds_since_last_pass, is_pass_expected",
    [
        (LOG_ROTATION_INTERVAL_SECONDS - 1, False),
        (LOG_ROTATION_INTERVAL_SECONDS, True),
        (LOG_ROTATION_INTERVAL_SECONDS + 1, True),
    ],
)
def test_rotate_logs_if_due_respects_the_interval(
    seconds_since_last_pass: int, is_pass_expected: bool
) -> None:
    """Run a pass only once every LOG_ROTATION_INTERVAL_SECONDS.

    Parameters:
        seconds_since_last_pass: Seconds since the previous pass.
        is_pass_expected: Whether a pass should run now.
    """
    manager = ModuleFactory().create_log_rotation_manager_obj()
    manager.start()
    now = 1000.0
    manager.last_rotation_time = now - seconds_since_last_pass
    logs = [(Path("a.log"), None), (Path("b.log"), None)]

    with (
        patch.object(manager, "_get_logs_to_rotate", return_value=logs),
        patch.object(
            manager, "_rotate_log", side_effect=[True, False]
        ) as rotate_one_log,
    ):
        rotated_logs = manager.rotate_logs_if_due(now)

    if is_pass_expected:
        assert rotated_logs == 1
        assert rotate_one_log.call_count == len(logs)
        assert manager.last_rotation_time == now
    else:
        assert rotated_logs == 0
        rotate_one_log.assert_not_called()
        assert manager.last_rotation_time == now - seconds_since_last_pass


def test_rotate_logs_if_due_reports_a_failure_and_continues() -> None:
    """One log failing to rotate must not stop the rest of the pass."""
    manager = ModuleFactory().create_log_rotation_manager_obj()
    manager.start()
    logs = [(Path("a.log"), None), (Path("b.log"), None)]

    with (
        patch.object(manager, "_get_logs_to_rotate", return_value=logs),
        patch.object(
            manager, "_rotate_log", side_effect=[OSError("disk"), True]
        ),
    ):
        assert manager.rotate_logs_if_due(1000.0) == 1

    failure, success = manager.main.print.call_args_list
    assert "Failed to rotate a.log" in failure.args[0]
    assert "Rotated b.log" in success.args[0]


def test_rotate_logs_if_due_rotates_a_full_log(tmp_path: Path) -> None:
    """Rotate a real log that reached the size limit and keep it writable.

    Parameters:
        tmp_path: Temporary output directory.
    """
    manager = ModuleFactory().create_log_rotation_manager_obj()
    manager.main.args.output = str(tmp_path)
    errors_log = tmp_path / "errors.log"
    slips_log = tmp_path / "slips.log"
    manager.main.logger.errors_logfile = str(errors_log)
    manager.main.logger.slips_logfile = str(slips_log)
    errors_log.write_bytes(b"x" * 1024 * 1024)
    slips_log.write_text("small")
    manager.start()

    assert manager.rotate_logs_if_due() == 1

    assert errors_log.read_bytes() == b""
    assert len(list((tmp_path / "rotated").glob("errors.log.*"))) == 1
    assert slips_log.read_text() == "small"
