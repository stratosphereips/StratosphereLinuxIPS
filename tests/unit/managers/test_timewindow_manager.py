# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import Mock, patch

import pytest

from managers.timewindow_manager import TimewindowManager
from tests.module_factory import ModuleFactory


def test_init_reads_timewindow_width_from_configuration() -> None:
    """Initialize the manager from the main configuration."""
    main = ModuleFactory().create_main_obj()
    main.conf = Mock()
    main.conf.get_tw_width_in_seconds.return_value = 120
    main.db = Mock()

    manager = TimewindowManager(main)

    assert manager.twid_width == 120
    assert manager.current_timewindow == 1
    assert manager.next_timewindow_update is None


@pytest.mark.parametrize(
    "db_value",
    [
        True,
        False,
    ],
)
def test_is_running_non_stop_caches_database_value(db_value: bool) -> None:
    """Cache the non-stop state after the first database lookup."""
    main = ModuleFactory().create_main_obj()
    main.conf = Mock()
    main.conf.get_tw_width_in_seconds.return_value = 3600
    main.db = Mock()
    main.db.is_running_non_stop.return_value = db_value

    manager = TimewindowManager(main)

    assert manager._is_running_non_stop() is db_value
    assert manager._is_running_non_stop() is db_value
    main.db.is_running_non_stop.assert_called_once_with()


def test_init_first_timewindow_ever_sets_initial_values() -> None:
    """Set the first live timewindow using the stored Slips start time."""
    main = ModuleFactory().create_main_obj()
    main.conf = Mock()
    main.conf.get_tw_width_in_seconds.return_value = 300
    main.db = Mock()
    main.db.get_slips_start_time.return_value = 1_000.0

    manager = TimewindowManager(main)
    manager._init_first_timewindow_ever()

    assert manager.current_timewindow == 1
    assert manager.next_timewindow_update == 1_300.0
    main.db.incr_current_timewindow.assert_called_once_with()


def test_init_first_timewindow_ever_is_noop_after_first_init() -> None:
    """Avoid reinitializing once the first timewindow already exists."""
    main = ModuleFactory().create_main_obj()
    main.conf = Mock()
    main.conf.get_tw_width_in_seconds.return_value = 3600
    main.db = Mock()

    manager = TimewindowManager(main)
    manager.next_timewindow_update = 2_000.0

    manager._init_first_timewindow_ever()

    main.db.get_slips_start_time.assert_not_called()
    main.db.incr_current_timewindow.assert_not_called()


def test_update_current_timewindow_if_due_skips_non_stop_disabled() -> None:
    """Skip current-timewindow tracking outside non-stop mode."""
    main = ModuleFactory().create_main_obj()
    main.conf = Mock()
    main.conf.get_tw_width_in_seconds.return_value = 3600
    main.db = Mock()
    main.db.is_running_non_stop.return_value = False

    manager = TimewindowManager(main)
    manager.update_current_timewindow_if_due()

    main.db.get_slips_start_time.assert_not_called()
    main.db.incr_current_timewindow.assert_not_called()


@pytest.mark.parametrize(
    "now_value, expected_timewindow, expected_next_update, expected_calls",
    [
        (1_250.0, 1, 1_300.0, 1),
        (1_350.0, 2, 1_600.0, 2),
    ],
)
def test_update_current_timewindow_if_due(
    now_value: float,
    expected_timewindow: int,
    expected_next_update: float,
    expected_calls: int,
) -> None:
    """Update the current live timewindow only when the deadline is reached."""
    main = ModuleFactory().create_main_obj()
    main.conf = Mock()
    main.conf.get_tw_width_in_seconds.return_value = 300
    main.db = Mock()
    main.db.is_running_non_stop.return_value = True
    main.db.get_slips_start_time.return_value = 1_000.0

    manager = TimewindowManager(main)

    with patch(
        "managers.timewindow_manager.time.time", return_value=now_value
    ):
        manager.update_current_timewindow_if_due()

    assert manager.current_timewindow == expected_timewindow
    assert manager.next_timewindow_update == expected_next_update
    assert main.db.incr_current_timewindow.call_count == expected_calls
