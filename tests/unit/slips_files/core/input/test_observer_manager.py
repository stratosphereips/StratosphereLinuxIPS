# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import MagicMock, patch
from tests.module_factory import ModuleFactory
from slips_files.core.input.observer_manager import InputObserver


def test_input_observer_start_schedules_dirs():
    input_process = ModuleFactory().create_input_obj("", "zeek_log_file")
    observer = InputObserver(input_process)

    with (
        patch(
            "slips_files.core.input.observer_manager.FileEventHandler"
        ) as mock_handler,
        patch("slips_files.core.input.observer_manager.Observer") as mock_obs,
    ):
        observer.start("/tmp/zeek", "eth0")

    mock_handler.assert_called_once_with("/tmp/zeek", input_process.db, "eth0")
    obs_instance = mock_obs.return_value
    obs_instance.schedule.assert_any_call(
        mock_handler.return_value, "/tmp/zeek", recursive=True
    )
    obs_instance.schedule.assert_any_call(
        mock_handler.return_value, "config/", recursive=True
    )
    obs_instance.start.assert_called_once()


def test_input_observer_stop_handles_missing_observer():
    input_process = ModuleFactory().create_input_obj("", "zeek_log_file")
    observer = InputObserver(input_process)
    observer.observer = MagicMock()

    observer.stop()
    observer.observer.stop.assert_called_once()
    observer.observer.join.assert_called_once_with(10)
