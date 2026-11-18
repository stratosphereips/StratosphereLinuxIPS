# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
import os
from unittest.mock import MagicMock, patch, Mock, call
import queue
import threading

from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "output_dir, file_to_clean, file_exists",
    [
        ("/tmp", "nonexistent.log", False),
        ("/tmp", "existing.log", True),
        ("/tmp", "/var/log/app.log", True),
    ],
)
def test_clean_file(output_dir, file_to_clean, file_exists):
    logger = ModuleFactory().create_evidence_loggr_obj()

    with patch("os.path.exists") as mock_exists, patch(
        "os.makedirs"
    ) as mock_makedirs, patch("builtins.open") as mock_open:

        mock_exists.return_value = file_exists

        mock_file = Mock()
        truncate_handle = Mock()
        mock_open.side_effect = (
            [truncate_handle, mock_file] if file_exists else [mock_file]
        )

        result = logger.clean_file(output_dir, file_to_clean)

        expected_path = (
            file_to_clean
            if os.path.isabs(file_to_clean)
            else os.path.join(output_dir, file_to_clean)
        )
        expected_dir = os.path.dirname(expected_path)

        mock_exists.assert_called_once_with(expected_path)
        mock_makedirs.assert_called_once_with(expected_dir, exist_ok=True)

        if file_exists:
            assert mock_open.call_args_list == [
                call(expected_path, "w"),
                call(expected_path, "a"),
            ]
            truncate_handle.close.assert_called_once_with()
        else:
            assert mock_open.call_args_list == [
                call(expected_path, "a"),
            ]

        assert result == mock_file


@pytest.mark.parametrize(
    "msg, expected_method",
    [
        (
            {"where": "alerts.log", "to_log": "log this"},
            "print_to_alerts_logfile",
        ),
        (
            {"where": "alerts.json", "to_log": {"key": "value"}},
            "print_to_alerts_json",
        ),
    ],
)
def test_run_logger_thread(msg, expected_method):
    # create logger instance
    logger = ModuleFactory().create_evidence_loggr_obj()

    # mock the printing methods
    logger.print_to_alerts_logfile = MagicMock()
    logger.print_to_alerts_json = MagicMock()
    logger.shutdown_gracefully = MagicMock()

    # prepare a mock queue
    q_items = [msg]  # the messages queue will yield

    def mock_get(timeout=None):
        try:
            return q_items.pop(0)
        except IndexError:
            raise queue.Empty

    logger.evidence_logger_q = MagicMock()
    logger.evidence_logger_q.get = MagicMock(side_effect=mock_get)

    # prepare stop signal so loop stops after one iteration
    logger.logger_stop_signal = threading.Event()

    # run in a thread to prevent blocking (since loop checks stop signal)
    def run_logger():
        logger.run_logger_thread()

    thread = threading.Thread(target=run_logger)
    thread.start()

    # wait a short moment and then stop the loop
    threading.Timer(0.1, logger.logger_stop_signal.set).start()
    thread.join()

    # assert the correct method was called with the correct argument
    if expected_method == "print_to_alerts_logfile":
        logger.print_to_alerts_logfile.assert_called_once_with(msg["to_log"])
    else:
        logger.print_to_alerts_json.assert_called_once_with(msg["to_log"])

    # assert shutdown was called once
    logger.shutdown_gracefully.assert_called_once()


@pytest.mark.parametrize("is_rotated", [True, False])
def test_reopen_logfile_if_rotated(tmp_path, is_rotated):
    logger = ModuleFactory().create_evidence_loggr_obj()
    path = tmp_path / "alerts.log"
    logfile = open(path, "a")
    if is_rotated:
        path.rename(tmp_path / "alerts.log.rotated")
        path.touch()

    reopened = logger._reopen_logfile_if_rotated(logfile)
    reopened.write("new line\n")
    reopened.close()

    assert (reopened is logfile) is not is_rotated
    assert logfile.closed
    assert path.read_text() == "new line\n"


def test_reopen_logfile_if_rotated_recreates_a_missing_log(tmp_path):
    logger = ModuleFactory().create_evidence_loggr_obj()
    path = tmp_path / "alerts.log"
    logfile = open(path, "a")
    path.rename(tmp_path / "alerts.log.rotated")

    reopened = logger._reopen_logfile_if_rotated(logfile)
    reopened.close()

    assert reopened is not logfile
    assert path.exists()


@pytest.mark.parametrize(
    "is_rotation_enabled, seconds_since_last_check, expected_checks",
    [
        (True, 5, 2),
        (True, 0, 0),
        (False, 5, 0),
    ],
)
def test_reopen_rotated_logfiles_if_due(
    is_rotation_enabled, seconds_since_last_check, expected_checks
):
    logger = ModuleFactory().create_evidence_loggr_obj()
    logger.is_log_rotation_enabled = is_rotation_enabled
    logger._reopen_logfile_if_rotated = Mock(side_effect=lambda file: file)

    with patch("slips_files.core.evidence_logger.time.monotonic") as now:
        now.return_value = 100.0
        logger.last_rotated_logfiles_check_time = (
            100.0 - seconds_since_last_check
        )
        logger.reopen_rotated_logfiles_if_due()

    assert logger._reopen_logfile_if_rotated.call_count == expected_checks


def test_reopen_rotated_logfiles_if_due_keeps_handles_on_os_error():
    logger = ModuleFactory().create_evidence_loggr_obj()
    logger.is_log_rotation_enabled = True
    logfile = logger.logfile
    logger._reopen_logfile_if_rotated = Mock(side_effect=OSError("disk"))

    logger.reopen_rotated_logfiles_if_due()

    assert logger.logfile is logfile
