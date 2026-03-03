# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
import os
from unittest.mock import MagicMock, patch, Mock
import queue
import threading

from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "output_dir, file_to_clean, file_exists",
    [
        # testcase1: File doesn't exist
        ("/tmp", "nonexistent.log", False),
        # testcase2: File exists
        ("/tmp", "existing.log", True),
    ],
)
def test_clean_file(output_dir, file_to_clean, file_exists):
    logger = ModuleFactory().create_evidence_loggr_obj()
    with patch("os.path.exists") as mock_exists, patch(
        "builtins.open"
    ) as mock_open:
        mock_exists.return_value = file_exists
        mock_file = Mock()
        mock_open.return_value = mock_file

        result = logger.clean_file(output_dir, file_to_clean)

        expected_path = os.path.join(output_dir, file_to_clean)
        mock_exists.assert_called_once_with(expected_path)
        mock_open.assert_called_with(expected_path, "a")

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
