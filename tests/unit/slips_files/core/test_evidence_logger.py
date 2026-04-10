# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
import os
from unittest.mock import MagicMock, patch, Mock, call
import queue
import threading

from slips_files.core.evidence_logger import EvidenceLogger
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


def test_init_latency_file_places_latency_csv_under_performance_csv_dir(
    tmp_path, monkeypatch
):
    module_factory = ModuleFactory()
    assert module_factory is not None

    def fake_read_configuration(self):
        self.GID = 0
        self.UID = 0
        self.generate_performance_plots = False

    monkeypatch.chdir(tmp_path)

    with patch.object(
        EvidenceLogger, "read_configuration", fake_read_configuration
    ), patch(
        "slips_files.core.evidence_logger.utils.change_logfiles_ownership"
    ):
        logger = EvidenceLogger(
            logger_stop_signal=threading.Event(),
            evidence_logger_q=Mock(),
            output_dir="output_dir",
        )
        logger._init_latency_file()
        logger.shutdown_gracefully()

    assert (
        tmp_path / "output_dir" / "performance_plots" / "csv" / "latency.csv"
    ).exists()
    assert not (
        tmp_path
        / "output_dir"
        / "output_dir"
        / "performance_plots"
        / "csv"
        / "latency.csv"
    ).exists()
