# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for slips_files/core/iperformance_profiler.py"""

from unittest.mock import Mock, patch

from tests.module_factory import ModuleFactory
import pytest


def mock_print(*args, **kwargs):
    pass


def test_mark_process_as_done_processing(monkeypatch):
    profiler = ModuleFactory().create_profiler_obj()
    profiler.done_processing = Mock()
    profiler.is_profiler_done_event = Mock()

    monkeypatch.setattr(profiler, "print", mock_print)

    profiler.mark_process_as_done_processing()

    profiler.done_processing.release.assert_called_once()
    profiler.is_profiler_done_event.set.assert_called_once()


@pytest.mark.parametrize(
    "msg_from_queue, handler_obj, should_stop_side_effect, expected_start_workers, expect_print_called",
    [
        # Case 1: triggers all branches
        ({"line": {"f1": "v1"}}, Mock(), [False, True], 5, False),
        # Case 2: unsupported input type, no input_handler_obj
        ({"line": {"f1": "v1"}}, None, [True], 0, True),
        # Case 3: empty queue initially, then valid msg
        ({"line": {"f1": "v1"}}, Mock(), [False, True], 5, False),
    ],
)
def test_main(
    msg_from_queue,
    handler_obj,
    should_stop_side_effect,
    expected_start_workers,
    expect_print_called,
):
    profiler = ModuleFactory().create_profiler_obj()
    profiler.last_worker_id = 0

    # Mock methods
    profiler._check_if_high_throughput_and_add_workers = Mock()
    profiler.start_profiler_worker = Mock()
    profiler.store_flows_read_per_second = Mock()
    profiler._update_lines_read_by_all_workers = Mock()
    profiler.print = Mock()

    # Mock should_stop
    profiler.should_stop = Mock(side_effect=should_stop_side_effect)

    # Handle empty queue case
    if msg_from_queue is None:
        profiler.get_msg_from_queue = Mock(
            side_effect=[None, {"line": {"f1": "v1"}}]
        )
    else:
        profiler.get_msg_from_queue = Mock(side_effect=[msg_from_queue])

    # Mock input handler
    profiler.get_handler_obj = Mock(return_value=handler_obj)

    profiler.profiler_queue = Mock()
    profiler.workers = []
    with patch("time.sleep"):
        profiler.main()

    if handler_obj:
        handler_obj.process_line.assert_called_once_with(
            msg_from_queue["line"]
        )
        assert (
            profiler.start_profiler_worker.call_count == expected_start_workers
        )
    else:
        profiler.print.assert_called_once()
        assert profiler.start_profiler_worker.call_count == 0


def test_shutdown_gracefully(monkeypatch):
    profiler = ModuleFactory().create_profiler_obj()
    profiler.workers = [
        Mock(received_lines=10),
        Mock(received_lines=20),
        Mock(received_lines=3),
    ]
    profiler.mark_process_as_done_processing = Mock()

    # monkeypatch.setattr(profiler, "print", Mock())
    profiler.shutdown_gracefully()
    profiler.print.assert_called_with(
        "Stopping. Total lines read: 33", log_to_logfiles_only=True
    )
    profiler.mark_process_as_done_processing.assert_called_once()


def test_notify_observers_no_observers():
    profiler = ModuleFactory().create_profiler_obj()
    test_msg = {"action": "test"}
    try:
        profiler.notify_observers(test_msg)
    except Exception as e:
        pytest.fail(f"Unexpected error occurred: {e}")


def test_notify_observers():
    profiler = ModuleFactory().create_profiler_obj()
    observer_mock = Mock()
    profiler.observers.append(observer_mock)
    test_msg = {"test": "message"}
    profiler.notify_observers(test_msg)
    observer_mock.update.assert_called_once_with(test_msg)


def test_notify_observers_with_correct_message():
    observer_mock = Mock()
    profiler = ModuleFactory().create_profiler_obj()
    profiler.observers.append(observer_mock)
    test_msg = {"action": "test_action"}
    profiler.notify_observers(test_msg)
    observer_mock.update.assert_called_once_with(test_msg)
