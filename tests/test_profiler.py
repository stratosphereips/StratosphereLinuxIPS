# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for slips_files/core/iperformance_profiler.py"""

from unittest.mock import Mock

from tests.module_factory import ModuleFactory
import pytest
import queue


def test_check_for_stop_msg(monkeypatch):
    profiler = ModuleFactory().create_profiler_obj()
    assert profiler.is_stop_msg("stop") is True
    assert profiler.is_stop_msg("not_stop") is False


def test_main_stop_msg_received():
    profiler = ModuleFactory().create_profiler_obj()
    profiler.should_stop = Mock(side_effect=[False, True])

    profiler.profiler_queue = Mock(spec=queue.Queue)
    profiler.profiler_queue.get.return_value = "stop"

    stopped = profiler.main()
    assert stopped
    # profiler.check_for_st op_msg.assert_called()


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


def test_main():
    profiler = ModuleFactory().create_profiler_obj()
    profiler.last_worker_id = 0
    profiler.check_if_high_throughput_and_add_workers = Mock()

    profiler.is_first_msg = False  # <--- SKIP FIRST-MSG BRANCH

    profiler.should_stop = Mock(side_effect=[False, True])

    msg = {"somemsg": 1, "line": "test line"}
    profiler.get_msg_from_queue = Mock(side_effect=[msg])

    profiler.profiler_queue = Mock()
    profiler.workers = []  # so sum([...]) doesn't fail
    profiler.main()
    profiler.profiler_queue.put.assert_called_once_with(msg)


def test_main_with_first_msg():
    profiler = ModuleFactory().create_profiler_obj()
    profiler.last_worker_id = 0
    profiler.check_if_high_throughput_and_add_workers = Mock()
    profiler.should_stop = Mock(side_effect=[False, False, True])

    # First msg triggers init; second msg is the one we expect to send to queue
    first = {"line": {"x": 1}}
    second = {"somemsg": 1, "line": {"y": 2}}

    profiler.get_msg_from_queue = Mock(side_effect=[first, second])

    profiler.input_handler_cls = Mock()
    profiler.get_handler_class = Mock(return_value=profiler.input_handler_cls)

    profiler.start_profiler_worker = Mock()

    profiler.profiler_queue = Mock()
    profiler.workers = []

    profiler.main()

    profiler.profiler_queue.put.assert_called_once_with(second)


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
