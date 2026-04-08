# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for the profiler core process."""

from unittest.mock import Mock, patch

import pytest
from tests.module_factory import ModuleFactory


def mock_print(*args, **kwargs):
    pass


def test_mark_process_as_done_processing(monkeypatch):
    profiler = ModuleFactory().create_profiler_obj()
    profiler.done_processing = Mock()
    profiler.is_profiler_done_event = Mock()

    monkeypatch.setattr(profiler, "print", mock_print)

    profiler.mark_self_as_done_processing()

    profiler.done_processing.release.assert_called_once()
    profiler.is_profiler_done_event.set.assert_called_once()


@pytest.mark.parametrize(
    "msg_from_queue, handler_obj, expected_start_workers",
    [
        # Case 1: valid input starts the default profiler workers
        ({"line": {"f1": "v1"}}, Mock(), 3),
        # Case 2: unsupported input type, no input_handler_obj
        ({"line": {"f1": "v1"}}, None, 0),
        # Case 3: empty queue initially, then valid msg
        (None, Mock(), 3),
    ],
)
def test_main(
    msg_from_queue,
    handler_obj,
    expected_start_workers,
):
    profiler = ModuleFactory().create_profiler_obj()
    profiler.last_worker_id = 0

    # Mock methods
    profiler._check_if_high_throughput_and_add_workers = Mock()
    profiler.start_profiler_worker = Mock()
    profiler.store_flows_read_per_second = Mock()
    profiler._update_lines_read_by_all_workers = Mock()
    profiler.print = Mock()
    profiler.profiler_monitor_thread = Mock()

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
    with (
        patch("time.sleep"),
        patch("slips_files.core.profiler.utils.start_thread") as start_thread,
    ):
        profiler.main()

    if handler_obj:
        handler_obj.process_line.assert_called_once_with({"f1": "v1"})
        start_thread.assert_called_once_with(
            profiler.profiler_monitor_thread, profiler.db
        )
        assert (
            profiler.start_profiler_worker.call_count == expected_start_workers
        )
    else:
        profiler.print.assert_called_once()
        start_thread.assert_not_called()
        assert profiler.start_profiler_worker.call_count == 0


def test_shutdown_gracefully(monkeypatch):
    profiler = ModuleFactory().create_profiler_obj()
    profiler.workers = [
        Mock(received_lines=10),
        Mock(received_lines=20),
        Mock(received_lines=3),
    ]
    profiler.stop_profiler_workers = Mock()
    profiler.aid_queue = Mock()
    profiler.aid_manager = Mock()
    profiler.profiler_queue = Mock()
    profiler.profiler_monitor_thread = Mock()
    profiler.mark_self_as_done_processing = Mock()
    profiler.shutdown_gracefully()

    profiler.stop_profiler_workers.assert_called_once()
    profiler.aid_queue.put.assert_called_once_with("stop")
    profiler.aid_manager.shutdown.assert_called_once()
    profiler.profiler_queue.cancel_join_thread.assert_called_once()
    profiler.profiler_queue.close.assert_called_once()
    profiler.aid_queue.cancel_join_thread.assert_called_once()
    profiler.aid_queue.close.assert_called_once()
    profiler.print.assert_called_with("Stopping.", log_to_logfiles_only=True)
    profiler.mark_self_as_done_processing.assert_called_once()


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


@patch("slips_files.core.profiler.ProfilerWorker")
def test_start_profiler_worker_uses_parent_output_dir(mock_worker_cls):
    profiler = ModuleFactory().create_profiler_obj()
    worker = mock_worker_cls.return_value
    profiler.profiler_child_processes = []
    profiler.workers = []
    profiler.profiler_queue = Mock()
    profiler.input_handler_obj = Mock()
    profiler.aid_queue = Mock()
    profiler.aid_manager = Mock()
    profiler.is_input_done_event = Mock()

    profiler.start_profiler_worker(7)

    mock_worker_cls.assert_called_once_with(
        logger=profiler.logger,
        output_dir=profiler.parent_output_dir,
        redis_port=profiler.redis_port,
        termination_event=profiler.termination_event,
        conf=profiler.conf,
        ppid=profiler.ppid,
        slips_args=profiler.args,
        bloom_filters_manager=profiler.bloom_filters,
        name="profiler_worker_process_7",
        profiler_queue=profiler.profiler_queue,
        input_handler=profiler.input_handler_obj,
        aid_queue=profiler.aid_queue,
        aid_manager=profiler.aid_manager,
        is_input_done_event=profiler.is_input_done_event,
    )
    worker.start.assert_called_once()
    assert profiler.profiler_child_processes == [worker]
    assert profiler.workers == []
    profiler.db.increment_profiler_workers_started.assert_called_once()
