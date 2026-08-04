# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from unittest.mock import Mock, call, patch

from slips_files.core.evidence_handler import (
    DEFAULT_EVIDENCE_HANDLER_WORKERS,
    EVIDENCE_HANDLER_SHUTDOWN_GRACE_PERIOD_SECONDS,
)
from tests.module_factory import ModuleFactory


def test_shutdown_gracefully():
    handler = ModuleFactory().create_evidence_handler_obj()
    handler.stop_evidence_workers = Mock()
    handler.logger_stop_signal = Mock()
    handler.logger_thread = Mock()
    handler.evidence_worker_queue = Mock()
    handler.evidence_logger_q = Mock()

    handler.shutdown_gracefully()

    handler.stop_evidence_workers.assert_called_once()
    handler.logger_stop_signal.set.assert_called_once()
    handler.logger_thread.join.assert_called_once_with(timeout=5)
    handler.evidence_worker_queue.cancel_join_thread.assert_called_once()
    handler.evidence_worker_queue.close.assert_called_once()
    handler.evidence_logger_q.cancel_join_thread.assert_called_once()
    handler.evidence_logger_q.close.assert_called_once()


def test_stop_evidence_workers():
    handler = ModuleFactory().create_evidence_handler_obj()
    process_1 = Mock()
    process_2 = Mock()
    handler.evidence_worker_child_processes = [process_1, process_2]
    handler.evidence_worker_queue = Mock()

    handler.stop_evidence_workers()

    assert handler.evidence_worker_queue.put.call_args_list == [
        call("stop"),
        call("stop"),
    ]
    process_1.join.assert_called_once()
    process_2.join.assert_called_once()


@patch("slips_files.core.evidence_handler.EvidenceHandlerWorker")
def test_start_evidence_worker(mock_worker_cls):
    handler = ModuleFactory().create_evidence_handler_obj()
    worker = mock_worker_cls.return_value
    handler.evidence_worker_child_processes = []
    handler.evidence_worker_queue = Mock()
    handler.evidence_logger_q = Mock()

    handler.start_evidence_worker(7)

    mock_worker_cls.assert_called_once_with(
        logger=handler.logger,
        output_dir=handler.parent_output_dir,
        redis_port=handler.redis_port,
        termination_event=handler.termination_event,
        conf=handler.conf,
        ppid=handler.ppid,
        slips_args=handler.args,
        bloom_filters_manager=handler.bloom_filters,
        name="evidence_handler_worker_process_7",
        evidence_queue=handler.evidence_worker_queue,
        evidence_logger_q=handler.evidence_logger_q,
    )
    worker.start.assert_called_once()
    assert handler.evidence_worker_child_processes == [worker]


def test_should_stop_returns_false_if_termination_not_set():
    handler = ModuleFactory().create_evidence_handler_obj()
    handler.termination_event.is_set.return_value = False

    assert handler.should_stop() is False


@patch("slips_files.core.evidence_handler.time.time", return_value=100.0)
def test_queue_incoming_messages_updates_last_message_time(_mock_time):
    handler = ModuleFactory().create_evidence_handler_obj()
    handler.get_msg = Mock(side_effect=[{"data": "evidence"}, None])
    handler.evidence_worker_queue = Mock()
    handler.last_msg_received_time = 10.0

    assert handler.queue_incoming_messages() is True
    assert handler.last_msg_received_time == 100.0
    handler.evidence_worker_queue.put.assert_called_once_with(
        {
            "channel": "evidence_added",
            "message": {"data": "evidence"},
        }
    )


@patch("slips_files.core.evidence_handler.time.time", return_value=120.0)
def test_should_stop_waits_for_grace_period(_mock_time):
    handler = ModuleFactory().create_evidence_handler_obj()
    handler.termination_event.is_set.return_value = True
    handler.last_msg_received_time = 100.0

    assert handler.should_stop() is False


@patch(
    "slips_files.core.evidence_handler.time.time",
    return_value=(100.0 + EVIDENCE_HANDLER_SHUTDOWN_GRACE_PERIOD_SECONDS + 1),
)
def test_should_stop_after_grace_period(_mock_time):
    handler = ModuleFactory().create_evidence_handler_obj()
    handler.termination_event.is_set.return_value = True
    handler.last_msg_received_time = 100.0

    assert handler.should_stop() is True


def test_pre_main_starts_default_workers():
    handler = ModuleFactory().create_evidence_handler_obj()
    handler.start_evidence_worker = Mock()

    handler.pre_main()

    assert handler.start_evidence_worker.call_count == (
        DEFAULT_EVIDENCE_HANDLER_WORKERS
    )
    handler.start_evidence_worker.assert_has_calls([call(0), call(1), call(2)])


def test_main_queues_received_messages():
    handler = ModuleFactory().create_evidence_handler_obj()
    handler.queue_incoming_messages = Mock(side_effect=[True, False])
    handler.should_stop = Mock(side_effect=[False, True])

    handler.main()

    assert handler.queue_incoming_messages.call_count == 2
    assert handler.should_stop.call_count == 2


@patch(
    "slips_files.core.evidence_handler.time.time",
    side_effect=[200.0, 200.0, 231.0],
)
def test_main_drains_new_messages_before_shutdown(_mock_time):
    handler = ModuleFactory().create_evidence_handler_obj()
    handler.evidence_worker_queue = Mock()
    handler.termination_event.is_set.return_value = True
    handler.last_msg_received_time = 100.0

    def get_msg(channel):
        calls = get_msg.calls.setdefault(channel, 0)
        get_msg.calls[channel] = calls + 1
        if channel == "evidence_added" and calls == 0:
            return {"data": "late-evidence"}
        return None

    get_msg.calls = {}
    handler.get_msg = Mock(side_effect=get_msg)

    handler.main()

    assert handler.evidence_worker_queue.put.call_args_list == [
        call(
            {
                "channel": "evidence_added",
                "message": {"data": "late-evidence"},
            }
        )
    ]
