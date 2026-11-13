"""Unit tests for AIDManager task submission, worker loop and shutdown."""

from queue import Empty
from unittest.mock import Mock, patch

import pytest

from slips_files.core.aid_manager import AIDManager


def make_task(flow=None, profileid="profile_1.1.1.1", twid="timewindow1"):
    return {
        "flow": flow or Mock(),
        "profileid": profileid,
        "twid": twid,
        "label": "benign",
    }


def make_manager(queue=None) -> AIDManager:
    return AIDManager.for_queue(queue or Mock())


def test_for_queue_creates_client_with_only_the_queue():
    queue = Mock()
    client = AIDManager.for_queue(queue)

    assert client._aid_queue is queue
    assert not hasattr(client, "_process")
    assert not hasattr(client, "db")


def test_submit_aid_task_puts_task_dict_in_queue():
    queue = Mock()
    manager = make_manager(queue)
    flow = Mock()

    manager.submit_aid_task(flow, "profile_1.1.1.1", "timewindow1", "benign")

    queue.put.assert_called_once_with(
        {
            "flow": flow,
            "profileid": "profile_1.1.1.1",
            "twid": "timewindow1",
            "label": "benign",
        }
    )


def test_worker_loop_hashes_and_stores_flow_then_stops():
    task = make_task()
    queue = Mock()
    queue.get.side_effect = [task, "stop"]
    db = Mock()

    with patch(
        "slips_files.core.aid_manager.utils.get_aid", return_value="aid123"
    ) as get_aid:
        make_manager(queue)._worker_loop(queue, db)

    get_aid.assert_called_once_with(task["flow"])
    assert task["flow"].aid == "aid123"
    db.add_flow.assert_called_once_with(
        task["flow"], task["profileid"], task["twid"], label="benign"
    )


def test_worker_loop_preserves_queue_order():
    tasks = [make_task(profileid=f"profile_{i}") for i in range(3)]
    queue = Mock()
    queue.get.side_effect = [*tasks, "stop"]
    db = Mock()

    with patch(
        "slips_files.core.aid_manager.utils.get_aid", return_value="aid"
    ):
        make_manager(queue)._worker_loop(queue, db)

    stored = [call.args[1] for call in db.add_flow.call_args_list]
    assert stored == ["profile_0", "profile_1", "profile_2"]


def test_worker_loop_stop_sentinel_stores_nothing():
    queue = Mock()
    queue.get.side_effect = ["stop"]
    db = Mock()

    make_manager(queue)._worker_loop(queue, db)

    db.add_flow.assert_not_called()


@pytest.mark.parametrize("interruption", [Empty(), KeyboardInterrupt()])
def test_worker_loop_keeps_running_after_empty_or_interrupt(interruption):
    task = make_task()
    queue = Mock()
    queue.get.side_effect = [interruption, task, "stop"]
    db = Mock()

    with patch(
        "slips_files.core.aid_manager.utils.get_aid", return_value="aid"
    ):
        make_manager(queue)._worker_loop(queue, db)

    db.add_flow.assert_called_once()


def test_shutdown_sends_stop_sentinel_and_joins_process():
    queue = Mock()
    manager = make_manager(queue)
    manager._process = Mock()

    manager.shutdown()

    queue.put.assert_called_once_with("stop")
    manager._process.join.assert_called_once_with()


def test_run_worker_sets_watchdog_event_even_if_loop_fails():
    queue = Mock()
    watchdog = Mock()

    with patch("slips_files.core.aid_manager.DBManager") as db_cls, patch(
        "managers.process_manager.worker_lifecycle.start_parent_watchdog",
        return_value=watchdog,
    ), patch.object(
        AIDManager, "_worker_loop", side_effect=RuntimeError("boom")
    ):
        with pytest.raises(RuntimeError):
            AIDManager._run_worker(queue, {"redis_port": 6379})

    db_cls.assert_called_once_with(redis_port=6379)
    watchdog.set.assert_called_once_with()
