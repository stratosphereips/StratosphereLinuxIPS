"""Bounded AID writes preserve queue order, immediate work and shutdown draining."""

from queue import Empty, Queue
from unittest.mock import Mock, patch

import pytest

from slips_files.core.aid_manager import AIDManager
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("count", [0, 1, 63, 64, 65, 130])
def test_aid_batches_drain_before_stop(count: int) -> None:
    """Store every queued task once with bounded transactions before stopping.

    Parameters:
        count: Number of tasks preceding the stop sentinel.
    """
    _factory = ModuleFactory()
    queue = Queue()
    tasks = [{"flow": Mock(uid=str(n)), "profileid": f"profile_{n % 2}",
              "twid": "timewindow1", "label": "benign"} for n in range(count)]
    for task in tasks:
        queue.put(task)
    queue.put("stop")
    db = Mock()
    with patch("slips_files.core.aid_manager.utils.get_aid", return_value="hash"):
        AIDManager.for_queue(queue)._worker_loop(queue, db)
    batches = [call.args[0] for call in db.add_flows.call_args_list]
    assert all(0 < len(batch) <= 64 for batch in batches)
    assert [task for batch in batches for task in batch] == tasks
    assert all(task["flow"].aid == "hash" for task in tasks)
    db.add_flow.assert_not_called()


def test_aid_sparse_flow_is_written_without_waiting_for_a_batch() -> None:
    """Commit an isolated flow immediately when no other task is ready."""
    _factory = ModuleFactory()
    queue = Mock()
    task = {"flow": Mock(), "profileid": "profile_1", "twid": "tw1", "label": "benign"}
    queue.get.side_effect = [task, "stop"]
    queue.get_nowait.side_effect = Empty
    db = Mock()
    with patch("slips_files.core.aid_manager.utils.get_aid", return_value="hash"):
        AIDManager.for_queue(queue)._worker_loop(queue, db)
    db.add_flows.assert_called_once_with([task])
