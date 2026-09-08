"""Exercise real spawn/forkserver boundaries without external services."""

import multiprocessing
import os
import threading

import pytest

from tests.module_factory import ModuleFactory
from unittest.mock import Mock, patch


class ChildProbe:
    """Require unpicklable resources that must be initialized in the child."""

    name = "profiler_worker_process_probe"
    description = "Process boundary test"

    def __init__(self, result_queue: object, logger: object) -> None:
        """Record the constructor PID and create a local thread lock.

        Parameters:
            result_queue: Shared queue for the observed PIDs.
            logger: Logger whose synchronization state must be shared.
        """
        self.constructor_pid = os.getpid()
        self.result_queue = result_queue
        self.logger = logger
        self.lock = threading.Lock()

    def run(self) -> None:
        """Report child ownership and update shared counters and logger state."""
        with self.lock, self.logger.cli_lock:
            self.logger._cli_has_dangling_line.value = True
            self._received_lines.value = 7
            self.result_queue.put((self.constructor_pid, os.getpid()))


@pytest.mark.parametrize("method", ["spawn", "forkserver"])
def test_child_initialization_and_shared_state(method: str) -> None:
    """Check construction location and shared state across real processes.

    Parameters:
        method: Portable multiprocessing start method to exercise.
    """
    factory = ModuleFactory()
    previous = multiprocessing.get_start_method()
    multiprocessing.set_start_method(method, force=True)
    process = None
    result_queue = None
    try:
        from slips_files.core.output import Output

        logger = Output(create_logfiles=False)
        result_queue = multiprocessing.Queue()
        process = factory.create_module_process_obj(
            ChildProbe, result_queue, logger
        )
        assert process.received_lines == 0
        process.start()
        constructor_pid, run_pid = result_queue.get(timeout=30)
        process.join(timeout=30)
        assert process.exitcode == 0
        assert constructor_pid == run_pid == process.pid
        assert run_pid != os.getpid()
        assert process.received_lines == 7
        assert logger._cli_has_dangling_line.value
    finally:
        if process is not None:
            if process.is_alive():
                process.kill()
                process.join(timeout=5)
            process.close()
        if result_queue is not None:
            result_queue.close()
            result_queue.join_thread()
        multiprocessing.set_start_method(previous, force=True)


def test_aid_worker_owns_database_and_drains_tasks() -> None:
    """Create the AID database in the consumer and store queued flows."""
    factory = ModuleFactory()
    from slips_files.core.aid_manager import AIDManager

    flow = Mock()
    queue = Mock()
    queue.get.side_effect = [
        {
            "flow": flow,
            "profileid": "profile_1",
            "twid": "tw1",
            "label": "benign",
        },
        "stop",
    ]
    options = {
        "logger": factory.logger,
        "start_redis_server": False,
        "flush_db": False,
    }
    with patch(
        "slips_files.core.aid_manager.DBManager"
    ) as database_class, patch(
        "slips_files.core.aid_manager.utils.get_aid", return_value="aid-value"
    ):
        AIDManager._run_worker(queue, options)
        database_class.assert_called_once_with(**options)
        database_class.return_value.add_flow.assert_called_once_with(
            flow, "profile_1", "tw1", label="benign"
        )
        assert flow.aid == "aid-value"


def test_aid_shutdown_waits_for_storage() -> None:
    """Wait for AID storage before the profiler can exit."""
    factory = ModuleFactory()
    from slips_files.core.aid_manager import AIDManager

    manager = AIDManager.for_queue(factory.profiler_queue)
    manager._process = Mock()
    manager.shutdown()
    assert factory.profiler_queue.get(timeout=2) == "stop"
    manager._process.join.assert_called_once_with()
