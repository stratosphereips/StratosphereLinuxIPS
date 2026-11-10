"""Exercise real spawn/forkserver boundaries without external services."""
import os
import signal
import threading
import time

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


class StopProbe:
    """Wait for the parent's stop event and report that saving completed."""

    name = "profiler_worker_process_stop_probe"
    description = "Shutdown process boundary test"

    def __init__(self, stop: object, results: object) -> None:
        """Keep the process-local stop event and result channel.

        Parameters:
            stop: Parent-owned shared event.
            results: Pipe for startup and saved-state acknowledgements.
        """
        self.stop = stop
        self.results = results

    def run(self) -> None:
        """Finish saving only after the coordinator's event is delivered."""
        self.results.send(("ready", signal.getsignal(signal.SIGINT) == signal.SIG_IGN))
        self.stop.wait(20)
        self.results.send(("saved", self.stop.is_set()))


def wait_for_cleanup(ready: object) -> None:
    """Keep an isolated child alive until the process manager reaps it.

    Parameters:
        ready: Queue reporting that the child has started.
    """
    ready.put(os.getpid())
    time.sleep(30)


def test_aid_shutdown_waits_for_storage() -> None:
    """Wait for AID storage before the profiler can exit."""
    factory = ModuleFactory()
    from slips_files.core.aid_manager import AIDManager

    manager = AIDManager.for_queue(factory.profiler_queue)
    manager._process = Mock()
    manager.shutdown()
    assert factory.profiler_queue.get(timeout=2) == "stop"
    manager._process.join.assert_called_once_with()
