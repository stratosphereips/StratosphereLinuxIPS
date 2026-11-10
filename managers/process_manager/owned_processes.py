"""Remember owned process identities before their parents can exit."""

import os
import signal
import time

import psutil


class OwnedProcesses:
    """Keep a shutdown-only record of this run's workers and subprocesses."""

    def __init__(self) -> None:
        """Create an empty record owned by the calling coordinator."""
        self.owner_pid = os.getpid()
        self.processes: dict[int, psutil.Process] = {}

    def remember(self, pid: int) -> None:
        """Record a worker and descendants while ownership is verifiable.

        Parameters:
            pid: Worker PID belonging to the current coordinator.
        """
        if pid in self.processes or pid <= 1 or pid == self.owner_pid:
            return
        try:
            process = psutil.Process(pid)
            if self.owner_pid not in {
                parent.pid for parent in process.parents()
            }:
                return
            self.processes[pid] = process
            for child in process.children(recursive=True):
                self.processes.setdefault(child.pid, child)
        except psutil.NoSuchProcess:
            return

    def refresh(self) -> None:
        """Remember descendants before a worker exits or is forcibly killed."""
        for process in list(self.processes.values()):
            try:
                if process.is_running():
                    for child in process.children(recursive=True):
                        self.processes.setdefault(child.pid, child)
            except psutil.NoSuchProcess:
                continue

    def stop(
        self, exclude: frozenset[int] = frozenset(), grace_seconds: float = 0
    ) -> None:
        """Kill retained identities together and verify that none still run.

        Parameters:
            exclude: Owned PIDs deliberately retained for the web prompt.
            grace_seconds: Optional wait for SIGTERM before forced cleanup.

        Raises:
            RuntimeError: An owned process could not be stopped or verified.
        """
        self.refresh()
        pending = []
        for process in reversed(list(self.processes.values())):
            if process.pid in exclude:
                continue
            try:
                # psutil checks PID and creation time before sending signals.
                if (
                    process.is_running()
                    and process.status() != psutil.STATUS_ZOMBIE
                ):
                    process.send_signal(
                        signal.SIGTERM if grace_seconds else signal.SIGKILL
                    )
                    pending.append(process)
            except psutil.NoSuchProcess:
                continue
        if grace_seconds:
            pending = self._wait_for_exit(pending, grace_seconds)
            for process in pending:
                try:
                    process.kill()
                except psutil.NoSuchProcess:
                    continue
        alive = self._wait_for_exit(pending, 2)
        if alive:
            raise RuntimeError(
                f"Slips processes still running after cleanup: {[process.pid for process in alive]}"
            )

    def _wait_for_exit(
        self, processes: list[psutil.Process], timeout: float
    ) -> list[psutil.Process]:
        """Verify exit without stealing waitpid results from multiprocessing.

        Parameters:
            processes: Retained identities to check together.
            timeout: Shared maximum wait in seconds.

        Returns:
            Processes still executing at the deadline; zombies cannot execute.
        """
        deadline = time.monotonic() + timeout
        while True:
            alive = []
            for process in processes:
                try:
                    if (
                        process.is_running()
                        and process.status() != psutil.STATUS_ZOMBIE
                    ):
                        alive.append(process)
                except psutil.NoSuchProcess:
                    continue
            remaining = deadline - time.monotonic()
            if not alive or remaining <= 0:
                return alive
            processes = alive
            time.sleep(min(0.05, remaining))
