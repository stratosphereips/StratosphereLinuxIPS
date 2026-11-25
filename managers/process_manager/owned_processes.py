"""Track the processes a Slips process started, so they can still be
killed after their parents exit."""

import os
import signal
import time

import psutil


class OwnedProcesses:
    """
    Keeps track of the workers started by the calling process, and of
    everything those workers start (e.g. zeek, the web server).

    When a parent exits, its subprocesses are adopted by init and can't be
    found through the parent anymore. So they are recorded here while the
    parent is still alive.
    """

    def __init__(self) -> None:
        """Start with nothing tracked; the calling process is the owner."""
        self.owner_pid = os.getpid()
        self.processes: dict[int, psutil.Process] = {}

    def track(self, pid: int) -> None:
        """
        Start tracking a worker and all of its current descendants.

        PIDs that the owner didn't start are ignored, so we never kill an
        unrelated process by mistake.

        Parameters:
            pid: PID of a worker started by the owner.
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

    def track_new_descendants(self) -> None:
        """
        Start tracking the subprocesses that tracked processes started
        since the last call. Call it before a worker exits or is killed,
        while its subprocesses can still be found through it.
        """
        for process in list(self.processes.values()):
            try:
                if process.is_running():
                    for child in process.children(recursive=True):
                        self.processes.setdefault(child.pid, child)
            except psutil.NoSuchProcess:
                continue

    def kill_all(
        self,
        pids_to_keep: frozenset[int] = frozenset(),
        grace_seconds: float = 0,
    ) -> None:
        """
        Kill every tracked process and make sure none is still running.

        Parameters:
            pids_to_keep: Tracked PIDs to leave running.
            grace_seconds: When set, send SIGTERM first and only SIGKILL
                the processes still running after this many seconds.

        Raises:
            RuntimeError: A tracked process is still running after SIGKILL.
        """
        self.track_new_descendants()
        pending = []
        for process in reversed(list(self.processes.values())):
            if process.pid in pids_to_keep:
                continue
            try:
                # psutil checks the PID and start time first, so a reused PID is safe.
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
        """
        Wait for processes to exit by polling them. We can't use waitpid()
        here because it would steal the exit status that multiprocessing
        needs for its own join().

        Parameters:
            processes: Tracked processes to wait for.
            timeout: Maximum seconds to wait for all of them together.

        Returns:
            The processes still running when the time is up. Zombies have already
            exited, so they are not included.
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
