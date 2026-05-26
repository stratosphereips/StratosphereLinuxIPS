# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import multiprocessing
import time
import threading
from multiprocessing import Process
from typing import List, Optional

from slips_files.core.profiler_worker import ProfilerWorker

FIVE_MINS = 300


class WorkerManagerMixin:
    """
    Contains all logic for managing, terminating, increasing and decreasing
    workers, etc.
    """

    def init_worker_manager(self) -> None:
        """
        Initialize profiler worker manager state.

        Return:
        None.
        """
        # to close them on shutdown
        self.profiler_child_processes: List[Process] = []
        # to access their internal attributes if needed
        self.workers: List[ProfilerWorker] = []
        # is set by this module to indicate to the monitor thread that
        # workers stopped.
        self.did_all_workers_stop = multiprocessing.Event()
        self.last_worker_id = -1
        self.active_profiler_workers = 0
        self.num_of_initial_profiler_workers = 3
        # max parallel profiler workers to start when high throughput is
        # detected
        self.max_workers = 6
        now = time.monotonic()
        self.next_throughput_check_time = now + FIVE_MINS
        self.next_worker_decrease_check_time = now + FIVE_MINS
        self.profiler_monitor_thread = threading.Thread(
            target=self._run_profiler_workers_manager_loop,
            name="profiler_monitor_loop",
            daemon=True,
        )

    def stop_profiler_workers(self) -> None:
        """
        Wait as long as needed for each worker to stop.

        Return:
        None.
        """
        # ensure we don't block forever waiting for workers that will never
        # receive the stop sentinel
        if self.is_input_done_event is not None:
            self.is_input_done_event.wait()

        for process in self.profiler_child_processes:
            try:
                process.join()
            except (OSError, ChildProcessError):
                pass

        self.did_all_workers_stop.set()

    def start_profiler_worker(self, worker_id: Optional[int] = None) -> None:
        """
        Start a profiler worker for faster processing of the flows.

        Parameters:
        worker_id: The identifier to include in the worker process name.

        Return:
        None.
        """
        worker_name = f"profiler_worker_process_{worker_id}"
        worker = ProfilerWorker(
            logger=self.logger,
            output_dir=self.parent_output_dir,
            redis_port=self.redis_port,
            termination_event=self.termination_event,
            conf=self.conf,
            ppid=self.ppid,
            slips_args=self.args,
            bloom_filters_manager=self.bloom_filters,
            # module specific kwargs
            name=worker_name,
            profiler_queue=self.profiler_queue,
            input_handler=self.input_handler_obj,
            aid_queue=self.aid_queue,
            aid_manager=self.aid_manager,
            is_input_done_event=self.is_input_done_event,
        )
        worker.start()
        self.profiler_child_processes.append(worker)
        self.active_profiler_workers += 1
        self.db.increment_profiler_workers_started()

    def did_5min_pass_since_last_throughput_check(self) -> bool:
        """
        Return whether 5 minutes passed since the last throughput check.

        Return:
        True when throughput should be checked.
        """
        now = time.monotonic()
        if now < self.next_throughput_check_time:
            return False

        while self.next_throughput_check_time <= now:
            self.next_throughput_check_time += FIVE_MINS
        return True

    def did_5min_pass_since_last_worker_decrease_check(self) -> bool:
        """
        Return whether 5 minutes passed since the last worker decrease check.

        Return:
        True when worker decrease should be checked.
        """
        now = time.monotonic()
        if now < self.next_worker_decrease_check_time:
            return False

        while self.next_worker_decrease_check_time <= now:
            self.next_worker_decrease_check_time += FIVE_MINS
        return True

    def max_workers_started(self) -> bool:
        """
        Return whether the maximum number of profiler workers is started.

        Return:
        True when no more profiler workers should be started.
        """
        if self.active_profiler_workers >= self.max_workers:
            return True
        return False

    def is_the_min_number_of_workers_active(self) -> bool:
        return (
            self.active_profiler_workers
            <= self.num_of_initial_profiler_workers
        )

    def _get_flows_per_second(self, module_name: str) -> float:
        """
        Get the latest stored flows per second for a core module.

        Parameters:
        module_name: The core module name.

        Return:
        The module flow rate as a float.
        """
        try:
            return float(
                self.db.get_core_module_flows_per_second(module_name) or 0
            )
        except (TypeError, ValueError):
            return 0

    def _check_if_high_throughput_and_add_workers(self) -> None:
        """
        Check for input and profile flows/sec imbalance and add workers.

        Return:
        None.
        """
        if self.max_workers_started():
            return

        if not self.did_5min_pass_since_last_throughput_check():
            return

        profiler_fps = self._get_flows_per_second(self.name)
        input_fps = self._get_flows_per_second("input")
        if input_fps > (profiler_fps * 1.1):
            worker_id = self.last_worker_id + 1
            self.start_profiler_worker(worker_id)
            self.last_worker_id = worker_id
            self.print(
                f"Warning: High throughput detected. Started "
                f"additional worker: "
                f"profiler_worker_{worker_id} to handle the flows."
            )

            if self.last_worker_id == self.max_workers - 1:
                self.print(
                    f"Maximum number of profiler workers "
                    f"({self.max_workers}) started."
                )

    def _update_lines_read_by_all_workers(self) -> None:
        """
        Update the number of lines read by all workers.
        """
        # needed by store_flows_read_per_second()
        self.lines = sum([worker.received_lines for worker in self.workers])

    def _run_profiler_workers_manager_loop(self) -> None:
        """
        Monitor profiler workers and update profiler stats while they run.
        """
        while not self.did_all_workers_stop.is_set():
            self._update_lines_read_by_all_workers()
            # implemented in icore.py
            self.store_flows_read_per_second()
            self._check_if_high_throughput_and_add_workers()
            self._check_if_stabled_throughput_and_remove_workers()

    def _check_if_stabled_throughput_and_remove_workers(self) -> None:
        """
        Remove one extra worker when profiler throughput has stabilized.
        """
        if self.is_the_min_number_of_workers_active():
            # can't decrese more than that
            return

        if not self.did_5min_pass_since_last_worker_decrease_check():
            return

        profiler_fps = self._get_flows_per_second(self.name)
        input_fps = self._get_flows_per_second("input")

        if profiler_fps < input_fps:
            # still under high throughput
            return

        self.profiler_queue.put("stop")
        self.active_profiler_workers -= 1
        self.last_worker_id -= 1
        self.print(
            "Stable throughput detected. Requested one additional "
            "profiler worker to stop."
        )
        self.db.decrement_profiler_workers_started()
