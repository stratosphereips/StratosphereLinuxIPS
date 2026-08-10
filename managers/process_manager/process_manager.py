# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from multiprocessing import Event, Process, Queue, Semaphore
from typing import List

from .config_mixin import ConfigMixin
from .module_loading_mixin import ModuleLoadingMixin
from .reporting_mixin import ReportingMixin
from .shutdown_mixin import ShutdownMixin
from .startup_mixin import StartupMixin


class ProcessManager(
    ReportingMixin,
    ConfigMixin,
    StartupMixin,
    ModuleLoadingMixin,
    ShutdownMixin,
):
    """
    Responsible for starting and stopping all the slips processes and
    modules.
    Here's how the stopping of input.py and profiler.py works
    input.py
      -> realizes that no more flows are arriving
      -> puts "stop" in the profiler_queue
      -> is_input_done_event.set()
      -> waits on is_profiler_done_event

    profiler.py
      <- recvs is_input_done_event for normal input completion
      <- recvs is_input_failed_event for abnormal input failure
      -> waits/join() profiler workers

    profiler workers
      <- recvs the "stop" from the  profiler_queue
      -> exit

    profiler.py
      <- realizes that all workers exited
      -> is_profiler_done_semaphore.release()
      -> is_profiler_done_event.set()

    input.py
      <- is_profiler_done_event
      -> is_input_done.release()

    process_manager
      <- is_input_done
      <- is_profiler_done_semaphore
      -> Slips can finish shutdown
    """

    def __init__(self, main: object) -> None:
        """
        Initialize shared process-manager state.

        Parameters:
            main: Main Slips coordinator object.
        """
        self.main = main
        # Can be used by signal handlers before startup finishes.
        self.processes: List[Process] = []
        # this is the queue that will be used by the input process
        # to pass flows to the profiler
        # this max size is decided based on the avg size of each flow (650
        # bytes), and the max memory that this queue is allowed to
        # use (1GB), so 1321528 bytes will be 2033 flows in queue at max
        self.profiler_queue = Queue(maxsize=1321528)
        self.termination_event = Event()
        # to make sure we only warn the user once about
        # the pending modules
        self.warning_printed_once = False
        self.llm_dependency_warning_printed = False
        # this one has its own termination event because we want it to
        # shutdown at the very end of all other slips modules.
        self.evidence_handler_termination_event = Event()
        self.stopped_modules: List[str] = []
        # used to stop slips when these 2 are done
        # since the semaphore count is zero, slips.py will wait until another
        # thread (input and profiler)
        # release the semaphore. Once having the semaphore, then slips.py can
        # terminate slips.
        self.is_input_done = Semaphore(0)
        # when profiler is done processing, it releases this semaphore,
        self.is_profiler_done_semaphore = Semaphore(0)
        # is set by the profiler process to indicate that it's done so
        # input can shutdown no issue
        # now without this event, input process doesn't know that profiler
        # is still waiting for the queue to stop
        # and input stops and renders the profiler queue useless and profiler
        # cant get more lines any more!
        self.is_profiler_done_event = Event()
        self.is_profiler_done_starting_initial_workers_event = Event()
        # is set by the input process to indicate no more flows are coming
        # so profiler can safely begin shutdown/joins.
        self.is_input_done_event = Event()
        # is set by the input process when it stops because of a failure.
        self.is_input_failed_event = Event()
        self.is_slips_live_updating_event = Event()
        self.user_disabled_modules: List[str] = []
        self.slips_disabled_modules: List[str] = []
        self.read_config()
        self.all_children_started = False
        self.core_module_failure = False
