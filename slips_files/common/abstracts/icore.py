# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import time
import traceback
from multiprocessing import Process

from slips_files.common.abstracts.imodule import IModule

# in seconds
ONE_MIN = 60


class ICore(IModule, Process):
    """
    Interface for all Core files placed in slips_files/core/
    """

    name = ""
    description = "Short description of the core class purpose"
    authors = ["Name of the author creating the class"]

    def __init__(self, *args, **kwargs):
        """
        contains common initializations in all core files in
         slips_files/core/
        the goal of this is to have one common __init__()
        for all core file and module, which is the one in the IModule
        interface
        """
        IModule.__init__(self, *args, **kwargs)
        self.last_flows_count = 0
        # used to keep track of the FPs of this module
        now = time.monotonic()
        self.last_fps_check_time = now
        self.next_fps_check_time = now + ONE_MIN

    def pre_main(self): ...

    def store_flows_read_per_second(self):
        """
        updates the db about the flows read per second.
        this func estimates the flows processed per second by observing flows
        over 1 min span.
        """
        if not hasattr(self, "next_fps_check_time"):
            # Defensive init for cases where ICore.__init__ wasn't invoked.
            now = time.monotonic()
            self.last_flows_count = getattr(self, "last_flows_count", 0)
            self.last_fps_check_time = now
            self.next_fps_check_time = now + ONE_MIN

        now = time.monotonic()
        if now < self.next_fps_check_time:
            return

        flows_now = self.lines

        # delta since last check
        flows_delta = flows_now - self.last_flows_count
        time_delta = now - self.last_fps_check_time

        flows_per_sec = int(flows_delta / time_delta)
        self.db.store_core_module_flows_per_second(self.name, flows_per_sec)

        self.last_fps_check_time = now
        self.next_fps_check_time = now + ONE_MIN
        self.last_flows_count = flows_now

    def run(self):
        """
        must be called run because this is what multiprocessing runs
        """
        try:
            self._pre_main()
            # this should be defined in every core file
            # this won't run in a loop because it's not a module
            self.main()
            self.shutdown_gracefully()

        except KeyboardInterrupt:
            # never print traceback on sigint :D:D:D never.
            self.keyboard_int_ctr += 1
            if self.keyboard_int_ctr >= 2:
                return
            self.shutdown_gracefully()

        except Exception:
            self.print(f"Problem in {self.name}", 0, 1)
            self.print_traceback()
            self.print(traceback.format_exc(), 0, 1)
        return True
