# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import traceback
from multiprocessing import Process

from slips_files.common.abstracts.module import IModule


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

    def pre_main(self): ...

    def run(self):
        """
        must be called run because this is what multiprocessing runs
        """
        try:
            self.pre_main()
            # this should be defined in every core file
            # this won't run in a loop because it's not a module
            self.main()
            self.shutdown_gracefully()

        except KeyboardInterrupt:
            self.keyboard_int_ctr += 1
            if self.keyboard_int_ctr >= 2:
                return
            self.shutdown_gracefully()

        except Exception:
            self.print(f"Problem in {self.name}", 0, 1)
            self.print(traceback.format_exc(), 0, 1)
        return True
