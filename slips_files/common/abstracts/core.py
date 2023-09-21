import sys
import traceback
from multiprocessing import Process, Event

from slips_files.common.abstracts._module import IModule
from slips_files.core.database.database_manager import DBManager


class ICore(IModule, Process):
    """
    Interface for all Core files placed in slips_files/core/
    """
    name = ''
    description = 'Short description of the core class purpose'
    authors = ['Name of the author creating the class']

    def __init__(
            self,
            output_queue,
            output_dir,
            redis_port,
            termination_event,
            **kwargs
            ):
        """
        contains common initializations in all core files in  slips_files/core/
        the goal of this is to have one common __init__() for all modules, which is the one
        in this file
        """
        Process.__init__(self)
        self.output_queue = output_queue
        self.output_dir = output_dir
        # used to tell all slips.py children to stop
        self.termination_event: Event = termination_event
        self.db = DBManager(output_dir, output_queue, redis_port)
        self.msg_received = False
        self.init(**kwargs)

    def run(self):
        """
        must be called run because this is what multiprocessing runs
        """
        try:
            # this should be defined in every core file
            # this won't run in a loop because it's not a module
            error: bool = self.main()
            if error or self.should_stop():
                # finished with some error
                self.output_queue.cancel_join_thread()
                self.shutdown_gracefully()

        except KeyboardInterrupt:
            # self.output_queue.cancel_join_thread()
            self.shutdown_gracefully()
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem in main() line {exception_line}', 0, 1)
            self.print(traceback.format_exc(), 0, 1)

        return True

    def __del__(self):
        self.db.close()