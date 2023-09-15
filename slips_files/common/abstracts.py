from abc import ABC, abstractmethod
# common imports for all modules
from slips_files.core.database.database_manager import DBManager
from multiprocessing import Event
from slips_files.common.slips_utils import utils
from multiprocessing import Process
import sys
import traceback

# This is the abstract Module class to check against. Do not modify
class Module(ABC):
    name = ''
    description = 'Template module'
    authors = ['Template Author']
    def __init__(self,
                 output_queue,
                 output_dir,
                 redis_port,
                 termination_event,
                 **kwargs):
        Process.__init__(self)
        self.output_queue = output_queue
        self.db = DBManager(output_dir, output_queue, redis_port)
        self.msg_received = False
        # used to tell all slips.py children to stop
        self.termination_event: Event = termination_event
        self.init(**kwargs)

    @abstractmethod
    def init(self, **kwargs):
        """
        all the code that was in the __init__ of all modules, is now in this method
        the goal of this is to have one common __init__() for all modules, which is the one
        in this file
        this init will have access to all keyword args passes when initializing the module
        """

    def should_stop(self) -> bool:
        """
        The module should stop on the following 2 conditions
        1. no new msgs are received in any of the channels the module is subscribed to
        2. the termination event is set by the process_manager.py
        """
        if self.msg_received or not self.termination_event.is_set():
            # this module is still receiving msgs,
            # don't stop
            return False
        return True

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        self.output_queue.put(f'{levels}|{self.name}|{text}')
    
    def shutdown_gracefully(self):
        """
        Tells slips.py that this module is
        done processing and does necessary cleanup
        """
        pass
    @abstractmethod
    def main(self):
        """
        Main function of every module, all the logic implemented
        here will be executed in a loop
        """

    def pre_main(self):
        """
        This function is for initializations that are executed once before the main loop
        """
        pass

    def get_msg(self, channel_name):
        message = self.db.get_message(self.channels[channel_name])
        if utils.is_msg_intended_for(message, channel_name):
            self.msg_received = True
            return message
        else:
            self.msg_received = False
            return False

    def run(self):
        """ This is the loop function, it runs non-stop as long as the module is online """
        try:
            error: bool = self.pre_main()
            if error or self.should_stop():
                self.output_queue.cancel_join_thread()
                self.shutdown_gracefully()
                return True
        except KeyboardInterrupt:
            self.output_queue.cancel_join_thread()
            self.shutdown_gracefully()
            return True
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem in pre_main() line {exception_line}', 0, 1)
            self.print(traceback.format_exc(), 0, 1)
            return True

        error = False
        try:
            while not self.should_stop():
                # keep running main() in a loop as long as the module is online
                # if a module's main() returns 1, it means there's an error and it needs to stop immediately
                error: bool = self.main()
                if error:
                    self.output_queue.cancel_join_thread()
                    self.shutdown_gracefully()

        except KeyboardInterrupt:
            self.output_queue.cancel_join_thread()
            self.shutdown_gracefully()
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem in main() line {exception_line}', 0, 1)
            self.print(traceback.format_exc(), 0, 1)

        return True

    def __del__(self):
        self.db.close()


class Core(Module, Process):
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


class ProfilerInterface(ABC):
    @abstractmethod
    def _create_profiler(self):
        pass

    @abstractmethod
    def start(self):
        pass

    @abstractmethod
    def stop(self):
        pass

    @abstractmethod
    def print(self):
        pass