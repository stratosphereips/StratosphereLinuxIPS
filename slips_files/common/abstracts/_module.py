import sys
import traceback
from abc import ABC, abstractmethod
from multiprocessing import Process, Event

from slips_files.core.output import Output
from slips_files.common.slips_utils import utils
from slips_files.core.database.database_manager import DBManager
from slips_files.common.abstracts.observer import IObservable

class IModule(IObservable, ABC, Process):
    """
    An interface for all slips modules
    """
    name = ''
    description = 'Template module'
    authors = ['Template Author']
    def __init__(self,
                 logger: Output,
                 output_dir,
                 redis_port,
                 termination_event,
                 **kwargs):
        Process.__init__(self)
        self.redis_port = redis_port
        self.output_dir = output_dir
        self.msg_received = False
        # used to tell all slips.py children to stop
        self.termination_event: Event = termination_event
        self.logger = logger
        self.db = DBManager(self.logger, self.output_dir, self.redis_port)
        IObservable.__init__(self)
        self.add_observer(self.logger)
        self.init(**kwargs)


    @abstractmethod
    def init(self, **kwargs):
        """
        all the code that was in the __init__ of all modules, is
        now in this method
        the goal of this is to have one common __init__() for all
        modules, which is the one in this file
        this init will have access to all keyword args passes when
        initializing the module
        """

    def should_stop(self) -> bool:
        """
        The module should stop on the following 2 conditions
        1. no new msgs are received in any of the channels the
            module is subscribed to
        2. the termination event is set by the process_manager.py
        """
        if self.msg_received or not self.termination_event.is_set():
            # this module is still receiving msgs,
            # don't stop
            return False

        return True

    def print(self, text, verbose=1, debug=0, log_to_logfiles_only=False):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text
        by taking all the processes into account
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
        :param text: text to print. Can include format
                    like 'Test {}'.format('here')
        :param log_to_logfiles_only: logs to slips.log only, not to cli
        """

        self.notify_observers(
            {
                'from': self.name,
                'txt': str(text),
                'verbose': verbose,
                'debug': debug,
                'log_to_logfiles_only': log_to_logfiles_only
           }
        )
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
        This function is for initializations that are
        executed once before the main loop
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
        """
        This is the loop function, it runs non-stop as long as
        the module is running
        """
        try:
            error: bool = self.pre_main()
            if error or self.should_stop():
                self.shutdown_gracefully()
                return True
        except KeyboardInterrupt:
            self.shutdown_gracefully()
            return True
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem in pre_main() line {exception_line}', 0, 1)
            self.print(traceback.print_stack(), 0, 1)
            return True

        try:
            while not self.should_stop():
                # keep running main() in a loop as long as the module is
                # online
                # if a module's main() returns 1, it means there's an
                # error and it needs to stop immediately
                error: bool = self.main()
                if error:
                    self.shutdown_gracefully()

        except KeyboardInterrupt:
            self.shutdown_gracefully()
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem in {self.name}\'s main() '
                       f'line {exception_line}',
                       0, 1)
            traceback.print_stack()

        return True
