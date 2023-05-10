from abc import ABC, abstractmethod
from slips_files.core.database.database import __database__
import sys
import traceback
# This is the abstract Module class to check against. Do not modify
class Module(ABC):
    name = ''
    description = 'Template abstract module'
    authors = ['Template abstract Author']

    def __init__(self, outputqueue):
        self.outputqueue = outputqueue
        self.control_channel = __database__.subscribe('control_module')
        self.msg_received = True

    def should_stop(self) -> bool:
        """
        The module should stop on the following 2 conditions
        1. slips.py publishes the stop_process msg in the control_module channel
        2. no msgs left to process in the module
        This function calls the shutdown_gracefully pf the module when the 2 conditions are true
        """
        if self.msg_received:
            # this module is still receiving msgs, don't stop
            return False

        message = __database__.get_message(self.control_channel)
        if message and message['data'] == 'stop_process':
            self.shutdown_gracefully()
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
        self.outputqueue.put(f'{levels}|{self.name}|{text}')

    @abstractmethod
    def shutdown_gracefully(self):
        """
        Tells slips.py that this module is
        done processing and does necessary cleanup
        """
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

    def run(self):
        """ This is the loop function, it runs non-stop as long as the module is online """
        try:
            self.pre_main()
        except KeyboardInterrupt:
            self.shutdown_gracefully()
            return True
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem in pre_main() of module: {self.name}.'
                       f' line {exception_line}', 0, 1)
            self.print(traceback.format_exc(), 0, 1)
            return True

        while True:
            try:
                self.main()

                if self.should_stop():
                    return True
            except KeyboardInterrupt:
                if self.should_stop():
                    return True
                else:
                    continue
            except Exception:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem in main() line {exception_line}', 0, 1)
                self.print(traceback.format_exc(), 0, 1)
                return True