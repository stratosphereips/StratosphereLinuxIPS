import sys
import traceback
from abc import ABC, abstractmethod
from multiprocessing import Process, Event
from typing import Dict

from slips_files.core.output import Output
from slips_files.common.slips_utils import utils
from slips_files.core.database.database_manager import DBManager
from slips_files.common.abstracts.observer import IObservable


class IModule(IObservable, ABC, Process):
    """
    An interface for all slips modules
    """

    name = ""
    description = "Template module"
    authors = ["Template Author"]
    # should be filled with the channels each module subscribes to
    channels = {}

    def __init__(
        self,
        logger: Output,
        output_dir,
        redis_port,
        termination_event,
        **kwargs,
    ):
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
        # should after the module's init() so the module has a chance to
        # set its own channels
        # tracks whether or not in the last iteration there was a msg
        # received in that channel
        self.channel_tracker = self.init_channel_tracker()

    @property
    @abstractmethod
    def name(self):
        pass

    @property
    @abstractmethod
    def description(self):
        pass

    @property
    @abstractmethod
    def authors(self):
        pass

    def init_channel_tracker(self) -> Dict[str, bool]:
        """
        tracks if in the last loop, a msg was received in any of the
        subscribed channels or not
        the goal of this is to keep looping if only 1 channel did receive
        a msg, bc it's possible that that 1 channel will receive another msg
        return a dict with the channel name and the values are either 0 or 1
        False: received a msg in the last loop for this channel
        True: didn't receive a msg
        The goal of this whole thing is to terminate the module only if no
        channels receive msgs in the last iteration, but keep looping
        otherwise.
        """
        tracker = {}
        for channel_name in self.channels:
            tracker[channel_name] = False
        return tracker

    @abstractmethod
    def init(self, **kwargs):
        """
        handles the initialization of modules
        the goal of this is to have one common __init__() for all
        modules, which is the one in this file, and a different init() per
        module
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
        if (
            any(self.channel_tracker.values())
            or not self.termination_event.is_set()
        ):
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
                "from": self.name,
                "txt": str(text),
                "verbose": verbose,
                "debug": debug,
                "log_to_logfiles_only": log_to_logfiles_only,
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

    def get_msg(self, channel_name):
        message = self.db.get_message(self.channels[channel_name])
        if utils.is_msg_intended_for(message, channel_name):
            self.channel_tracker[channel_name] = True
            # if "Flow Alerts" in self.name:
            #     print(
            #         f"@@@@@@@@@@@@@@@@ setting the get msg of flowalerts to "
            #         f"true"
            #         )
            return message
        else:
            # if "Flow Alerts" in self.name:
            #     print(
            #         f"@@@@@@@@@@@@@@@@ no flowalerts msgs received!"
            #         )
            self.channel_tracker[channel_name] = False
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
            self.print(f"Problem in pre_main() line {exception_line}", 0, 1)
            self.print(traceback.format_exc(), 0, 1)
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
            self.print(f"Problem in {self.name}", 0, 1)
            self.print(traceback.format_exc(), 0, 1)
        return True
