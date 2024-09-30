import sys
import traceback
from abc import ABC, abstractmethod
from multiprocessing import Process, Event
from typing import (
    Dict,
    Optional,
)

from slips_files.common.printer import Printer
from slips_files.core.output import Output
from slips_files.common.slips_utils import utils
from slips_files.core.database.database_manager import DBManager


class IModule(ABC, Process):
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
        self.printer = Printer(self.logger, self.name)
        self.db = DBManager(self.logger, self.output_dir, self.redis_port)
        self.keyboard_int_ctr = 0
        self.init(**kwargs)
        # should after the module's init() so the module has a chance to
        # set its own channels
        # tracks whether or not in the last iteration there was a msg
        # received in that channel
        self.channel_tracker: Dict[str, dict] = self.init_channel_tracker()

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

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
            tracker[channel_name] = {
                "msg_received": False,
            }
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

    def is_msg_received_in_any_channel(self) -> bool:
        """
        return True if a msg was received in any channel of the ones
        this module is subscribed to
        """
        return any(
            info["msg_received"] for info in self.channel_tracker.values()
        )

    def should_stop(self) -> bool:
        """
        The module should stop on the following 2 conditions
        1. no new msgs are received in any of the channels the
            module is subscribed to
        2. the termination event is set by the process_manager.py
        """
        if (
            self.is_msg_received_in_any_channel()
            or not self.termination_event.is_set()
        ):
            # this module is still receiving msgs,
            # don't stop
            return False
        return True

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

    def get_msg(self, channel: str) -> Optional[dict]:
        message = self.db.get_message(self.channels[channel])
        if utils.is_msg_intended_for(message, channel):
            self.channel_tracker[channel]["msg_received"] = True
            self.db.incr_msgs_received_in_channel(self.name, channel)
            return message

        self.channel_tracker[channel]["msg_received"] = False

    def print_traceback(self):
        exception_line = sys.exc_info()[2].tb_lineno
        self.print(f"Problem in pre_main() line {exception_line}", 0, 1)
        self.print(traceback.format_exc(), 0, 1)

    def run(self) -> bool:
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
            self.print_traceback()
            return True

        while True:
            try:
                if self.should_stop():
                    self.shutdown_gracefully()
                    return True

                # if a module's main() returns 1, it means there's an
                # error and it needs to stop immediately
                error: bool = self.main()
                if error:
                    self.shutdown_gracefully()

            except KeyboardInterrupt:
                self.keyboard_int_ctr += 1

                if self.keyboard_int_ctr >= 2:
                    # on the second ctrl+c the module immediately stops
                    return True

                # on the first ctrl + C keep looping until the should_stop
                # returns true
                continue
            except Exception:
                self.print_traceback()
                return False
