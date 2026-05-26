# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# Stratosphere Linux IPS. A machine-learning Intrusion Detection System
# Copyright (C) 2021 Sebastian Garcia
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# Contact: eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz,
# stratosphere@aic.fel.cvut.cz
import queue
import multiprocessing
import time
from multiprocessing.synchronize import Event, Semaphore
from typing import (
    List,
    Union,
    Optional,
)

from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address


from slips_files.common.abstracts.iobserver import IObservable
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.abstracts.icore import ICore
from slips_files.common.style import green
from slips_files.common.input_type import InputType
from slips_files.common.slips_utils import utils
from slips_files.core.aid_manager import AIDManager
from slips_files.core.helpers.symbols_handler import SymbolHandler
from slips_files.core.input_profilers.argus import Argus
from slips_files.core.input_profilers.nfdump import Nfdump
from slips_files.core.input_profilers.suricata import Suricata
from slips_files.core.input_profilers.zeek import ZeekJSON, ZeekTabs
from slips_files.core.worker_manager_mixin import WorkerManagerMixin

SUPPORTED_INPUT_TYPES = {
    InputType.ZEEK: ZeekJSON,
    InputType.BINETFLOW: Argus,
    InputType.BINETFLOW_TABS: Argus,
    InputType.SURICATA: Suricata,
    InputType.ZEEK_TABS: ZeekTabs,
    InputType.NFDUMP: Nfdump,
}
SEPARATORS = {
    InputType.ZEEK: "",
    InputType.SURICATA: "",
    InputType.NFDUMP: ",",
    InputType.BINETFLOW: ",",
    InputType.ZEEK_TABS: "\t",
    InputType.BINETFLOW_TABS: "\t",
}


class Profiler(WorkerManagerMixin, ICore, IObservable):
    """A class to create the profiles for IPs"""

    name = "profiler"

    def init(
        self,
        is_profiler_done_semaphore: Optional[Semaphore] = None,
        profiler_queue=None,
        is_profiler_done_event: Optional[Event] = None,
        is_input_done_event: Optional[Event] = None,
        is_input_failed_event: Optional[Event] = None,
        is_profiler_done_starting_initial_workers_event: Optional[
            Event
        ] = None,
    ) -> None:
        IObservable.__init__(self)
        self.add_observer(self.logger)
        # when profiler is done processing, it releases this semaphore,
        # that's how the process_manager knows it's done
        # when both the input and the profiler are done,
        # the input process signals the rest of the modules to stop
        self.is_profiler_done_semaphore: Optional[Semaphore] = (
            is_profiler_done_semaphore
        )
        self.is_profiler_done_starting_initial_workers_event: Optional[
            Event
        ] = is_profiler_done_starting_initial_workers_event
        # every line put in this queue should be profiled
        self.profiler_queue: multiprocessing.Queue = profiler_queue

        self.timeformat = None
        self.input_type = ""
        self.rec_lines = 0
        self.read_configuration()
        self.symbol = SymbolHandler(self.logger, self.db)
        self.channels = {}
        # is set by this proc to tell input proc that we are done
        # processing and it can shutdown now
        self.is_profiler_done_event: Optional[Event] = is_profiler_done_event
        # is set by input to indicate no more flows are coming
        self.is_input_done_event: Optional[Event] = is_input_done_event
        # is set by input to indicate it stopped because of a failure
        self.is_input_failed_event: Optional[Event] = is_input_failed_event
        self.input_handler_obj = None
        self.init_worker_manager()
        # 30MBs max size of this queue to avoid growing forever in mem
        self.aid_queue = multiprocessing.Queue(maxsize=30000000)
        # This starts a process that handles calculatng aid hash and stores
        # the conn fows in the db. why? because it's cpu intensive so we dont
        # want it to block the profiler workers
        self.aid_manager = AIDManager(
            self.db,
            self.aid_queue,
        )

    def subscribe_to_channels(self):
        self.channels = {}

    def read_configuration(self):
        conf = ConfigParser()
        self.client_ips: List[
            Union[IPv4Network, IPv6Network, IPv4Address, IPv6Address]
        ]
        self.client_ips = conf.client_ips()

    def get_input_type(self, line: dict, input_type: str) -> str:
        """
        for example if the input_type is zeek_folder
        this function determines if it's tab or json
        etc
        :param line: dict with the line as read from the input file/dir
        given to slips using -f and the name of the logfile this line was read
         from
        :param input_type: as determined by slips.py

        returns zeek, zeek-tabs, binetflow, binetflow tabs, nfdump, suricata
        """
        if input_type in (
            InputType.ZEEK_FOLDER,
            InputType.ZEEK_LOG_FILE,
            InputType.PCAP,
            InputType.INTERFACE,
        ):
            # is it tab separated or comma separated?
            actual_line = line["data"]
            if isinstance(actual_line, dict):
                return InputType.ZEEK
            return InputType.ZEEK_TABS
        elif input_type == InputType.STDIN:
            # ok we're reading flows from stdin, but what type of flows?
            return line["line_type"]
        else:
            # if it's none of the above cases
            # it's probably one of the following:
            # binetflow, binetflow tabs, nfdump, suricata
            return input_type

    def mark_self_as_done_processing(self) -> None:
        """
        is called to mark this process as done processing so
        slips.py would know when to terminate
        """
        # signal slips.py that this process is done
        self.print(
            "Marking Profiler as done processing.", log_to_logfiles_only=True
        )
        if self.is_profiler_done_semaphore is not None:
            self.is_profiler_done_semaphore.release()
        self.print("Profiler is done processing.", log_to_logfiles_only=True)
        if self.is_profiler_done_event is not None:
            self.is_profiler_done_event.set()
        self.print(
            "Profiler is done telling input.py that it's done processing.",
            log_to_logfiles_only=True,
        )

    def get_msg_from_queue(self, q: multiprocessing.Queue):
        """
        retrieves a msg from the given queue
        """
        try:
            return q.get(timeout=1, block=False)
        except queue.Empty:
            return None
        except Exception:
            return None

    def get_handler_obj(
        self, first_msg: dict
    ) -> ZeekTabs | ZeekJSON | Argus | Suricata | ZeekTabs | Nfdump:
        """
        This function determines the class that handles the given flows.
        based on the exact input type.

        :param first_msg: the first msg received from the input process

        returns the input handler class from SUPPORTED_INPUT_TYPES
        """
        line: dict = first_msg["line"]
        # can be ("zeek_folder", "zeek_log_file", "pcap", "interface")
        input_type_from_input_proc: str = first_msg["input_type"]

        # if input process says it's an interface, this func says whether
        # the flows are zeek or zeek-tabs and gets the class based on it.
        input_type = self.get_input_type(line, input_type_from_input_proc)
        if not input_type:
            # the above define_type can't define the type of input
            self.print("Can't determine input type.")
            return None

        input_handler_cls = SUPPORTED_INPUT_TYPES[input_type](self.db)
        return input_handler_cls

    def shutdown_gracefully(self):
        try:
            # wait for all flows to be processed by the profiler processes.
            self.stop_profiler_workers()

            self.aid_queue.put("stop")
            self.aid_manager.shutdown()

            used_queues = [
                self.profiler_queue,
                self.aid_queue,
            ]

            for q in used_queues:
                # By default if a process is not the creator of the queue then on
                # exit it will attempt to join the queue’s background thread. The
                # process can call cancel_join_thread() to make join_thread()
                # do nothing.
                q.cancel_join_thread()

                # close the queues to avoid deadlocks.
                # this step SHOULD NEVER be done before closing the workers
                q.close()

            if self.profiler_monitor_thread.is_alive():
                self.profiler_monitor_thread.join(timeout=5)
        finally:
            self.print(
                "Stopping.",
                log_to_logfiles_only=True,
            )
            self.mark_self_as_done_processing()
            self.db.set_new_incoming_flows(False)

    def pre_main(self):
        client_ips = [str(ip) for ip in self.client_ips]
        if client_ips:
            self.print(f"Used client IPs: {green(', '.join(client_ips))}")

    def should_stop(self):
        """
        overrides IModule.should_stop().

        why? because this module is the one that triggers the termination
        event (through process_manager), so checking that event here is
        meaningless, it will never be set before this module stops.
        """
        return self.stop_other_workers.is_set()

    def _is_input_done(self) -> bool:
        return (
            self.is_input_done_event is not None
            and self.is_input_done_event.is_set()
        )

    def _did_input_fail(self) -> bool:
        """
        Return whether input stopped because of a failure.

        Return:
        True when the input failure event is set.
        """
        return (
            self.is_input_failed_event is not None
            and self.is_input_failed_event.is_set()
        )

    def main(self):
        # process the first msg only here, to determine what kind of input
        # slips is given, then the workers will use the determined type.
        # wait as long as needed for it
        msg = None
        while not msg:
            if self._did_input_fail():
                self.print(
                    "Stopping profiler, input stopped before profiling began.",
                )
                self.is_profiler_done_starting_initial_workers_event.set()
                return 1

            if self.args.interface:
                # we know the input type, no need to wait for the first msg
                # to determine it, we can start the workers right away
                break

            msg = self.get_msg_from_queue(self.profiler_queue)
            if not msg and self._is_input_done():
                self.print(
                    "Stopping profiler, no more msgs are coming.",
                )
                self.is_profiler_done_starting_initial_workers_event.set()
                return 1
            time.sleep(0.1)

        if self.args.interface:
            self.input_handler_obj = SUPPORTED_INPUT_TYPES[InputType.ZEEK](
                self.db
            )
        else:
            self.input_handler_obj = self.get_handler_obj(msg)
            # put again that msg in queue to be processed by the profilers,
            # we just checked it here to determine the input handler obj
            self.profiler_queue.put(msg)
            if not self.input_handler_obj:
                self.print("Unsupported input type, exiting.")
                return 1

            line: dict = msg["line"]
            # updates internal zeek to slips mapping if needed, just once
            self.input_handler_obj.process_line(line)

        # start the thread now after we know the input type
        utils.start_thread(self.profiler_monitor_thread, self.db)

        # slips starts with these workers by default until it detects
        # high throughput that these workers arent enough to handle
        for worker_id in range(self.num_of_initial_profiler_workers):
            self.last_worker_id = worker_id
            self.start_profiler_worker(worker_id)

        self.is_profiler_done_starting_initial_workers_event.set()

        # ICore() will call shutdown_gracefully() on return
        return
