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
from multiprocessing import Process
from typing import (
    List,
    Union,
)

from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address


from slips_files.common.abstracts.iobserver import IObservable
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.abstracts.icore import ICore
from slips_files.common.style import green
from slips_files.core.aid_manager import AIDManager
from slips_files.core.helpers.symbols_handler import SymbolHandler
from slips_files.core.input_profilers.argus import Argus
from slips_files.core.input_profilers.nfdump import Nfdump
from slips_files.core.input_profilers.suricata import Suricata
from slips_files.core.input_profilers.zeek import ZeekJSON, ZeekTabs
from slips_files.core.profiler_worker import ProfilerWorker

SUPPORTED_INPUT_TYPES = {
    "zeek": ZeekJSON,
    "binetflow": Argus,
    "binetflow-tabs": Argus,
    "suricata": Suricata,
    "zeek-tabs": ZeekTabs,
    "nfdump": Nfdump,
}
SEPARATORS = {
    "zeek": "",
    "suricata": "",
    "nfdump": ",",
    "binetflow": ",",
    "zeek-tabs": "\t",
    "binetflow-tabs": "\t",
}


class Profiler(ICore, IObservable):
    """A class to create the profiles for IPs"""

    name = "Profiler"

    def init(
        self,
        is_profiler_done: multiprocessing.Semaphore = None,
        profiler_queue=None,
        is_profiler_done_event: multiprocessing.Event = None,
    ):
        IObservable.__init__(self)
        self.add_observer(self.logger)
        # when profiler is done processing, it releases this semaphore,
        # that's how the process_manager knows it's done
        # when both the input and the profiler are done,
        # the input process signals the rest of the modules to stop
        self.done_processing: multiprocessing.Semaphore = is_profiler_done
        # every line put in this queue should be profiled
        self.profiler_queue: multiprocessing.Queue = profiler_queue

        self.timeformat = None
        self.input_type = ""
        self.rec_lines = 0
        self.read_configuration()
        self.symbol = SymbolHandler(self.logger, self.db)
        # there has to be a timeout or it will wait forever and never
        # receive a new line
        self.timeout = 0.0000001
        self.channels = {}
        # is set by this proc to tell input proc that we are done
        # processing and it can exit no issue
        self.is_profiler_done_event = is_profiler_done_event
        # to close them on shutdown
        self.profiler_child_processes: List[Process] = []
        # to access their internal attributes if needed
        self.workers: List[ProfilerWorker] = []

        self.stop_profiler_workers_event = multiprocessing.Event()
        # each msg received from inputprocess will be put here, and each one
        # profiler worker will retrieve msgs from this queue.
        # the goal of this q is to have main() handle the stop msg.
        # so without this, only 1 of the 3 workers receives the stop msg
        # and exits, and the rest of the 2 workers AND the main() keep
        # waiting for new msgs
        self.flows_to_process_q = multiprocessing.Queue(maxsize=50000)
        self.handle_setting_local_net_lock = multiprocessing.Lock()
        # runs a separate server process behind the scenes.
        self.manager = multiprocessing.Manager()
        self.localnet_cache = self.manager.dict()
        # max parallel profiler workers to start when high throughput is detected
        self.max_workers = 10
        self.aid_queue = multiprocessing.Queue()
        # This starts a process that handles calculatng aid hash and stores
        # the conn fows in the db. why?
        # because it's cpu intensive so we dont want it to
        # block the profiler workers
        self.aid_manager = AIDManager(
            self.db,
            self.aid_queue,
            self.stop_profiler_workers_event,
        )
        # the event that the workers use to tell this process to stop
        self.stop_profiler_event = multiprocessing.Event()

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
        if input_type in ("zeek_folder", "zeek_log_file", "pcap", "interface"):
            # is it tab separated or comma separated?
            actual_line = line["data"]
            if isinstance(actual_line, dict):
                return "zeek"
            return "zeek-tabs"
        elif input_type == "stdin":
            # ok we're reading flows from stdin, but what type of flows?
            return line["line_type"]
        else:
            # if it's none of the above cases
            # it's probably one of the following:
            # binetflow, binetflow tabs, nfdump, suricata
            return input_type

    def stop_profiler_workers(self):
        self.stop_profiler_workers_event.set()  # Signal workers to exit
        time.sleep(2)
        # Try to join gracefully first
        for process in self.profiler_child_processes:
            try:
                process.join(timeout=3)
            except (OSError, ChildProcessError):
                pass

        # Terminate any processes that are still alive after the join timeout
        for process in self.profiler_child_processes:
            try:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=0.1)
            except (OSError, ChildProcessError):
                pass

    def mark_process_as_done_processing(self):
        """
        is called to mark this process as done processing so
        slips.py would know when to terminate
        """
        # signal slips.py that this process is done
        self.print(
            "Marking Profiler as done processing.", log_to_logfiles_only=True
        )
        self.done_processing.release()
        self.print("Profiler is done processing.", log_to_logfiles_only=True)
        self.is_profiler_done_event.set()
        self.print(
            "Profiler is done telling input.py " "that it's done processing.",
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

    def start_profiler_worker(self, worker_id: int = None):
        """starts A profiler worker for faster processing of the flows"""
        worker_name = f"ProfilerWorker_Process_{worker_id}"
        worker = ProfilerWorker(
            logger=self.logger,
            output_dir=self.output_dir,
            redis_port=self.redis_port,
            termination_event=self.stop_profiler_workers_event,
            conf=self.conf,
            ppid=self.ppid,
            slips_args=self.args,
            bloom_filters_manager=self.bloom_filters,
            # module specific kwargs
            name=worker_name,
            localnet_cache=self.localnet_cache,
            profiler_queue=self.profiler_queue,
            handle_setting_local_net_lock=self.handle_setting_local_net_lock,
            input_handler=self.input_handler_obj,
            aid_queue=self.aid_queue,
            aid_manager=self.aid_manager,
            stop_profiler_event=self.stop_profiler_event,
        )
        worker.start()
        self.profiler_child_processes.append(worker)

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
        self.aid_manager.shutdown()

        for worker in self.workers:
            self.rec_lines += worker.received_lines

        # wait for all flows to be processed by the profiler processes.
        self.stop_profiler_workers()
        # close the queues to avoid deadlocks.
        # this step SHOULD NEVER be done before closing the workers
        self.flows_to_process_q.close()
        # By default if a process is not the creator of the queue then on
        # exit it will attempt to join the queue’s background thread. The
        # process can call cancel_join_thread() to make join_thread()
        # do nothing.
        self.flows_to_process_q.cancel_join_thread()
        self.profiler_queue.close()
        self.aid_queue.close()

        self.manager.shutdown()
        self.db.set_new_incoming_flows(False)
        self.print(
            f"Stopping. Total lines read: {self.rec_lines}",
            log_to_logfiles_only=True,
        )
        self.mark_process_as_done_processing()

    def did_5min_pass_since_last_throughput_check(self) -> bool:
        """
        returns true if 5 mins passed since the last time we checked
        the flows read per second
        """
        now = time.time()
        self.last_throughput_check_time = getattr(
            self, "last_throughput_check_time", now
        )
        time_diff = now - self.last_throughput_check_time
        if time_diff < 300:  # check every 5 minutes
            return False

        self.last_throughput_check_time = now
        return True

    def max_workers_started(self) -> bool:
        """
        returns true if the maximum number of profiler workers
        is already started
        """
        # bc workers start from 0
        if self.last_worker_id + 1 >= self.max_workers:
            return True
        return False

    def _check_if_high_throughput_and_add_workers(self):
        """
        Checks for input and profile flows/sec imbalance and adds more
        profiler workers if needed.
        """
        if self.max_workers_started():
            return

        if not self.did_5min_pass_since_last_throughput_check():
            return

        profiler_fps = self.db.get_module_flows_per_second(self.name)
        input_fps = self.db.get_module_flows_per_second("Input")
        if float(input_fps) > (
            float(profiler_fps) * 1.1
        ):  # 10% more input fps than profiler fps
            worker_id = self.last_worker_id + 1
            self.start_profiler_worker(worker_id)
            self.last_worker_id = worker_id
            self.print(
                f"Warning: High throughput detected. Started "
                f"additional worker: "
                f"ProfilerWorker_{worker_id} to handle the flows."
            )

            if self.last_worker_id == self.max_workers - 1:
                self.print(
                    f"Maximum number of profiler workers "
                    f"({self.max_workers}) started."
                )

    def pre_main(self):
        client_ips = [str(ip) for ip in self.client_ips]
        if client_ips:
            self.print(f"Used client IPs: {green(', '.join(client_ips))}")

    def _update_lines_read_by_all_workers(self):
        # needed by store_flows_read_per_second()
        self.lines = sum([worker.received_lines for worker in self.workers])

    def should_stop(self):
        """
        overrides IModule.should_stop() which returns True when all channels
        are empty and the termination event is set.

        why? because this module is the one that triggers the termination
        event (through process_manager), so checking that event here is
        meaningless, it will never be set before this module stops.

        instead, the "stop" message coming from input.py causes one of the
        profiler workers to set stop_profiler_event, this func then
        return True, that worker then exits, and then profiler shuts down
        the remaining workers and stops.
        docs on how slips stops:
        https://stratospherelinuxips.readthedocs.io/en/develop/contributing.html#how-does-slips-stop
        """
        return self.stop_profiler_event.wait(timeout=5 * 60)

    def main(self):
        # process the first msg only here, to determine what kind of input
        # slips is given, then the workers will use the determined type.
        # wait as long as needed for it
        msg = None
        while not msg:
            msg = self.get_msg_from_queue(self.profiler_queue)
            time.sleep(0.1)

        self.input_handler_obj = self.get_handler_obj(msg)
        if not self.input_handler_obj:
            self.print("Unsupported input type, exiting.")
            return 1

        line: dict = msg["line"]
        # updates internal zeek to slips mapping if needed, just once
        self.input_handler_obj.process_line(line)

        # slips starts with these workers by default until it detects
        # high throughput that these workers arent enough to handle
        num_of_profiler_workers = 5
        for worker_id in range(num_of_profiler_workers):
            self.last_worker_id = worker_id
            self.start_profiler_worker(worker_id)

        while not self.should_stop():
            self._update_lines_read_by_all_workers()
            # implemented in icore.py
            self.store_flows_read_per_second()
            self._check_if_high_throughput_and_add_workers()
            # PS: do not exit when max workers is reached, we need this
            # parent up to handle the shutdown of its child workers

        # ICore() will call shutdown_gracefully() on return
        return
