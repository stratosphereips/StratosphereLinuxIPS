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
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.icore import ICore
from slips_files.common.style import green
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
        self.localnet_cache = {}
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
        # the goal of this is to have main() handle the stop msg.
        # so without this, only 1 of the 3 workers receives the stop msg
        # and exits, and the rest of the 2 workers AND the main() keep
        # waiting for new msgs
        self.flows_to_process_q = multiprocessing.Queue(maxsize=5162220)
        self.handle_setting_local_net_lock = multiprocessing.Lock()
        self.is_first_msg = True
        self.manager = multiprocessing.Manager()
        self.localnet_cache = self.manager.dict()
        # max parallel profiler workers to start when high throughput is detected
        self.max_workers = 1

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
        self.stop_profiler_workers_event.set()
        for process in self.profiler_child_processes:
            try:
                if process.is_alive():
                    process.terminate()
                process.join(timeout=3)
            except (OSError, ChildProcessError):
                # continue loop; don't abort shutdown
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

    def is_stop_msg(self, msg: str) -> bool:
        """
        this 'stop' msg is the last msg ever sent by the input process
        to indicate that no more flows are coming
        """
        return msg == "stop"

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

    def worker(
        self,
        name,
        input_handler_obj: (
            ZeekTabs | ZeekJSON | Argus | Suricata | ZeekTabs | Nfdump
        ),
    ):
        ProfilerWorker(
            name=name,
            logger=self.logger,
            output_dir=self.output_dir,
            redis_port=self.redis_port,
            conf=self.conf,
            ppid=self.ppid,
            args=self.args,
            localnet_cache=self.localnet_cache,
            profiler_queue=self.profiler_queue,
            stop_profiler_workers=self.stop_profiler_workers_event,
            handle_setting_local_net_lock=self.handle_setting_local_net_lock,
            flows_to_process_q=self.flows_to_process_q,
            input_handler=input_handler_obj,
            bloom_filters=self.bloom_filters,
        ).start()

    def start_profiler_worker(self, worker_id: int = None):
        """starts A profiler worker for faster processing of the flows"""
        worker_name = f"ProfilerWorker_{worker_id}"
        proc = multiprocessing.Process(
            target=self.worker,
            args=(
                worker_name,
                self.input_handler_cls,
            ),
            name=worker_name,
        )
        utils.start_process(proc, self.db)
        self.profiler_child_processes.append(proc)

    def get_handler_class(
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

        input_handler_cls = SUPPORTED_INPUT_TYPES[input_type]()
        return input_handler_cls

    def should_stop(self):
        """
        overrides Imodule's should_stop()
        the common Imodule's should_stop() stop when there's no msg in
        each channel and the termination event is set
        since this module is the one responsible for signaling the
        termination event (via process_manager) then it doesnt make sense
        to check for it. it will never be set before this module stops.
        """
        return False

    def shutdown_gracefully(self):
        for worker in self.workers:
            self.rec_lines += worker.received_lines

        # wait for all flows to be processed by the profiler processes.
        self.stop_profiler_workers()

        # close the queues to avoid deadlocks.
        # this step SHOULD NEVER be done before closing the workers
        self.flows_to_process_q.close()
        self.profiler_queue.close()

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

    def check_if_high_throughput_and_add_workers(self):
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

    def main(self):
        # the only thing that stops this loop is the 'stop' msg
        # we're using self.should_stop() here instead of while True to be
        # able to unit test this function:D
        while not self.should_stop():

            self.lines = sum(
                [worker.received_lines for worker in self.workers]
            )
            # implemented in icore.py
            self.store_flows_read_per_second()

            msg = self.get_msg_from_queue(self.profiler_queue)
            if not msg:
                # wait for msgs
                continue

            # ALYA, DO NOT REMOVE THIS CHECK
            # without it, there's no way this module will know it's
            # time to stop and no new flows are coming
            if self.is_stop_msg(msg):
                # shutdown gracefully will be called by ICore() once this
                # function returns
                return 1

            if self.is_first_msg:
                self.is_first_msg = False

                self.input_handler_cls = self.get_handler_class(msg)
                if not self.input_handler_cls:
                    self.print("Unsupported input type, exiting.")
                    return 1

                line: dict = msg["line"]
                # updates internal zeek to slips mapping if needed
                self.input_handler_cls.process_line(line)

                # slips starts with 3 workers by default until it detects
                # high throughput that 3 workers arent enough to handle
                num_of_profiler_workers = 3
                for worker_id in range(num_of_profiler_workers):
                    self.last_worker_id = worker_id
                    self.start_profiler_worker(worker_id)
                continue

            self.flows_to_process_q.put(msg, block=True, timeout=None)
            self.check_if_high_throughput_and_add_workers()
