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

import os

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# Contact: eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz, stratosphere@aic.fel.cvut.cz


from slips_files.common.abstracts.icore import ICore

# common imports for all modules
from slips_files.common.slips_utils import utils
import multiprocessing

from slips_files.common.style import yellow
from slips_files.core.input_readers.binetflow_reader import BinetflowReader
from slips_files.core.input_readers.cyst_reader import CYSTReader
from slips_files.core.input_readers.nfdump_reader import NfdumpReader
from slips_files.core.input_readers.stdin_reader import StdinReader
from slips_files.core.input_readers.suricata_reader import SuricataReader
from slips_files.core.input_readers.zeek_reader import ZeekReader, ZeekRotator


class Input(ICore):
    """A class process to run the process of the flows"""

    name = "Input"

    def init(
        self,
        is_input_done: multiprocessing.Semaphore = None,
        profiler_queue=None,
        input_type=None,
        input_information=None,
        cli_packet_filter=None,
        zeek_or_bro=None,
        zeek_dir=None,
        line_type=None,
        is_profiler_done_event: multiprocessing.Event = None,
    ):
        self.input_type = input_type
        self.profiler_queue = profiler_queue
        # in case of reading from stdin, the user must tell slips what
        # type of lines is the input using -f <type>
        self.line_type: str = line_type
        # entire path
        self.given_path: str = input_information
        self.zeek_dir: str = zeek_dir
        self.zeek_or_bro: str = zeek_or_bro
        self.cli_packet_filter: str = cli_packet_filter

        self.nfdump_reader = NfdumpReader(
            self.logger,
            self.output_dir,
            self.redis_port,
            self.conf,
            self.ppid,
            self.profiler_queue,
            self.input_type,
        )

        self.read_lines_delay = 0
        # when input is done processing, it reeleases this semaphore, that's how the process_manager knows it's done
        # when both the input and the profiler are done, the input process signals the rest of the modules to stop
        self.done_processing: multiprocessing.Semaphore = is_input_done

        # set to true in unit tests
        self.testing = False
        # number of lines read
        self.lines = 0

        self.open_file_handlers = {}
        self.c1 = self.db.subscribe("remove_old_files")
        self.channels = {"remove_old_files": self.c1}
        self.timeout = None

        # is set by the profiler to tell this proc that we it is done processing
        # the input process and shut down and close the profiler queue no issue
        self.is_profiler_done_event = is_profiler_done_event
        self.is_running_non_stop: bool = self.db.is_running_non_stop()

    def mark_self_as_done_processing(self):
        """
        marks this process as done processing and wait for the profiler to
        stop so slips.py would know when to terminate
        """
        # signal slips.py that this process is done
        # tell profiler that this process is
        # done and no more flows are arriving
        self.print(
            "Telling Profiler to stop because " "no more input is arriving.",
            log_to_logfiles_only=True,
        )
        self.profiler_queue.put("stop")
        self.print("Waiting for Profiler to stop.", log_to_logfiles_only=True)
        self.is_profiler_done_event.wait()
        # reaching here means the wait() is over and profiler did stop.
        self.print("Input is done processing.", log_to_logfiles_only=True)
        self.done_processing.release()

    def stop_queues(self):
        """Stops the profiler queue"""
        # By default if a process is not the creator of the queue then on
        # exit it will attempt to join the queue’s background thread. The
        # process can call cancel_join_thread() to make join_thread()
        # do nothing.
        self.profiler_queue.cancel_join_thread()

    def read_zeek_folder(self):
        self.zeek_reader = ZeekReader(
            self.logger,
            self.output_dir,
            self.redis_port,
            self.conf,
            self.ppid,
            self.profiler_queue,
            self.input_type,
            args=self.args,
            input_proc=self,
            zeek_dir=self.zeek_dir,
            zeek_or_bro=self.zeek_or_bro,
            cli_packet_filter=self.cli_packet_filter,
        )
        self.lines = self.zeek_reader.read("zeek_folder", self.given_path)
        self.print_lines_read()
        self.mark_self_as_done_processing()
        return True

    def print_lines_read(self):
        self.print(
            f"Done reading all flows. Stopping the input process. "
            f"Sent {self.lines} lines for the profiler process."
        )

    def read_from_stdin(self) -> bool:
        self.stdin_reader = StdinReader(
            self.logger,
            self.output_dir,
            self.redis_port,
            self.conf,
            self.ppid,
            self.profiler_queue,
            self.input_type,
        )
        return self.stdin_reader.read(self.line_type)

    def handle_binetflow(self):
        binetflow_reader = BinetflowReader(
            self.logger,
            self.output_dir,
            self.redis_port,
            self.conf,
            self.ppid,
            self.profiler_queue,
            self.input_type,
        )
        self.lines = binetflow_reader.read(self.given_path)
        self.print_lines_read()
        self.mark_self_as_done_processing()
        return True

    def handle_suricata(self):
        suricata_reader = SuricataReader(
            self.logger,
            self.output_dir,
            self.redis_port,
            self.conf,
            self.ppid,
            self.profiler_queue,
            self.input_type,
        )
        self.lines = suricata_reader.read(self.given_path)
        self.print_lines_read()
        self.mark_self_as_done_processing()
        return True

    def handle_zeek_log_file(self):
        """
        Handles conn.log files given to slips directly,
         and conn.log flows given to slips through CYST unix socket.
        """
        if (
            utils.is_ignored_zeek_log_file(self.given_path)
            and "cyst" not in self.given_path.lower()
        ):
            # unsupported file
            return False

        if os.path.exists(self.given_path):
            # in case of CYST flows, the given path is 'cyst' and there's no
            # way to get the total flows
            self.is_zeek_tabs = self.is_zeek_tabs_file(self.given_path)
            total_flows = self.get_flows_number(self.given_path)
            self.db.set_input_metadata({"total_flows": total_flows})
            self.total_flows = total_flows

        # Add log file to database
        self.db.add_zeek_file(self.given_path, "default")

        # this timeout is the only thing that
        # makes the read_zeek_files() return
        # without it, it will keep listening forever for new zeek log files
        # as we're running on an interface
        self.bro_timeout = 30
        self.lines = self.read_zeek_files()
        self.mark_self_as_done_processing()
        return True

    def handle_pcap_and_interface(self) -> bool:
        """
        runs when slips is given a pcap with -f, an interface with -i,
        or 2 interfaces with -ap
        """
        if not os.path.exists(self.zeek_dir):
            os.makedirs(self.zeek_dir)
        self.print(f"Storing zeek log files in {self.zeek_dir}")

        if self.input_type == "interface":
            # slips is running with -i or -ap
            # We don't want to stop bro if we read from an interface
            self.bro_timeout = float("inf")
            # format is {interface: zeek_dir_path}
            interfaces_to_monitor = {}
            if self.args.interface:
                interfaces_to_monitor.update(
                    {
                        self.args.interface: {
                            "dir": self.zeek_dir,
                            "type": "main_interface",
                        }
                    }
                )

            elif self.args.access_point:
                # slips is running in AP mode, we need to monitor the 2
                # interfaces, wifi and eth.
                for _type, interface in self.db.get_ap_info().items():
                    # _type can be 'wifi_interface' or "ethernet_interface"
                    dir_to_store_interface_logs = os.path.join(
                        self.zeek_dir, interface
                    )
                    interfaces_to_monitor.update(
                        {
                            interface: {
                                "dir": dir_to_store_interface_logs,
                                "type": _type,
                            }
                        }
                    )
            for interface, interface_info in interfaces_to_monitor.items():
                interface_dir = interface_info["dir"]
                if not os.path.exists(interface_dir):
                    os.makedirs(interface_dir)

                if interface_info["type"] == "ethernet_interface":
                    cidr = utils.get_cidr_of_interface(interface)
                    tcpdump_filter = f"dst net {cidr}"
                    logline = yellow(
                        f"Zeek is logging incoming traffic only "
                        f"for interface: {interface}."
                    )
                    self.print(logline)
                else:
                    tcpdump_filter = None
                    logline = yellow(
                        f"Zeek is logging all traffic on interface:"
                        f" {interface}."
                    )
                    self.print(logline)

                self.init_zeek(
                    interface_dir, interface, tcpdump_filter=tcpdump_filter
                )

        elif self.input_type == "pcap":
            # This is for stopping the inputprocess
            # if bro does not receive any new line while reading a pcap
            self.bro_timeout = 30
            self.init_zeek(self.zeek_dir, self.given_path)

        self.lines = self.read_zeek_files()
        self.print_lines_read()
        self.mark_self_as_done_processing()
        self.stop_observer()
        return True

    def shutdown_gracefully(self):
        self.print(f"Stopping. Total lines read: {self.lines}")
        self.stop_queues()

        if hasattr(self, "zeek_rotator"):
            self.zeek_rotator.stop()

        if hasattr(self, "zeek_reader"):
            self.zeek_reader.shutdown_gracefully()

        return True

    def handle_cyst(self):
        cyst_reader = CYSTReader(
            self.logger,
            self.output_dir,
            self.redis_port,
            self.conf,
            self.ppid,
            self.profiler_queue,
            self.input_type,
            input_proc=self,
        )
        self.lines = cyst_reader.read(self.line_type)
        self.print_lines_read()
        self.mark_self_as_done_processing()

    def give_profiler(self, line):
        """
        sends the given txt/dict to the profilerqueue for process
        sends the total amount of flows to process with the first flow only
        """
        to_send = {"line": line, "input_type": self.input_type}
        # when the queue is full, the default behaviour is to block
        # if necessary until a free slot is available
        self.profiler_queue.put(to_send)

    def handle_nfdump(self):
        self.lines = self.nfdump_reader.read(self.given_path)
        self.print_lines_read()
        self.mark_self_as_done_processing()

    def main(self):
        if self.is_running_non_stop:
            # this thread should be started from run() to get the PID of
            # inputprocess and have shared variables
            # if it started from __init__() it will have the PID of slips.py
            # therefore, any changes made to the shared variables in
            # inputprocess will not appear in the thread
            # delete old zeek-date.log files
            self.zeek_rotator = ZeekRotator()
            self.zeek_rotator.start()

        input_handlers = {
            "stdin": self.read_from_stdin,
            "zeek_folder": self.read_zeek_folder,
            "zeek_log_file": self.handle_zeek_log_file,
            "nfdump": self.handle_nfdump,
            "binetflow": self.handle_binetflow,
            "binetflow-tabs": self.handle_binetflow,
            "pcap": self.handle_pcap_and_interface,
            "interface": self.handle_pcap_and_interface,
            "suricata": self.handle_suricata,
            "CYST": self.handle_cyst,
        }

        try:
            # Process the file that was given
            input_handlers[self.input_type]()
        except KeyError:
            self.print(
                f'Error: Unrecognized file type "{self.input_type}". '
                f"Stopping.",
                0,
                1,
            )
            return False

        # no logic should be put here
        # because some of the above handlers never return
        # e.g. interface, stdin, cyst etc.
        return 1
