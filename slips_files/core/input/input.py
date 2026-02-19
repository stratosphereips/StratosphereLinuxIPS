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
# Contact: eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz, stratosphere@aic.fel.cvut.cz


from slips_files.common.abstracts.icore import ICore

# common imports for all modules
from slips_files.common.parsers.config_parser import ConfigParser
import multiprocessing

from slips_files.core.input.binetflow.binetflow_input import BinetflowInput
from slips_files.core.input.binetflow.binetflow_tabs_input import (
    BinetflowTabsInput,
)
from slips_files.core.input.cyst.cyst_input import CystInput
from slips_files.core.input.zeek.interface_input import InterfaceInput
from slips_files.core.input.nfdump.nfdump_input import NfdumpInput
from slips_files.core.input.zeek.pcap_input import PcapInput
from slips_files.core.input.stdin.stdin_input import StdinInput
from slips_files.core.input.suricata.suricata_input import SuricataInput
from slips_files.core.input.zeek.zeek_dir_input import ZeekDirInput
from slips_files.core.input.zeek.zeek_log_file_input import ZeekLogFileInput
from slips_files.core.input.zeek.utils.zeek_input_utils import ZeekInputUtils


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
        self.read_lines_delay = 0
        # when input is done processing, it reeleases this semaphore, that's h
        # ow the process_manager knows it's done
        # when both the input and the profiler are done, the input process
        # signals the rest of the modules to stop
        self.done_processing: multiprocessing.Semaphore = is_input_done
        self.packet_filter = False
        if cli_packet_filter:
            self.packet_filter = f"'{cli_packet_filter}'"

        self.read_configuration()
        # set to true in unit tests
        self.testing = False
        # number of lines read
        self.lines = 0
        self.channels = {
            "remove_old_files": self.db.subscribe("remove_old_files"),
        }
        self.timeout = None
        self.zeek_utils = ZeekInputUtils(self)
        self._done_processing_marked = False

        # is set by the profiler to tell this proc that we it is done processing
        # the input process and shut down and close the profiler queue no issue
        self.is_profiler_done_event = is_profiler_done_event
        self.is_running_non_stop: bool = self.db.is_running_non_stop()
        self.input_handlers = self._build_input_handlers()
        self.active_handler = None

    def _build_input_handlers(self):
        return {
            "stdin": StdinInput(self),
            "zeek_folder": ZeekDirInput(self),
            "zeek_log_file": ZeekLogFileInput(self),
            "nfdump": NfdumpInput(self),
            "binetflow": BinetflowInput(self),
            "binetflow-tabs": BinetflowTabsInput(self),
            "pcap": PcapInput(self),
            "interface": InterfaceInput(self),
            "suricata": SuricataInput(self),
            "CYST": CystInput(self),
        }

    def mark_self_as_done_processing(self):
        """
        marks this process as done processing and wait for the profiler to
        stop so slips.py would know when to terminate
        """
        if self._done_processing_marked:
            return
        self._done_processing_marked = True
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

    def read_configuration(self):
        conf = ConfigParser()
        # If we were given something from command line, has preference
        # over the configuration file
        self.packet_filter = self.packet_filter or conf.packet_filter()
        self.tcp_inactivity_timeout = conf.tcp_inactivity_timeout()
        self.enable_rotation = conf.rotation()
        self.rotation_period = conf.rotation_period()
        self.keep_rotated_files_for = conf.keep_rotated_files_for()

    def stop_queues(self):
        """Stops the profiler queue"""
        # By default if a process is not the creator of the queue then on
        # exit it will attempt to join the queue’s background thread. The
        # process can call cancel_join_thread() to make join_thread()
        # do nothing.
        self.profiler_queue.cancel_join_thread()

    def _make_gen(self, reader):
        """yeilds (64 kilobytes) at a time from the file"""
        while True:
            b = reader(2**16)
            if not b:
                break
            yield b

    def get_flows_number(self, file: str) -> int:
        """
        returns the number of flows/lines in a given file
        """
        # using wc -l doesn't count last line of the file if it does not have
        # end of line character
        # using  grep -c "" returns incorrect line numbers sometimes
        # this method is the most efficient and accurate i found online
        # https://stackoverflow.com/a/68385697/11604069

        with open(file, "rb") as f:
            # counts the occurances of \n in a file
            count = sum(buf.count(b"\n") for buf in self._make_gen(f.raw.read))

        if hasattr(self, "is_zeek_tabs") and self.is_zeek_tabs:
            # subtract comment lines in zeek tab files,
            # they shouldn't be considered flows

            # NOTE: the counting of \n returns the actual lines-1 bc the
            # very last line of a zeek tab log file doesn't contain a \n
            # so instead of subtracting the 9 comment lines, we'll subtract
            # 8 bc the very last comment line isn't even included in count
            count -= 9

        return count

    def print_lines_read(self):
        self.print(
            f"Done reading all flows. Stopping the input process. "
            f"Sent {self.lines} lines for the profiler process."
        )

    def shutdown_gracefully(self):
        self.print(f"Stopping. Total lines read: {self.lines}")
        self.stop_queues()
        if self.active_handler:
            try:
                self.active_handler.shutdown_gracefully()
            except Exception:
                pass

        return True

    def give_profiler(self, line):
        """
        sends the given txt/dict to the profilerqueue for process
        sends the total amount of flows to process with the first flow only
        """
        to_send = {"line": line, "input_type": self.input_type}
        # when the queue is full, it blocks forever until a free slot is
        # available
        self.profiler_queue.put(to_send, block=True, timeout=None)

    def main(self):
        try:
            self.active_handler = self.input_handlers[self.input_type]
            self.active_handler.run()
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
