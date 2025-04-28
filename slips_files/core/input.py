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

import datetime
import json
import os
import signal
import subprocess
import sys
import threading
import time

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# Contact: eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz, stratosphere@aic.fel.cvut.cz
from re import split

from watchdog.observers import Observer

from slips_files.common.abstracts.core import ICore

# common imports for all modules
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
import multiprocessing
from slips_files.core.helpers.filemonitor import FileEventHandler
from slips_files.core.supported_logfiles import SUPPORTED_LOGFILES


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
        # when input is done processing, it reeleases this semaphore, that's how the process_manager knows it's done
        # when both the input and the profiler are done, the input process signals the rest of the modules to stop
        self.done_processing: multiprocessing.Semaphore = is_input_done
        self.packet_filter = False
        if cli_packet_filter:
            self.packet_filter = f"'{cli_packet_filter}'"

        self.read_configuration()
        self.event_observer = None
        # set to true in unit tests
        self.testing = False
        # number of lines read
        self.lines = 0

        # create the remover thread
        self.remover_thread = threading.Thread(
            target=self.remove_old_zeek_files, daemon=True
        )
        self.open_file_handlers = {}
        self.c1 = self.db.subscribe("remove_old_files")
        self.channels = {"remove_old_files": self.c1}
        self.timeout = None
        # zeek rotated files to be deleted after a period of time
        self.to_be_deleted = []
        self.zeek_thread = threading.Thread(target=self.run_zeek, daemon=True)
        # used to give the profiler the total amount of flows to
        # read with the first flow only
        self.is_first_flow = True
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

    def read_nfdump_output(self) -> int:
        """
        A binary file generated by nfcapd can be read by nfdump.
        The task for this function is to send nfdump output line by line to
        performance_profiler.py for processing
        """
        if not self.nfdump_output:
            # The nfdump command returned nothing
            self.print("Error reading nfdump output ", 1, 3)
        else:
            self.total_flows = len(self.nfdump_output.splitlines())
            self.db.set_input_metadata({"total_flows": self.total_flows})
            for nfdump_line in self.nfdump_output.splitlines():
                # this line is taken from stdout we need to remove whitespaces
                nfdump_line.replace(" ", "")
                line = {"type": "nfdump", "data": nfdump_line}
                self.give_profiler(line)
                if self.testing:
                    break

        return self.total_flows

    def check_if_time_to_del_rotated_files(self):
        """
        After a specific period (keep_rotated_files_for), slips deletes all rotated files
        Check if it's time to do so
        """
        if not hasattr(self, "time_rotated"):
            return False

        now = float(
            utils.convert_format(datetime.datetime.now(), "unixtimestamp")
        )
        time_to_delete = now >= self.time_rotated + self.keep_rotated_files_for
        if time_to_delete:
            # getting here means that the rotated
            # files are kept enough ( keep_rotated_files_for seconds)
            # and it's time to delete them
            for file in self.to_be_deleted:
                try:
                    os.remove(file)
                except FileNotFoundError:
                    pass
            self.to_be_deleted = []

    def get_file_handle(self, filename):
        # Update which files we know about
        try:
            # We already opened this file
            file_handler = self.open_file_handlers[filename]
        except KeyError:
            # First time opening this file.
            try:
                file_handler = open(filename, "r")
                lock = threading.Lock()
                lock.acquire()
                self.open_file_handlers[filename] = file_handler
                lock.release()
                # now that we replaced the old handle with the newly created file handle
                # delete the old .log file, that has a timestamp in its name.
            except FileNotFoundError:
                # for example dns.log
                # zeek changes the dns.log file name every 1d, it adds a
                # timestamp to it it doesn't create the new dns.log until a
                # new dns request
                # occurs
                # if slips tries to read from the old dns.log now it won't
                # find it because it's been renamed and the new one isn't
                # created yet simply continue until the new log file is
                # created and added to the zeek_files list
                return False
        return file_handler

    def get_ts_from_line(self, zeek_line: str):
        """
        used only by zeek log files
        :param line: can be a json or a json serialized dict
        """
        if self.is_zeek_tabs:
            # It is not JSON format. It is tab format line.
            nline = zeek_line
            nline_list = (
                nline.split("\t") if "\t" in nline else split(r"\s{2,}", nline)
            )
            timestamp = nline_list[0]
        else:
            try:
                nline = json.loads(zeek_line)
            except json.decoder.JSONDecodeError:
                return False, False
            # In some Zeek files there may not be a ts field
            # Like in some weird smb files
            timestamp = nline.get("ts", 0)
        try:
            timestamp = float(timestamp)
        except ValueError:
            # this ts doesnt repr a float value, ignore it
            return False, False

        return timestamp, nline

    def cache_nxt_line_in_file(self, filename: str):
        """
        reads 1 line of the given file and stores in queue for sending to the profiler
        :param: full path to the file. includes the .log extension
        """
        file_handle = self.get_file_handle(filename)
        if not file_handle:
            return False

        # Only read the next line if the previous line from this file was sent
        # to profiler
        if filename in self.cache_lines:
            # We have still something to send, do not read the next line from
            # this file
            return False

        # We don't have any waiting line for this file, so proceed
        try:
            zeek_line = file_handle.readline()
        except ValueError:
            # remover thread just finished closing all old handles.
            # comes here if I/O operation failed due to a closed file.
            # to get the new dict of open handles.
            return False

        # Did the file end?
        if not zeek_line or zeek_line.startswith("#close"):
            # We reached the end of one of the files that we were reading.
            # Wait for more lines to come from another file
            return False

        if zeek_line.startswith("#fields"):
            # this line contains the zeek fields, we want to cache it and
            # send it to the profiler normally
            nline = zeek_line
            # to send the line as early as possible
            timestamp = -1
        else:
            timestamp, nline = self.get_ts_from_line(zeek_line)
            if not timestamp:
                return False

        self.file_time[filename] = timestamp
        # Store the line in the cache
        self.cache_lines[filename] = {"type": filename, "data": nline}
        return True

    def reached_timeout(self) -> bool:
        # If we don't have any cached lines to send,
        # it may mean that new lines are not arriving. Check
        if not self.cache_lines:
            # Verify that we didn't have any new lines in the
            # last 10 seconds. Seems enough for any network to have
            # ANY traffic
            # Since we actually read something form any file, update
            # the last time of read
            diff = utils.get_time_diff(
                self.last_updated_file_time, datetime.datetime.now()
            )
            if diff >= self.bro_timeout:
                # It has been <bro_timeout> seconds without any file
                # being updated. So stop Zeek
                return True
        return False

    def close_all_handles(self):
        # We reach here after the break produced
        # if no zeek files are being updated.
        # No more files to read. Close the files
        for file, handle in self.open_file_handlers.items():
            self.print(f"Closing file {file}", 2, 0)
            handle.close()

    def get_earliest_line(self):
        """
        loops through all the caches lines and returns the line with the
        earliest ts
        """
        # Now read lines in order. The line with the earliest timestamp first
        files_sorted_by_ts = sorted(self.file_time, key=self.file_time.get)

        try:
            # get the file that has the earliest flow
            file_with_earliest_flow = files_sorted_by_ts[0]
        except IndexError:
            # No more sorted keys. Just loop waiting for more lines
            # It may happen that we check all the files in the folder,
            # and there is still no files for us.
            # To cover this case, just refresh the list of files
            self.zeek_files = self.db.get_all_zeek_files()
            return False, False

        # comes here if we're done with all conn.log flows and it's time to
        # process other files
        earliest_line = self.cache_lines[file_with_earliest_flow]
        return earliest_line, file_with_earliest_flow

    def read_zeek_files(self) -> int:
        self.zeek_files = self.db.get_all_zeek_files()
        self.open_file_handlers = {}
        # stores zeek_log_file_name: timestamp of the last flow read from
        # that file
        self.file_time = {}
        self.cache_lines = {}
        # Try to keep track of when was the last update so we stop this reading
        self.last_updated_file_time = datetime.datetime.now()
        while not self.should_stop():
            self.check_if_time_to_del_rotated_files()
            # Go to all the files generated by Zeek and read 1
            # line from each of them
            for filename in self.zeek_files:
                if utils.is_ignored_zeek_log_file(filename):
                    continue

                # reads 1 line from the given file and cache it
                # from in self.cache_lines
                self.cache_nxt_line_in_file(filename)

            if self.reached_timeout():
                break

            earliest_line, file_with_earliest_flow = self.get_earliest_line()
            if not file_with_earliest_flow:
                continue

            # self.print('	> Sent Line: {}'.format(earliest_line), 0, 3)

            self.give_profiler(earliest_line)
            self.lines += 1
            # when testing, no need to read the whole file!
            if self.lines == 10 and self.testing:
                break
            # Delete this line from the cache and the time list
            del self.cache_lines[file_with_earliest_flow]
            del self.file_time[file_with_earliest_flow]

            # Get the new list of files. Since new files may have been created by
            # Zeek while we were processing them.
            self.zeek_files = self.db.get_all_zeek_files()

        self.close_all_handles()
        return self.lines

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
        # using wc -l doesn't count last line of the file if it does not have end of line character
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

    def read_zeek_folder(self):
        # This is the case that a folder full of zeek files is passed with -f
        # wait max 10 seconds before stopping slips if no new flows are read
        self.bro_timeout = 10
        growing_zeek_dir: bool = self.db.is_growing_zeek_dir()
        if growing_zeek_dir:
            # slips is given a dir that is growing i.e zeek dir running on an
            # interface
            # don't stop zeek or slips
            self.bro_timeout = float("inf")

        self.zeek_dir = self.given_path
        self.start_observer()

        # if 1 file is zeek tabs the rest should be the same
        if not hasattr(self, "is_zeek_tabs"):
            full_path = os.path.join(
                self.given_path, os.listdir(self.given_path)[0]
            )
            self.is_zeek_tabs = self.is_zeek_tabs_file(full_path)

        total_flows = 0
        for file in os.listdir(self.given_path):
            full_path = os.path.join(self.given_path, file)

            # exclude ignored files from the total flows to be processed
            if utils.is_ignored_zeek_log_file(full_path):
                continue

            if not growing_zeek_dir:
                # get the total number of flows slips is going to read
                total_flows += self.get_flows_number(full_path)

            # Add log file to the database
            self.db.add_zeek_file(full_path)

            # in testing mode, we only need to read one zeek file to know
            # that this function is working correctly
            if self.testing:
                break

        if total_flows == 0 and not growing_zeek_dir:
            # we're given an empty dir/ zeek logfile
            self.mark_self_as_done_processing()
            return True

        self.total_flows = total_flows
        self.db.set_input_metadata({"total_flows": total_flows})
        self.lines = self.read_zeek_files()
        self.print_lines_read()
        self.mark_self_as_done_processing()
        return True

    def print_lines_read(self):
        self.print(
            f"Done reading all flows. Stopping the input process. "
            f"Sent {self.lines} lines for the profiler process."
        )

    def stdin(self):
        """opens the stdin in read mode"""
        sys.stdin.close()
        sys.stdin = os.fdopen(0, "r")
        return sys.stdin

    def read_from_stdin(self) -> bool:
        self.print("Receiving flows from stdin.")
        for line in self.stdin():
            if line == "\n":
                continue
            if line == "done":
                break
            # slips supports reading zeek json conn.log only using stdin,
            # tabs aren't supported
            if self.line_type == "zeek":
                try:
                    line = json.loads(line)
                except json.decoder.JSONDecodeError:
                    self.print("Invalid json line")
                    continue

            line_info = {
                "type": "stdin",
                "line_type": self.line_type,
                "data": line,
            }
            self.print(f"	> Sent Line: {line_info}", 0, 3)
            self.give_profiler(line_info)
            self.lines += 1
            self.print("Done reading 1 flow.\n ", 0, 3)
        return True

    def handle_binetflow(self):
        # the number of flows returned by get_flows_number contains the header
        # , so subtract that
        self.total_flows = self.get_flows_number(self.given_path) - 1
        self.db.set_input_metadata({"total_flows": self.total_flows})

        self.lines = 0
        with open(self.given_path) as file_stream:
            # read first line to determine the type of line, tab or comma separated
            t_line = file_stream.readline()
            type_ = "argus-tabs" if "\t" in t_line else "argus"
            line = {"type": type_, "data": t_line}
            self.give_profiler(line)
            self.lines += 1

            # go through the rest of the file
            for t_line in file_stream:
                line = {"type": type_, "data": t_line}
                # argus files are either tab separated orr comma separated
                if len(t_line.strip()) != 0:
                    self.give_profiler(line)

                self.lines += 1
                if self.testing:
                    break

        self.mark_self_as_done_processing()
        return True

    def handle_suricata(self):
        self.total_flows = self.get_flows_number(self.given_path)
        self.db.set_input_metadata({"total_flows": self.total_flows})
        with open(self.given_path) as file_stream:
            for t_line in file_stream:
                line = {
                    "type": "suricata",
                    "data": t_line,
                }
                self.print(f"	> Sent Line: {line}", 0, 3)
                if len(t_line.strip()) != 0:
                    self.give_profiler(line)
                self.lines += 1
                if self.testing:
                    break
        self.mark_self_as_done_processing()
        return True

    def is_zeek_tabs_file(self, filepath: str) -> bool:
        """
        returns true if the given path is a zeek tab separated file
        :param filepath: full log file path with the .log extension
        """
        with open(filepath, "r") as f:
            line = f.readline()

        if "\t" in line:
            return True

        if line.startswith("#separator"):
            return True
        try:
            json.loads(line)
            return False
        except json.decoder.JSONDecodeError:
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
        self.db.add_zeek_file(self.given_path)

        # this timeout is the only thing that
        # makes the read_zeek_files() return
        # without it, it will keep listening forever for new zeek log files
        # as we're running on an interface
        self.bro_timeout = 30
        self.lines = self.read_zeek_files()
        self.mark_self_as_done_processing()
        return True

    def handle_nfdump(self):
        command = f"nfdump -b -N -o csv -q -r {self.given_path}"
        # Execute command
        result = subprocess.run(command.split(), stdout=subprocess.PIPE)
        # Get command output
        self.nfdump_output = result.stdout.decode("utf-8")
        self.lines = self.read_nfdump_output()
        self.print_lines_read()
        self.mark_self_as_done_processing()
        return True

    def start_observer(self):
        # Now start the observer of new files. We need the observer because Zeek does not create all the files
        # at once, but when the traffic appears. That means that we need
        # some process to tell us which files to read in real time when they appear
        # Get the file eventhandler
        # We have to set event_handler and event_observer before running zeek.
        event_handler = FileEventHandler(
            self.zeek_dir, self.input_type, self.db
        )
        # Create an observer
        self.event_observer = Observer()
        # Schedule the observer with the callback on the file handler
        self.event_observer.schedule(
            event_handler, self.zeek_dir, recursive=True
        )
        # monitor changes to whitelist
        self.event_observer.schedule(event_handler, "config/", recursive=True)
        # Start the observer
        self.event_observer.start()

    def handle_pcap_and_interface(self) -> int:
        """Returns the number of zeek lines read"""

        # Create zeek_folder if does not exist.
        if not os.path.exists(self.zeek_dir):
            os.makedirs(self.zeek_dir)
        self.print(f"Storing zeek log files in {self.zeek_dir}")
        self.start_observer()

        if self.input_type == "interface":
            # We don't want to stop bro if we read from an interface
            self.bro_timeout = float("inf")
        elif self.input_type == "pcap":
            # This is for stopping the inputprocess
            # if bro does not receive any new line while reading a pcap
            self.bro_timeout = 30

        zeek_files = os.listdir(self.zeek_dir)
        if len(zeek_files) > 0:
            # First clear the zeek folder of old .log files
            for f in zeek_files:
                os.remove(os.path.join(self.zeek_dir, f))

        # run zeek
        self.zeek_thread.start()
        # Give Zeek some time to generate at least 1 file.
        time.sleep(3)

        self.db.store_pid("Zeek", self.zeek_pid)
        if not hasattr(self, "is_zeek_tabs"):
            self.is_zeek_tabs = False
        self.lines = self.read_zeek_files()
        self.print_lines_read()
        self.mark_self_as_done_processing()

        connlog_path = os.path.join(self.zeek_dir, "conn.log")

        self.print(
            f"Number of zeek generated flows in conn.log: "
            f"{self.get_flows_number(connlog_path)}",
            2,
            0,
        )

        self.stop_observer()
        return True

    def stop_observer(self):
        # Stop the observer
        try:
            self.event_observer.stop()
            self.event_observer.join(10)
        except AttributeError:
            # In the case of nfdump, there is no observer
            pass

    def remove_old_zeek_files(self):
        """
        This thread waits for filemonitor.py to tell it that zeek changed the log files,
        it deletes old zeek-date.log files and clears slips' open handles and sleeps again
        """
        while not self.should_stop():
            # keep the rotated files for the period specified in slips.yaml
            if msg := self.get_msg("remove_old_files"):
                # this channel receives renamed zeek log files,
                # we can safely delete them and close their handle
                changed_files = json.loads(msg["data"])

                # for example the old log file should be  ./zeek_files/dns.2022-05-11-14-43-20.log
                # new log file should be dns.log without the ts
                old_log_file = changed_files["old_file"]
                new_log_file = changed_files["new_file"]
                new_logfile_without_path = new_log_file.split("/")[-1].split(
                    "."
                )[0]
                # ignored files have no open handle, so we should only delete them from disk
                if new_logfile_without_path not in SUPPORTED_LOGFILES:
                    # just delete the old file
                    os.remove(old_log_file)
                    continue

                # don't allow inputprocess to access the
                # open_file_handlers dict until this thread sleeps again
                lock = threading.Lock()
                lock.acquire()
                try:
                    # close slips' open handles
                    self.open_file_handlers[new_log_file].close()
                    # delete cached filename
                    del self.open_file_handlers[new_log_file]
                except KeyError:
                    # we don't have a handle for that file,
                    # we probably don't need it in slips
                    # ex: loaded_scripts.log, stats.log etc..
                    pass
                # delete the old log file (the one with the ts)
                self.to_be_deleted.append(old_log_file)
                self.time_rotated = float(
                    utils.convert_format(
                        datetime.datetime.now(), "unixtimestamp"
                    )
                )
                # os.remove(old_log_file)
                lock.release()

    def shutdown_gracefully(self):
        self.print(f"Stopping. Total lines read: {self.lines}")
        self.stop_observer()
        self.stop_queues()
        try:
            self.remover_thread.join(3)
        except Exception:
            pass
        try:
            self.zeek_thread.join(3)
        except Exception:
            pass

        if hasattr(self, "open_file_handlers"):
            self.close_all_handles()

        if hasattr(self, "zeek_pid"):
            # kill zeek manually if it started bc it's detached from this
            # process and will never recv the sigint also withoutt this,
            # inputproc will never shutdown and will always remain in memory
            # causing 1000 bugs in proc_man:shutdown_gracefully()
            try:
                os.kill(self.zeek_pid, signal.SIGKILL)
            except Exception:
                pass

        return True

    def run_zeek(self):
        """
        This thread sets the correct zeek parameters and starts zeek
        """

        def detach_child():
            """
            Detach zeek from the parent process group(inputprocess), the child(zeek)
             will no longer receive signals
            """
            # we're doing this to fix zeek rotating on sigint, not when zeek has it's own
            # process group, it won't get the signals sent to slips.py
            os.setpgrp()

        # rotation is disabled unless it's an interface
        rotation = []
        if self.input_type == "interface":
            if self.enable_rotation:
                # how often to rotate zeek files? taken from slips.yaml
                rotation = [
                    "-e",
                    f"redef Log::default_rotation_interval = {self.rotation_period} ;",
                ]
            bro_parameter = ["-i", self.given_path]

        elif self.input_type == "pcap":
            # Find if the pcap file name was absolute or relative
            given_path = self.given_path
            if not os.path.isabs(self.given_path):
                # now the given pcap is relative to slips main dir
                # slips can store the zeek logs dir either in the
                # output dir (by default in Slips/output/<filename>_<date>/zeek_files/),
                # or in any dir specified with -o
                # construct an abs path from the given path so slips can find the given pcap
                # no matter where the zeek dir is placed
                given_path = os.path.join(os.getcwd(), self.given_path)

            # using a list of params instead of a str for storing the cmd
            # becaus ethe given path may contain spaces
            bro_parameter = ["-r", given_path]

        # Run zeek on the pcap or interface. The redef is to have json files
        zeek_scripts_dir = os.path.join(os.getcwd(), "zeek-scripts")
        packet_filter = (
            ["-f ", self.packet_filter] if self.packet_filter else []
        )

        # 'local' is removed from the command because it
        # loads policy/protocols/ssl/expiring-certs and
        # and policy/protocols/ssl/validate-certs and they have conflicts with our own
        # zeek-scripts/expiring-certs and validate-certs
        # we have our own copy pf local.zeek in __load__.zeek
        command = [self.zeek_or_bro, "-C"]
        command += bro_parameter
        command += [
            f"tcp_inactivity_timeout={self.tcp_inactivity_timeout}mins",
            "tcp_attempt_delay=1min",
            zeek_scripts_dir,
        ]
        command += rotation
        command += packet_filter

        self.print(f'Zeek command: {" ".join(command)}', 3, 0)

        zeek = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            cwd=self.zeek_dir,
            start_new_session=True,
        )
        # you have to get the pid before communicate()
        self.zeek_pid = zeek.pid

        out, error = zeek.communicate()
        if out:
            print(f"Zeek: {out}")
        if error:
            self.print(
                f"Zeek error. return code: {zeek.returncode} error:{error.strip()}"
            )

    def handle_cyst(self):
        """
        Read flows sent by any external module (for example the cYST module)
        Supported flows are of type zeek conn log
        """
        # slips supports reading zeek json conn.log only using CYST
        # this type is passed here by slips.py, so in the future
        # to support more types, modify slips.py
        if self.line_type != "zeek":
            return

        channel = self.db.subscribe("new_module_flow")
        self.channels.update({"new_module_flow": channel})
        while not self.should_stop():
            # the CYST module will send msgs to this channel when it read s a new flow from the CYST UDS
            # todo when to break? cyst should send something like stop?

            msg = self.get_msg("new_module_flow")
            if msg and msg["data"] == "stop_process":
                self.shutdown_gracefully()
                return True

            if msg := self.get_msg("new_module_flow"):
                msg: str = msg["data"]
                msg = json.loads(msg)
                flow = msg["flow"]
                src_module = msg["module"]
                line_info = {
                    "type": "external_module",
                    "module": src_module,
                    "line_type": self.line_type,
                    "data": flow,
                }
                self.print(f"   > Sent Line: {line_info}", 0, 3)
                self.give_profiler(line_info)
                self.lines += 1
                self.print("Done reading 1 CYST flow.\n ", 0, 3)

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

    def main(self):
        utils.drop_root_privs()
        if self.is_running_non_stop:
            # this thread should be started from run() to get the PID of inputprocess and have shared variables
            # if it started from __init__() it will have the PID of slips.py therefore,
            # any changes made to the shared variables in inputprocess will not appear in the thread
            # delete old zeek-date.log files
            self.remover_thread.start()

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
