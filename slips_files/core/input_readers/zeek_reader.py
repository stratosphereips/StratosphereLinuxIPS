# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import os
import subprocess
from typing import Dict
import datetime
import signal
import threading
import time

from re import split
from typing import List

from watchdog.observers import Observer


from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils


from slips_files.core.database.database_manager import DBManager
from slips_files.core.supported_logfiles import SUPPORTED_LOGFILES
from slips_files.common.abstracts.iinput_reader import IInputReader
from slips_files.core.helpers.filemonitor import FileEventHandler
from slips_files.core.zeek_cmd_builder import ZeekCommandBuilder


class ZeekRotator:
    def __init__(self):
        self.remover_thread = threading.Thread(
            target=self.remove_old_zeek_files,
            daemon=True,
            name="input_remover_thread",
        )

    def start(self):
        self.remover_thread.start()

    def remove_old_zeek_files(self):
        """
        This thread waits for filemonitor.py to tell it that zeek changed the log files,
        it deletes old zeek-date.log files and clears slips' open handles and sleeps again
        """
        while not self.input_proc.should_stop():
            # keep the rotated files for the period specified in slips.yaml
            if msg := self.input_proc.get_msg("remove_old_files"):
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
                    utils.convert_ts_format(
                        datetime.datetime.now(), "unixtimestamp"
                    )
                )
                lock.release()

    def stop(self):
        try:
            self.zeek_rotator.remover_thread.join(3)
        except Exception:
            pass


class ZeekObserver:
    def __init__(self, db: DBManager):
        self.db = db
        self.event_observer = None

    def start(self, zeek_dir: str, pcap_or_interface: str):
        """
        :param zeek_dir: directory to monitor
        """
        # Now start the observer of new files. We need the observer because Zeek does not create all the files
        # at once, but when the traffic appears. That means that we need
        # some process to tell us which files to read in real time when they appear
        # Get the file eventhandler
        # We have to set event_handler and event_observer before running zeek.
        event_handler = FileEventHandler(zeek_dir, self.db, pcap_or_interface)

        self.event_observer = Observer()
        # Schedule the observer with the callback on the file handler
        self.event_observer.schedule(event_handler, zeek_dir, recursive=True)
        # monitor changes to whitelist
        self.event_observer.schedule(event_handler, "config/", recursive=True)
        # Start the observer
        self.event_observer.start()

    def stop(self):
        # Stop the observer
        try:
            self.event_observer.stop()
            self.event_observer.join(10)
        except AttributeError:
            # In the case of nfdump, there is no observer
            pass


class ZeekReader(IInputReader):
    name = "ZeekReader"
    description = "Reads Zeek son and tab-separated files"

    def init(
        self,
        args=None,
        input_proc=None,
        zeek_dir=None,
        zeek_or_bro=None,
        cli_packet_filter=None,
    ):
        self.args = args
        print(f"@@@@@@@@@@@@@@@@ self.args {self.args}")
        self.bro_timeout = None
        self.open_file_handlers = {}
        self.zeek_threads = []
        self.input_proc = input_proc
        self.zeek_dir = (zeek_dir,)
        self.zeek_or_bro = zeek_or_bro

        self.packet_filter = False
        if cli_packet_filter:
            self.packet_filter = f"'{cli_packet_filter}'"

        self.read_configuration()
        self.zeek_pids = []

        # zeek rotated files to be deleted after a period of time
        self.to_be_deleted = []
        self.zeek_threads = []
        self.observer = None
        self.lines = 0

    def read_configuration(self):
        conf = ConfigParser()
        # If we were given something from command line, has preference
        # over the configuration file
        self.packet_filter = self.packet_filter or conf.packet_filter()
        self.tcp_inactivity_timeout = conf.tcp_inactivity_timeout()
        self.enable_rotation = conf.rotation()
        self.rotation_period = conf.rotation_period()
        self.keep_rotated_files_for = conf.keep_rotated_files_for()

    def read(self, _type: str, given_path: str):
        if _type == "zeek_folder":
            self.read_zeek_folder(given_path)

    def shutdown_gracefully(self):
        self.observer.stop()
        try:
            for zeek_thread in self.zeek_threads:
                zeek_thread.join(3)
        except Exception:
            pass

        if hasattr(self, "open_file_handlers"):
            self.close_all_handles()

        # kill zeek manually if it started bc it's detached from this
        # process and will never recv the sigint.
        # also without this, inputproc will never shutdown and will
        # always remain in memory causing 1000 bugs in
        # proc_man:shutdown_gracefully()
        for pid in self.zeek_pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass

    def init_zeek(
        self, zeek_dir: str, pcap_or_interface: str, tcpdump_filter=None
    ):
        """
        :param pcap_or_interface: name of the pcap or interface zeek
        is going to run on

        PS: this function contains a call to self.read_zeek_files that
        keeps running until slips stops
        """
        self.observer = ZeekObserver(self.db)
        self.observer.start(zeek_dir, pcap_or_interface)

        zeek_files = os.listdir(zeek_dir)
        if len(zeek_files) > 0:
            # First clear the zeek folder of old .log files
            for f in zeek_files:
                os.remove(os.path.join(zeek_dir, f))

        zeek_thread = threading.Thread(
            target=self.run_zeek,
            args=(zeek_dir, pcap_or_interface),
            kwargs={"tcpdump_filter": tcpdump_filter},
            daemon=True,
            name="run_zeek_thread",
        )
        zeek_thread.start()
        self.zeek_threads.append(zeek_thread)
        # Give Zeek some time to generate at least 1 file.
        time.sleep(3)

        self.db.store_pid(f"Zeek_{pcap_or_interface}", self.zeek_pids[-1])
        if not hasattr(self, "is_zeek_tabs"):
            self.is_zeek_tabs = False

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

    def cache_nxt_line_in_file(self, filename: str, interface: str):
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
        self.cache_lines[filename] = {
            "type": filename,
            "data": nline,
            "interface": interface,
        }
        return True

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
            self.zeek_files: Dict[str, str] = self.db.get_all_zeek_files()
            return False, False

        # comes here if we're done with all conn.log flows and it's time to
        # process other files
        earliest_line = self.cache_lines[file_with_earliest_flow]
        return earliest_line, file_with_earliest_flow

    def close_all_handles(self):
        # We reach here after the break produced
        # if no zeek files are being updated.
        # No more files to read. Close the files
        for file, handle in self.open_file_handlers.items():
            self.print(f"Closing file {file}", 2, 0)
            handle.close()

    def run_zeek(self, zeek_logs_dir, pcap_or_interface, tcpdump_filter=None):
        """
        This thread sets the correct zeek parameters and starts zeek
        :kwarg tcpdump_filter: optional tcp filter to use when
        starting zeek with -f
        """
        command = self._construct_zeek_cmd(pcap_or_interface, tcpdump_filter)
        str_cmd = " ".join(command)
        self.print(f"Zeek command: {str_cmd}", 3, 0)

        zeek = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            cwd=zeek_logs_dir,
            start_new_session=True,
        )
        # you have to get the pid before communicate()
        self.zeek_pids.append(zeek.pid)

        out, error = zeek.communicate()
        if out:
            print(f"Zeek: {out}")
        if error:
            self.print(
                f"Zeek error. return code: {zeek.returncode} error:{error.strip()}"
            )

    def _construct_zeek_cmd(
        self, pcap_or_interface: str, tcpdump_filter=None
    ) -> List[str]:
        """
        constructs the zeek command based on the user given
        pcap/interface/packet filter/etc.
        """
        builder = ZeekCommandBuilder(
            zeek_or_bro=self.zeek_or_bro,
            input_type=self.input_type,
            rotation_period=self.rotation_period,
            enable_rotation=self.enable_rotation,
            tcp_inactivity_timeout=self.tcp_inactivity_timeout,
            packet_filter=self.packet_filter,
        )

        cmd = builder.build(pcap_or_interface, tcpdump_filter=tcpdump_filter)
        return cmd

    def check_if_time_to_del_rotated_files(self):
        """
        After a specific period (keep_rotated_files_for), slips deletes all rotated files
        Check if it's time to do so
        """
        if not hasattr(self, "time_rotated"):
            return False

        now = float(
            utils.convert_ts_format(datetime.datetime.now(), "unixtimestamp")
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

    def read_zeek_files(self) -> int:
        print("@@@@@@@@@@@@@@@@ inside read_zeek_files!!!!")
        lines = 0
        try:
            self.zeek_files: Dict[str, str] = self.db.get_all_zeek_files()
            self.open_file_handlers = {}
            # stores zeek_log_file_name: timestamp of the last flow read from
            # that file
            self.file_time = {}
            self.cache_lines = {}
            # Try to keep track of when was the last update so we stop this reading
            self.last_updated_file_time = datetime.datetime.now()

            while not self.input_proc.should_stop():
                self.check_if_time_to_del_rotated_files()
                # Go to all the files generated by Zeek and read 1
                # line from each of them
                for filename, interface in self.zeek_files.items():
                    if utils.is_ignored_zeek_log_file(filename):
                        continue

                    # reads 1 line from the given file and cache it
                    # from in self.cache_lines
                    self.cache_nxt_line_in_file(filename, interface)

                if self.reached_timeout():
                    break

                earliest_line, file_with_earliest_flow = (
                    self.get_earliest_line()
                )
                if not file_with_earliest_flow:
                    continue

                # self.print('	> Sent Line: {}'.format(earliest_line), 0, 3)

                self.give_profiler(earliest_line)
                lines += 1
                # when testing, no need to read the whole file!
                if lines == 10 and self.testing:
                    break
                # Delete this line from the cache and the time list
                del self.cache_lines[file_with_earliest_flow]
                del self.file_time[file_with_earliest_flow]

                # Get the new list of files. Since new files may have been created by
                # Zeek while we were processing them.
                self.zeek_files: Dict[str, str] = self.db.get_all_zeek_files()

            self.close_all_handles()
        except KeyboardInterrupt:
            pass

        return lines

    def read_zeek_folder(self, given_path):
        """
        This function runs when
        - a finite zeek dir is given to slips with -f
        - a growing zeek dir is given to slips with -g
        This func does not run when slips is running on an interface with
        -i or -ap
        """
        # wait max 10 seconds before stopping slips if no new flows are read
        self.bro_timeout = 10
        growing_zeek_dir: bool = self.db.is_growing_zeek_dir()
        if growing_zeek_dir:
            # slips is given a dir that is growing i.e zeek dir running on an
            # interface
            # don't stop zeek or slips
            self.bro_timeout = float("inf")

        self.zeek_dir = given_path
        # if slips is just reading a finite zeek dir, there's no way to
        # know the interface
        interface = "default"
        if self.args.growing:
            interface = self.args.interface

        self.observer = ZeekObserver(self.db)
        self.observer.start(self.zeek_dir, interface)

        # if 1 file is zeek tabs the rest should be the same
        if not hasattr(self, "is_zeek_tabs"):
            full_path = os.path.join(given_path, os.listdir(given_path)[0])
            self.is_zeek_tabs = self.is_zeek_tabs_file(full_path)

        total_flows = 0
        for file in os.listdir(given_path):
            full_path = os.path.join(given_path, file)

            # exclude ignored files from the total flows to be processed
            if utils.is_ignored_zeek_log_file(full_path):
                continue

            if not growing_zeek_dir:
                # get the total number of flows slips is going to read
                total_flows += self.get_flows_number(full_path)

            # Add log file to the database
            self.db.add_zeek_file(full_path, interface)

            # in testing mode, we only need to read one zeek file to know
            # that this function is working correctly
            if self.testing:
                break

        if total_flows == 0 and not growing_zeek_dir:
            # we're given an empty dir/ zeek logfile
            return True

        self.total_flows = total_flows
        self.db.set_input_metadata({"total_flows": total_flows})
        self.lines = self.read_zeek_files()
        return True
