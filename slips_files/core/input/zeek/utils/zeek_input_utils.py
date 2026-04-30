# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import datetime
import json
import os
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import List, Tuple
from re import split

from slips_files.common.slips_utils import utils
from slips_files.core.input.zeek.utils.dos_protector import DoSProtector
from slips_files.core.zeek_cmd_builder import ZeekCommandBuilder


class ZeekInputUtils:
    def __init__(self, input_process):
        self.input = input_process
        self.open_file_handles = {}
        self.open_file_handlers_lock = threading.RLock()
        self.cache_lines = {}
        self.file_time = {}
        self.last_updated_file_time = None
        self.rotated_files_to_delete: List[Tuple[str, float]] = []
        self.zeek_files = {}
        self.zeek_threads = []
        self.zeek_pids = []
        self.dos_protector = DoSProtector(self.input)
        self.args = self.input.args
        self.print = self.input.print
        self.update_msg_printed = False
        self.is_running_non_stop = self.input.db.is_running_non_stop()

    def check_if_time_to_del_rotated_files(self):
        """
        After a specific period (keep_rotated_files_for), slips deletes all rotated files
        Check if it's time to do so
        """
        if not self.rotated_files_to_delete:
            return False

        now = time.time()
        while self.rotated_files_to_delete:
            file, delete_after = self.rotated_files_to_delete.pop()
            if now < delete_after:
                # not time to del it yet
                break

            try:
                os.remove(file)
                self.input.print(
                    f"Done deleting rotated zeek file:" f" {file}.",
                    log_to_logfiles_only=True,
                )
            except FileNotFoundError:
                pass

    def schedule_rotated_file_deletion(
        self, file_path: str, rotated_at: float = None
    ):
        """
        Schedule a rotated Zeek logfile for deletion after the configured delay.

        :param file_path: Full path to the rotated logfile.
        :param rotated_at: Rotation timestamp as a unix timestamp.
        :return: None
        """
        if rotated_at is None:
            rotated_at = time.time()

        delete_after = rotated_at + self.input.keep_rotated_files_for
        self.rotated_files_to_delete.append((file_path, delete_after))

    def close_rotated_file_handle(self, filename: str):
        """
        closes the given file's handle and removes it from
        self.open_file_handlers

        :param filename: Full path to the active logfile name.
        """
        with self.open_file_handlers_lock:
            file_handler = self.open_file_handles.pop(filename, None)

        if file_handler is not None:
            file_handler.close()

    def get_file_handle(self, filename: str):
        with self.open_file_handlers_lock:
            file_handle = self.open_file_handles.get(filename)

            if file_handle:
                return file_handle

            try:
                # First time opening this file.
                file_handle = open(filename, "r")
                self.open_file_handles[filename] = file_handle
                # now that we replaced the old handle with the newly created file handle
                # delete the old .log file, that has a timestamp in its name.
            except FileNotFoundError:
                # for example dns.log
                # zeek changes the dns.log file name every 1d, it adds a
                # timestamp to it, it doesn't create the new dns.log until a
                # new dns request
                # occurs
                # if slips tries to read from the old dns.log now it won't
                # find it because it's been renamed and the new one isn't
                # created yet simply continue until the new log file is
                # created and added to the zeek_files list
                return False
        return file_handle

    def get_ts_from_line(self, zeek_line: str):
        """
        used only by zeek log files
        :param line: can be a json or a json serialized dict
        """
        if self.input.is_zeek_tabs:
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

    def cache_nxt_line_in_file(self, filename: str, interface: str):
        """
        reads 1 line of the given file and stores in queue for sending to the
        profiler

        :param filename: full path to the file. includes the .log extension
        :param interface: interface that generated the Zeek file
        :return: True if a line was cached, False otherwise
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
            flows_to_skip_reading_if_under_heavy_load: int = (
                self.dos_protector.get_number_of_flows_to_skip()
            )

            # skips flows
            for _ in range(flows_to_skip_reading_if_under_heavy_load):
                file_handle.readline()

            while zeek_line := file_handle.readline():
                if zeek_line.startswith("#close"):
                    # We reached the end of one of the files that we were
                    # reading.
                    return False

                if zeek_line.startswith("#fields"):
                    # this line contains the zeek fields, we want to cache it
                    # and send it to the profiler normally
                    nline = zeek_line
                    # to send the line as early as possible
                    timestamp = -1
                    break

                timestamp, nline = self.get_ts_from_line(zeek_line)
                if timestamp:
                    break
            else:
                # We reached the end of one of the files that we were reading.
                # Wait for more lines to come from another file.
                return False

        except ValueError:
            # remover thread just finished closing all old handles.
            # comes here if I/O operation failed due to a closed file.
            # to get the new dict of open handles.
            return False

        self.file_time[filename] = timestamp
        # Store the line in the cache
        self.cache_lines[filename] = {
            "type": filename,
            "data": nline,
            "interface": interface,
        }
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
            if diff >= self.input.bro_timeout:
                # It has been <bro_timeout> seconds without any file
                # being updated. So stop Zeek
                return True
        return False

    def close_all_handles(self):
        # We reach here after the break that happens
        # if no zeek files are being updated.
        # No more files to read. Close the files
        with self.open_file_handlers_lock:
            handles = list(self.open_file_handles.items())
            self.open_file_handles = {}

            for file, handle in handles:
                self.input.print(f"Closing file {file}", 2, 0)
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
            self.zeek_files = self.input.db.get_all_zeek_files()
            return False, False

        # comes here if we're done with all conn.log flows and it's time to
        # process other files
        earliest_line = self.cache_lines[file_with_earliest_flow]
        return earliest_line, file_with_earliest_flow

    def _print_update_msg(self):
        if not self.update_msg_printed:
            self.print(
                "Slips is live updating. Slips will stop receiving new "
                "flows in this instance and start receiving new flows using "
                "the updated version. "
            )
            self.update_msg_printed = True

    def read_zeek_files(self) -> int:
        """
        Runs when slips is analyzing pcaps, interface, zeek dirs, and zeek
        log files
        """
        try:
            self.zeek_files = self.input.db.get_all_zeek_files()
            self.open_file_handles = {}
            # stores zeek_log_file_name: timestamp of the last flow read from
            # that file
            self.file_time = {}
            self.cache_lines = {}
            # Try to keep track of when was the last update so we stop this
            # reading
            self.last_updated_file_time = datetime.datetime.now()
            is_draining = False
            while True:
                is_live_updating = (
                    self.input.is_slips_live_updating_event is not None
                    and self.input.is_slips_live_updating_event.is_set()
                )
                if is_live_updating and not is_draining:
                    # Stop Zeek first so this instance has a finite set of
                    # generated logs to drain before the updated instance
                    # continues.
                    self._print_update_msg()
                    self.shutdown_zeek_runtime()
                    self.zeek_files = self.input.db.get_all_zeek_files()
                    is_draining = True

                if self.input.should_stop() and not is_draining:
                    break

                self.check_if_time_to_del_rotated_files()

                # implemented in icore.py
                self.input.store_flows_read_per_second()

                # Go to all the files generated by Zeek and read 1
                # line from each of them

                # PS: self.zeek_files ties each zeek file to its interface (
                # beacause slips supports reading multiple interfaces)

                if is_draining:
                    self.zeek_files = self.input.db.get_all_zeek_files()

                cached_new_line = False
                for filename, interface in self.zeek_files.items():
                    if utils.is_ignored_zeek_log_file(filename):
                        continue

                    # reads 1 line from the given file and cache it
                    # from in self.cache_lines
                    if self.cache_nxt_line_in_file(filename, interface):
                        self.last_updated_file_time = datetime.datetime.now()
                        cached_new_line = True

                if (
                    is_draining
                    and not cached_new_line
                    and not self.cache_lines
                ):
                    # done draining the flows left
                    break

                if self.reached_timeout():
                    break

                earliest_line, file_with_earliest_flow = (
                    self.get_earliest_line()
                )
                if not file_with_earliest_flow:
                    continue

                # self.print('\t> Sent Line: {}'.format(earliest_line), 0, 3)
                self.input.give_profiler(earliest_line)
                self.input.lines += 1

                # when testing, no need to read the whole file! #TODO this
                #  is bad practice, fix it
                if self.input.lines == 10 and self.input.testing:
                    break

                # Delete this line from the cache and the time list
                del self.cache_lines[file_with_earliest_flow]
                del self.file_time[file_with_earliest_flow]

                # Get the new list of files. Since new files may have been
                # created by Zeek while we were processing them.
                self.zeek_files = self.input.db.get_all_zeek_files()
            self.close_all_handles()
        except KeyboardInterrupt:
            pass

        return self.input.lines

    def _is_auto_update_enabled(self) -> bool:
        """
        returns true if slips is analyzing an interface (-i , -ap or -g)
        and auto_update is enabled in slips.yaml
        """
        return self.is_running_non_stop and self.input.conf.auto_update_slips()

    def create_zeek_output_dir(self) -> str:
        """
        Return the Zeek output directory, create it if needed,
        and store its path in the DB.

        :return: Directory where Zeek should write log files.
        """

        without_ext = Path(self.input.given_path).stem
        if self.input.conf.store_zeek_files_in_the_output_dir():
            zeek_dir = Path(self.input.args.output) / "zeek_files"
        else:
            zeek_dir = Path(f"zeek_files_{without_ext}")

        if self._is_auto_update_enabled():
            # slips is gonna be auto updating for each new version, we need
            # 1 zeek dir for each started version
            zeek_dir = Path(zeek_dir) / f"slips_v{utils.get_current_version()}"

        zeek_dir = str(zeek_dir)

        Path(zeek_dir).mkdir(parents=True, exist_ok=True)
        self.input.db.set_input_metadata({"zeek_dir": zeek_dir})
        return zeek_dir

    def init_zeek(
        self,
        observer,
        zeek_dir: str,
        pcap_or_interface: str,
        tcpdump_filter=None,
    ):
        """
        :param pcap_or_interface: name of the pcap or interface zeek
        is going to run on

        PS: this function contains a call to self.run_zeek that
        keeps running until slips stops
        """
        observer.start(zeek_dir, pcap_or_interface)

        zeek_files = os.listdir(zeek_dir)
        if len(zeek_files) > 0 and not self.args.is_slips_started_by_an_update:
            # First clear the zeek folder of old .log files
            for file_name in zeek_files:
                os.remove(os.path.join(zeek_dir, file_name))

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

        if self.zeek_pids:
            self.input.db.store_pid(
                f"Zeek_{pcap_or_interface}", self.zeek_pids[-1]
            )
        if not hasattr(self.input, "is_zeek_tabs"):
            self.input.is_zeek_tabs = False

    def _construct_zeek_cmd(self, pcap_or_interface: str, tcpdump_filter=None):
        """
        constructs the zeek command based on the user given
        pcap/interface/packet filter/etc.
        """
        builder = ZeekCommandBuilder(
            zeek_or_bro=self.input.zeek_or_bro,
            input_type=self.input.input_type,
            default_rotation_interval=self.input.default_rotation_interval,
            enable_rotation=self.input.enable_rotation,
            tcp_inactivity_timeout=self.input.tcp_inactivity_timeout,
            packet_filter=self.input.packet_filter,
        )

        cmd = builder.build(pcap_or_interface, tcpdump_filter=tcpdump_filter)
        return cmd

    def run_zeek(self, zeek_logs_dir, pcap_or_interface, tcpdump_filter=None):
        """
        This thread sets the correct zeek parameters and starts zeek
        :kwarg tcpdump_filter: optional tcp filter to use when
        starting zeek with -f
        """
        command = self._construct_zeek_cmd(pcap_or_interface, tcpdump_filter)
        str_cmd = " ".join(command)
        self.input.print(f"Zeek command: {str_cmd}", 3, 0)

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
            self.input.print(
                f"Zeek error. return code: {zeek.returncode} "
                f"error:{error.strip()}"
            )

    def shutdown_zeek_runtime(self):
        try:
            for zeek_thread in self.zeek_threads:
                zeek_thread.join(3)
        except Exception:
            pass

        for pid in self.zeek_pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass

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
