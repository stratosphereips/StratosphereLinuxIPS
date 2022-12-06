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
from slips_files.common.slips_utils import utils
from slips_files.common.config_parser import ConfigParser
import multiprocessing
import sys
import os
from datetime import datetime
from watchdog.observers import Observer
from .filemonitor import FileEventHandler
from slips_files.core.database.database import __database__
import time
import json
import traceback
import threading
import subprocess
import signal


# Input Process
class InputProcess(multiprocessing.Process):
    """A class process to run the process of the flows"""

    def __init__(
            self,
            outputqueue,
            profilerqueue,
            input_type,
            input_information,
            cli_packet_filter,
            zeek_or_bro,
            zeek_folder,
            line_type,
            redis_port,
    ):
        multiprocessing.Process.__init__(self)
        self.name = 'Input'
        self.outputqueue = outputqueue
        self.profilerqueue = profilerqueue
        __database__.start(redis_port)
        self.redis_port = redis_port
        self.input_type = input_type
        # in case of reading from stdin, the user mst tell slips what type of lines is the input
        self.line_type = line_type
        # entire path
        self.given_path = input_information
        # filename only
        self.zeek_folder = zeek_folder
        self.zeek_or_bro = zeek_or_bro
        self.read_lines_delay = 0

        self.packet_filter = False
        if cli_packet_filter:
            self.packet_filter = "'" + cli_packet_filter + "'"

        self.read_configuration()
        self.event_observer = None
        # set to true in unit tests
        self.testing = False
        # number of lines read
        self.lines = 0
        self.marked_as_growing = False
        # these are the files that slips doesn't read
        self.ignored_files = {
            'capture_loss',
            'loaded_scripts',
            'packet_filter',
            'stats',
            'ocsp',
            'reporter',
            'x509',
        }
        # create the remover thread
        self.remover_thread = threading.Thread(
            target=self.remove_old_zeek_files, daemon=True
        )
        self.open_file_handlers = {}
        self.c1 = __database__.subscribe('remove_old_files')
        self.timeout = None
        # zeek rotated files to be deleted after a period of time
        self.to_be_deleted = []
        self.zeek_thread = threading.Thread(
            target=self.run_zeek,
            daemon=True
        )

    def read_configuration(self):
        conf = ConfigParser()
        # If we were given something from command line, has preference
        # over the configuration file
        self.packet_filter = self.packet_filter or conf.packet_filter()
        self.tcp_inactivity_timeout = conf.tcp_inactivity_timeout()
        self.enable_rotation = conf.rotation()
        self.rotation_period = conf.rotation_period()
        self.keep_rotated_files_for = conf.keep_rotated_files_for()

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
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
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        self.outputqueue.put(f'{levels}|{self.name}|{text}')

    def stop_queues(self):
        """Stops the profiler and output queues"""
        self.profilerqueue.put('stop')
        now = utils.convert_format(datetime.now(), utils.alerts_format)
        self.outputqueue.put(
            '02|input|[In] No more input. Stopping input process. Sent {} lines ({}).\n'.format(
                self.lines, now
            )
        )
        self.outputqueue.close()
        self.profilerqueue.close()

    def read_nfdump_output(self) -> int:
        try:
            """
            A binary file generated by nfcapd can be read by nfdump.
            The task for this function is to send nfdump output line by line to profilerProcess.py for processing
            """

            line = {'type': 'nfdump'}
            if not self.nfdump_output:
                # The nfdump command returned nothing
                self.print('Error reading nfdump output ', 1, 3)
            else:
                lines = len(self.nfdump_output.splitlines())
                for nfdump_line in self.nfdump_output.splitlines():
                    # this line is taken from stdout we need to remove whitespaces
                    nfdump_line.replace(' ', '')
                    ts = nfdump_line.split(',')[0]
                    if not ts[0].isdigit():
                        # The first letter is not digit -> not valid line.
                        # TODO: What is this valid line check?? explain
                        continue
                    line['data'] = nfdump_line
                    self.profilerqueue.put(line)
                    if self.testing: break

            return lines
        except KeyboardInterrupt:
            return True

    def check_if_time_to_del_rotated_files(self):
        """
        After a specific period (keep_rotated_files_for), slips deletes all rotated files
        Check if it's time to do so
        """
        if not hasattr(self, 'time_rotated'):
            return False

        now = float(utils.convert_format(datetime.now(), 'unixtimestamp'))
        time_to_delete = now >= self.time_rotated + self.keep_rotated_files_for

        if time_to_delete:
            for file in self.to_be_deleted:
                try:
                    os.remove(file)
                except FileNotFoundError:
                    pass
            self.to_be_deleted = []

    def read_zeek_files(self) -> int:
        try:
            # Get the zeek files in the folder now
            zeek_files = __database__.get_all_zeek_file()
            self.open_file_handlers = {}
            file_time = {}
            cache_lines = {}
            # Try to keep track of when was the last update so we stop this reading
            last_updated_file_time = datetime.now()
            lines = 0
            while True:
                self.check_if_time_to_del_rotated_files()
                # Go to all the files generated by Zeek and read them
                for filename in zeek_files:
                    # filename is the log file name with .log extension in case of interface or pcap
                    # and without the ext in case of zeek files
                    if not filename.endswith('.log'):
                        filename += '.log'
                    # Ignore the files that do not contain data. These are the zeek log files that we don't use
                    filename_without_ext = filename.split('/')[-1].split('.')[
                        0
                    ]
                    if filename_without_ext in self.ignored_files:
                        continue

                    # Update which files we know about
                    try:
                        # We already opened this file
                        file_handler = self.open_file_handlers[filename]
                    except KeyError:
                        # First time opening this file.
                        try:
                            file_handler = open(filename, 'r')
                            lock = threading.Lock()
                            lock.acquire()
                            self.open_file_handlers[filename] = file_handler
                            lock.release()
                            # now that we replaced the old handle with the newly created file handle
                            # delete the old .log file, that has a timestamp in its name.
                        except FileNotFoundError:
                            # for example dns.log
                            # zeek changes the dns.log file name every 1d, it adds a timestamp to it
                            # it doesn't create the new dns.log until a new dns request occurs
                            # if slips tries to read from the old dns.log now it won't find it
                            # because it's been renamed and the new one isn't created yet
                            # simply continue until the new log file is created and added to the zeek_files list
                            continue

                    # Only read the next line if the previous line was sent
                    try:
                        _ = cache_lines[filename]
                        # We have still something to send, do not read the next line from this file
                    except KeyError:
                        # We don't have any waiting line for this file, so proceed
                        try:
                            zeek_line = file_handler.readline()
                        except ValueError:
                            # remover thread just finished closing all old handles.
                            # comes here if I/O operation failed due to a closed file.
                            # to get the new dict of open handles.
                            continue

                        # self.print(f'Reading from file {filename}, the line {zeek_line}', 0, 6)
                        # Did the file end?
                        if not zeek_line:
                            # We reached the end of one of the files that we were reading. Wait for more data to come
                            continue

                        # Since we actually read something form any file, update the last time of read
                        last_updated_file_time = datetime.now()
                        try:
                            nline = json.loads(zeek_line)
                            line = {'type': filename, 'data': nline}

                            # All bro files have a field 'ts' with the timestamp.
                            # So we are safe here not checking the type of line
                            # In some Zeek files there may not be a ts field
                            # Like in some weird smb files
                            timestamp = nline.get('ts', 0)

                        except json.decoder.JSONDecodeError:
                            # It is not JSON format. It is tab format line.
                            nline = zeek_line
                            # Ignore comments at the beginning of the file.
                            if not nline or nline[0] == '#':
                                continue

                            line = {'type': filename, 'data': nline}
                            timestamp = nline.split('\t')[0]

                        try:

                            # is a dict with {'filename': ts, ...}
                            file_time[filename] = float(timestamp)
                            # self.print(f'File {filename}. TS: {timestamp}')
                            # Store the line in the cache
                            # self.print(f'Adding cache and time of {filename}')
                            cache_lines[filename] = line
                        except ValueError:
                            # this ts doesnt repr a float value, ignore it
                            pass


                ###################################################################################
                # Out of the for that check each Zeek file one by one
                # self.print('Cached lines: {}'.format(str(cache_lines)))

                # If we don't have any cached lines to send, it may mean that new lines are not arriving. Check
                if not cache_lines:
                    # Verify that we didn't have any new lines in the
                    # last 10 seconds. Seems enough for any network to have ANY traffic
                    diff = utils.get_time_diff(last_updated_file_time, datetime.now())
                    if diff >= self.bro_timeout:
                        # It has been <bro_timeout> seconds without any file
                        # being updated. So stop Zeek
                        break

                # Now read lines in order. The line with the smallest timestamp first
                files_sorted_by_ts = sorted(file_time, key=file_time.get)
                # self.print('Sorted times: {}'.format(str(files_sorted_by_ts)))
                try:
                    # get the file that has the earliest flow
                    file_with_earliest_flow = files_sorted_by_ts[0]
                except IndexError:
                    # No more sorted keys. Just loop waiting for more lines
                    # It may happen that we check all the files in the folder, and there is still no file for us.
                    # To cover this case, just refresh the list of files
                    zeek_files = __database__.get_all_zeek_file()
                    time.sleep(1)
                    continue

                # to fix the problem of evidence being generated BEFORE their corresponding flows are added to our db
                # make sure we read flows in the following order:
                # dns.log  (make it a priority to avoid FP connection without dns resolution alerts)
                # conn.log
                # any other flow
                # for key in cache_lines:
                #     if 'dns' in key:
                #         file_with_earliest_flow = key
                #         break
                # comes here if we're done with all conn.log flows and it's time to process other files
                line_to_send = cache_lines[file_with_earliest_flow]

                # self.print('Line to send from file {}. {}'.format(file_with_earliest_flow, line_to_send))
                self.print('	> Sent Line: {}'.format(line_to_send), 0, 3)
                self.profilerqueue.put(line_to_send)
                # Count the read lines
                lines += 1
                # Delete this line from the cache and the time list
                # self.print('Deleting cache and time of {}'.format(earliest_flow))
                del cache_lines[file_with_earliest_flow]
                del file_time[file_with_earliest_flow]
                # Get the new list of files. Since new files may have been created by Zeek while we were processing them.
                zeek_files = __database__.get_all_zeek_file()

            ################
            # Out of the while

            # We reach here after the break produced if no zeek files are being updated.
            # No more files to read. Close the files
            for file, handle in self.open_file_handlers.items():
                self.print(f'Closing file {file}', 2, 0)
                handle.close()
            return lines
        except KeyboardInterrupt:
            return False

    def read_zeek_folder(self):
        # This is the case that a folder full of zeek files is passed with -f
        try:
            # wait max 3 seconds before stopping slips if no new flows are read
            self.bro_timeout = 3
            if __database__.is_growing_zeek_dir():
                # slips is given a dir that is growing i.e zeek dir running on an interface
                # don't stop zeek or slips
                self.bro_timeout = float('inf')


            self.zeek_folder = self.given_path
            self.start_observer()

            for file in os.listdir(self.given_path):
                # Remove .log extension and add file name to database.
                extension = file[-4:]
                if extension == '.log':
                    # Add log file to database
                    file_name_without_extension = file[:-4]
                    __database__.add_zeek_file(
                        f'{self.given_path}/{file_name_without_extension}'
                    )
                # in testing mode, we only need to read one zeek file to know
                # that this function is working correctly
                if self.testing: break

            lines = self.read_zeek_files()

            self.print(
                f'\nWe read everything from the folder.'
                f' No more input. Stopping input process. Sent {lines} lines', 2, 0,
            )
            self.stop_queues()
            return True
        except KeyboardInterrupt:
            return False

    def read_from_stdin(self):
        self.print('Receiving flows from stdin.')
        # By default read the stdin
        sys.stdin.close()
        sys.stdin = os.fdopen(0, 'r')
        file_stream = sys.stdin
        # tell profilerprocess the type of line the user gave slips
        line_info = {
            'type': 'stdin',
            'line_type': self.line_type
        }
        for line in file_stream:
            if line == '\n':
                continue

            # slips supports zeek json only, tabs arent supported
            if self.line_type == 'zeek':
                try:
                    line = json.loads(line)
                except json.decoder.JSONDecodeError:
                    self.print(f'Invalid json line')
                    continue

            line_info['data'] = line
            self.print(f'	> Sent Line: {line_info}', 0, 3)
            self.profilerqueue.put(line_info)
            self.lines += 1
            self.print('Done reading 1 flow.\n ', 0, 3)

        self.stop_queues()
        return True

    def handle_binetflow(self):
        try:
            self.lines = 0
            self.read_lines_delay = 0.02
            with open(self.given_path) as file_stream:
                line = {'type': 'argus'}
                # fake = {'type': 'argus', 'data': 'StartTime,Dur,Proto,SrcAddr,Sport,
                # Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,SrcPkts,Label\n'}
                # self.profilerqueue.put(fake)

                # read first line to determine the type of line, tab or comma separated
                t_line = file_stream.readline()
                if '\t' in t_line:
                    # this is the header line
                    line['type'] = 'argus-tabs'
                line['data'] = t_line
                self.profilerqueue.put(line)
                self.lines += 1

                # go through the rest of the file
                for t_line in file_stream:
                    time.sleep(self.read_lines_delay)
                    line['data'] = t_line
                    # argus files are either tab separated orr comma separated
                    if len(t_line.strip()) != 0:
                        self.profilerqueue.put(line)
                    self.lines += 1
                    if self.testing: break
            self.stop_queues()
            return True
        except KeyboardInterrupt:
            return True

    def handle_suricata(self):
        try:
            with open(self.given_path) as file_stream:
                line = {'type': 'suricata'}
                self.read_lines_delay = 0.02
                for t_line in file_stream:
                    time.sleep(self.read_lines_delay)
                    line['data'] = t_line
                    self.print(f'	> Sent Line: {line}', 0, 3)
                    if len(t_line.strip()) != 0:
                        self.profilerqueue.put(line)
                    self.lines += 1
                    if self.testing: break
            self.stop_queues()
            return True
        except KeyboardInterrupt:
            return True

    def handle_zeek_log_file(self):
        try:
            try:
                file_name_without_extension = self.given_path[: self.given_path.index('.log')]
            except IndexError:
                # filename doesn't have an extension, probably not a conn.log
                return False
            # Add log file to database
            __database__.add_zeek_file(file_name_without_extension)
            self.bro_timeout = 3
            self.lines = self.read_zeek_files()
            self.stop_queues()
            return True
        except KeyboardInterrupt:
            return True

    def handle_nfdump(self):
        try:
            command = f'nfdump -b -N -o csv -q -r {self.given_path}'
            # Execute command
            result = subprocess.run(command.split(), stdout=subprocess.PIPE)
            # Get command output
            self.nfdump_output = result.stdout.decode('utf-8')
            self.lines = self.read_nfdump_output()
            self.print(
                f'We read everything. No more input. Stopping input process. Sent {self.lines} lines'
            )
            return True
        except KeyboardInterrupt:
            return True


    def start_observer(self):
        # Now start the observer of new files. We need the observer because Zeek does not create all the files
        # at once, but when the traffic appears. That means that we need
        # some process to tell us which files to read in real time when they appear
        # Get the file eventhandler
        # We have to set event_handler and event_observer before running zeek.
        event_handler = FileEventHandler(self.redis_port, self.zeek_folder, self.input_type)
        # Create an observer
        self.event_observer = Observer()
        # Schedule the observer with the callback on the file handler
        self.event_observer.schedule(
            event_handler, self.zeek_folder, recursive=True
        )
        # Start the observer
        self.event_observer.start()

    def handle_pcap_and_interface(self) -> int:
        """Returns the number of zeek lines read"""

        try:
            # Create zeek_folder if does not exist.
            if not os.path.exists(self.zeek_folder):
                os.makedirs(self.zeek_folder)
            self.print(f'Storing zeek log files in {self.zeek_folder}')
            self.start_observer()

            if self.input_type == 'interface':
                # We don't want to stop bro if we read from an interface
                self.bro_timeout = float('inf')
            elif self.input_type == 'pcap':
                # This is for stopping the inputprocess
                # if bro does not receive any new line while reading a pcap
                self.bro_timeout = 30

            zeek_files = os.listdir(self.zeek_folder)
            if len(zeek_files) > 0:
                # First clear the zeek folder of old .log files
                for f in zeek_files:
                    os.remove(os.path.join(self.zeek_folder, f))

            # run zeek
            self.zeek_thread.start()
            # Give Zeek some time to generate at least 1 file.
            time.sleep(3)

            __database__.store_process_PID('Zeek', self.zeek_pid)
            lines = self.read_zeek_files()
            self.print(
                f'We read everything. No more input. Stopping input process. Sent {lines} lines'
            )

            self.stop_observer()
            return True
        except KeyboardInterrupt:
            return False

    def stop_observer(self):
        # Stop the observer
        try:
            self.event_observer.stop()
            self.event_observer.join()
        except AttributeError:
            # In the case of nfdump, there is no observer
            pass

    def remove_old_zeek_files(self):
        """
        This thread waits for filemonitor.py to tell it that zeek changed the files,
        it deletes old zeek-date.log files and clears slips' open handles and sleeps again
        """
        while True:
            # keep the rotated files for the period specified in slips.conf
            msg = __database__.get_message(self.c1)
            if msg and msg['data'] == 'stop_process':
                return True
            if utils.is_msg_intended_for(msg, 'remove_old_files'):


                # this channel receives renamed zeek log files, we can safely delete them and close their handle
                changed_files = json.loads(msg['data'])

                # for example the old log file should be  ./zeek_files/dns.2022-05-11-14-43-20.log
                # new log file should be dns.log without the ts
                old_log_file = changed_files['old_file']
                new_log_file = changed_files['new_file']
                new_logfile_without_path = new_log_file.split('/')[-1].split(
                    '.'
                )[0]
                # ignored files have no open handle, so we should only delete them from disk
                if new_logfile_without_path in self.ignored_files:
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
                self.time_rotated = float(utils.convert_format(datetime.now(), 'unixtimestamp'))
                # os.remove(old_log_file)
                lock.release()

    def shutdown_gracefully(self):
        self.stop_observer()

        if hasattr(self, 'zeek_pid'):
            __database__.publish('finished_modules', 'Zeek')

        __database__.publish('finished_modules', self.name)

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
        if self.input_type == 'interface':
            if self.enable_rotation:
                # how often to rotate zeek files? taken from slips.conf
                rotation = ['-e', f"redef Log::default_rotation_interval = {self.rotation_period} ;"]
            bro_parameter = f'-i {self.given_path}'

        elif self.input_type == 'pcap':
            # Find if the pcap file name was absolute or relative
            given_path = self.given_path
            if not os.path.isabs(self.given_path):
                # move 1 dir back since we will move into zeek_Files dir
                given_path = os.path.join('..', self.given_path)
            bro_parameter = f'-r {given_path}'


        # Run zeek on the pcap or interface. The redef is to have json files
        zeek_scripts_dir = os.path.join(os.getcwd(), 'zeek-scripts')
        packet_filter = ['-f ', self.packet_filter] if self.packet_filter else []

        # 'local' is removed from the command because it
        # loads policy/protocols/ssl/expiring-certs and
        # and policy/protocols/ssl/validate-certs and they have conflicts with our own
        # zeek-scripts/expiring-certs and validate-certs
        # we have our own copy pf local.zeek in __load__.zeek
        command = [self.zeek_or_bro, '-C']
        command += bro_parameter.split()
        command += [
            f'tcp_inactivity_timeout={self.tcp_inactivity_timeout}mins',
            'tcp_attempt_delay=1min',
            zeek_scripts_dir
        ]
        command += rotation
        command += packet_filter
        self.print(f'Zeek command: {" ".join(command)}', 3, 0)

        zeek = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            cwd=self.zeek_folder,
            preexec_fn=detach_child
        )

        # you have to get the pid before communicate()
        self.zeek_pid = zeek.pid

        out, error = zeek.communicate()
        if out:
            print(f"Zeek: {out}")
        if error:
            self.print (f"Zeek error {zeek.returncode}: {error.strip()}")


    def run(self):
        utils.drop_root_privs()
        # this thread should be started from run() to get the PID of inputprocess and have shared variables
        # if it started from __init__() it will have the PID of slips.py therefore,
        # any changes made to the shared variables in inputprocess will not appear in the thread
        running_on_interface = '-i' in sys.argv or __database__.is_growing_zeek_dir()
        if running_on_interface:
            # delete old zeek-date.log files
            self.remover_thread.start()

        try:
            # Process the file that was given
            # If the type of file is 'file (-f) and the name of the file is '-' then read from stdin
            if self.input_type == 'stdin':
                self.read_from_stdin()
            elif self.input_type == 'zeek_folder':
                # is a zeek folder
                self.read_zeek_folder()
            elif self.input_type == 'zeek_log_file':
                # Is a zeek.log file
                file_name = self.given_path.split('/')[-1]
                if 'log' in file_name:
                    self.handle_zeek_log_file()
                else:
                    return False
            elif self.input_type == 'nfdump':
                # binary nfdump file
                self.handle_nfdump()
            elif self.input_type == 'binetflow' or 'binetflow-tabs' in self.input_type:
                # argus or binetflow
                self.handle_binetflow()
            elif self.input_type in ['pcap', 'interface']:
                self.handle_pcap_and_interface()
            elif self.input_type == 'suricata':
                self.handle_suricata()
            else:
                # if self.input_type is 'file':
                # default value
                self.print(
                    f'Unrecognized file type "{self.input_type}". Stopping.'
                )
                return False
            self.shutdown_gracefully()

            # keep the module idle until slips.py kills it
            # without this, the module exits but the pid will remain in memory as <defunct>
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.shutdown_gracefully()
            return False
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f'Problem with Input Process. line {exception_line}', 0, 1
            )
            self.print(
                f'Stopping input process. Sent {self.lines} lines', 0, 1
            )
            self.print(type(inst), 0, 1)
            self.print(inst.args, 0, 1)
            self.print(inst, 0, 1)
            self.print(traceback.format_exc(), 0, 1)
            self.shutdown_gracefully()
            return False
