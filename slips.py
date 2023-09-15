#!/usr/bin/env python3
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

import contextlib
import multiprocessing
from slips_files.common.imports import *
from slips_files.common.cpu_profiler import CPUProfiler
from slips_files.common.memory_profiler import MemoryProfiler
from exclusiveprocess import Lock, CannotAcquireLock
from redis_manager import RedisManager
from metadata_manager import MetadataManager
from process_manager import ProcessManager
from ui_manager import UIManager
from checker import Checker
from style import green


from slips_files.core.inputProcess import InputProcess
from slips_files.core.outputProcess import OutputProcess
from slips_files.core.profilerProcess import ProfilerProcess
from slips_files.core.evidenceProcess import EvidenceProcess
from slips_files.core.database.database_manager import DBManager


import signal
import sys
import os
import time
import shutil
import warnings
import json
import subprocess
import re
from datetime import datetime
from distutils.dir_util import copy_tree
from daemon import Daemon
from multiprocessing import Queue



# Ignore warnings on CPU from tensorflow
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
# Ignore warnings in general
warnings.filterwarnings('ignore')
# ---------------------


class Main:
    def __init__(self, testing=False):
        self.name = 'Main'
        self.alerts_default_path = 'output/'
        self.mode = 'interactive'
        # objects to manage various functionality
        self.redis_man = RedisManager(self)
        self.ui_man = UIManager(self)
        self.metadata_man = MetadataManager(self)
        self.proc_man = ProcessManager(self)
        self.checker = Checker(self)
        self.conf = ConfigParser()
        self.version = self.get_slips_version()
        # will be filled later
        self.commit = 'None'
        self.branch = 'None'
        # in testing mode we manually set the following params
        if not testing:
            self.args = self.conf.get_args()
            self.pid = os.getpid()
            self.checker.check_given_flags()
            if not self.args.stopdaemon:
                # Check the type of input
                self.input_type, self.input_information, self.line_type = self.checker.check_input_type()
                # If we need zeek (bro), test if we can run it.
                self.check_zeek_or_bro()
                self.prepare_output_dir()
                # this is the zeek dir slips will be using
                self.prepare_zeek_output_dir()
                self.twid_width = self.conf.get_tw_width()

    def cpu_profiler_init(self):
        self.cpuProfilerEnabled = slips.conf.get_cpu_profiler_enable() == 'yes'
        self.cpuProfilerMode = slips.conf.get_cpu_profiler_mode()
        self.cpuProfilerMultiprocess = slips.conf.get_cpu_profiler_multiprocess() == 'yes'
        if self.cpuProfilerEnabled:
            try:
                if (self.cpuProfilerMultiprocess and self.cpuProfilerMode == "dev"):
                    args = sys.argv
                    if (args[-1] != "--no-recurse"):
                        tracer_entries = str(slips.conf.get_cpu_profiler_dev_mode_entries())
                        viz_args = ['viztracer', '--tracer_entries', tracer_entries, '--max_stack_depth', '10', '-o', str(os.path.join(self.args.output, 'cpu_profiling_result.json'))]
                        viz_args.extend(args)
                        viz_args.append("--no-recurse")
                        print("Starting multiprocess profiling recursive subprocess")
                        subprocess.run(viz_args)
                        exit(0)
                else:
                    self.cpuProfiler = CPUProfiler(
                        db=self.db,
                        output=self.args.output,
                        mode=slips.conf.get_cpu_profiler_mode(),
                        limit=slips.conf.get_cpu_profiler_output_limit(),
                        interval=slips.conf.get_cpu_profiler_sampling_interval()
                        )
                    self.cpuProfiler.start()
            except Exception as e:
                print(e)
                self.cpuProfilerEnabled = False
    
    def cpu_profiler_release(self):
        if hasattr(self, 'cpuProfilerEnabled' ):
            if self.cpuProfilerEnabled and not self.cpuProfilerMultiprocess:
                self.cpuProfiler.stop()
                self.cpuProfiler.print()
    
    def memory_profiler_init(self):
        self.memoryProfilerEnabled = slips.conf.get_memory_profiler_enable() == "yes"
        memoryProfilerMode = slips.conf.get_memory_profiler_mode()
        memoryProfilerMultiprocess = slips.conf.get_memory_profiler_multiprocess() == "yes"
        if self.memoryProfilerEnabled:
            output_dir = os.path.join(slips.args.output,'memoryprofile/')
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            output_file = os.path.join(output_dir, 'memory_profile.bin')
            self.memoryProfiler = MemoryProfiler(output_file, db=self.db, mode=memoryProfilerMode, multiprocess=memoryProfilerMultiprocess)
            self.memoryProfiler.start()
    
    def memory_profiler_release(self):
        if self.memoryProfilerEnabled:
            self.memoryProfiler.stop()
    
    def memory_profiler_multiproc_test(self):
        def target_function():
            print("Target function started")
            time.sleep(5)

        def mem_function():
            print("Mem function started")
            while True:
                time.sleep(1)
                array = []
                for i in range(1000000):
                    array.append(i)
        processes = []
        num_processes = 3
        
        for _ in range(num_processes):
            process = multiprocessing.Process(target=target_function if _%2 else mem_function)
            process.start()
            processes.append(process)
        
        # Message passing
        self.db.publish("memory_profile", processes[1].pid) # successful
        # subprocess.Popen(["memray", "live", "1234"])
        time.sleep(5) # target_function will timeout and tracker will be cleared
        self.db.publish("memory_profile", processes[0].pid) # end but maybe don't start
        time.sleep(5) # mem_function will get tracker started
        self.db.publish("memory_profile", processes[0].pid) # start successfully
        input()

    def get_slips_version(self):
        version_file = 'VERSION'
        with open(version_file, 'r') as f:
            version = f.read()
        return version

    def check_zeek_or_bro(self):
        """
        Check if we have zeek or bro
        """
        self.zeek_bro = None
        if self.input_type not in ('pcap', 'interface'):
            return False

        if shutil.which('zeek'):
            self.zeek_bro = 'zeek'
        elif shutil.which('bro'):
            self.zeek_bro = 'bro'
        else:
            print('Error. No zeek or bro binary found.')
            self.terminate_slips()
            return False

        return self.zeek_bro

    def prepare_zeek_output_dir(self):
        from pathlib import Path
        without_ext = Path(self.input_information).stem
        if self.conf.store_zeek_files_in_the_output_dir():
            self.zeek_dir = os.path.join(self.args.output, 'zeek_files')
        else:
            self.zeek_dir = f'zeek_files_{without_ext}/'

    def terminate_slips(self):
        """
        Shutdown slips, is called when stopping slips before
        starting all modules. for example using -cb
        """
        if self.mode == 'daemonized':
            self.daemon.stop()
        if self.conf.get_cpu_profiler_enable() != "yes":
            sys.exit(0)

    def update_local_TI_files(self):
        from modules.update_manager.update_manager import UpdateManager
        try:
            # only one instance of slips should be able to update ports and orgs at a time
            # so this function will only be allowed to run from 1 slips instance.
            with Lock(name="slips_ports_and_orgs"):
                # pass a dummy termination event for update manager to update orgs and ports info
                update_manager = UpdateManager(self.output_queue,
                                               self.args.output,
                                               self.redis_port,
                                               multiprocessing.Event())
                update_manager.update_ports_info()
                update_manager.update_org_files()
        except CannotAcquireLock:
            # another instance of slips is updating ports and orgs
            return

    def save_the_db(self):
        # save the db to the output dir of this analysis
        # backups_dir = os.path.join(os.getcwd(), 'redis_backups/')
        # try:
        #     os.mkdir(backups_dir)
        # except FileExistsError:
        #     pass
        backups_dir = self.args.output
        # The name of the interface/pcap/nfdump/binetflow used is in self.input_information
        # if the input is a zeek dir, remove the / at the end
        if self.input_information.endswith('/'):
            self.input_information = self.input_information[:-1]
        # We need to separate it from the path
        self.input_information = os.path.basename(self.input_information)
        # Remove the extension from the filename
        with contextlib.suppress(ValueError):
            self.input_information = self.input_information[
                : self.input_information.index('.')
            ]
        # Give the exact path to save(), this is where our saved .rdb backup will be
        rdb_filepath = os.path.join(backups_dir, self.input_information)
        self.db.save(rdb_filepath)
        # info will be lost only if you're out of space and redis can't write to dump.self.rdb, otherwise you're fine
        print(
            '[Main] [Warning] stop-writes-on-bgsave-error is set to no, information may be lost in the redis backup file.'
        )

    def was_running_zeek(self) -> bool:
        """returns true if zeek wa sused in this run """
        return self.db.get_input_type() in ('pcap', 'interface') or self.db.is_growing_zeek_dir()

    def store_zeek_dir_copy(self):
        store_a_copy_of_zeek_files = self.conf.store_a_copy_of_zeek_files()
        was_running_zeek = self.was_running_zeek()
        if store_a_copy_of_zeek_files and was_running_zeek:
            # this is where the copy will be stored
            dest_zeek_dir = os.path.join(self.args.output, 'zeek_files')
            copy_tree(self.zeek_dir, dest_zeek_dir)
            print(
                f'[Main] Stored a copy of zeek files to {dest_zeek_dir}'
            )

    def delete_zeek_files(self):
        if self.conf.delete_zeek_files():
            shutil.rmtree(self.zeek_dir)

    def is_debugger_active(self) -> bool:
        """Return if the debugger is currently active"""
        gettrace = getattr(sys, 'gettrace', lambda: None)
        return gettrace() is not None

    def prepare_output_dir(self):
        """
        Clears the output dir if it already exists , or creates a new one if it doesn't exist
        Log dirs are stored in output/<input>_%Y-%m-%d_%H:%M:%S
        @return: None
        """
        # default output/
        if '-o' in sys.argv:
            # -o is given
            # delete all old files in the output dir
            if os.path.exists(self.args.output):
                for file in os.listdir(self.args.output):
                    # in integration tests, slips redirects its output to slips_output.txt,
                    # don't delete that file
                    if self.args.testing and 'slips_output.txt' in file:
                        continue

                    file_path = os.path.join(self.args.output, file)
                    with contextlib.suppress(Exception):
                        if os.path.isfile(file_path):
                            os.remove(file_path)
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path)
            else:
                os.makedirs(self.args.output)
            return

        # self.args.output is the same as self.alerts_default_path
        self.input_information = os.path.normpath(self.input_information)
        # now that slips can run several instances,
        # each created dir will be named after the instance
        # that created it
        # it should be output/wlp3s0
        self.args.output = os.path.join(
            self.alerts_default_path,
            os.path.basename(self.input_information)  # get pcap name from path
        )
        # add timestamp to avoid conflicts wlp3s0_2022-03-1_03:55
        ts = utils.convert_format(datetime.now(), '%Y-%m-%d_%H:%M:%S')
        self.args.output += f'_{ts}/'

        os.makedirs(self.args.output)

        print(f'[Main] Storing Slips logs in {self.args.output}')

    def set_mode(self, mode, daemon=''):
        """
        Slips has 2 modes, daemonized and interactive, this function
        sets up the mode so that slips knows in which mode it's operating
        :param mode: daemonized of interavtive
        :param daemon: Daemon() instance
        """
        self.mode = mode
        self.daemon = daemon

    def log(self, txt):
        """
        Is used instead of print for daemon debugging
        """
        with open(self.daemon.stdout, 'a') as f:
            f.write(f'{txt}\n')

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
        :param text: text to print. Can include format like f'Test {here}'
        """

        levels = f'{verbose}{debug}'
        self.output_queue.put(f'{levels}|{self.name}|{text}')

    def handle_flows_from_stdin(self, input_information):
        """
        Make sure the stdin line type is valid (argus, suricata, or zeek)
        """
        if input_information.lower() not in (
                'argus',
                'suricata',
                'zeek',
        ):
            print(
                f'[Main] Invalid file path {input_information}. Stopping.'
            )
            sys.exit(-1)
            return False

        if self.mode == 'daemonized':
            print(
                "Can't read input from stdin in daemonized mode. "
                "Stopping"
            )
            sys.exit(-1)
            return False
        line_type = input_information
        input_type = 'stdin'
        return input_type, line_type.lower()

    def get_input_file_type(self, given_path):
        """
        given_path: given file
        returns binetflow, pcap, nfdump, zeek_folder, suricata, etc.
        """
        # default value
        input_type = 'file'
        # Get the type of file
        cmd_result = subprocess.run(
            ['file', given_path], stdout=subprocess.PIPE
        )
        # Get command output
        cmd_result = cmd_result.stdout.decode('utf-8')
        if (
                ('pcap capture file' in cmd_result
                or 'pcapng capture file' in cmd_result)
                and os.path.isfile(given_path)
        ):
            input_type = 'pcap'
        elif (
                ('dBase' in cmd_result
                 or 'nfcap' in given_path
                 or 'nfdump' in given_path
                )
                and os.path.isfile(given_path)
        ):
            input_type = 'nfdump'
            if shutil.which('nfdump') is None:
                # If we do not have nfdump, terminate Slips.
                print(
                    'nfdump is not installed. terminating slips.'
                )
                self.terminate_slips()
        elif 'CSV' in cmd_result and os.path.isfile(given_path):
            input_type = 'binetflow'
        elif 'directory' in cmd_result and os.path.isdir(given_path):
            input_type = 'zeek_folder'
        else:
            # is it a zeek log file or suricata, binetflow tabs, or binetflow comma separated file?
            # use first line to determine
            with open(given_path, 'r') as f:
                while True:
                    # get the first line that isn't a comment
                    first_line = f.readline().replace('\n', '')
                    if not first_line.startswith('#'):
                        break
            if 'flow_id' in first_line and os.path.isfile(given_path):
                input_type = 'suricata'
            elif os.path.isfile(given_path):
                # this is a text file, it can be binetflow or zeek_log_file
                try:
                    # is it a json log file
                    json.loads(first_line)
                    input_type = 'zeek_log_file'
                except json.decoder.JSONDecodeError:
                    # this is a tab separated file
                    # is it zeek log file or binetflow file?

                    # zeek tab files are separated by several spaces or tabs
                    sequential_spaces_found = re.search(
                        '\s{1,}-\s{1,}', first_line
                    )
                    tabs_found = re.search(
                        '\t{1,}', first_line
                    )

                    if (
                            '->' in first_line
                            or 'StartTime' in first_line
                    ):
                        # tab separated files are usually binetflow tab files
                        input_type = 'binetflow-tabs'
                    elif sequential_spaces_found or tabs_found:
                        input_type = 'zeek_log_file'

        return input_type

    def setup_print_levels(self):
        """
        setup debug and verbose levels
        """
        # Any verbosity passed as parameter overrides the configuration. Only check its value
        if self.args.verbose is None:
            self.args.verbose = self.conf.verbose()

        # Limit any verbosity to > 0
        self.args.verbose = max(self.args.verbose, 1)
        # Any debug passed as parameter overrides the configuration. Only check its value
        if self.args.debug is None:
            self.args.debug = self.conf.debug()

        # Limit any debuggisity to > 0
        self.args.debug = max(self.args.debug, 0)

    def print_version(self):
        slips_version = f'Slips. Version {green(self.version)}'
        branch_info = utils.get_branch_info()
        if branch_info is not False:
            # it's false when we're in docker because there's no .git/ there
            self.commit, self.branch = branch_info
            slips_version += f' ({self.commit[:8]})'
        print(slips_version)

    def should_run_non_stop(self) -> bool:
        """
        determines if slips shouldn't terminate because by default,
        it terminates when there's no more incoming flows
        """
        # these are the cases where slips should be running non-stop
        # when slips is reading from a special module other than the input process
        # this module should handle the stopping of slips
        if (
                self.is_debugger_active()
                or self.input_type in ('stdin','CYST')
                or self.is_interface
        ):
            return True
        return False

    def start(self):
        """Main Slips Function"""
        try:

            self.print_version()
            print('https://stratosphereips.org')
            print('-' * 27)

            self.setup_print_levels()

            # this is used in get_random_redis_port(), don't move this line
            self.output_queue = Queue()


            # get the port that is going to be used for this instance of slips
            if self.args.port:
                self.redis_port = int(self.args.port)
                # close slips if port is in use
                self.metadata_man.check_if_port_is_in_use(self.redis_port)
            elif self.args.multiinstance:
                self.redis_port = self.redis_man.get_random_redis_port()
                if not self.redis_port:
                    # all ports are unavailable
                    inp = input("Press Enter to close all ports.\n")
                    if inp == '':
                        self.redis_man.close_all_ports()
                    self.terminate_slips()
            else:
                # even if this port is in use, it will be overwritten by slips
                self.redis_port = 6379
                # self.check_if_port_is_in_use(self.redis_port)


            self.db = DBManager(self.args.output, self.output_queue, self.redis_port)
            self.db.set_input_metadata({
                    'output_dir': self.args.output,
                    'commit': self.commit,
                    'branch': self.branch,
                })
            
            self.cpu_profiler_init()
            self.memory_profiler_init()
            # uncomment line to see that memory profiler works correctly
            # Should print out red text if working properly
            # self.memory_profiler_multiproc_test()

            # if stdout is redirected to a file,
            # tell outputProcess.py to redirect it's output as well
            current_stdout, stderr, slips_logfile = self.checker.check_output_redirection()

            # outputprocess should be created first because it handles
            # the output of the rest of the threads.
            output_process = self.proc_man.start_output_process(
                current_stdout, stderr, slips_logfile
                )

            if self.args.growing:
                if self.input_type != 'zeek_folder':
                    self.print(f"Parameter -g should be using with "
                               f"-f <dirname> not a {self.input_type}. Ignoring -g")
                else:
                    self.print(f"Running on a growing zeek dir: {self.input_information}")
                    self.db.set_growing_zeek_dir()

            # log the PID of the started redis-server
            # should be here after we're sure that the server was started
            redis_pid = self.redis_man.get_pid_of_redis_server(self.redis_port)
            self.redis_man.log_redis_server_PID(self.redis_port, redis_pid)

            self.db.set_slips_mode(self.mode)

            if self.mode == 'daemonized':
                std_files = {
                    'stderr': self.daemon.stderr,
                    'stdout': self.daemon.stdout,
                    'stdin': self.daemon.stdin,
                    'pidfile': self.daemon.pidfile,
                    'logsfile': self.daemon.logsfile
                }
            else:
                std_files = {
                    'stderr': stderr,
                    'stdout': slips_logfile,
                }

            self.db.store_std_file(**std_files)

            self.print(f'Using redis server on port: {green(self.redis_port)}', 1, 0)
            self.print(f'Started {green("Main")} process [PID {green(self.pid)}]', 1, 0)
            self.print(f'Started {green("Output Process")} [PID {green(output_process.pid)}]', 1, 0)
            self.print('Starting modules', 1, 0)

            # if slips is given a .rdb file, don't load the modules as we don't need them
            if not self.args.db:
                # update local files before starting modules
                self.update_local_TI_files()
                self.proc_man.load_modules()

            if self.args.webinterface:
                self.ui_man.start_webinterface()

            # call shutdown_gracefully on sigterm
            def sig_handler(sig, frame):
                self.proc_man.shutdown_gracefully()
            # The signals SIGKILL and SIGSTOP cannot be caught, blocked, or ignored.
            signal.signal(signal.SIGTERM, sig_handler)

            self.proc_man.start_evidence_process()
            self.proc_man.start_profiler_process()

            self.c1 = self.db.subscribe('control_channel')

            self.metadata_man.enable_metadata()

            self.proc_man.start_input_process()

            # obtain the list of active processes
            self.proc_man.processes = multiprocessing.active_children()

            self.db.store_process_PID(
                'slips.py',
                int(self.pid)
            )
            self.metadata_man.set_input_metadata()

            if self.conf.use_p2p() and not self.args.interface:
                self.print('Warning: P2P is only supported using an interface. Disabled P2P.')

            # warn about unused open redis servers
            open_servers = len(self.redis_man.get_open_redis_servers())
            if open_servers > 1:
                self.print(
                    f'Warning: You have {open_servers} '
                    f'redis servers running. '
                    f'Run Slips with --killall to stop them.'
                )

            self.print("Warning: Slips may generate a large amount of traffic by querying TI sites.")


            hostIP = self.metadata_man.store_host_ip()

            # Check every 5 secs if we should stop slips or not
            sleep_time = 5

            # In each interval we check if there has been any modifications to
            # the database by any module.
            # If not, wait this amount of intervals and then stop slips.
            max_intervals_to_wait = 4
            intervals_to_wait = max_intervals_to_wait

            # Don't try to stop slips if it's capturing from an interface or a growing zeek dir
            self.is_interface: bool = self.args.interface or self.db.is_growing_zeek_dir()

            while True:
                message = self.c1.get_message(timeout=0.01)
                if (
                    message
                    and utils.is_msg_intended_for(message, 'control_channel')
                    and message['data'] == 'stop_slips'
                ):
                    self.proc_man.shutdown_gracefully()
                    break

                # Sleep some time to do routine checks
                time.sleep(sleep_time)

                # if you remove the below logic anywhere before the above sleep() statement
                # it will try to get the return value very quickly before
                # the webinterface thread sets it
                self.ui_man.check_if_webinterface_started()

                modified_ips_in_the_last_tw, modified_profiles = self.metadata_man.update_slips_running_stats()
                # for input of type : pcap, interface and growing zeek directories, we prin the stats using slips.py
                # for other files, we print a progress bar + the stats using outputprocess
                if self.mode != 'daemonized' and (self.input_type in ('pcap', 'interface') or self.args.growing):
                    # How many profiles we have?
                    profilesLen = self.db.get_profiles_len()
                    now = utils.convert_format(datetime.now(), '%Y/%m/%d %H:%M:%S')
                    evidence_number = self.db.get_evidence_number() or 0
                    print(
                        f'Total analyzed IPs so '
                        f'far: {profilesLen}. '
                        f'Evidence added: {evidence_number}. '
                        f'IPs sending traffic in the last {self.twid_width}: {modified_ips_in_the_last_tw}. '
                        f'({now})',
                        end='\r',
                    )

                # Check if we need to close any TWs
                self.db.check_TW_to_close()

                if self.is_interface and hostIP not in modified_profiles:
                    # In interface we keep track of the host IP. If there was no
                    # modified TWs in the host IP, we check if the network was changed.
                    if hostIP := self.metadata_man.get_host_ip():
                        self.db.set_host_ip(hostIP)

                if self.should_run_non_stop():
                    continue

                # Reaches this point if we're running Slips on a file.
                # countdown until slips stops if no TW modifications are happening
                if modified_ips_in_the_last_tw == 0:
                    # waited enough. stop slips
                    if intervals_to_wait == 0:
                        self.proc_man.shutdown_gracefully()
                        break

                    # If there were no modified TWs in the last timewindow time,
                    # then start counting down
                    intervals_to_wait -= 1


                self.db.check_health()
        except KeyboardInterrupt:
            # the EINTR error code happens if a signal occurred while the system call was in progress
            # comes here if zeek terminates while slips is still working
            self.proc_man.shutdown_gracefully()


####################
# Main
####################
if __name__ == '__main__':
    slips = Main()
    if slips.args.stopdaemon:
        # -S is provided
        daemon = Daemon(slips)
        if not daemon.pid:
            # pidfile doesn't exist
            print(
                "Trying to stop Slips daemon.\n"
                "Daemon is not running."
            )
        else:
            daemon.stop()
            # it takes about 5 seconds for the stop_slips msg to arrive in the channel, so give slips time to stop
            time.sleep(3)
            print('Daemon stopped.')
    elif slips.args.daemon:
        daemon = Daemon(slips)
        if daemon.pid is not None:
            print(f'pidfile {daemon.pidfile} already exists. Daemon already running?')
        else:
            print('Slips daemon started.')
            daemon.start()
    else:
        # interactive mode
        pass
        slips.start()
    slips.cpu_profiler_release()
    slips.memory_profiler_release()
