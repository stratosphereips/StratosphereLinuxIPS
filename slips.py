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
from slips_files.common.slips_utils import utils
from slips_files.core.database.database import __database__
from slips_files.common.config_parser import ConfigParser
from exclusiveprocess import Lock, CannotAcquireLock
from redis_manager import RedisManager
from metadata_manager import MetadataManager
from process_manager import ProcessManager
from ui_manager import UIManager
from checker import Checker
from style import green
import socket

from slips_files.core.inputProcess import InputProcess
from slips_files.core.outputProcess import OutputProcess
from slips_files.core.profilerProcess import ProfilerProcess
from slips_files.core.logsProcess import LogsProcess
from slips_files.core.evidenceProcess import EvidenceProcess

import signal
import sys
import os
import time
import shutil
import warnings
import json
import errno
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
        self.redis_man = RedisManager(terminate_slips=self.terminate_slips)
        self.ui_man = UIManager(self)
        self.metadata_man = MetadataManager(self)
        self.proc_man = ProcessManager(self)
        self.checker = Checker(self)
        self.conf = ConfigParser()
        self.version = self.get_slips_version()
        self.args = self.conf.get_args()
        # in testing mode we manually set the following params
        if not testing:
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
            self.zeek_folder = os.path.join(self.args.output, 'zeek_files')
        else:
            self.zeek_folder = f'zeek_files_{without_ext}/'

    def create_folder_for_logs(self):
        """
        Create a dir for logs if logs are enabled
        """
        logs_folder = utils.convert_format(datetime.now(), '%Y-%m-%d--%H-%M-%S')
        # place the logs dir inside the output dir
        logs_folder = os.path.join(self.args.output, f'detailed_logs_{logs_folder}')
        try:
            os.makedirs(logs_folder)
        except OSError as e:
            if e.errno != errno.EEXIST:
                # doesn't exist and can't create
                return False
        return logs_folder

    def terminate_slips(self):
        """
        Shutdown slips, is called when stopping slips before
        starting all modules. for example using -cb
        """
        if self.mode == 'daemonized':
            self.daemon.stop()
        sys.exit(0)

    def setup_detailed_logs(self, LogsProcess):
        """
        Detailed logs are the ones created by logsProcess
        """

        do_logs = self.conf.create_log_files()
        # if -l is provided or create_log_files is yes then we will create log files
        if self.args.createlogfiles or do_logs:
            # Create a folder for logs
            logs_dir = self.create_folder_for_logs()
            # Create the logsfile thread if by parameter we were told,
            # or if it is specified in the configuration
            self.logsProcessQueue = Queue()
            logs_process = LogsProcess(
                self.logsProcessQueue,
                self.outputqueue,
                self.args.verbose,
                self.args.debug,
                logs_dir,
                self.redis_port
            )
            logs_process.start()
            self.print(
                f'Started {green("Logs Process")} '
                f'[PID {green(logs_process.pid)}]', 1, 0
            )
            __database__.store_process_PID(
                'Logs', int(logs_process.pid)
            )
        else:
            # If self.args.nologfiles is False, then we don't want log files,
            # independently of what the conf says.
            logs_dir = False

    def update_local_TI_files(self):
        from modules.update_manager.update_file_manager import UpdateFileManager
        try:
            # only one instance of slips should be able to update ports and orgs at a time
            # so this function will only be allowed to run from 1 slips instance.
            with Lock(name="slips_ports_and_orgs"):
                update_manager = UpdateFileManager(self.outputqueue, self.redis_port)
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
        __database__.save(rdb_filepath)
        # info will be lost only if you're out of space and redis can't write to dump.rdb, otherwise you're fine
        print(
            '[Main] [Warning] stop-writes-on-bgsave-error is set to no, information may be lost in the redis backup file.'
        )

    def was_running_zeek(self) -> bool:
        """returns true if zeek wa sused in this run """
        return __database__.get_input_type() in ('pcap', 'interface') or __database__.is_growing_zeek_dir()

    def store_zeek_dir_copy(self):
        store_a_copy_of_zeek_files = self.conf.store_a_copy_of_zeek_files()
        was_running_zeek = self.was_running_zeek()
        if store_a_copy_of_zeek_files and was_running_zeek:
            # this is where the copy will be stored
            dest_zeek_dir = os.path.join(self.args.output, 'zeek_files')
            copy_tree(self.zeek_folder, dest_zeek_dir)
            print(
                f'[Main] Stored a copy of zeek files to {dest_zeek_dir}'
            )

    def delete_zeek_files(self):
        if self.conf.delete_zeek_files():
            shutil.rmtree(self.zeek_folder)

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
            # delet all old files in the output dir
            if os.path.exists(self.args.output):
                for file in os.listdir(self.args.output):
                    # in integration tests, slips redirct its' output to slips_output.txt,
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




    def log_redis_server_PID(self, redis_port, redis_pid):
        now = utils.convert_format(datetime.now(), utils.alerts_format)
        try:
            # used in case we need to remove the line using 6379 from running logfile
            with open(self.redis_man.running_logfile, 'a') as f:
                # add the header lines if the file is newly created
                if f.tell() == 0:
                    f.write(
                        '# This file contains a list of used redis ports.\n'
                        '# Once a server is killed, it will be removed from this file.\n'
                        'Date, File or interface, Used port, Server PID,'
                        ' Output Zeek Dir, Logs Dir, Slips PID, Is Daemon, Save the DB\n'
                    )

                f.write(
                    f'{now},{self.input_information},{redis_port},'
                    f'{redis_pid},{self.zeek_folder},{self.args.output},'
                    f'{os.getpid()},'
                    f'{bool(self.args.daemon)},{self.args.save}\n'
                )
        except PermissionError:
            # last run was by root, change the file ownership to non-root
            os.remove(self.redis_man.running_logfile)
            open(self.redis_man.running_logfile, 'w').close()
            self.log_redis_server_PID(redis_port, redis_pid)

        if redis_port == 6379:
            # remove the old logline using this port
            self.redis_man.remove_old_logline(6379)

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
        self.outputqueue.put(f'{levels}|{self.name}|{text}')



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


    def load_db(self):
        self.input_type = 'database'
        # self.input_information = 'database'
        from slips_files.core.database.database import __database__
        __database__.start(6379)

        # this is where the db will be loaded
        redis_port = 32850
        # make sure the db on 32850 is flushed and ready for the new db to be loaded
        if pid := self.redis_man.get_pid_of_redis_server(redis_port):
            self.redis_man.flush_redis_server(pid=pid)
            self.redis_man.kill_redis_server(pid)

        if not __database__.load(self.args.db):
            print(f'Error loading the database {self.args.db}')
        else:
            self.load_redis_db(redis_port)
            # __database__.disable_redis_persistence()

        self.terminate_slips()

    def load_redis_db(self, redis_port):
        # to be able to use running_slips_info later as a non-root user,
        # we shouldn't modify it as root

        self.input_information = os.path.basename(self.args.db)
        redis_pid = self.redis_man.get_pid_of_redis_server(redis_port)
        self.zeek_folder = '""'
        self.log_redis_server_PID(redis_port, redis_pid)
        self.redis_man.remove_old_logline(redis_port)

        print(
            f'{self.args.db} loaded successfully.\n'
            f'Run ./kalipso.sh and choose port {redis_port}'
        )

    def get_input_file_type(self, input_information):
        """
        input_information: given file
        returns binetflow, pcap, nfdump, zeek_folder, suricata, etc.
        """
        # default value
        input_type = 'file'
        # Get the type of file
        cmd_result = subprocess.run(
            ['file', input_information], stdout=subprocess.PIPE
        )
        # Get command output
        cmd_result = cmd_result.stdout.decode('utf-8')
        if 'pcap' in cmd_result:
            input_type = 'pcap'
        elif 'dBase' in cmd_result or 'nfcap' in input_information or 'nfdump' in input_information:
            input_type = 'nfdump'
            if shutil.which('nfdump') is None:
                # If we do not have nfdump, terminate Slips.
                print(
                    'nfdump is not installed. terminating slips.'
                )
                self.terminate_slips()
        elif 'CSV' in cmd_result:
            input_type = 'binetflow'
        elif 'directory' in cmd_result:
            input_type = 'zeek_folder'
        else:
            # is it a zeek log file or suricata, binetflow tabs, or binetflow comma separated file?
            # use first line to determine
            with open(input_information, 'r') as f:
                while True:
                    # get the first line that isn't a comment
                    first_line = f.readline().replace('\n', '')
                    if not first_line.startswith('#'):
                        break
            if 'flow_id' in first_line:
                input_type = 'suricata'
            else:
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
        setup debug and verose levels
        """
        # Any verbosity passed as parameter overrides the configuration. Only check its value
        if self.args.verbose is None:
            self.args.verbose = self.conf.verbose()

        # Limit any verbosity to > 0
        self.args.verbose = max(self.args.verbose, 1)
        # Any deug passed as parameter overrides the configuration. Only check its value
        if self.args.debug is None:
            self.args.debug = self.conf.debug()

        # Limit any debuggisity to > 0
        self.args.debug = max(self.args.debug, 0)

    def print_version(self):
        slips_version = f'Slips. Version {green(self.version)}'
        branch_info = utils.get_branch_info()
        if branch_info is not False:
            # it's false when we're in docker because there's no .git/ there
            commit = branch_info[0]
            slips_version += f' ({commit[:8]})'
        print(slips_version)


    def check_if_port_is_in_use(self, port):
        if port == 6379:
            # even if it's already in use, slips will override it
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("localhost", port))
            return False
        except OSError:
            print(f"[Main] Port {port} already is use by another process."
                  f" Choose another port using -P <portnumber> \n"
                  f"Or kill your open redis ports using: ./slips.py -k ")
            self.terminate_slips()

    def update_slips_running_stats(self):
        """
        updates the number of processed ips, slips internal time, and modified tws so far in the db
        """
        slips_internal_time = float(__database__.getSlipsInternalTime()) + 1

        # Get the amount of modified profiles since we last checked
        modified_profiles, last_modified_tw_time = __database__.getModifiedProfilesSince(
            slips_internal_time
        )
        modified_ips_in_the_last_tw = len(modified_profiles)
        __database__.set_input_metadata({'modified_ips_in_the_last_tw': modified_ips_in_the_last_tw})
        # Get the time of last modified timewindow and set it as a new
        if last_modified_tw_time != 0:
            __database__.setSlipsInternalTime(
                last_modified_tw_time
            )
        return modified_ips_in_the_last_tw, modified_profiles

    def should_run_non_stop(self, is_interface) -> bool:
        """
        determines if slips shouldn't terminate because by defualt,
        it terminates when there's no moreincoming flows
        """
        # these are the cases where slips should be running non-stop
        if (
                self.is_debugger_active()
                or self.input_type in ('stdin','cyst')
                or is_interface
        ):
            return True

    def start(self):
        """Main Slips Function"""
        try:

            self.print_version()
            print('https://stratosphereips.org')
            print('-' * 27)



            self.setup_print_levels()
            ##########################
            # Creation of the threads
            ##########################

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

            # Output thread. outputprocess should be created first because it handles
            # the output of the rest of the threads.
            self.outputqueue = Queue()

            # if stdout is redirected to a file,
            # tell outputProcess.py to redirect it's output as well
            current_stdout, stderr, slips_logfile = self.checker.check_output_redirection()
            output_process = OutputProcess(
                self.outputqueue,
                self.args.verbose,
                self.args.debug,
                self.redis_port,
                stdout=current_stdout,
                stderr=stderr,
                slips_logfile=slips_logfile,
            )
            # this process starts the db
            output_process.start()
            __database__.store_process_PID('Output', int(output_process.pid))

            if self.args.growing:
                if self.input_type != 'zeek_folder':
                    self.print(f"Parameter -g should be using with -f <dirname> not a {self.input_type}. Ignoring -g")
                else:
                    self.print(f"Running on a growing zeek dir: {self.input_information}")
                    __database__.set_growing_zeek_dir()

            # log the PID of the started redis-server
            # should be here after we're sure that the server was started
            redis_pid = self.redis_man.get_pid_of_redis_server(self.redis_port)
            self.log_redis_server_PID(self.redis_port, redis_pid)

            __database__.set_slips_mode(self.mode)

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

            __database__.store_std_file(**std_files)

            self.print(f'Using redis server on port: {green(self.redis_port)}', 1, 0)
            self.print(f'Started {green("Main")} process [PID {green(self.pid)}]', 1, 0)
            self.print(f'Started {green("Output Process")} [PID {green(output_process.pid)}]', 1, 0)
            self.print('Starting modules', 1, 0)

            # if slips is given a .rdb file, don't load the modules as we don't need them
            if not self.args.db:
                # update local files before starting modules
                self.update_local_TI_files()
                self.proc_man.load_modules()

            # self.start_gui_process()
            if self.args.webinterface:
                self.ui_man.start_webinterface()

            # call shutdown_gracefully on sigterm
            def sig_handler(sig, frame):
                self.proc_man.shutdown_gracefully()
            # The signals SIGKILL and SIGSTOP cannot be caught, blocked, or ignored.
            signal.signal(signal.SIGTERM, sig_handler)

            logs_dir = self.setup_detailed_logs(LogsProcess)

            self.evidenceProcessQueue = Queue()
            evidence_process = EvidenceProcess(
                self.evidenceProcessQueue,
                self.outputqueue,
                self.args.output,
                logs_dir,
                self.redis_port,
            )
            evidence_process.start()
            self.print(
                f'Started {green("Evidence Process")} '
                f'[PID {green(evidence_process.pid)}]', 1, 0
            )
            __database__.store_process_PID(
                'Evidence',
                int(evidence_process.pid)
            )
            __database__.store_process_PID(
                'slips.py',
                int(self.pid)
            )

            self.profilerProcessQueue = Queue()
            profiler_process = ProfilerProcess(
                self.profilerProcessQueue,
                self.outputqueue,
                self.args.verbose,
                self.args.debug,
                self.redis_port,
            )
            profiler_process.start()
            self.print(
                f'Started {green("Profiler Process")} '
                f'[PID {green(profiler_process.pid)}]', 1, 0
            )
            __database__.store_process_PID(
                'Profiler',
                int(profiler_process.pid)
            )

            self.c1 = __database__.subscribe('finished_modules')
            self.metadata_man.enable_metadata()

            inputProcess = InputProcess(
                self.outputqueue,
                self.profilerProcessQueue,
                self.input_type,
                self.input_information,
                self.args.pcapfilter,
                self.zeek_bro,
                self.zeek_folder,
                self.line_type,
                self.redis_port,
            )
            inputProcess.start()
            self.print(
                f'Started {green("Input Process")} '
                f'[PID {green(inputProcess.pid)}]', 1, 0
            )
            __database__.store_process_PID(
                'Input Process',
                int(inputProcess.pid)
            )
            self.zeek_folder = inputProcess.zeek_folder
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

            hostIP = self.metadata_man.store_host_ip()

            # Check every 5 secs if we should stop slips or not
            sleep_time = 5

            # In each interval we check if there has been any modifications to
            # the database by any module.
            # If not, wait this amount of intervals and then stop slips.
            max_intervals_to_wait = 4
            intervals_to_wait = max_intervals_to_wait

            # Don't try to stop slips if it's capturing from an interface or a growing zeek dir
            is_interface: bool = self.args.interface or __database__.is_growing_zeek_dir()

            while True:
                message = self.c1.get_message(timeout=0.01)
                if (
                    message
                    and utils.is_msg_intended_for(message, 'finished_modules')
                    and message['data'] == 'stop_slips'
                ):
                    self.proc_man.shutdown_gracefully()

                # Sleep some time to do routine checks
                time.sleep(sleep_time)

                # if you remove the below logic anywhere before the above sleep() statement
                # it will try to get the return value very quickly before
                # the webinterface thread sets it
                self.ui_man.check_if_webinterface_started()

                modified_ips_in_the_last_tw, modified_profiles = self.metadata_man.update_slips_running_stats()
                # for input of type : pcap, interface and growing zeek directories, we prin the stats using slips.py
                # for other files, we prin a progress bar + the stats using outputprocess
                if self.mode != 'daemonized' and (self.input_type in ('pcap', 'interface') or self.args.growing):
                    # How many profiles we have?
                    profilesLen = str(__database__.getProfilesLen())
                    now = utils.convert_format(datetime.now(), '%Y/%m/%d %H:%M:%S')
                    print(
                        f'Total analyzed IPs so '
                        f'far: {profilesLen}. '
                        f'IPs sending traffic in the last {self.twid_width}: {modified_ips_in_the_last_tw}. '
                        f'({now})',
                        end='\r',
                    )

                # Check if we need to close any TWs
                __database__.check_TW_to_close()

                if is_interface and hostIP not in modified_profiles:
                    # In interface we keep track of the host IP. If there was no
                    # modified TWs in the host IP, we check if the network was changed.
                    if hostIP := self.metadata_man.get_host_ip():
                        __database__.set_host_ip(hostIP)

                if self.should_run_non_stop(is_interface):
                    continue

                # Reaches this point if we're running Slips on a file.
                # countdown until slips stops if no TW modifications are happening
                if modified_ips_in_the_last_tw == 0:
                    # waited enough. stop slips
                    if intervals_to_wait == 0:
                        self.proc_man.shutdown_gracefully()

                    # If there were no modified TWs in the last timewindow time,
                    # then start counting down
                    intervals_to_wait -= 1


                __database__.pubsub.check_health()
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
        slips.start()
