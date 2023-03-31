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

from slips_files.common.abstracts import Module
from slips_files.common.slips_utils import utils
from slips_files.core.database.database import __database__
from slips_files.common.config_parser import ConfigParser
from exclusiveprocess import Lock, CannotAcquireLock

import threading
import signal
import sys
import redis
import os
import time
import shutil
import psutil
import socket
import warnings
import json
import pkgutil
import inspect
import modules
import importlib
import errno
import subprocess
import re
from datetime import datetime
from collections import OrderedDict
from distutils.dir_util import copy_tree
from daemon import Daemon
from multiprocessing import Queue
from termcolor import colored

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
        self.running_logfile = 'running_slips_info.txt'
        # slips picks a redis port from the following range
        self.start_port = 32768
        self.end_port = 32850
        self.conf = ConfigParser()
        self.version = self.get_slips_version()
        self.args = self.conf.get_args()
        # in testing mode we manually set the following params
        if not testing:
            self.pid = os.getpid()
            self.check_given_flags()
            if not self.args.stopdaemon:
                # Check the type of input
                self.input_type, self.input_information, self.line_type = self.check_input_type()
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

    def prepare_zeek_output_dir(self):
        from pathlib import Path
        without_ext = Path(self.input_information).stem
        # do we store the zeek dir inside the output dir?
        store_zeek_files_in_the_output_dir = self.conf.store_zeek_files_in_the_output_dir()
        if store_zeek_files_in_the_output_dir:
            self.zeek_folder = os.path.join(self.args.output, 'zeek_files')
        else:
            self.zeek_folder = f'zeek_files_{without_ext}/'

    def get_host_ip(self):
        """
        Recognize the IP address of the machine
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('1.1.1.1', 80))
            ipaddr_check = s.getsockname()[0]
            s.close()
        except (socket.error):
            # not connected to the internet
            return None
        return ipaddr_check

    def get_pid_using_port(self, port):
        """
        Returns the PID of the process using the given port or False if no process is using it
        """
        port = int(port)
        for conn in psutil.net_connections():
            if conn.laddr.port == port:
                return psutil.Process(conn.pid).pid #.name()
        return None

    def check_if_webinterface_started(self):
        if not hasattr(self, 'webinterface_return_value'):
            return

        # now that the web interface had enough time to start,
        # check if it successfully started or not
        if self.webinterface_return_value.empty():
            # to make sure this function is only executed once
            delattr(self, 'webinterface_return_value')
            return
        if self.webinterface_return_value.get() != True:
            # to make sure this function is only executed once
            delattr(self, 'webinterface_return_value')
            return

        self.print(f"Slips {self.green('web interface')} running on "
                   f"http://localhost:55000/")
        delattr(self, 'webinterface_return_value')

    def start_webinterface(self):
        """
        Starts the web interface shell script if -w is given
        """
        def detach_child():
            """
            Detach the web interface from the parent process group(slips.py), the child(web interface)
             will no longer receive signals and should be manually killed in shutdown_gracefully()
            """
            os.setpgrp()

        def run_webinterface():
            # starting the wbeinterface using the shell script results in slips not being able to
            # get the PID of the python proc started by the .sh scrip
            command = ['python3', 'webinterface/app.py']
            webinterface = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                preexec_fn=detach_child
            )
            # self.webinterface_pid = webinterface.pid
            __database__.store_process_PID('Web Interface', webinterface.pid)
            # we'll assume that it started, and if not, the return value will immidiately change and this thread will
            # print an error
            self.webinterface_return_value.put(True)

            # waits for process to terminate, so if no errors occur
            # we will never get the return value of this thread
            error = webinterface.communicate()[1]
            if error:
                # pop the True we just added
                self.webinterface_return_value.get()
                # set false as the return value of this thread
                self.webinterface_return_value.put(False)

                pid = self.get_pid_using_port(55000)
                self.print (f"Web interface error:\n"
                            f"{error.strip().decode()}\n"
                            f"Port 55000 is used by PID {pid}")

        # if theres's an error, this will be set to false, and the error will be printed
        # otherwise we assume that the inetrface started
        # self.webinterface_started = True
        self.webinterface_return_value = Queue()
        self.webinterface_thread = threading.Thread(
            target=run_webinterface,
            daemon=True,
        )
        self.webinterface_thread.start()
        # we'll be checking the return value of this thread later

    def store_host_ip(self):
        """
        Store the host IP address if input type is interface
        """
        running_on_interface = '-i' in sys.argv or __database__.is_growing_zeek_dir()
        if not running_on_interface:
            return

        hostIP = self.get_host_ip()
        while True:
            try:
                __database__.set_host_ip(hostIP)
                break
            except redis.exceptions.DataError:
                self.print(
                    'Not Connected to the internet. Reconnecting in 10s.'
                )
                time.sleep(10)
                hostIP = self.get_host_ip()
        return hostIP

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

    def check_redis_database(
        self, redis_host='localhost', redis_port=6379
    ) -> bool:
        """
        Check if we have redis-server running (this is the cache db it should always be running)
        """
        tries = 0
        while True:
            try:
                r = redis.StrictRedis(
                    host=redis_host,
                    port=redis_port,
                    db=1,
                    charset='utf-8',
                    decode_responses=True,
                )
                r.ping()
                return True
            except Exception as ex:
                # only try to open redi-server once.
                if tries == 2:
                    print(f'[Main] Problem starting redis cache database. \n{ex}\nStopping')
                    self.terminate_slips()
                    return False

                print('[Main] Starting redis cache database..')
                os.system(
                    f'redis-server redis.conf --daemonize yes  > /dev/null 2>&1'
                )
                # give the server time to start
                time.sleep(1)
                tries += 1


    def get_random_redis_port(self):
        """
        Keeps trying to connect to random generated ports until we're connected.
        returns the used port
        """
        # generate a random unused port
        for port in range(self.start_port, self.end_port+1):
            # check if 1. we can connect
            # 2.server is not being used by another instance of slips
            # note: using r.keys() blocks the server
            try:
                connected = __database__.connect_to_redis_server(port)
                if connected:
                    server_used = len(list(__database__.r.keys())) < 2
                    if server_used:
                        # if the db managed to connect to this random port, then this is
                        # the port we'll be using
                        return port
            except redis.exceptions.ConnectionError:
                # Connection refused to this port
                continue
        else:
            # there's no usable port in this range
            print(f"All ports from {self.start_port} to {self.end_port} are used. "
                   "Unable to start slips.\n")
            return False


    def clear_redis_cache_database(
        self, redis_host='localhost', redis_port=6379
    ) -> bool:
        """
        Clear cache database
        """
        rcache = redis.StrictRedis(
            host=redis_host,
            port=redis_port,
            db=1,
            charset='utf-8',
            decode_responses=True,
        )
        rcache.flushdb()
        return True

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

    def terminate_slips(self):
        """
        Shutdown slips, is called when stopping slips before
        starting all modules. for example using -cb
        """
        if self.mode == 'daemonized':
            self.daemon.stop()
        sys.exit(0)


    def get_modules(self, to_ignore):
        """
        Get modules from the 'modules' folder.
        """
        # This plugins import will automatically load the modules and put them in
        # the __modules__ variable

        plugins = {}
        failed_to_load_modules = 0
        # Walk recursively through all modules and packages found on the . folder.
        # __path__ is the current path of this python program
        for loader, module_name, ispkg in pkgutil.walk_packages(
                modules.__path__, f'{modules.__name__}.'
        ):
            if any(module_name.__contains__(mod) for mod in to_ignore):
                continue
            # If current item is a package, skip.
            if ispkg:
                continue
            # to avoid loading everything in the dir,
            # only load modules that have the same name as the dir name
            dir_name = module_name.split('.')[1]
            file_name = module_name.split('.')[2]
            if dir_name != file_name:
                continue

            # Try to import the module, otherwise skip.
            try:
                # "level specifies whether to use absolute or relative imports. The default is -1 which
                # indicates both absolute and relative imports will be attempted. 0 means only perform
                # absolute imports. Positive values for level indicate the number of parent
                # directories to search relative to the directory of the module calling __import__()."
                module = importlib.import_module(module_name)
            except ImportError as e:
                print(
                    'Something wrong happened while importing the module {0}: {1}'.format(
                        module_name, e
                    )
                )
                failed_to_load_modules += 1
                continue

            # Walk through all members of currently imported modules.
            for member_name, member_object in inspect.getmembers(module):
                # Check if current member is a class.
                if inspect.isclass(member_object) and (issubclass(
                        member_object, Module
                ) and member_object is not Module):
                    plugins[member_object.name] = dict(
                        obj=member_object,
                        description=member_object.description,
                    )

        # Change the order of the blocking module(load it first)
        # so it can receive msgs sent from other modules
        if 'Blocking' in plugins:
            plugins = OrderedDict(plugins)
            # last=False to move to the beginning of the dict
            plugins.move_to_end('Blocking', last=False)

        return plugins, failed_to_load_modules

    def load_modules(self):
        to_ignore = self.conf.get_disabled_modules(self.input_type)
        # Import all the modules
        modules_to_call = self.get_modules(to_ignore)[0]
        for module_name in modules_to_call:
            if module_name in to_ignore:
                continue

            module_class = modules_to_call[module_name]['obj']
            if 'P2P Trust' == module_name:
                module = module_class(
                    self.outputqueue,
                    self.redis_port,
                    output_dir=self.args.output
                )
            else:
                module = module_class(
                    self.outputqueue,
                    self.redis_port
                )
            module.start()
            __database__.store_process_PID(
                module_name, int(module.pid)
            )
            description = modules_to_call[module_name]['description']
            self.print(
                f'\t\tStarting the module {self.green(module_name)} '
                f'({description}) '
                f'[PID {self.green(module.pid)}]', 1, 0
                )
        # give outputprocess time to print all the started modules
        time.sleep(0.5)
        print('-' * 27)
        self.print(f"Disabled Modules: {to_ignore}", 1, 0)

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
                f'Started {self.green("Logs Process")} '
                f'[PID {self.green(logs_process.pid)}]', 1, 0
            )
            __database__.store_process_PID(
                'Logs', int(logs_process.pid)
            )
        else:
            # If self.args.nologfiles is False, then we don't want log files,
            # independently of what the conf says.
            logs_dir = False


    def start_gui_process(self):
        # Get the type of output from the parameters
        # Several combinations of outputs should be able to be used
        if self.args.gui:
            # Create the curses thread
            guiProcessQueue = Queue()
            guiProcess = GuiProcess(
                guiProcessQueue, self.outputqueue, self.args.verbose,
                self.args.debug
            )
            __database__.store_process_PID(
                'GUI',
                int(guiProcess.pid)
            )
            guiProcess.start()
            self.print('quiet')


    def close_all_ports(self):
        """
        Closes all the redis ports  in logfile and in slips supported range of ports
        """
        if not hasattr(self, 'open_servers_PIDs'):
            self.get_open_redis_servers()

        # close all ports in logfile
        for pid in self.open_servers_PIDs:
            self.flush_redis_server(pid=pid)
            self.kill_redis_server(pid)


        # closes all the ports in slips supported range of ports
        slips_supported_range = [port for port in range(self.start_port, self.end_port + 1)]
        slips_supported_range.append(6379)
        for port in slips_supported_range:
            pid = self.get_pid_of_redis_server(port)
            if pid:
                self.flush_redis_server(pid=pid)
                self.kill_redis_server(pid)


        # print(f"Successfully closed all redis servers on ports {self.start_port} to {self.end_port}")
        print(f"Successfully closed all open redis servers")

        try:
            os.remove(self.running_logfile)
        except FileNotFoundError:
            pass
        self.terminate_slips()
        return

    def get_pid_of_redis_server(self, port: int) -> str:
        """
        Gets the pid of the redis server running on this port
        Returns str(port) or false if there's no redis-server running on this port
        """
        cmd = 'ps aux | grep redis-server'
        cmd_output = os.popen(cmd).read()
        for line in cmd_output.splitlines():
            if str(port) in line:
                pid = line.split()[1]
                return pid
        return False

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


    def add_metadata(self):
        """
        Create a metadata dir output/metadata/ that has a copy of slips.conf, whitelist.conf, current commit and date
        """
        if not self.enable_metadata:
            return

        metadata_dir = os.path.join(self.args.output, 'metadata')
        try:
            os.mkdir(metadata_dir)
        except FileExistsError:
            # if the file exists it will be overwritten
            pass

        # Add a copy of slips.conf
        config_file = self.args.config or 'config/slips.conf'
        shutil.copy(config_file, metadata_dir)

        # Add a copy of whitelist.conf
        whitelist = self.conf.whitelist_path()
        shutil.copy(whitelist, metadata_dir)

        branch_info = utils.get_branch_info()
        commit, branch = None, None
        if branch_info != False:
            # it's false when we're in docker because there's no .git/ there
            commit, branch = branch_info[0], branch_info[1]

        now = datetime.now()
        now = utils.convert_format(now, utils.alerts_format)

        self.info_path = os.path.join(metadata_dir, 'info.txt')

        with open(self.info_path, 'w') as f:
            f.write(f'Slips version: {self.version}\n'
                    f'File: {self.input_information}\n'
                    f'Branch: {branch}\n'
                    f'Commit: {commit}\n'
                    f'Slips start date: {now}\n'
                    )

        print(f'[Main] Metadata added to {metadata_dir}')
        return self.info_path

    def kill(self, module_name, INT=False):
        sig = signal.SIGINT if INT else signal.SIGKILL
        try:
            pid = int(self.PIDs[module_name])
            os.kill(pid, sig)
        except (KeyError, ProcessLookupError):
            # process hasn't started yet
            pass

    def kill_all(self, PIDs):
        for module in PIDs:
            if module not in self.PIDs:
                # modules the are last to kill aren't always started and there in self.PIDs
                # ignore them
                continue

            self.kill(module)
            self.print_stopped_module(module)

    def stop_core_processes(self):
        self.kill('Input')

        if self.mode == 'daemonized':
            # when using -D, we kill the processes because
            # the queues are not there yet to send stop msgs
            for process in (
                        'ProfilerProcess',
                        'logsProcess',
                        'OutputProcess'

            ):
                self.kill(process, INT=True)

        else:
            # Send manual stops to the processes using queues
            stop_msg = 'stop_process'
            self.profilerProcessQueue.put(stop_msg)
            self.outputqueue.put(stop_msg)
            if hasattr(self, 'logsProcessQueue'):
                self.logsProcessQueue.put(stop_msg)


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
        try:
            self.input_information = self.input_information[
                : self.input_information.index('.')
            ]
        except ValueError:
            # it's a zeek dir
            pass
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
        delete = self.conf.delete_zeek_files()
        if delete:
            shutil.rmtree(self.zeek_folder)

    def green(self, txt):
        """
        returns the text in green
        """
        return colored(txt, "green")


    def print_stopped_module(self, module):
        self.PIDs.pop(module, None)
        # all text printed in green should be wrapped in the following

        modules_left = len(list(self.PIDs.keys()))
        # to vertically align them when printing
        module += ' ' * (20 - len(module))
        print(
            f'\t{self.green(module)} \tStopped. '
            f'{self.green(modules_left)} left.'
        )

    def get_already_stopped_modules(self):
        already_stopped_modules = []
        for module, pid in self.PIDs.items():
            try:
                # signal 0 is used to check if the pid exists
                os.kill(int(pid), 0)
            except ProcessLookupError:
                # pid doesn't exist because module already stopped
                # to be able to remove it's pid from the dict
                already_stopped_modules.append(module)
        return already_stopped_modules

    def warn_about_pending_modules(self, finished_modules):
        # exclude the module that are already stopped from the pending modules
        pending_modules = [
            module
            for module in list(self.PIDs.keys())
            if module not in finished_modules
        ]
        if not len(pending_modules):
            return
        print(
            f'\n[Main] The following modules are busy working on your data.'
            f'\n\n{pending_modules}\n\n'
            'You can wait for them to finish, or you can '
            'press CTRL-C again to force-kill.\n'
        )
        return True

    def set_analysis_end_date(self):
        """
        Add the analysis end date to the metadata file and
        the db for the web inerface to display
        """
        self.enable_metadata = self.conf.enable_metadata()
        end_date = utils.convert_format(datetime.now(), utils.alerts_format)
        __database__.set_input_metadata({'analysis_end': end_date})
        if self.enable_metadata:
            # add slips end date in the metadata dir
            try:
                with open(self.info_path, 'a') as f:
                    f.write(f'Slips end date: {end_date}\n')
            except (NameError, AttributeError):
                pass
        return end_date

    def should_kill_all_modules(self, function_start_time, wait_for_modules_to_finish) -> bool:
        """
        checks if x minutes has passed since the start of the function
        :param wait_for_modules_to_finish: time in mins to wait before force killing all modules
                                            defined by wait_for_modules_to_finish in slips.conf
        """
        now = datetime.now()
        diff = utils.get_time_diff(function_start_time, now, return_type='minutes')
        return True if diff >= wait_for_modules_to_finish else False


    def shutdown_gracefully(self):
        """
        Wait for all modules to confirm that they're done processing
        or kill them after 15 mins
        """
        # 15 mins from this time, all modules should be killed
        function_start_time = datetime.now()
        try:
            if not self.args.stopdaemon:
                print('\n' + '-' * 27)
            print('Stopping Slips')

            wait_for_modules_to_finish  = self.conf.wait_for_modules_to_finish()
            # close all tws
            __database__.check_TW_to_close(close_all=True)

            # set analysis end date
            end_date = self.set_analysis_end_date()

            start_time = __database__.get_slips_start_time()
            analysis_time = utils.get_time_diff(start_time, end_date, return_type='minutes')
            print(f'[Main] Analysis finished in {analysis_time:.2f} minutes')

            # Stop the modules that are subscribed to channels
            __database__.publish_stop()

            finished_modules = []

            # get dict of PIDs spawned by slips
            self.PIDs = __database__.get_PIDs()

            # we don't want to kill this process
            self.PIDs.pop('slips.py', None)

            if self.mode == 'daemonized':
                profilesLen = __database__.getProfilesLen()
                self.daemon.print(f'Total analyzed IPs: {profilesLen}.')


            modules_to_be_killed_last = {
                'EvidenceProcess',
                'Blocking',
                'Exporting Alerts',
            }

            self.stop_core_processes()
            # only print that modules are still running once
            warning_printed = False

            # timeout variable so we don't loop forever
            # give slips enough time to close all modules - make sure
            # all modules aren't considered 'busy' when slips stops
            max_loops = 430

            # loop until all loaded modules are finished
            # in the case of -S, slips doesn't even start the modules,
            # so they don't publish in finished_modules. we don't need to wait for them we have to kill them
            if not self.args.stopdaemon:
                #  modules_to_be_killed_last are ignored when they publish a msg in finished modules channel,
                # we will kill them aletr, so we shouldn't be looping and waiting for them to get outta the loop
                slips_processes = len(list(self.PIDs.keys())) - len(modules_to_be_killed_last)

                try:
                    while (
                        len(finished_modules) < slips_processes  and max_loops != 0
                    ):
                        # print(f"Modules not finished yet {set(loaded_modules) - set(finished_modules)}")
                        try:
                            message = self.c1.get_message(timeout=0.00000001)
                        except NameError:
                            continue

                        if message and message['data'] in ('stop_process', 'stop_slips'):
                            continue

                        if utils.is_msg_intended_for(message, 'finished_modules'):
                            # all modules must reply with their names in this channel after
                            # receiving the stop_process msg
                            # to confirm that all processing is done and we can safely exit now
                            module_name = message['data']

                            if module_name in modules_to_be_killed_last:
                                # we should kill these modules the very last, or else we'll miss evidence generated
                                # right before slips stops
                                continue


                            if module_name not in finished_modules:
                                finished_modules.append(module_name)
                                self.kill(module_name)
                                self.print_stopped_module(module_name)

                                # some modules publish in finished_modules channel before slips.py starts listening,
                                # but they finished gracefully.
                                # remove already stopped modules from PIDs dict
                                for module in self.get_already_stopped_modules():
                                    finished_modules.append(module)
                                    self.print_stopped_module(module)

                        max_loops -= 1
                        # after reaching the max_loops and before killing the modules that aren't finished,
                        # make sure we're not processing
                        # the logical flow is self.pids should be empty by now as all modules
                        # are closed, the only ones left are the ones we want to kill last
                        if len(self.PIDs) > len(modules_to_be_killed_last) and max_loops < 2:
                            if not warning_printed and self.warn_about_pending_modules(finished_modules):
                                if 'Update Manager' not in finished_modules:
                                    print(
                                        f"[Main] Update Manager may take several minutes "
                                        f"to finish updating 45+ TI files."
                                    )
                                warning_printed = True

                            # -t flag is only used in integration tests,
                            # so we don't care about the modules finishing their job when testing
                            # instead, kill them
                            if self.args.testing:
                                break

                            # delay killing unstopped modules until all of them
                            # are done processing
                            max_loops += 1

                            # checks if 15 minutes has passed since the start of the function
                            if self.should_kill_all_modules(function_start_time, wait_for_modules_to_finish):
                                print(f"Killing modules that took more than "
                                      f"{wait_for_modules_to_finish} mins to finish.")
                                break

                except KeyboardInterrupt:
                    # either the user wants to kill the remaining modules (pressed ctrl +c again)
                    # or slips was stuck looping for too long that the os sent an automatic sigint to kill slips
                    # pass to kill the remaining modules
                    pass

            # modules that aren't subscribed to any channel will always be killed and not stopped
            # comes here if the user pressed ctrl+c again
            self.kill_all(self.PIDs.copy())
            self.kill_all(modules_to_be_killed_last)

            # save redis database if '-s' is specified
            if self.args.save:
                self.save_the_db()

            # if store_a_copy_of_zeek_files is set to yes in slips.conf,
            # copy the whole zeek_files dir to the output dir
            self.store_zeek_dir_copy()

            # if delete_zeek_files is set to yes in slips.conf,
            # delete zeek_files/ dir
            self.delete_zeek_files()

            if self.mode == 'daemonized':
                # if slips finished normally without stopping the daemon with -S
                # then we need to delete the pidfile
                self.daemon.delete_pidfile()

            os._exit(-1)
        except KeyboardInterrupt:
            return False

    def get_open_redis_servers(self) -> dict:
        """
        Returns the dict of PIDs and ports of the redis servers started by slips
        """
        self.open_servers_PIDs = {}
        try:
            with open(self.running_logfile, 'r') as f:
                for line in f.read().splitlines():
                    # skip comments
                    if (
                        line.startswith('#')
                        or line.startswith('Date')
                        or len(line) < 3
                    ):
                        continue
                    line = line.split(',')
                    pid, port = line[3], line[2]
                    self.open_servers_PIDs[pid] = port
            return self.open_servers_PIDs
        except FileNotFoundError:
            # print(f"Error: {self.running_logfile} is not found. Can't kill open servers. Stopping.")
            return {}

    def print_open_redis_servers(self):
        """
        Returns a dict {counter: (used_port,pid) }
        """
        open_servers = {}
        to_print = f"Choose which one to kill [0,1,2 etc..]\n" \
                   f"[0] Close all Redis servers\n"
        there_are_ports_to_print = False
        try:
            with open(self.running_logfile, 'r') as f:
                line_number = 0
                for line in f.read().splitlines():
                    # skip comments
                    if (
                        line.startswith('#')
                        or line.startswith('Date')
                        or len(line) < 3
                    ):
                        continue
                    line_number += 1
                    line = line.split(',')
                    file, port, pid = line[1], line[2], line[3]
                    there_are_ports_to_print = True
                    to_print += f"[{line_number}] {file} - port {port}\n"
                    open_servers[line_number] = (port, pid)
        except FileNotFoundError:
            print(f"{self.running_logfile} is not found. Can't get open redis servers. Stopping.")
            return False

        if there_are_ports_to_print:
            print(to_print)
        else:
            print(f"No open redis servers in {self.running_logfile}")

        return open_servers


    def get_port_of_redis_server(self, pid: str):
        """
        returns the port of the redis running on this pid
        """
        cmd = 'ps aux | grep redis-server'
        cmd_output = os.popen(cmd).read()
        for line in cmd_output.splitlines():
            if str(pid) in line:
                port = line.split(':')[-1]
                return port
        return False


    def flush_redis_server(self, pid: str='', port: str=''):
        """
        Flush the redis server on this pid, only 1 param should be given, pid or port
        :param pid: can be False if port is given
        Gets the pid of the port is not given
        """
        if not port and not pid:
            return False

        # sometimes the redis port is given, no need to get it manually
        if not port and pid:
            if not hasattr(self, 'open_servers_PIDs'):
                self.get_open_redis_servers()
            port = self.open_servers_PIDs.get(str(pid), False)
            if not port:
                # try to get the port using a cmd
                port = self.get_port_of_redis_server(pid)
        port = str(port)

        # clear the server opened on this port
        try:
            # if connected := __database__.connect_to_redis_server(port):
            # noinspection PyTypeChecker
            #todo move this to the db
            r = redis.StrictRedis(
                    host='localhost',
                    port=port,
                    db=0,
                    charset='utf-8',
                    socket_keepalive=True,
                    decode_responses=True,
                    retry_on_timeout=True,
                    health_check_interval=20,
                    )
            r.flushall()
            r.flushdb()
            r.script_flush()
            return True
        except redis.exceptions.ConnectionError:
            # server already killed!
            return False


    def kill_redis_server(self, pid):
        """
        Kill the redis server on this pid
        """
        try:
            pid = int(pid)
        except ValueError:
            # The server was killed before logging its PID
            # the pid of it is 'not found'
            return False

        # signal 0 is to check if the process is still running or not
        # it returns 1 if the process used_redis_servers.txt exited
        try:
            # check if the process is still running
            while os.kill(pid, 0) != 1:
                # sigterm is 9
                os.kill(pid, 9)
        except ProcessLookupError:
            # ProcessLookupError: process already exited, sometimes this exception is raised
            # but the process is still running, keep trying to kill it
            return True
        except PermissionError:
            # PermissionError happens when the user tries to close redis-servers
            # opened by root while he's not root,
            # or when he tries to close redis-servers
            # opened without root while he's root
            return False
        return True

    def remove_old_logline(self, redis_port):
        """
        This function should be called after adding a new duplicate line with redis_port
        The only line with redis_port will be the last line, remove all the ones above
        """
        redis_port = str(redis_port)
        tmpfile = 'tmp_running_slips_log.txt'
        with open(self.running_logfile, 'r') as logfile:
            with open(tmpfile, 'w') as tmp:
                all_lines = logfile.read().splitlines()
                # we want to delete the old log line containing this port
                # but leave the new one (the last one)
                for line in all_lines[:-1]:
                    if redis_port not in line:
                        tmp.write(f'{line}\n')

                # write the last line
                tmp.write(all_lines[-1]+'\n')
        # replace file with original name
        os.replace(tmpfile, self.running_logfile)


    def remove_server_from_log(self, redis_port):
        """ deletes the server running on the given pid from running_slips_logs """
        redis_port = str(redis_port)
        tmpfile = 'tmp_running_slips_log.txt'
        with open(self.running_logfile, 'r') as logfile:
            with open(tmpfile, 'w') as tmp:
                all_lines = logfile.read().splitlines()
                # delete the line using that port
                for line in all_lines:
                    if redis_port not in line:
                        tmp.write(f'{line}\n')

        # replace file with original name
        os.replace(tmpfile, self.running_logfile)


    def close_open_redis_servers(self):
        """
        Function to close unused open redis-servers based on what the user chooses
        """
        if not hasattr(self, 'open_servers_PIDs'):
            # fill the dict
            self.get_open_redis_servers()

        try:
            # open_servers {counter: (port,pid),...}}
            open_servers:dict = self.print_open_redis_servers()
            if not open_servers:
                self.terminate_slips()

            server_to_close = input()
            # close all ports in running_slips_logs.txt and in our supported range
            if server_to_close == '0':
                self.close_all_ports()

            elif len(open_servers) > 0:
                # close the given server number
                try:
                    pid = open_servers[int(server_to_close)][1]
                    port = open_servers[int(server_to_close)][0]
                    if self.flush_redis_server(pid=pid) and self.kill_redis_server(pid):
                        print(f"Killed redis server on port {port}.")
                    else:
                        print(f"Redis server running on port {port} "
                              f"is either already killed or you don't have "
                              f"enough permission to kill it.")
                    self.remove_server_from_log(port)
                except (KeyError, ValueError):
                    print(f"Invalid input {server_to_close}")

        except KeyboardInterrupt:
            pass
        self.terminate_slips()


    def is_debugger_active(self) -> bool:
        """Return if the debugger is currently active"""
        gettrace = getattr(sys, 'gettrace', lambda: None)
        return gettrace() is not None

    def prepare_output_dir(self):
        """
        :param self.input_information: either an interface or a filename (wlp3s0, sample.pcap, zeek_dir/ etc.)
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
                    try:
                        if os.path.isfile(file_path):
                            os.remove(file_path)
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path)
                    except Exception as ex:
                        pass
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

        # print(f'[Main] Storing Slips logs in {self.args.output}')


    def log_redis_server_PID(self, redis_port, redis_pid):
        now = utils.convert_format(datetime.now(), utils.alerts_format)
        try:
            # used in case we need to remove the line using 6379 from running logfile
            with open(self.running_logfile, 'a') as f:
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
            os.remove(self.running_logfile)
            open(self.running_logfile, 'w').close()
            self.log_redis_server_PID(redis_port, redis_pid)

        if redis_port == 6379:
            # remove the old logline using this port
            self.remove_old_logline(6379)

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
        if pid := self.get_pid_of_redis_server(redis_port):
            self.flush_redis_server(pid=pid)
            self.kill_redis_server(pid)

        if not __database__.load(self.args.db):
            print(f'Error loading the database {self.args.db}')
        else:
            # to be able to use running_slips_info later as a non-root user,
            # we shouldn't modify it as root

            self.input_information = os.path.basename(self.args.db)
            redis_pid = self.get_pid_of_redis_server(redis_port)
            self.zeek_folder = '""'
            self.log_redis_server_PID(redis_port, redis_pid)
            self.remove_old_logline(redis_port)

            print(
                f'{self.args.db} loaded successfully.\n'
                f'Run ./kalipso.sh and choose port {redis_port}'
            )
            # __database__.disable_redis_persistence()

        self.terminate_slips()

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

    def check_input_type(self) -> tuple:
        """
        returns line_type, input_type, input_information
        supported input types are:
            interface, argus, suricata, zeek, nfdump, db
        supported self.input_information:
            given filepath, interface or type of line given in stdin
        """
        # only defined in stdin lines
        line_type = False
        # -I
        if self.args.interface:
            input_information = self.args.interface
            input_type = 'interface'
            # return input_type, self.input_information
            return input_type, input_information, line_type

        if self.args.db:
            self.load_db()
            return

        if not self.args.filepath:
            print('[Main] You need to define an input source.')
            sys.exit(-1)
        # -f file/stdin-type
        input_information = self.args.filepath
        if os.path.exists(input_information):
            input_type = self.get_input_file_type(input_information)
        else:
            input_type, line_type = self.handle_flows_from_stdin(
                input_information
            )

        return input_type, input_information, line_type

    def check_given_flags(self):
        """
        check the flags that don't require starting slips
        for ex: clear db, clearing the blocking chain, killing all servers, stopping the daemon, etc.
        """

        if self.args.help:
            self.print_version()
            arg_parser = self.conf.get_parser(help=True)
            arg_parser.parse_arguments()
            arg_parser.print_help()
            self.terminate_slips()

        if self.args.interface and self.args.filepath:
            print('Only -i or -f is allowed. Stopping slips.')
            self.terminate_slips()


        if (self.args.save or self.args.db) and os.getuid() != 0:
            print('Saving and loading the database requires root privileges.')
            self.terminate_slips()

        if (self.args.verbose and int(self.args.verbose) > 3) or (
            self.args.debug and int(self.args.debug) > 3
        ):
            print('Debug and verbose values range from 0 to 3.')
            self.terminate_slips()

        # Check if redis server running
        if not self.args.killall and self.check_redis_database() is False:
            print('Redis database is not running. Stopping Slips')
            self.terminate_slips()

        if self.args.config and not os.path.exists(self.args.config):
            print(f"{self.args.config} doesn't exist. Stopping Slips")
            self.terminate_slips()

        if self.args.interface:
            interfaces = psutil.net_if_addrs().keys()
            if self.args.interface not in interfaces:
                print(f"{self.args.interface} is not a valid interface. Stopping Slips")
                self.terminate_slips()


        # Clear cache if the parameter was included
        if self.args.clearcache:
            print('Deleting Cache DB in Redis.')
            self.clear_redis_cache_database()
            self.input_information = ''
            self.zeek_folder = ''
            self.log_redis_server_PID(6379, self.get_pid_of_redis_server(6379))
            self.terminate_slips()


        # Clear cache if the parameter was included
        if self.args.blocking and not self.args.interface:
            print('Blocking is only allowed when running slips using an interface.')
            self.terminate_slips()

        # kill all open unused redis servers if the parameter was included
        if self.args.killall:
            self.close_open_redis_servers()
            self.terminate_slips()

        if self.args.version:
            self.print_version()
            self.terminate_slips()

        if (
            self.args.interface
            and self.args.blocking
            and os.geteuid() != 0
        ):
            # If the user wants to blocks, we need permission to modify iptables
            print(
                'Run Slips with sudo to enable the blocking module.'
            )
            self.terminate_slips()

        if self.args.clearblocking:
            if os.geteuid() != 0:
                print(
                    'Slips needs to be run as root to clear the slipsBlocking chain. Stopping.'
                )
                self.terminate_slips()
            else:
                # start only the blocking module process and the db
                from slips_files.core.database.database import __database__
                from multiprocessing import Queue, active_children
                from modules.blocking.blocking import Module

                blocking = Module(Queue())
                blocking.start()
                blocking.delete_slipsBlocking_chain()
                # kill the blocking module manually because we can't
                # run shutdown_gracefully here (not all modules has started)
                for child in active_children():
                    child.kill()
                self.terminate_slips()


        # Check if user want to save and load a db at the same time
        if self.args.save and self.args.db:
            print("Can't use -s and -d together")
            self.terminate_slips()

    def set_input_metadata(self):
        """
        save info about name, size, analysis start date in the db
        """
        now = utils.convert_format(datetime.now(), utils.alerts_format)
        to_ignore = self.conf.get_disabled_modules(self.input_type)

        info = {
            'slips_version': self.version,
            'name': self.input_information,
            'analysis_start': now,
            'disabled_modules': json.dumps(to_ignore),
            'output_dir': self.args.output,
            'input_type': self.input_type,
        }

        if hasattr(self, 'zeek_folder'):
            info.update({
                'zeek_dir': self.zeek_folder
            })

        size_in_mb = '-'
        if self.args.filepath not in (False, None) and os.path.exists(self.args.filepath):
            size = os.stat(self.args.filepath).st_size
            size_in_mb = float(size) / (1024 * 1024)
            size_in_mb = format(float(size_in_mb), '.2f')

        info.update({
            'size_in_MB': size_in_mb,
        })
        # analysis end date will be set in shutdown_gracefully
        # file(pcap,netflow, etc.) start date will be set in
        __database__.set_input_metadata(info)


    def setup_print_levels(self):
        """
        setup debug and verose levels
        """
        # Any verbosity passed as parameter overrides the configuration. Only check its value
        if self.args.verbose == None:
            self.args.verbose = self.conf.verbose()

        # Limit any verbosity to > 0
        if self.args.verbose < 1:
            self.args.verbose = 1

        # Any deug passed as parameter overrides the configuration. Only check its value
        if self.args.debug == None:
            self.args.debug = self.conf.debug()

        # Limit any debuggisity to > 0
        if self.args.debug < 0:
            self.args.debug = 0


    def check_output_redirection(self) -> tuple:
        """
        Determine where slips will place stdout, stderr and logfile based on slips mode
        """
        # lsof will provide a list of all open fds belonging to slips
        command = f'lsof -p {self.pid}'
        result = subprocess.run(command.split(), capture_output=True)
        # Get command output
        output = result.stdout.decode('utf-8')
        # if stdout is being redirected we'll find '1w' in one of the lines
        # 1 means stdout, w means write mode
        # by default, stdout is not redirected
        current_stdout = ''
        for line in output.splitlines():
            if '1w' in line:
                # stdout is redirected, get the file
                current_stdout = line.split(' ')[-1]
                break

        if self.mode == 'daemonized':
            stderr = self.daemon.stderr
            slips_logfile = self.daemon.stdout
        else:
            stderr = os.path.join(self.args.output, 'errors.log')
            slips_logfile = os.path.join(self.args.output, 'slips.log')
        return (current_stdout, stderr, slips_logfile)

    def print_version(self):
        slips_version = f'Slips. Version {self.green(self.version)}'
        branch_info = utils.get_branch_info()
        if branch_info != False:
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

    def start(self):
        """Main Slips Function"""
        try:

            self.print_version()
            print('https://stratosphereips.org')
            print('-' * 27)

            """
            Import modules here because if user wants to run "./slips.py --help" it should never throw error. 
            """
            from multiprocessing import Queue
            from slips_files.core.inputProcess import InputProcess
            from slips_files.core.outputProcess import OutputProcess
            from slips_files.core.profilerProcess import ProfilerProcess
            from slips_files.core.guiProcess import GuiProcess
            from slips_files.core.logsProcess import LogsProcess
            from slips_files.core.evidenceProcess import EvidenceProcess

            self.setup_print_levels()
            ##########################
            # Creation of the threads
            ##########################

            # get the port that is going to be used for this instance of slips
            if self.args.port:
                self.redis_port = int(self.args.port)
                # close slips if port is in use
                self.check_if_port_is_in_use(self.redis_port)
            elif self.args.multiinstance:
                self.redis_port = self.get_random_redis_port()
                if not self.redis_port:
                    # all ports are unavailable
                    inp = input("Press Enter to close all ports.\n")
                    if inp == '':
                        self.close_all_ports()
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
            current_stdout, stderr, slips_logfile = self.check_output_redirection()
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
            redis_pid = self.get_pid_of_redis_server(self.redis_port)
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

            self.print(f'Using redis server on port: {self.green(self.redis_port)}', 1, 0)
            self.print(f'Started {self.green("Main")} process [PID {self.green(self.pid)}]', 1, 0)
            self.print(f'Started {self.green("Output Process")} [PID {self.green(output_process.pid)}]', 1, 0)
            self.print('Starting modules', 1, 0)

            # if slips is given a .rdb file, don't load the modules as we don't need them
            if not self.args.db:
                # update local files before starting modules
                self.update_local_TI_files()
                self.load_modules()

            # self.start_gui_process()
            if self.args.webinterface:
                self.start_webinterface()

            # call shutdown_gracefully on sigterm
            def sig_handler(sig, frame):
                self.shutdown_gracefully()
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
                f'Started {self.green("Evidence Process")} '
                f'[PID {self.green(evidence_process.pid)}]', 1, 0
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
                f'Started {self.green("Profiler Process")} '
                f'[PID {self.green(profiler_process.pid)}]', 1, 0
            )
            __database__.store_process_PID(
                'Profiler',
                int(profiler_process.pid)
            )

            self.c1 = __database__.subscribe('finished_modules')
            self.enable_metadata = self.conf.enable_metadata()

            if self.enable_metadata:
                self.info_path = self.add_metadata()

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
                f'Started {self.green("Input Process")} '
                f'[PID {self.green(inputProcess.pid)}]', 1, 0
            )
            __database__.store_process_PID(
                'Input Process',
                int(inputProcess.pid)
            )
            self.zeek_folder = inputProcess.zeek_folder
            self.set_input_metadata()

            if self.conf.use_p2p() and not self.args.interface:
                self.print('Warning: P2P is only supported using an interface. Disabled P2P.')

            # warn about unused open redis servers
            open_servers = len(self.get_open_redis_servers())
            if open_servers > 1:
                self.print(
                    f'Warning: You have {open_servers} '
                    f'redis servers running. '
                    f'Run Slips with --killall to stop them.'
                )

            hostIP = self.store_host_ip()

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
                    self.shutdown_gracefully()

                # Sleep some time to do routine checks
                time.sleep(sleep_time)

                # if you remove the below logic anywhere before the above sleep() statement
                # it will try to get the return value very quickly before
                # the webinterface thread sets it
                self.check_if_webinterface_started()

                modified_ips_in_the_last_tw, modified_profiles = self.update_slips_running_stats()
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
                    if hostIP := self.get_host_ip():
                        __database__.set_host_ip(hostIP)

                # these are the cases where slips should be running non-stop
                if self.is_debugger_active() or self.input_type == 'stdin' or is_interface:
                    continue

                # Reaches this point if we're running Slips on a file.
                # countdown until slips stops if no TW modifications are happening
                if modified_ips_in_the_last_tw == 0:
                    # waited enough. stop slips
                    if intervals_to_wait == 0:
                        self.shutdown_gracefully()

                    # If there were no modified TWs in the last timewindow time,
                    # then start counting down
                    intervals_to_wait -= 1


                __database__.pubsub.check_health()
        except KeyboardInterrupt:
            # the EINTR error code happens if a signal occurred while the system call was in progress
            # comes here if zeek terminates while slips is still working
            self.shutdown_gracefully()


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
                f"Trying to stop Slips daemon.\n"
                f"Daemon is not running."
            )
        else:
            daemon.stop()
            # it takes about 5 seconds for the stop_slips msg to arrive in the channel, so give slips time to stop
            time.sleep(3)
            print('Daemon stopped.')
    elif slips.args.daemon:
        daemon = Daemon(slips)
        if daemon.pid != None:
            print(f'pidfile {daemon.pidfile} already exists. Daemon already running?')
        else:
            print('Slips daemon started.')
            daemon.start()
    else:
        # interactive mode
        slips.start()
