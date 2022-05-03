#!/usr/bin/env python3
# Slips. A machine-learning Intrusion Detection System
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

import configparser
import argparse
import sys
import redis
import os
import time
import shutil
from datetime import datetime
import socket
import warnings
from modules.UpdateManager.update_file_manager import UpdateFileManager
import json
import pkgutil
import inspect
import modules
import importlib
from slips_files.common.abstracts import Module
from slips_files.common.argparse import ArgumentParser
import errno
import subprocess
from slips_files.common.abstracts import Module
from slips_files.core.database import __database__
import sys, os, time
from signal import SIGTERM
version = '0.7.3'

# Ignore warnings on CPU from tensorflow
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
# Ignore warnings in general
warnings.filterwarnings('ignore')
#---------------------


class Daemon():
    description = 'This module runs when slips is in daemonized mode'

    def __init__(self, slips):
        # to use read_configurations defined in Main
        self.slips = slips
        self.read_configuration()
        # Get the pid from pidfile
        try:
            with open(self.pidfile,'r') as pidfile:
                self.pid = int(pidfile.read().strip())
        except IOError:
            self.pid = None

    def print(self, text):
        """ Prints output to logsfile specified in slips.conf"""
        with open(self.logsfile,'a') as f:
            f.write(f'{text}\n')

    def setup_std_streams(self):
        """ Create standard steam files and dirs and clear them """

        std_streams = [self.stderr, self.stdout, self.logsfile]
        for file in std_streams:
            # we don't want to clear the logfile when we stop the daemon using -S
            if '-S' in sys.argv and file == self.stdout:
                continue
            # create the file if it doesn't exist or clear it if it exists
            try:
                open(file,'w').close()
            except (FileNotFoundError,NotADirectoryError):
                os.mkdir(os.path.dirname(file))
                open(file,'w').close()

    def read_configuration(self):
        """ Read the configuration file to get stdout,stderr, logsfile path."""
        self.config = self.slips.read_conf_file()

        try:
            # output dir to store running.log and error.log
            self.output_dir = self.config.get('modes', 'output_dir')
            if not self.output_dir.endswith('/'): self.output_dir = self.output_dir+'/'
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.output_dir = '/var/log/slips/'

        try:
            # this file has info about the daemon, started, ended, pid , etc.. by default it's the same as stdout
            self.logsfile = self.config.get('modes', 'logsfile')
            self.logsfile = self.output_dir + self.logsfile
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.logsfile = '/var/log/slips/running.log'

        try:
            self.stdout = self.config.get('modes', 'stdout')
            self.stdout = self.output_dir + self.stdout
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.stdout = '/var/log/slips/running.log'

        try:
            self.stderr = self.config.get('modes', 'stderr')
            self.stderr  = self.output_dir + self.stderr
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.stderr = '/var/log/slips/errors.log'

        # this is a conf file used to store the pid of the daemon and is deleted when the daemon stops
        self.pidfile = '/etc/slips/pidfile'
        # we don't use it anyway
        self.stdin='/dev/null'

        # this is where alerts.log and alerts.json are stored, in interactive mode
        # they're stored in output/ dir in slips main dir
        # in daemonized mode they're stored in the same dir as running.log and error.log
        self.slips.alerts_default_path = self.output_dir

        self.setup_std_streams()
        # when stoppng the daemon don't log this info again
        if '-S' not in sys.argv:
            self.print(f"Logsfile: {self.logsfile}\n"
                       f"pidfile:{self.pidfile}\n"
                       f"stdin : {self.stdin}\n"
                       f"stdout: {self.stdout}\n"
                       f"stderr: {self.stderr}\n")
            self.print("Done reading configuration and setting up files.\n")

    def terminate(self):
        """ Deletes the pidfile to mark the daemon as closed """

        self.print("Deleting pidfile...")

        if os.path.exists(self.pidfile):
            os.remove(self.pidfile)
            self.print("pidfile deleted.")
        else:
            self.print(f"Can't delete pidfile, {self.pidfile} doesn't exist.")
            # if an error occured it will be written in logsfile
            self.print("Either Daemon stopped normally or an error occurred.")
            self.print("pidfile needs to be deleted before running Slips again.")

    def daemonize(self):
        """
        Does the Unix double-fork to create a daemon
        """
        # double fork explaination
        # https://stackoverflow.com/questions/881388/what-is-the-reason-for-performing-a-double-fork-when-creating-a-daemon

        try:
            self.pid = os.fork()
            if self.pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError as e:
            sys.stderr.write(f"Fork #1 failed: {e.errno} {e.strerror}\n")
            self.print(f"Fork #1 failed: {e.errno} {e.strerror}\n")
            sys.exit(1)

        # os.chdir("/")
        # dissociate the daemon from its controlling terminal.
        # calling setsid means that this child will be the session leader of the new session
        os.setsid()
        os.umask(0)

        # If you want to prevent a process from acquiring a tty, the process shouldn't be the session leader
        # fork again so that the second child is no longer a session leader
        try:
            self.pid = os.fork()
            if self.pid > 0:
                # exit from second parent (aka first child)
                sys.exit(0)
        except OSError as e:
            sys.stderr.write(f"Fork #2 failed: {e.errno} {e.strerror}\n")
            self.print(f"Fork #2 failed: {e.errno} {e.strerror}\n")
            sys.exit(1)

        # Now this code is run from the daemon
        # A daemon must close it's input and output file descriptors otherwise, it would still
        # be attached to the terminal it was started in.
        sys.stdout.flush()
        sys.stderr.flush()

        # redirect standard file descriptors
        with open(self.stdin, 'r') as stdin,\
            open(self.stdout, 'a+') as stdout,\
            open(self.stderr,'a+') as stderr:
            os.dup2(stdin.fileno(), sys.stdin.fileno())
            os.dup2(stdout.fileno(), sys.stdout.fileno())
            os.dup2(stderr.fileno(), sys.stderr.fileno())

        # write the pid of the daemon to a file so we can check if it's already opened before re-opening
        self.pid = str(os.getpid())
        with open(self.pidfile,'w+') as pidfile:
            pidfile.write(self.pid)

        # Register a function to be executed if sys.exit() is called or the main module’s execution completes
        # atexit.register(self.terminate)

    def start(self):
        """ Main function, Starts the daemon and starts slips normally."""
        self.print("Daemon starting...")
        # Check for a pidfile to see if the daemon is already running
        if self.pid:
            self.print(f"pidfile {self.pid} already exists. Daemon already running?")
            sys.exit(1)

        # Start the daemon
        self.daemonize()

        # any code run after daemonizing will be run inside the daemon
        self.print(f"Slips Daemon is running. [PID {self.pid}]")
        # tell Main class that we're running in daemonized mode
        self.slips.set_mode('daemonized', daemon=self)
        # start slips normally
        self.slips.start()

    def stop(self):
        """Stop the daemon"""
        if not self.pid:
            self.print(f"Trying to stop Slips daemon. PID {self.pid} doesn't exist. Daemon not running.")
            return

        # Try killing the daemon process
        try:
            # delete the pid file
            self.terminate()
            self.print(f"Daemon killed [PID {self.pid}]")
            while 1:
                os.kill(int(self.pid), SIGTERM)
                time.sleep(0.1)
        except OSError as e:
            e = str(e)
            if e.find("No such process") <= 0:
                # some error occured, print it
                self.print(e)

    def restart(self):
        """Restart the daemon"""
        self.print("Daemon restarting...")
        self.stop()
        self.pid = False
        self.start()

class Main():
    def __init__(self):
        # Set up the default path for alerts.log and alerts.json. In our case, it is output folder.
        self.alerts_default_path = 'output/'
        self.mode = 'interactive'

    def read_configuration(self, config, section, name):
        """ Read the configuration file for what slips.py needs. Other processes also access the configuration """
        try:
            return config.get(section, name)
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            return False

    def recognize_host_ip(self):
        """
        Recognize the IP address of the machine
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("1.1.1.1", 80))
            ipaddr_check = s.getsockname()[0]
            s.close()
        except Exception as ex:
            # not connected to the internet
            return None
        return ipaddr_check

    def create_folder_for_logs(self):
        '''
        Create a folder for logs if logs are enabled
        '''
        logs_folder = datetime.now().strftime('%Y-%m-%d--%H-%M-%S')
        if not os.path.exists(logs_folder):
            os.makedirs(logs_folder)
        return logs_folder

    def update_malicious_file(self, outputqueue, config):
        '''
        Update malicious files and store them in database before slips start
        '''
        update_manager = UpdateFileManager(outputqueue, config)
        update_manager.update()

    def check_redis_database(self, redis_host='localhost', redis_port=6379) -> str:
        """
        Check if we have redis-server running
        """
        try:
            r = redis.StrictRedis(host=redis_host, port=redis_port, db=0, charset="utf-8",
                                       decode_responses=True)
            r.ping()
        except Exception as ex:
            print('[DB] Error: Is redis database running? You can run it as: "redis-server --daemonize yes"')
            return False
        return True

    def clear_redis_cache_database(self, redis_host = 'localhost', redis_port = 6379) -> str:
        """
        Clear cache database
        """
        rcache = redis.StrictRedis(host=redis_host, port=redis_port, db=1, charset="utf-8",
                                   decode_responses=True)
        rcache.flushdb()
        return True

    def check_zeek_or_bro(self):
        """
        Check if we have zeek or bro
        """
        if shutil.which('zeek'):
            return 'zeek'
        elif shutil.which('bro'):
            return 'bro'
        return False

    def terminate_slips(self):
        """
        Do all necessary stuff to stop process any clear any files.
        """
        if self.mode == 'daemonized':
            self.daemon.stop()
        sys.exit(-1)

    def load_modules(self, to_ignore):
        """
        Import modules and loads the modules from the 'modules' folder. Is very relative to the starting position of slips
        """

        plugins = dict()
        failed_to_load_modules = 0
        # Walk recursively through all modules and packages found on the . folder.
        # __path__ is the current path of this python program
        for loader, module_name, ispkg in pkgutil.walk_packages(modules.__path__, modules.__name__ + '.'):
            if any(module_name.__contains__(mod) for mod in to_ignore):
                continue
            # If current item is a package, skip.
            if ispkg:
                continue

            # Try to import the module, otherwise skip.
            try:
                # "level specifies whether to use absolute or relative imports. The default is -1 which
                # indicates both absolute and relative imports will be attempted. 0 means only perform
                # absolute imports. Positive values for level indicate the number of parent
                # directories to search relative to the directory of the module calling __import__()."
                module = importlib.import_module(module_name)
            except ImportError as e:
                print("Something wrong happened while importing the module {0}: {1}".format(module_name, e))
                continue

            # Walk through all members of currently imported modules.
            for member_name, member_object in inspect.getmembers(module):
                # Check if current member is a class.
                if inspect.isclass(member_object):
                    if issubclass(member_object, Module) and member_object is not Module:
                        plugins[member_object.name] = dict(obj=member_object, description=member_object.description)

        return plugins,failed_to_load_modules

    def get_cwd(self):
        # Can't use os.getcwd() because slips directory name won't always be Slips plus this way requires less parsing
        for arg in sys.argv:
            if 'slips.py' in arg:
                # get the path preceeding slips.py (may be ../ or  ../../ or '' if slips.py is in the cwd) , this path is where slips.conf will be
                cwd = arg[:arg.index('slips.py')]
                return cwd

    def shutdown_gracefully(self):
        """ Wait for all modules to confirm that they're done processing and then shutdown """

        try:
            print('Stopping Slips')
            # Stop the modules that are subscribed to channels
            __database__.publish_stop()
            # Here we should Wait for any channel if it has still
            # data to receive in its channel
            finished_modules = []
            loaded_modules = self.modules_to_call.keys()
            # get dict of pids spawned by slips
            PIDs = __database__.get_PIDs()
            # timeout variable so we don't loop forever
            max_loops = 130
            # loop until all loaded modules are finished
            while len(finished_modules) < len(loaded_modules) and max_loops != 0:
                # print(f"Modules not finished yet {set(loaded_modules) - set(finished_modules)}")
                message = self.c1.get_message(timeout=0.01)
                if message and message['data'] == 'stop_process':
                    continue
                if message and message['channel'] == 'finished_modules' and type(message['data']) is not int:
                    # all modules must reply with their names in this channel after
                    # receiving the stop_process msg
                    # to confirm that all processing is done and we can safely exit now
                    module_name = message['data']
                    if module_name not in finished_modules:
                        finished_modules.append(module_name)
                        # remove module from the list of opened pids
                        PIDs.pop(module_name)
                        modules_left = len(set(loaded_modules) - set(finished_modules))
                        print(f"\033[1;32;40m{module_name}\033[00m Stopped... \033[1;32;40m{modules_left}\033[00m left.")
                max_loops -=1
            # kill processes that didn't stop after timeout
            for unstopped_proc,pid in PIDs.items():
                try:
                    os.kill(int(pid), 9)
                    print(f'\033[1;32;40m{unstopped_proc}\033[00m Killed.')
                except ProcessLookupError:
                    print(f'\033[1;32;40m{unstopped_proc}\033[00m Already exited.')
            # Send manual stops to the process not using channels
            try:
                self.logsProcessQueue.put('stop_process')
            except (NameError,AttributeError):
                # The logsProcessQueue is not there because we
                # didnt started the logs files (used -l)
                pass
            self.outputProcessQueue.put('stop_process')
            self.profilerProcessQueue.put('stop_process')
            self.inputProcess.terminate()
            if self.mode == 'daemonized':
                profilesLen = str(__database__.getProfilesLen())
                print(f"Total Number of Profiles in DB: {profilesLen}.")
                self.daemon.stop()
            os._exit(-1)
            return
        except KeyboardInterrupt:
            return

    def parse_arguments(self):
        slips_conf_path = str(self.get_cwd()) + 'slips.conf'
        parser = ArgumentParser(usage = "./slips.py -c <configfile> [options] [file ...]",
                                add_help=False)
        parser.add_argument('-c','--config', metavar='<configfile>',action='store',default=slips_conf_path,required=False,
                            help='path to the Slips config file.')
        parser.add_argument('-v', '--verbose',metavar='<verbositylevel>',action='store', required=False, type=int,
                            help='amount of verbosity. This shows more info about the results.')
        parser.add_argument('-e', '--debug', metavar='<debuglevel>',action='store', required=False, type=int,
                            help='amount of debugging. This shows inner information about the program.')
        parser.add_argument('-f', '--filepath',metavar='<file>', action='store',required=False,
                            help='read an Argus binetflow, suricata flow, nfdump, PCAP, or a Zeek folder.')
        parser.add_argument('-i','--interface', metavar='<interface>',action='store', required=False,
                            help='read packets from an interface.')
        parser.add_argument('-l','--nologfiles',action='store_true',required=False,
                            help='do not create log files with all the traffic info and detections.')
        parser.add_argument('-F','--pcapfilter',action='store',required=False,type=str,
                            help='packet filter for Zeek. BPF style.')
        parser.add_argument('-G', '--gui', help='Use the nodejs GUI interface.', required=False, default=False, action='store_true')
        parser.add_argument('-cc','--clearcache',action='store_true', required=False,
                            help='clear a cache database.')
        parser.add_argument('-p', '--blocking',action='store_true',required=False,
                            help='block IPs that connect to the computer. Supported only on Linux.')
        parser.add_argument('-o', '--output', action='store', required=False, default=self.alerts_default_path,
                            help='store alerts.json and alerts.txt in the provided folder.')
        parser.add_argument('-I', '--interactive',required=False, default=False, action='store_true',
                            help="run slips in interactive mode - don't daemonize")
        parser.add_argument('-S', '--stopdaemon',required=False, default=False, action='store_true',
                            help="stop slips daemon")
        parser.add_argument('-R', '--restartdaemon',required=False, default=False, action='store_true',
                            help="restart slips daemon")
        parser.add_argument("-h", "--help", action="help", help="command line help")

        self.args = parser.parse_args()

    def read_conf_file(self):
        # Read the config file name given from the parameters
        # don't use '%' for interpolation.
        self.config = configparser.ConfigParser(interpolation=None)
        try:
            with open(self.args.config) as source:
                self.config.read_file(source)
        except IOError:
            pass
        except TypeError:
            # No conf file provided
            pass
        return self.config

    def set_mode(self, mode, daemon=''):
        """
        Slips has 2 modes, daemonized and interactive, this function sets up the mode so that slips knows in which mode it's operating
        :param mode: daemonized of interavtive
        :param daemon: Daemon() instance
        """
        self.mode = mode
        self.daemon = daemon

    def start(self):
        """ Main Slips Function """

        print('Slips. Version {}'.format(version))
        print('https://stratosphereips.org\n')

        self.read_conf_file()

        # Check if redis server running
        if self.check_redis_database() is False:
            self.terminate_slips()

        # Clear cache if the parameter was included
        if self.args.clearcache:
            print('Deleting Cache DB in Redis.')
            self.clear_redis_cache_database()
            self.terminate_slips()

        # Check the type of input
        if self.args.interface:
            input_information = self.args.interface
            input_type = 'interface'
        elif self.args.filepath:
            input_information = self.args.filepath
            # default value
            input_type = 'file'
            # Get the type of file
            command = 'file ' + input_information
            # Execute command
            cmd_result = subprocess.run(command.split(), stdout=subprocess.PIPE)
            # Get command output
            cmd_result = cmd_result.stdout.decode('utf-8')

            if 'pcap' in cmd_result:
                input_type = 'pcap'
            elif 'dBase' in cmd_result:
                input_type = 'nfdump'
            elif 'CSV' in cmd_result:
                input_type = 'binetflow'
            elif 'directory'in cmd_result:
                input_type = 'zeek_folder'
            else:
                # is a json file, is it a zeek log file or suricata?
                # use first line to determine
                with open(input_information,'r') as f:
                    first_line = f.readline()
                if 'flow_id' in first_line:
                    input_type = 'suricata'
                else:
                    input_type = 'zeek_log_file'
        else:
            print('You need to define an input source.')
            sys.exit(-1)

        # If we need zeek (bro), test if we can run it.
        # Need to be assign to something because we pass it to inputProcess later
        zeek_bro = None
        if input_type == 'pcap' or self.args.interface:
            zeek_bro = self.check_zeek_or_bro()
            if zeek_bro is False:
                # If we do not have bro or zeek, terminate Slips.
                print('no zeek nor bro')
                self.terminate_slips()

        # See if we have the nfdump, if we need it according to the input type
        if input_type == 'nfdump' and shutil.which('nfdump') is None:
            # If we do not have nfdump, terminate Slips.
            self.terminate_slips()

        # set alerts.log and alerts.json default paths,
        # using argparse default= will cause files to be stored in output/ dir even in daemonized mode
        if not self.args.output:
            self.args.output = self.alerts_default_path

        # If the user wants to blocks, the user needs to give a permission to modify iptables
        # Also check if the user blocks on interface, does not make sense to block on files
        if self.args.interface and self.args.blocking:
            print('Allow Slips to block malicious connections. Executing "sudo iptables -N slipsBlocking"')
            os.system('sudo iptables -N slipsBlocking')

        """
        Import modules here because if user wants to run "./slips.py --help" it should never throw error. 
        """
        from multiprocessing import Queue
        from inputProcess import InputProcess
        from outputProcess import OutputProcess
        from profilerProcess import ProfilerProcess
        from guiProcess import GuiProcess
        from logsProcess import LogsProcess
        from evidenceProcess import EvidenceProcess

        # Any verbosity passed as parameter overrides the configuration. Only check its value
        if self.args.verbose == None:
            # Read the verbosity from the config
            try:
                self.args.verbose = int(self.config.get('parameters', 'verbose'))
            except (configparser.NoOptionError, configparser.NoSectionError, NameError, ValueError):
                # There is a conf, but there is no option, or no section or no configuration file specified
                # By default, 1
                self.args.verbose = 1

        # Limit any verbosity to > 0
        if self.args.verbose < 1:
            self.args.verbose = 1

        # Any debuggsity passed as parameter overrides the configuration. Only check its value
        if self.args.debug == None:
            # Read the debug from the config
            try:
                self.args.debug = int(self.config.get('parameters', 'debug'))
            except (configparser.NoOptionError, configparser.NoSectionError, NameError, ValueError):
                # There is a conf, but there is no option, or no section or no configuration file specified
                # By default, 0
                self.args.debug = 0

        # Limit any debuggisity to > 0
        if self.args.debug < 0:
            self.args.debug = 0



        ##########################
        # Creation of the threads
        ##########################
        from slips_files.core.database import __database__
        # Output thread. This thread should be created first because it handles
        # the output of the rest of the threads.
        # Create the queue
        self.outputProcessQueue = Queue()
        # Create the output thread and start it
        outputProcessThread = OutputProcess(self.outputProcessQueue, self.args.verbose, self.args.debug, self.config)
        outputProcessThread.start()

        # Before starting update malicious file
        self.update_malicious_file(self.outputProcessQueue, self.config)
        # Print the PID of the main slips process. We do it here because we needed the queue to the output process
        self.outputProcessQueue.put('20|main|Started main program [PID {}]'.format(os.getpid()))
        # Output pid
        self.outputProcessQueue.put('20|main|Started output thread [PID {}]'.format(outputProcessThread.pid))
        __database__.store_process_PID('outputProcess',int(outputProcessThread.pid))

        # Start each module in the folder modules
        self.outputProcessQueue.put('01|main|[main] Starting modules')
        to_ignore = self.read_configuration(self.config, 'modules', 'disable')
        # This plugins import will automatically load the modules and put them in the __modules__ variable
        if to_ignore:
            # Convert string to list
            to_ignore = to_ignore.replace("[","").replace("]","").replace(" ","").split(",")
            # Ignore exporting alerts module if export_to is empty
            export_to = self.config.get('ExportingAlerts', 'export_to').rstrip("][").replace(" ","")
            if 'stix' not in export_to.lower() and 'slack' not in export_to.lower():
                to_ignore.append('ExportingAlerts')
            # Disable blocking if was not asked and if it is not interface
            if not self.args.blocking or not self.args.interface:
                to_ignore.append('blocking')
            try:
                # This 'imports' all the modules somehow, but then we ignore some
                self.modules_to_call = self.load_modules(to_ignore)[0]
                for module_name in self.modules_to_call:
                    if not module_name in to_ignore:
                        module_class = self.modules_to_call[module_name]['obj']
                        ModuleProcess = module_class(self.outputProcessQueue, self.config)
                        ModuleProcess.start()
                        self.outputProcessQueue.put('20|main|\t[main] Starting the module {} ({}) [PID {}]'.format(module_name, self.modules_to_call[module_name]['description'], ModuleProcess.pid))
                        __database__.store_process_PID(module_name, int(ModuleProcess.pid))
            except TypeError:
                # There are not modules in the configuration to ignore?
                print('No modules are ignored')

        # Get the type of output from the parameters
        # Several combinations of outputs should be able to be used
        if self.args.gui:
            # Create the curses thread
            guiProcessQueue = Queue()
            guiProcessThread = GuiProcess(guiProcessQueue, self.outputProcessQueue, self.args.verbose, self.args.debug, self.config)
            guiProcessThread.start()
            self.outputProcessQueue.put('quiet')
        # By default, don't log unless specified in slips.conf and -l isn't provided
        logs_folder = False
        # if there is no -l
        if not self.args.nologfiles:
            # By parameter, this is True. Then check the conf. Only create the logs if the conf file says True
            do_logs = self.read_configuration(self.config, 'parameters', 'create_log_files')
            if do_logs == 'yes':
                # Create a folder for logs
                logs_folder = self.create_folder_for_logs()
                # Create the logsfile thread if by parameter we were told, or if it is specified in the configuration
                self.logsProcessQueue = Queue()
                logsProcessThread = LogsProcess(self.logsProcessQueue, self.outputProcessQueue, self.args.verbose, self.args.debug, self.config, logs_folder)
                logsProcessThread.start()
                self.outputProcessQueue.put('20|main|Started logsfiles thread [PID {}]'.format(logsProcessThread.pid))
                __database__.store_process_PID('logsProcess',int(logsProcessThread.pid))
        # If self.args.nologfiles is False, then we don't want log files, independently of what the conf says.
        else:
            logs_folder = False
        # Evidence thread
        # Create the queue for the evidence thread
        evidenceProcessQueue = Queue()
        # Create the thread and start it
        evidenceProcessThread = EvidenceProcess(evidenceProcessQueue, self.outputProcessQueue, self.config, self.args.output, logs_folder)
        evidenceProcessThread.start()
        self.outputProcessQueue.put('20|main|Started Evidence thread [PID {}]'.format(evidenceProcessThread.pid))
        __database__.store_process_PID('evidenceProcess', int(evidenceProcessThread.pid))


        # Profile thread
        # Create the queue for the profile thread
        self.profilerProcessQueue = Queue()
        # Create the profile thread and start it
        profilerProcessThread = ProfilerProcess(self.profilerProcessQueue, self.outputProcessQueue, self.args.verbose, self.args.debug, self.config)
        profilerProcessThread.start()
        self.outputProcessQueue.put('20|main|Started profiler thread [PID {}]'.format(profilerProcessThread.pid))
        __database__.store_process_PID('profilerProcess', int(profilerProcessThread.pid))

        # Input process
        # Create the input process and start it
        self.inputProcess = InputProcess(self.outputProcessQueue, self.profilerProcessQueue, input_type, input_information, self.config, self.args.pcapfilter, zeek_bro)
        self.inputProcess.start()
        self.outputProcessQueue.put('20|main|Started input thread [PID {}]'.format(self.inputProcess.pid))
        __database__.store_process_PID('inputProcess', int(self.inputProcess.pid))

        self.c1 = __database__.subscribe('finished_modules')

        # Store the host IP address if input type is interface
        if input_type == 'interface':
            hostIP = self.recognize_host_ip()
            while True:
                try:
                    __database__.set_host_ip(hostIP)
                    break
                except redis.exceptions.DataError:
                    print("Not Connected to the internet. Reconnecting in 10s.")
                    time.sleep(10)
                    hostIP = self.recognize_host_ip()

        # As the main program, keep checking if we should stop slips or not
        # This is not easy since we need to be sure all the modules are stopped
        # Each interval of checking is every 5 seconds
        check_time_sleep = 5
        # In each interval we check if there has been any modifications to the database by any module.
        # If not, wait this amount of intervals and then stop slips.
        # We choose 6 to wait 30 seconds.
        limit_minimum_intervals_to_wait = 4
        minimum_intervals_to_wait = limit_minimum_intervals_to_wait
        fieldseparator = __database__.getFieldSeparator()
        slips_internal_time = 0
        try:
            while True:
                # Sleep some time to do rutine checks
                time.sleep(check_time_sleep)
                slips_internal_time = __database__.getSlipsInternalTime()
                # Get the amount of modified time windows since we last checked
                TWModifiedforProfile = __database__.getModifiedTWSinceTime(float(slips_internal_time) + 1)
                # TWModifiedforProfile = __database__.getModifiedTW()
                amount_of_modified = len(TWModifiedforProfile)
                # Get th time of last modified timewindow and set it as a new
                if amount_of_modified != 0:
                    time_last_modified_tw = TWModifiedforProfile[-1][-1]
                    __database__.setSlipsInternalTime(time_last_modified_tw)
                # How many profiles we have?
                profilesLen = str(__database__.getProfilesLen())
                if self.mode != 'daemonized':
                    self.outputProcessQueue.put('20|main|[Main] Total Number of Profiles in DB so far: {}. Modified Profiles in the last TW: {}. ({})'.format(profilesLen, amount_of_modified, datetime.now().strftime('%Y-%m-%d--%H:%M:%S')))

                # Check if we need to close some TW
                __database__.check_TW_to_close()

                # In interface we keep track of the host IP. If there was no
                # modified TWs in the host NotIP, we check if the network was changed.
                # Dont try to stop slips if its catpurting from an interface
                if self.args.interface:
                    # To check of there was a modified TW in the host IP. If not,
                    # count down.
                    modifiedTW_hostIP = False
                    for profileTW in TWModifiedforProfile:
                        profileIP = profileTW[0].split(fieldseparator)[1]
                        # True if there was a modified TW in the host IP
                        if hostIP == profileIP:
                            modifiedTW_hostIP = True

                    # If there was no modified TW in the host IP
                    # then start counting down
                    # After count down we update the host IP, to check if the
                    # network was changed
                    if not modifiedTW_hostIP and self.args.interface:
                        if minimum_intervals_to_wait == 0:
                            hostIP = self.recognize_host_ip()
                            if hostIP:
                                __database__.set_host_ip(hostIP)
                            minimum_intervals_to_wait = limit_minimum_intervals_to_wait
                        minimum_intervals_to_wait -= 1
                    else:
                        minimum_intervals_to_wait = limit_minimum_intervals_to_wait

                # ---------------------------------------- Stopping slips

                # When running Slips in the file.
                # If there were no modified TW in the last timewindow time,
                # then start counting down
                else:
                    if amount_of_modified == 0:
                        # print('Counter to stop Slips. Amount of modified
                        # timewindows: {}. Stop counter: {}'.format(amount_of_modified, minimum_intervals_to_wait))
                        if minimum_intervals_to_wait == 0:
                            self.shutdown_gracefully()
                            break
                        minimum_intervals_to_wait -= 1
                    else:
                        minimum_intervals_to_wait = limit_minimum_intervals_to_wait

        except KeyboardInterrupt:
            self.shutdown_gracefully()


####################
# Main
####################
if __name__ == '__main__':
    slips = Main()
    slips.parse_arguments()
    if slips.args.interactive:
        # -I is provided
        slips.start()
        sys.exit()

    daemon = Daemon(slips)
    if slips.args.stopdaemon:
        # -S is provided
        print("Daemon stopped.")
        daemon.stop()
    elif slips.args.restartdaemon:
        # -R is provided
        print("Daemon restarted.")
        daemon.restart()
    else:
        # Default mode (daemonized)
        print("Slips daemon started.")
        daemon.start()


