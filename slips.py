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

import configparser
import argparse
import json
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
import re

version = '0.7.3'

# Ignore warnings on CPU from tensorflow
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
# Ignore warnings in general
warnings.filterwarnings('ignore')


def read_configuration(config, section, name):
    """ Read the configuration file for what slips.py needs. Other processes also access the configuration """
    try:
        return config.get(section, name)
    except (configparser.NoOptionError, configparser.NoSectionError, NameError):
        # There is a conf, but there is no option, or no section or no configuration file specified
        return False

def recognize_host_ip():
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

def create_folder_for_logs():
    '''
    Create a folder for logs if logs are enabled
    '''
    logs_folder = datetime.now().strftime('%Y-%m-%d--%H-%M-%S')
    try:
        os.makedirs(logs_folder)
    except OSError as e:
        if e.errno != errno.EEXIST:
            # doesn't exist and can't create
            return False
    return logs_folder

def update_malicious_file(outputqueue, config):
    '''
    Update malicious files and store them in database before slips start
    '''
    update_manager = UpdateFileManager(outputqueue, config)
    update_manager.update()

def check_redis_database(redis_host='localhost', redis_port=6379) -> str:
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

def clear_redis_cache_database(redis_host = 'localhost', redis_port = 6379) -> str:
    """
    Clear cache database
    """
    rcache = redis.StrictRedis(host=redis_host, port=redis_port, db=1, charset="utf-8",
                               decode_responses=True)
    rcache.flushdb()
    return True


def check_zeek_or_bro():
    """
    Check if we have zeek or bro
    """
    if shutil.which('zeek'):
        return 'zeek'
    elif shutil.which('bro'):
        return 'bro'
    return False

def terminate_slips():
    """
    Do all necessary stuff to stop process any clear any files.
    """
    sys.exit(-1)

def load_modules(to_ignore):
    """
    Import modules and loads the modules from the 'modules' folder. Is very relative to the starting position of slips
    """

    plugins = {}
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

def get_cwd():
    # Can't use os.getcwd() because slips directory name won't always be Slips plus this way requires less parsing
    for arg in sys.argv:
        if 'slips.py' in arg:
            # get the path preceeding slips.py (may be ../ or  ../../ or '' if slips.py is in the cwd) , this path is where slips.conf will be
            cwd = arg[:arg.index('slips.py')]
            return cwd

def shutdown_gracefully(input_information):
    """ Wait for all modules to confirm that they're done processing and then shutdown
    :param input_information: the interface/pcap/nfdump/binetflow used. we need it to save the db
    """

    try:
        print('Stopping Slips')
        # Stop the modules that are subscribed to channels
        __database__.publish_stop()
        # Here we should Wait for any channel if it has still
        # data to receive in its channel
        finished_modules = []
        try:
            loaded_modules = modules_to_call.keys()
        except NameError:
            # this is the case of -d <rdb file> we don't have loaded_modules
            loaded_modules = []

        # get dict of PIDs spawned by slips
        PIDs = __database__.get_PIDs()

        # timeout variable so we don't loop forever
        max_loops = 130
        # loop until all loaded modules are finished
        while len(finished_modules) < len(loaded_modules) and max_loops != 0:
            # print(f"Modules not finished yet {set(loaded_modules) - set(finished_modules)}")
            message = c1.get_message(timeout=0.01)
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
                    modules_left = len(list(PIDs.keys()))
                    # to vertically align them when printing
                    module_name = module_name+' '*(20-len(module_name))
                    print(f"\t\033[1;32;40m{module_name}\033[00m \tStopped. \033[1;32;40m{modules_left}\033[00m left.")
            max_loops -=1
        # modules that aren't subscribed to any channel will always be killed and not stopped
        # some modules continue on sigint, but recieve other msgs (other than stop_message) in the queue before stop_process
        # they will always be killed
        # kill processes that didn't stop after timeout
        for unstopped_proc,pid in PIDs.items():
            unstopped_proc = unstopped_proc+' '*(20-len(unstopped_proc))
            try:
                os.kill(int(pid), 9)
                print(f'\t\033[1;32;40m{unstopped_proc}\033[00m \tKilled.')
            except ProcessLookupError:
                print(f'\t\033[1;32;40m{unstopped_proc}\033[00m \tAlready stopped.')
        # Send manual stops to the process not using channels
        try:
            logsProcessQueue.put('stop_process')
        except NameError:
            # The logsProcessQueue is not there because we
            # didnt started the logs files (used -l)
            pass
        try:
            outputProcessQueue.put('stop_process')
        except NameError:
            pass
        try:
            profilerProcessQueue.put('stop_process')
        except NameError:
            pass
        try:
            inputProcess.terminate()
        except NameError:
            pass
        if args.save:
            # Create a new dir to store backups
            backups_dir = get_cwd() +'redis_backups' + '/'
            try:
                os.mkdir(backups_dir)
            except FileExistsError:
                pass
            # The name of the interface/pcap/nfdump/binetflow used is in input_information
            # We need to seperate it from the path
            input_information = os.path.basename(input_information)
            # Remove the extension from the filename
            input_information = input_information[:input_information.index('.')]
            # Give the exact path to save(), this is where the .rdb backup will be
            __database__.save(backups_dir + input_information)
            print(f"[Main] Database saved to {backups_dir[:]}{input_information}" )

        os._exit(-1)
        return True
    except KeyboardInterrupt:
        return False

####################
# Main
####################
if __name__ == '__main__':
    # Before the argparse, we need to set up the default path fr alerts.log and alerts.json. In our case, it is output folder.
    alerts_default_path = 'output/'

    print('Slips. Version {}'.format(version))
    print('https://stratosphereips.org\n')

    # Parse the parameters
    slips_conf_path = get_cwd() + 'slips.conf'
    parser = ArgumentParser(usage = "./slips.py -c <configfile> [options] [file ...]",
                            add_help=False)
    parser.add_argument('-c','--config', metavar='<configfile>',action='store',required=False, default=slips_conf_path,
                        help='path to the Slips config file.')
    parser.add_argument('-v', '--verbose',metavar='<verbositylevel>',action='store', required=False, type=int,
                        help='amount of verbosity. This shows more info about the results.')
    parser.add_argument('-e', '--debug', metavar='<debuglevel>',action='store', required=False, type=int,
                        help='amount of debugging. This shows inner information about the program.')
    parser.add_argument('-f', '--filepath',metavar='<file>', action='store',required=False,
                        help='read a Zeek folder, Argus binetflow, pcapfile or nfdump.')
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
    parser.add_argument('-o', '--output', action='store', required=False, default=alerts_default_path,
                        help='store alerts.json and alerts.txt in the provided folder.')
    parser.add_argument('-s', '--save',action='store_true',required=False,
                        help='To Save redis db to disk. Requires root access.')
    parser.add_argument('-d', '--db',action='store',required=False,
                        help='To read a redis (rdb) saved file. Requires root access.')
    parser.add_argument("-h", "--help", action="help", help="command line help")

    args = parser.parse_args()

    # Read the config file name given from the parameters
    # don't use '%' for interpolation.
    config = configparser.ConfigParser(interpolation=None)
    try:
        with open(args.config) as source:
            config.read_file(source)
    except IOError:
        pass
    except TypeError:
        # No conf file provided
        pass

    # Check if redis server running
    if check_redis_database() is False:
        terminate_slips()
        # Clear cache if the parameter was included
    if args.clearcache:
        print('Deleting Cache DB in Redis.')
        clear_redis_cache_database()
        terminate_slips()
    # Check if user want to save and load a db at the same time
    if args.save :
        # make sure slips is running as root
        if os.geteuid() != 0:
            print("Slips needs to be run as root to save the database. Stopping.")
            terminate_slips()
        if args.db:
            print("Can't use -s and -b together")
            terminate_slips()

    # Check the type of input
    if args.interface:
        input_information = args.interface
        input_type = 'interface'
    elif args.filepath:
        input_information = args.filepath
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
            # is it a zeek log file or suricata, binetflow tabs , or binetflow comma separated file?
            # use first line to determine
            with open(input_information,'r') as f:
                while True:
                    # get the first line that isn't a comment
                    first_line = f.readline().replace('\n','')
                    if not first_line.startswith('#'):
                        break
            if 'flow_id' in first_line:
                input_type = 'suricata'
            else:
                #this is a text file , it can be binetflow or zeek_log_file
                try:
                    #is it a json log file
                    json.loads(first_line)
                    input_type = 'zeek_log_file'
                except json.decoder.JSONDecodeError:
                    # this is a tab separated file
                    # is it zeek log file or binetflow file?
                    # line = re.split(r'\s{2,}', first_line)[0]
                    x= re.search('\s{1,}-\s{1,}', first_line)
                    if '->' in first_line or 'StartTime' in first_line:
                        # tab separated files are usually binetflow tab files
                        input_type = 'binetflow-tabs'
                    elif re.search('\s{1,}-\s{1,}', first_line):
                        input_type = 'zeek_log_file'
    elif args.db:
        input_type = 'database'
        input_information = 'database'
    else:
        print('You need to define an input source.')
        sys.exit(-1)

    # If we need zeek (bro), test if we can run it.
    # Need to be assign to something because we pass it to inputProcess later
    zeek_bro = None
    if input_type == 'pcap' or args.interface:
        zeek_bro = check_zeek_or_bro()
        if zeek_bro is False:
            # If we do not have bro or zeek, terminate Slips.
            print('no zeek nor bro')
            terminate_slips()
        else:
            zeek_scripts_dir  = os.getcwd() + '/zeek-scripts'
            # load all scripts in zeek-script dir
            with open(zeek_scripts_dir + '/__load__.zeek','r') as f:
                loaded_scripts = f.read()
            with open(zeek_scripts_dir + '/__load__.zeek','a') as f:

                for file_name in os.listdir(zeek_scripts_dir):
                    # ignore the load file
                    if file_name == '__load__.zeek':
                        continue
                    if file_name not in loaded_scripts:
                        # found a file in the dir that isn't in __load__.zeek, add it
                        f.write(f'\n@load ./{file_name}')

    # See if we have the nfdump, if we need it according to the input type
    if input_type == 'nfdump' and shutil.which('nfdump') is None:
        # If we do not have nfdump, terminate Slips.
        terminate_slips()


    # Remove default folder for alerts, if exists
    if os.path.exists(args.output):
        try:
            os.remove(args.output + 'alerts.log')
            os.remove(args.output + 'alerts.json')
        except OSError :
            # Directory not empty (may contain hidden non-deletable files), don't delete dir
            pass

    # Create output folder for alerts.txt and alerts.json if they do not exist
    if not args.output.endswith('/'): args.output = args.output + '/'
    if not os.path.exists(args.output):
        os.makedirs(args.output)

    # If the user wants to blocks, the user needs to give a permission to modify iptables
    # Also check if the user blocks on interface, does not make sense to block on files
    if args.interface and args.blocking:
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
    if args.verbose == None:
        # Read the verbosity from the config
        try:
            args.verbose = int(config.get('parameters', 'verbose'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError, ValueError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            # By default, 1
            args.verbose = 1

    # Limit any verbosity to > 0
    if args.verbose < 1:
        args.verbose = 1

    # Any debuggsity passed as parameter overrides the configuration. Only check its value
    if args.debug == None:
        # Read the debug from the config
        try:
            args.debug = int(config.get('parameters', 'debug'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError, ValueError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            # By default, 0
            args.debug = 0

    # Limit any debuggisity to > 0
    if args.debug < 0:
        args.debug = 0



    ##########################
    # Creation of the threads
    ##########################
    from slips_files.core.database import __database__
    # Output thread. This thread should be created first because it handles
    # the output of the rest of the threads.
    # Create the queue
    outputProcessQueue = Queue()
    # if stdout it redirected to a file, tell outputProcess.py to redirect it's output as well
    # lsof will provide a list of all open fds belonging to slips
    command = f'lsof -p {os.getpid()}'
    result = subprocess.run(command.split(), capture_output=True)
    # Get command output
    output = result.stdout.decode('utf-8')
    # if stdout is being redirected we'll find '1w' in one of the lines 1 means stdout, w means write mode
    for line in output.splitlines():
        if '1w' in line:
            # stdout is redirected, get the file
            current_stdout = line.split(' ')[-1]
            break
    else:
        # stdout is not redirected
        current_stdout = ''

    # Create the output thread and start it
    outputProcessThread = OutputProcess(outputProcessQueue, args.verbose, args.debug, config, stdout=current_stdout)
    # this process starts the db
    outputProcessThread.start()




    # Before starting update malicious file
    update_malicious_file(outputProcessQueue,config)
    # Print the PID of the main slips process. We do it here because we needed the queue to the output process
    outputProcessQueue.put('20|main|Started main program [PID {}]'.format(os.getpid()))
    # Output pid
    outputProcessQueue.put('20|main|Started output thread [PID {}]'.format(outputProcessThread.pid))
    __database__.store_process_PID('OutputProcess',int(outputProcessThread.pid))


    # Start each module in the folder modules
    outputProcessQueue.put('01|main|[main] Starting modules')
    to_ignore = read_configuration(config, 'modules', 'disable')
    # This plugins import will automatically load the modules and put them in the __modules__ variable
    # if slips is given a .rdb file, don't load the modules as we don't need them
    if to_ignore and not args.db:
        # Convert string to list
        to_ignore = to_ignore.replace("[","").replace("]","").replace(" ","").split(",")
        # Ignore exporting alerts module if export_to is empty
        export_to = config.get('ExportingAlerts', 'export_to').rstrip("][").replace(" ","").lower()
        if 'stix' not in export_to and 'slack' not in export_to and 'json' not in export_to:
            to_ignore.append('ExportingAlerts')
        # Disable blocking if was not asked and if it is not interface
        if not args.blocking or not args.interface:
            to_ignore.append('blocking')
        try:
            # This 'imports' all the modules somehow, but then we ignore some
            modules_to_call = load_modules(to_ignore)[0]
            for module_name in modules_to_call:
                if not module_name in to_ignore:
                    module_class = modules_to_call[module_name]['obj']
                    ModuleProcess = module_class(outputProcessQueue, config)
                    ModuleProcess.start()
                    outputProcessQueue.put('20|main|\t[main] Starting the module {} ({}) [PID {}]'.format(module_name, modules_to_call[module_name]['description'], ModuleProcess.pid))
                    __database__.store_process_PID(module_name, int(ModuleProcess.pid))
        except TypeError:
            # There are not modules in the configuration to ignore?
            print('No modules are ignored')

    # Get the type of output from the parameters
    # Several combinations of outputs should be able to be used
    if args.gui:
        # Create the curses thread
        guiProcessQueue = Queue()
        guiProcessThread = GuiProcess(guiProcessQueue, outputProcessQueue, args.verbose, args.debug, config)
        guiProcessThread.start()
        outputProcessQueue.put('quiet')
    if not args.nologfiles:
        # By parameter, this is True. Then check the conf. Only create the logs if the conf file says True
        do_logs = read_configuration(config, 'parameters', 'create_log_files')
        if do_logs == 'yes':
            # Create a folder for logs
            logs_folder = create_folder_for_logs()
            # Create the logsfile thread if by parameter we were told, or if it is specified in the configuration
            logsProcessQueue = Queue()
            logsProcessThread = LogsProcess(logsProcessQueue, outputProcessQueue, args.verbose, args.debug, config, logs_folder)
            logsProcessThread.start()
            outputProcessQueue.put('20|main|Started logsfiles thread [PID {}]'.format(logsProcessThread.pid))
            __database__.store_process_PID('logsProcess',int(logsProcessThread.pid))

    # If args.nologfiles is False, then we don't want log files, independently of what the conf says.
    else:
        logs_folder = False

    # Evidence thread
    # Create the queue for the evidence thread
    evidenceProcessQueue = Queue()
    # Create the thread and start it
    evidenceProcessThread = EvidenceProcess(evidenceProcessQueue, outputProcessQueue, config, args.output, logs_folder)
    evidenceProcessThread.start()
    outputProcessQueue.put('20|main|Started Evidence thread [PID {}]'.format(evidenceProcessThread.pid))
    __database__.store_process_PID('EvidenceProcess', int(evidenceProcessThread.pid))


    # Profile thread
    # Create the queue for the profile thread
    profilerProcessQueue = Queue()
    # Create the profile thread and start it
    profilerProcessThread = ProfilerProcess(profilerProcessQueue, outputProcessQueue, args.verbose, args.debug, config)
    profilerProcessThread.start()
    outputProcessQueue.put('20|main|Started profiler thread [PID {}]'.format(profilerProcessThread.pid))
    __database__.store_process_PID('ProfilerProcess', int(profilerProcessThread.pid))

    c1 = __database__.subscribe('finished_modules')

    if args.db:
        if not __database__.load(args.db):
            print("[Main] Failed to load the database.")
            shutdown_gracefully(input_information)
        shutdown_gracefully(input_information)

    # Input process
    # Create the input process and start it
    inputProcess = InputProcess(outputProcessQueue, profilerProcessQueue, input_type, input_information, config, args.pcapfilter, zeek_bro)
    inputProcess.start()
    outputProcessQueue.put('20|main|Started input thread [PID {}]'.format(inputProcess.pid))
    __database__.store_process_PID('inputProcess', int(inputProcess.pid))



    # Store the host IP address if input type is interface
    if input_type == 'interface':
        hostIP = recognize_host_ip()
        while True:
            try:
                __database__.set_host_ip(hostIP)
                break
            except redis.exceptions.DataError:
                print("Not Connected to the internet. Reconnecting in 10s.")
                time.sleep(10)
                hostIP = recognize_host_ip()

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
            # Get the amount of modified profiles since we last checked
            modified_profiles, time_of_last_modified_tw  = __database__.getModifiedProfilesSinceTime(float(slips_internal_time) + 1)
            amount_of_modified = len(modified_profiles)
            # Get the time of last modified timewindow and set it as a new
            if time_of_last_modified_tw != 0:
                __database__.setSlipsInternalTime(time_of_last_modified_tw)
            # How many profiles we have?
            profilesLen = str(__database__.getProfilesLen())
            outputProcessQueue.put('20|main|[Main] Total Number of Profiles in DB so far: {}. Modified Profiles in the last TW: {}. ({})'.format(profilesLen, amount_of_modified, datetime.now().strftime('%Y-%m-%d--%H:%M:%S')))
            # Check if we need to close some TW
            __database__.check_TW_to_close()

            # In interface we keep track of the host IP. If there was no
            # modified TWs in the host NotIP, we check if the network was changed.
            # Dont try to stop slips if its catpurting from an interface
            if args.interface:
                # To check of there was a modified TW in the host IP. If not,
                # count down.
                modifiedTW_hostIP = False
                for profileIP in modified_profiles:
                    # True if there was a modified TW in the host IP
                    if hostIP == profileIP:
                        modifiedTW_hostIP = True

                # If there was no modified TW in the host IP
                # then start counting down
                # After count down we update the host IP, to check if the
                # network was changed
                if not modifiedTW_hostIP and args.interface:
                    if minimum_intervals_to_wait == 0:
                        hostIP = recognize_host_ip()
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
                         # If the user specified -s, save the database before stopping
                        shutdown_gracefully(input_information)
                        break
                    minimum_intervals_to_wait -= 1
                else:
                    minimum_intervals_to_wait = limit_minimum_intervals_to_wait

    except KeyboardInterrupt:
        shutdown_gracefully(input_information)


