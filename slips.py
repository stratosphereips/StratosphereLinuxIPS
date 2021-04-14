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
from slips.common.abstracts import Module

version = '0.7.1'

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
        print('Network is unreachable')
        return None
    return ipaddr_check

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

    plugins = dict()

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

    return plugins

def get_slips_conf_path():
    for arg in sys.argv:
        if 'slips.py' in arg:
            # get the path preceeding slips.py (may be ../ or  ../../ or '' if slips.py is in the cwd) , this path is where slips.conf will be
            slips_conf_path = arg[:arg.index('slips.py')]
            return slips_conf_path + 'slips.conf'


####################
# Main
####################
if __name__ == '__main__':  
    print('Stratosphere Linux IPS. Version {}'.format(version))
    print('https://stratosphereips.org\n')

    # Parse the parameters
    parser = argparse.ArgumentParser()
    parser.add_argument('-c','--config', action='store',required=False,
                        help='Path to the Slips config file.')
    parser.add_argument('-v', '--verbose',action='store', required=False, type=int,
                        help='Amount of verbosity. This shows more info about the results.')
    parser.add_argument('-e', '--debug', action='store', required=False, type=int,
                        help='Amount of debugging. This shows inner information about the program.')
    parser.add_argument('-f', '--filepath', action='store',required=False,
                        help='To read an Argus binetflow or a Zeek folder.')
    parser.add_argument('-i','--interface', action='store', required=False,
                        help='To read packets from an interface.')
    parser.add_argument('-r', '--pcapfile', action='store', required=False,
                        help='To read a PCAP - Packet Capture.')
    parser.add_argument('-b', '--nfdump',action='store',required=False,
                        help='To read an NFDUMP - netflow dump. ')
    parser.add_argument('-l','--nologfiles',action='store_true',required=False,
                        help='Do not create log files with all the traffic info and detections.')
    parser.add_argument('-F','--pcapfilter',action='store',required=False,type=str,
                        help='Packet filter for Zeek. BPF style.')
    parser.add_argument('-cc','--clearcache',action='store_true', required=False,
                        help='To clear a cache database.')
    parser.add_argument('-p', '--blocking',action='store_true',required=False,
                        help='Block IPs that connect to the computer. Supported only on Linux.')
    args = parser.parse_args()

    # Read the config file name given from the parameters
    config = configparser.ConfigParser()
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

    # If we need zeek (bro), test if we can run it.
    # Need to be assign to something because we pass it to inputProcess later
    zeek_bro = None
    if args.pcapfile or args.interface:
        zeek_bro = check_zeek_or_bro()
        if zeek_bro is False:
            # If we do not have bro or zeek, terminate Slips.
            print('no zeek nor bro')
            terminate_slips()

    # See if we have the nfdump, if we need it according to the input type
    if args.nfdump and shutil.which('nfdump') is None:
        # If we do not have nfdump, terminate Slips.
        terminate_slips()

    # Clear cache if the parameter was included
    if args.clearcache:
        print('Deleting Cache DB in Redis.')
        clear_redis_cache_database()

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

    # Check the type of input
    if args.interface:
        input_information = args.interface
        input_type = 'interface'
    elif args.pcapfile:
        input_information = args.pcapfile
        input_type = 'pcap'
    elif args.filepath:
        input_information = args.filepath
        input_type = 'file'
    elif args.nfdump:
        input_information = args.nfdump
        input_type = 'nfdump'
    else:
        print('You need to define an input source.')
        sys.exit(-1)

    ##########################
    # Creation of the threads
    ##########################
    from slips.core.database import __database__
    # Output thread. This thread should be created first because it handles
    # the output of the rest of the threads.
    # Create the queue
    outputProcessQueue = Queue()
    # Create the output thread and start it
    outputProcessThread = OutputProcess(outputProcessQueue, args.verbose, args.debug, config)
    outputProcessThread.start()

    # Before starting update malicious file
    update_malicious_file(outputProcessQueue,config)
    # Print the PID of the main slips process. We do it here because we needed the queue to the output process
    outputProcessQueue.put('20|main|Started main program [PID {}]'.format(os.getpid()))
    # Output pid
    outputProcessQueue.put('20|main|Started output thread [PID {}]'.format(outputProcessThread.pid))

    # Start each module in the folder modules
    outputProcessQueue.put('01|main|[main] Starting modules')
    to_ignore = read_configuration(config, 'modules', 'disable')
    # This plugins import will automatically load the modules and put them in the __modules__ variable
    if to_ignore:
        # Convert string to list
        to_ignore = eval(to_ignore)
        # Disable blocking if was not asked and if it is not interface
        if not args.blocking or not args.interface:
            to_ignore.append('blocking')
        try:
            # This 'imports' all the modules somehow, but then we ignore some
            modules_to_call = load_modules(to_ignore)
            for module_name in modules_to_call:
                if not module_name in to_ignore:
                    module_class = modules_to_call[module_name]['obj']
                    ModuleProcess = module_class(outputProcessQueue, config)
                    ModuleProcess.start()
                    outputProcessQueue.put('20|main|\t[main] Starting the module {} ({}) [PID {}]'.format(module_name, modules_to_call[module_name]['description'], ModuleProcess.pid))
        except TypeError:
            # There are not modules in the configuration to ignore?
            print('No modules are ignored')

    # # Get the type of output from the parameters
    # # Several combinations of outputs should be able to be used
    # if args.gui:
    #     # Create the curses thread
    #     guiProcessQueue = Queue()
    #     guiProcessThread = GuiProcess(guiProcessQueue, outputProcessQueue, args.verbose, args.debug, config)
    #     guiProcessThread.start()
    #     outputProcessQueue.put('quiet')
    if not args.nologfiles:
        # By parameter, this is True. Then check the conf. Only create the logs if the conf file says True
        do_logs = read_configuration(config, 'parameters', 'create_log_files')
        if do_logs == 'yes':
            # Create the logsfile thread if by parameter we were told, or if it is specified in the configuration
            logsProcessQueue = Queue()
            logsProcessThread = LogsProcess(logsProcessQueue, outputProcessQueue, args.verbose, args.debug, config)
            logsProcessThread.start()
            outputProcessQueue.put('20|main|Started logsfiles thread [PID {}]'.format(logsProcessThread.pid))
        # If args.nologfiles is False, then we don't want log files, independently of what the conf says.

    # Evidence thread
    # Create the queue for the evidence thread
    evidenceProcessQueue = Queue()
    # Create the thread and start it
    evidenceProcessThread = EvidenceProcess(evidenceProcessQueue, outputProcessQueue, config)
    evidenceProcessThread.start()
    outputProcessQueue.put('20|main|Started Evidence thread [PID {}]'.format(evidenceProcessThread.pid))

    # Profile thread
    # Create the queue for the profile thread
    profilerProcessQueue = Queue()
    # Create the profile thread and start it
    profilerProcessThread = ProfilerProcess(profilerProcessQueue, outputProcessQueue, config)
    profilerProcessThread.start()
    outputProcessQueue.put('20|main|Started profiler thread [PID {}]'.format(profilerProcessThread.pid))

    # Input process
    # Create the input process and start it
    inputProcess = InputProcess(outputProcessQueue, profilerProcessQueue, input_type, input_information, config, args.pcapfilter, zeek_bro)
    inputProcess.start()
    outputProcessQueue.put('20|main|Started input thread [PID {}]'.format(inputProcess.pid))

    # Store the host IP address if input type is interface
    if input_type == 'interface':
        hostIP = recognize_host_ip()
        __database__.set_host_ip(hostIP)

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
            outputProcessQueue.put('20|main|[Main] Total Number of Profiles in DB so far: {}. Modified Profiles in the last TW: {}. ({})'.format(profilesLen, amount_of_modified, datetime.now().strftime('%Y-%m-%d--%H:%M:%S')))

            # Check if we need to close some TW
            __database__.check_TW_to_close()

            # In interface we keep track of the host IP. If there was no
            # modified TWs in the host IP, we check if the network was changed.
            # Dont try to stop slips if its catpurting from an interface
            if args.interface:
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
                if not modifiedTW_hostIP and args.interface:
                    if minimum_intervals_to_wait == 0:
                        hostIP = recognize_host_ip()
                        if hostIP:
                            __database__.set_host_ip(hostIP)
                        minimum_intervals_to_wait = limit_minimum_intervals_to_wait
                    minimum_intervals_to_wait -= 1
                else:
                    minimum_intervals_to_wait = limit_minimum_intervals_to_wait

            # When running Slips in the file.
            # If there were no modified TW in the last timewindow time,
            # then start counting down
            else:
                if amount_of_modified == 0:
                    # print('Counter to stop Slips. Amount of modified
                    # timewindows: {}. Stop counter: {}'.format(amount_of_modified, minimum_intervals_to_wait))
                    if minimum_intervals_to_wait == 0:
                        # Stop the output Process
                        print('Stopping Slips')
                        # Stop the modules that are subscribed to channels
                        __database__.publish_stop()
                        # Here we should Wait for any channel if it has still
                        # data to receive in its channel
                        # Send manual stops to the process not using channels
                        try:
                            logsProcessQueue.put('stop_process')
                        except NameError:
                            # The logsProcessQueue is not there because we
                            # didnt started the logs files (used -l)
                            pass
                        outputProcessQueue.put('stop_process')
                        profilerProcessQueue.put('stop_process')
                        break
                    minimum_intervals_to_wait -= 1
                else:
                    minimum_intervals_to_wait = limit_minimum_intervals_to_wait

    except KeyboardInterrupt:
        print('Stopping Slips')
        # Stop the modules that are subscribed to channels
        __database__.publish_stop()
        # Here we should Wait for any channel if it has still data to receive
        # in its channel
        # Send manual stops to the process not using channels
        try:
            logsProcessQueue.put('stop_process')
        except NameError:
            # The logsProcessQueue is not there because we didnt started the
            # logs files (used -l)
            pass

        outputProcessQueue.put('stop_process')
        profilerProcessQueue.put('stop_process')
        inputProcess.terminate()
        os._exit(1)
