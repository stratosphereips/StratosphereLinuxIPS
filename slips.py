#!/usr/bin/env python3
# This file is part of the Stratosphere Linux IPS
# See the file 'LICENSE' for copying permission.
# Author: Sebastian Garcia. eldraco@gmail.com , sebastian.garcia@agents.fel.cvut.cz

import configparser
import argparse
import sys
import redis
import os
import time
from datetime import datetime

version = '0.6.4'

def read_configuration(config, section, name):
    """ Read the configuration file for what slips.py needs. Other processes also access the configuration """
    try:
        return config.get(section, name)
    except (configparser.NoOptionError, configparser.NoSectionError, NameError):
        # There is a conf, but there is no option, or no section or no configuration file specified
        return False


def test_redis_database(redis_host='localhost', redis_port=6379) -> str:
    server_redis_version = None
    try:
        r = redis.StrictRedis(host=redis_host, port=redis_port, db=0, charset="utf-8",
                                   decode_responses=True)
        server_redis_version = r.execute_command('INFO')['redis_version']
    except redis.exceptions.ConnectionError:
        print('[DB] Error: Is redis database running? You can run it as: "redis-server --daemonize yes"')
    return server_redis_version


def test_program(command: str) -> bool:
    """
    Test if we can run some program (e.g.: zeek, nfdump).
    """
    command = command + " 2>&1 > /dev/null"
    ret = os.system(command)
    if ret != 0:
        print("[main] Error: The command: " + command + " was not found. Did you set the path?")
        return False
    return True


def terminate_slips():
    """
    Do all necessary stuff to stop process any clear any files.
    """
    sys.exit(-1)


####################
# Main
####################
if __name__ == '__main__':  
    print('Stratosphere Linux IPS. Version {}'.format(version))
    print('https://stratosphereips.org\n')

    # Parse the parameters
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='Path to the slips config file.', action='store', required=False)
    parser.add_argument('-v', '--verbose', help='Amount of verbosity. This shows more info about the results.', action='store', required=False, type=int)
    parser.add_argument('-e', '--debug', help='Amount of debugging. This shows inner information about the program.', action='store', required=False, type=int)
    parser.add_argument('-w', '--width', help='Width of the time window used. In seconds.', action='store', required=False, type=int)
    parser.add_argument('-f', '--filepath', help='Path to the flow input file to read. It can be a Argus binetflow flow, a Zeek conn.log file, or a Zeek folder with all the log files.', required=False)
    parser.add_argument('-i', '--interface', help='Interface name to read packets from. Zeek is run on it and slips interfaces with Zeek.', required=False)
    parser.add_argument('-r', '--pcapfile', help='Pcap file to read. Zeek is run on it and slips interfaces with Zeek.', required=False)
    parser.add_argument('-b', '--nfdump', help='A binary file from NFDUMP to read. NFDUMP is used to send data to slips.', required=False)
    parser.add_argument('-G', '--gui', help='Use the nodejs gui interface.', required=False, default=False, action='store_true')
    parser.add_argument('-l', '--nologfiles', help='Do not create log files with all the traffic info and detections, only show in the stdout.', required=False, default=False, action='store_true')
    parser.add_argument('-F', '--pcapfilter', help='Packet filter for Zeek. BPF style.', required=False, type=str, action='store')
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
    server_redis_version = test_redis_database()
    if server_redis_version is None:
        terminate_slips()

    # If we need zeek (bro), test if we can run it.
    if args.pcapfile:
        visible_zeek = test_program('bro --version')
        if visible_zeek is False:
            # If we do not have access to zeek and we want to use it, kill it.
            terminate_slips()

    # See if we have the nfdump program, if we need it according to the input type
    if args.nfdump:
        visible_nfdump = test_program('nfdump -h')
        if visible_nfdump is False:
            # If we do not have access to nfdump and we want to use it, kill it.
            terminate_slips()

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
    # This plugins import will automatially load the modules and put them in the __modules__ variable
    from slips.core.plugins import __modules__

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

    # Output thread. This thread should be created first because it handles the output of the rest of the threads.
    # Create the queue
    outputProcessQueue = Queue()
    # Create the output thread and start it
    outputProcessThread = OutputProcess(outputProcessQueue, args.verbose, args.debug, config)
    outputProcessThread.start()
    # Print the PID of the main slips process. We do it here because we needed the queue to the output process
    outputProcessQueue.put('20|main|Started main program [PID {}]'.format(os.getpid()))
    # Output pid
    outputProcessQueue.put('20|main|Started output thread [PID {}]'.format(outputProcessThread.pid))

    # Start each module in the folder modules
    outputProcessQueue.put('01|main|[main] Starting modules')
    to_ignore = read_configuration(config, 'modules', 'disable')
    try:
        for module_name in __modules__:
            if not module_name in to_ignore:
                module_class = __modules__[module_name]['obj']
                ModuleProcess = module_class(outputProcessQueue, config)
                ModuleProcess.start()
                outputProcessQueue.put('20|main|\t[main] Starting the module {} ({}) [PID {}]'.format(module_name, __modules__[module_name]['description'], ModuleProcess.pid))
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
    profilerProcessThread = ProfilerProcess(profilerProcessQueue, outputProcessQueue, config, args.width)
    profilerProcessThread.start()
    outputProcessQueue.put('20|main|Started profiler thread [PID {}]'.format(profilerProcessThread.pid))

    # Input process
    # Create the input process and start it
    inputProcess = InputProcess(outputProcessQueue, profilerProcessQueue, input_type, input_information, config, args.pcapfilter)
    inputProcess.start()
    outputProcessQueue.put('20|main|Started input thread [PID {}]'.format(inputProcess.pid))


    # As the main program, keep checking if we should stop slips or not
    # This is not easy since we need to be sure all the modules are stopped
    # Each interval of checking is every 5 seconds
    check_time_sleep = 5
    # In each interval we check if there has been any modifications to the database by any module. 
    # If not, wait this amount of intervals and then stop slips. 
    # We choose 6 to wait 30 seconds.
    minimum_intervals_to_wait = 6
    while True:
        # Sleep 
        time.sleep(check_time_sleep)
        # Get the amount of modified time windows in the last interval
        TWModifiedforProfile = __database__.getModifiedTWLogs()
        amount_of_modified = len(TWModifiedforProfile)

        # How many profiles we have?
        profilesLen = str(__database__.getProfilesLen())
        outputProcessQueue.put('20|main|[Main] Total Number of Profiles in DB so far: {}. Modified Profiles in the last TW: {}. ({})'.format(profilesLen, amount_of_modified , datetime.now().strftime('%Y-%m-%d--%H:%M:%S')))

        #outputProcessQueue.put('11|Main|[Main] Counter to stop Slips. Amount of modified timewindows: {}. Stop counter: {}'.format(amount_of_modified, minimum_intervals_to_wait))

        # If there were no modified TW in the last timewindow time, then start counting down
        # Dont try to stop slips if its catpurting from an interface 
        if amount_of_modified == 0 and not args.interface:
            #print('Counter to stop Slips. Amount of modified timewindows: {}. Stop counter: {}'.format(amount_of_modified, minimum_intervals_to_wait))
            if minimum_intervals_to_wait == 0:
                # Stop the output Process
                print('Stopping Slips')
                # Stop the modules that are subscribed to channels
                __database__.publish_stop()
                # Here we should Wait for any channel if it has still data to receive in its channel
                # Send manual stops to the process not using channels
                logsProcessQueue.put('stop_process')
                outputProcessQueue.put('stop_process')
                profilerProcessQueue.put('stop_process')
                break
            #outputProcessQueue.put('11|Main|[Main] Decreasing one')
            minimum_intervals_to_wait -= 1
        else:
            #outputProcessQueue.put('11|Main|[Main] Back to 0')
            minimum_intervals_to_wait = 6
