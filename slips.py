#!/usr/bin/env python3
# This file is part of the Stratosphere Linux IPS
# See the file 'LICENSE' for copying permission.
# Author: Sebastian Garcia. eldraco@gmail.com , sebastian.garcia@agents.fel.cvut.cz

import sys
import os
import argparse
import multiprocessing
from multiprocessing import Queue
import configparser
from inputProcess import InputProcess
from outputProcess import OutputProcess
from profilerProcess import ProfilerProcess
from cursesProcess import CursesProcess
from logsProcess import LogsProcess

version = '0.5'


####################
# Main
####################
if __name__ == '__main__':  
    print('Stratosphere Linux IPS. Version {}'.format(version))
    print('https://stratosphereips.org')

    # Parse the parameters
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--amount', help='Minimum amount of flows that should be in a tuple to be printed.', action='store', required=False, type=int, default=-1)
    parser.add_argument('-c', '--config', help='Path to the slips config file.', action='store', required=False) 
    parser.add_argument('-v', '--verbose', help='Amount of verbosity. This shows more info about the results.', action='store', required=False, type=int, default=1)
    parser.add_argument('-e', '--debug', help='Amount of debugging. This shows inner information about the program.', action='store', required=False, type=int)
    parser.add_argument('-w', '--width', help='Width of the time window used. In minutes. Defaults to 60.', action='store', default=60, required=False, type=int)
    parser.add_argument('-d', '--datawhois', help='Get and show the WHOIS info for the destination IP in each tuple', action='store_true', default=False, required=False)
    parser.add_argument('-W','--whitelist',help="File with the IP addresses to whitelist. One per line.",action='store',required=False)
    parser.add_argument('-r', '--filepath', help='Path to the binetflow file to be read.', required=False)
    parser.add_argument('-C', '--curses', help='Use the curses output interface.', required=False, default=False, action='store_true')
    parser.add_argument('-l', '--logfiles', help='Create log files with all the info and detections.', required=False, default=False, action='store_true')
    args = parser.parse_args()

    # Read the config file from the parameter
    config = configparser.ConfigParser()
    try:
        with open(args.config) as source:
            config.read_file(source)
    except IOError:
        pass
    except TypeError:
        # No conf file provided
        pass
    
    # Get the verbosity, if it was not specified as a parameter
    if args.verbose == None:
        # No args verbose specified. Read the verbosity from the config
        try:
            args.verbose = int(config.get('parameters', 'verbose'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            args.verbose = 1
    # Limit any verbosity to > 0
    elif args.verbose < 1:
        args.verbose = 1

    # Get the Debugging, if it was not specified as a parameter 
    if args.debug == None:
        # No args debug specified. Read the debug from the config
        try:
            args.debug = int(config.get('parameters', 'debug'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            args.debug = 0
    # Limit any debuggisity to > 0
    elif args.debug < 0:
        args.debug = 0
    # Since the debuging level in the output process goes from 10 to 19, we sum here 10 to the debug level.
    args.debug = args.debug + 10


    ##
    # Creation of the threads
    ##

    # Output thread
    # Create the queue for the output thread first. Later the output process is created after we defined which type of output we have
    outputProcessQueue = Queue()
    # Create the output thread and start it
    # We need to tell the output process the type of output so he know if it should print in console or send the data to another process
    outputProcessThread = OutputProcess(outputProcessQueue, args.verbose, args.debug, config)
    outputProcessThread.start()
    outputProcessQueue.put('10|main|Started output thread')

    # Get the type of output from the parameters
    # Several combinations of outputs should be able to be used
    if args.curses:
        # Create the curses thread
        cursesProcessQueue = Queue()
        cursesProcessThread = CursesProcess(cursesProcessQueue, outputProcessQueue, args.verbose, args.debug, config)
        cursesProcessThread.start()
        outputProcessQueue.put('10|main|Started Curses thread')
    elif args.logfiles:
        # Create the logsfile thread
        logsProcessQueue = Queue()
        logsProcessThread = LogsProcess(logsProcessQueue, outputProcessQueue, args.verbose, args.debug, config)
        logsProcessThread.start()
        outputProcessQueue.put('10|main|Started logsfiles thread')
    else:
        # Text?
        pass

    # Profile thread
    # Create the queue for the profile thread
    profilerProcessQueue = Queue()
    # Create the profile thread and start it
    profilerProcessThread = ProfilerProcess(profilerProcessQueue, outputProcessQueue, config, args.width)
    profilerProcessThread.start()
    outputProcessQueue.put('10|main|Started profiler thread')

    # Input thread
    # Create the queue for the input thread
    inputProcessQueue = Queue()
    # Create the input thread and start it
    if args.filepath:
        inputProcessThread = InputProcess(inputProcessQueue, outputProcessQueue, profilerProcessQueue, args.filepath, config)
    else:
        newstdin = os.fdopen(os.dup(sys.stdin.fileno()))
        inputProcessThread = InputProcess(inputProcessQueue, outputProcessQueue, profilerProcessQueue, newstdin, config)
    inputProcessThread.start()
    outputProcessQueue.put('10|main|Started input thread')
