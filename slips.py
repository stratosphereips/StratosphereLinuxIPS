#!/usr/bin/env python3
# This file is part of the Stratosphere Linux IPS
# See the file 'LICENSE' for copying permission.
# Author: Sebastian Garcia. eldraco@gmail.com , sebastian.garcia@agents.fel.cvut.cz

import sys
import argparse
import multiprocessing
from multiprocessing import Queue
import configparser
import globaldata
from inputProcessing import InputProcessing

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
    parser.add_argument('-v', '--verbose', help='Amount of verbosity. This shows more info about the results.', action='store', required=False, type=int)
    parser.add_argument('-e', '--debug', help='Amount of debugging. This shows inner information about the flows.', action='store', required=False, type=int)
    parser.add_argument('-w', '--width', help='Width of the time slot used for the analysis. In minutes.', action='store', default=5, required=False, type=int)
    parser.add_argument('-d', '--datawhois', help='Get and show the WHOIS info for the destination IP in each tuple', action='store_true', default=False, required=False)
    parser.add_argument('-D', '--dontdetect', help='Dont detect the malicious behavior in the flows using the models. Just print the connections.', default=False, action='store_true', required=False)
    parser.add_argument('-f', '--folder', help='Folder with models to apply for detection.', action='store', required=False)
    parser.add_argument('-s', '--sound', help='Play a small sound when a periodic connections is found.', action='store_true', default=False, required=False)
    parser.add_argument('-t', '--threshold', help='Threshold for detection with IPHandler', action='store', default=0.002, required=False, type=float)
    parser.add_argument('-S', '--sdw_width', help='Width of sliding window. The unit is in \time windows\'. So a -S 10 and a -w 5, means a sliding window of 50 minutes.', action='store', default=10, required=False, type=int)
    parser.add_argument('-W','--whitelist',help="File with the IP addresses to whitelist. One per line.",action='store',required=False)
    parser.add_argument('-r', '--filepath', help='Path to the binetflow file to be read.', required=False)
    args = parser.parse_args()

    # Read the config file from the parameter
    config = configparser.ConfigParser()
    try:
        with open(args.config) as source:
            config.readfp(source)
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
        except configparser.NoOptionError:
            args.verbose = 1
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            pass
    # Limit any verbosity to > 0
    elif args.verbose < 1:
        args.verbose = 1

    # Get the Debugging, if it was not specified as a parameter 
    if args.debug == None:
        # No args debug specified. Read the debug from the config
        try:
            args.debug = int(config.get('parameters', 'debug'))
        except configparser.NoOptionError:
            args.debug = 0
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            pass
    # Limit any debuggisity to > 0
    elif args.debug < 0:
        args.debug = 0

    # Create the queue for the thread
    inputProcessingqueue = Queue()

    globaldata.ip_profiles['1'] = 'test'

    # Create the thread and start it
    inputProcessThread = InputProcessing(inputProcessingqueue, args.verbose, args.debug, config)
    inputProcessThread.start()

    inputProcessingqueue.put('hi')
