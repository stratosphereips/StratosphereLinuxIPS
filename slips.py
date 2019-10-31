#!/usr/bin/env python3
# This file is part of the Stratosphere Linux IPS
# See the file 'LICENSE' for copying permission.
# Author: Sebastian Garcia. eldraco@gmail.com , sebastian.garcia@agents.fel.cvut.cz

import configparser
import argparse
import multiprocessing
from multiprocessing import Queue
import time
from modules.markov_models_1 import __markov_models__
from os import listdir
from os.path import isfile, join
import logging
import re
import ConfigParser
from ip_handler import IpHandler
from utils import SignalHandler
import random
# Optional memory profiling
#from memory_profiler import profile
# Use with @profile

version = '0.3.5'

def timing(f):
    """ Function to measure the time another function takes."""
    def wrap(*args, **kwargs):
        time1 = time.time()
        ret = f(*args, **kwargs)
        time2 = time.time()
        print '%s function took %0.3f ms' % (f.func_name, (time2-time1)*1000.0)
        return ret
    return wrap


###################
# Tuple
class Tuple(object):
    """ The class to simply handle tuples """
    def __init__(self, tuple4):
        self.id = tuple4
        self.amount_of_flows = 0
        self.src_ip = tuple4.split('-')[0]
        self.dst_ip = tuple4.split('-')[1]
        self.protocol = tuple4.split('-')[3]
        self.state_so_far = ""
        self.winner_model_id = False
        self.winner_model_distance = float('inf')
        self.proto = ""
        self.datetime = ""
        self.T1 = False
        self.T2 = False
        self.TD = False
        self.current_size = -1
        self.current_duration = -1
        self.previous_size = -1
        self.previous_duration = -1
        self.previous_time = -1
        # Thresholds
        self.tto = timedelta(seconds=3600)
        self.tt1 = float(1.05)
        self.tt2 = float(1.3)
        self.tt3 = float(5)
        self.td1 = float(0.1)
        self.td2 = float(10)
        self.ts1 = float(250)
        self.ts2 = float(1100)
        # The state
        self.state = ""
        # Final values for getting the state
        self.duration = -1
        self.size = -1
        self.periodic = -1
        self.color = str
        # By default print all tuples. Depends on the arg
        self.should_be_printed = True
        self.desc = ''
        # After a tuple is detected, min_state_len holds the lower letter position in the state
        # where the detection happened.
        self.min_state_len = 0
        # After a tuple is detected, max_state_len holds the max letter position in the state
        # where the detection happened. The new arriving letters to be detected are between max_state_len and the real end of the state
        self.max_state_len = 0
        self.detected_label = False

    def set_detected_label(self, label):
        self.detected_label = label

    def unset_detected_label(self):
        self.detected_label = False

    def get_detected_label(self):
        return self.detected_label

    def get_state_detected_last(self):
        if self.max_state_len == 0:
            # First time before any detection
            return self.state[self.min_state_len:]
        # After the first detection
        return self.state[self.min_state_len:self.max_state_len]

    def set_min_state_len(self, state_len):
        self.min_state_len = state_len

    def get_min_state_len(self):
        return self.min_state_len

    def set_max_state_len(self, state_len):
        self.max_state_len = state_len

    def get_max_state_len(self):
        return self.max_state_len

    def get_protocol(self):
        return self.protocol

    def get_state(self):
        return self.state

    def set_verbose(self, verbose):
        self.verbose = verbose

    def set_debug(self, debug):
        self.debug = debug

    def add_new_flow(self, column_values):
        """ Add new stuff about the flow in this tuple """
        # 0:starttime, 1:dur, 2:proto, 3:saddr, 4:sport, 5:dir, 6:daddr: 7:dport, 8:state, 9:stos,  10:dtos, 11:pkts, 12:bytes
        # Store previous
        self.previous_size = self.current_size
        self.previous_duration = self.current_duration
        self.previous_time = self.datetime
        if self.debug > 2:
            print 'Adding flow {}'.format(column_values)
        # Get the starttime
        self.datetime = datetime.strptime(column_values[0], timeStampFormat)
        # Get the size
        try:
            self.current_size = float(column_values[12])
        except ValueError:
            # It can happen that we don't have this value in the binetflow
            # ------->>> it may not always be ValueError it can also be indexout of bound error.
            self.current_size = 0.0
        except Exception:
            self.current_size = 0.0
        # Get the duration
        try:
            self.current_duration = float(column_values[1])
        except ValueError:
            # It can happen that we dont have this value in the binetflow
            self.current_duration = 0.0
        # Get the protocol
        self.proto = str(column_values[2])
        # Get the amount of flows
        self.amount_of_flows += 1
        # Update value of T1
        self.T1 = self.T2
        try:
            # Update value of T2
            self.T2 = self.datetime - self.previous_time
            # Are flows sorted?
            if self.T2.total_seconds() < 0:
                # Flows are not sorted
                if self.debug > 2:
                    print '@',
                # What is going on here when the flows are not ordered?? Are we losing flows?
        except TypeError:
            self.T2 = False
        # Compute the rest
        self.compute_periodicity()
        self.compute_duration()
        self.compute_size()
        self.compute_state()
        self.compute_symbols()
        if self.debug > 4:
            print '\tTuple {}. Amount of flows so far: {}'.format(self.get_id(), self.amount_of_flows)

    def compute_periodicity(self):
        # If either T1 or T2 are False
        if (isinstance(self.T1, bool) and self.T1 == False) or (isinstance(self.T2, bool) and self.T2 == False):
            self.periodicity = -1
        elif self.T2 >= self.tto:
            t2_in_hours = self.T2.total_seconds() / self.tto.total_seconds()
            # Should be int always
            for i in range(int(t2_in_hours)):
                self.state += '0'
        elif self.T1 >= self.tto:
            t1_in_hours = self.T1.total_seconds() / self.tto.total_seconds()
            # Should be int always
            for i in range(int(t1_in_hours)):
                self.state += '0'
        if not isinstance(self.T1, bool) and not isinstance(self.T2, bool):
            try:
                if self.T2 >= self.T1:
                    self.TD = timedelta(seconds=(self.T2.total_seconds() / self.T1.total_seconds())).total_seconds()
                else:
                    self.TD = timedelta(seconds=(self.T1.total_seconds() / self.T2.total_seconds())).total_seconds()
            except ZeroDivisionError:
                self.TD = 1
            # Decide the periodic based on TD and the thresholds
            if self.TD <= self.tt1:
                # Strongly periodic
                self.periodic = 1
            elif self.TD < self.tt2:
                # Weakly periodic
                self.periodic = 2
            elif self.TD < self.tt3:
                # Weakly not periodic
                self.periodic = 3
            else:
                self.periodic = 4
        if self.debug > 3:
            print '\tPeriodic: {}'.format(self.periodic)

    def compute_duration(self):
        if self.current_duration <= self.td1:
            self.duration = 1
        elif self.current_duration > self.td1 and self.current_duration <= self.td2:
            self.duration = 2
        elif self.current_duration > self.td2:
            self.duration = 3
        if self.debug > 3:
            print '\tDuration: {}'.format(self.duration)

    def compute_size(self):
        if self.current_size <= self.ts1:
            self.size = 1
        elif self.current_size > self.ts1 and self.current_size <= self.ts2:
            self.size = 2
        elif self.current_size > self.ts2:
            self.size = 3
        if self.debug > 3:
            print '\tSize: {}'.format(self.size)

    def compute_state(self):
        if self.periodic == -1:
            if self.size == 1:
                if self.duration == 1:
                    self.state += '1'
                elif self.duration == 2:
                    self.state += '2'
                elif self.duration == 3:
                    self.state += '3'
            elif self.size == 2:
                if self.duration == 1:
                    self.state += '4'
                elif self.duration == 2:
                    self.state += '5'
                elif self.duration == 3:
                    self.state += '6'
            elif self.size == 3:
                if self.duration == 1:
                    self.state += '7'
                elif self.duration == 2:
                    self.state += '8'
                elif self.duration == 3:
                    self.state += '9'
        elif self.periodic == 1:
            if self.size == 1:
                if self.duration == 1:
                    self.state += 'a'
                elif self.duration == 2:
                    self.state += 'b'
                elif self.duration == 3:
                    self.state += 'c'
            elif self.size == 2:
                if self.duration == 1:
                    self.state += 'd'
                elif self.duration == 2:
                    self.state += 'e'
                elif self.duration == 3:
                    self.state += 'f'
            elif self.size == 3:
                if self.duration == 1:
                    self.state += 'g'
                elif self.duration == 2:
                    self.state += 'h'
                elif self.duration == 3:
                    self.state += 'i'
        elif self.periodic == 2:
            if self.size == 1:
                if self.duration == 1:
                    self.state += 'A'
                elif self.duration == 2:
                    self.state += 'B'
                elif self.duration == 3:
                    self.state += 'C'
            elif self.size == 2:
                if self.duration == 1:
                    self.state += 'D'
                elif self.duration == 2:
                    self.state += 'E'
                elif self.duration == 3:
                    self.state += 'F'
            elif self.size == 3:
                if self.duration == 1:
                    self.state += 'G'
                elif self.duration == 2:
                    self.state += 'H'
                elif self.duration == 3:
                    self.state += 'I'
        elif self.periodic == 3:
            if self.size == 1:
                if self.duration == 1:
                    self.state += 'r'
                elif self.duration == 2:
                    self.state += 's'
                elif self.duration == 3:
                    self.state += 't'
            elif self.size == 2:
                if self.duration == 1:
                    self.state += 'u'
                elif self.duration == 2:
                    self.state += 'v'
                elif self.duration == 3:
                    self.state += 'w'
            elif self.size == 3:
                if self.duration == 1:
                    self.state += 'x'
                elif self.duration == 2:
                    self.state += 'y'
                elif self.duration == 3:
                    self.state += 'z'
        elif self.periodic == 4:
            if self.size == 1:
                if self.duration == 1:
                    self.state += 'R'
                elif self.duration == 2:
                    self.state += 'S'
                elif self.duration == 3:
                    self.state += 'T'
            elif self.size == 2:
                if self.duration == 1:
                    self.state += 'U'
                elif self.duration == 2:
                    self.state += 'V'
                elif self.duration == 3:
                    self.state += 'W'
            elif self.size == 3:
                if self.duration == 1:
                    self.state += 'X'
                elif self.duration == 2:
                    self.state += 'Y'
                elif self.duration == 3:
                    self.state += 'Z'

    def compute_symbols(self):
        if not isinstance(self.T2, bool):
            if self.T2 <= timedelta(seconds=5):
                self.state += '.'
            elif self.T2 <= timedelta(seconds=60):
                self.state += ','
            elif self.T2 <= timedelta(seconds=300):
                self.state += '+'
            elif self.T2 <= timedelta(seconds=3600):
                self.state += '*'
        if self.debug > 3:
            print '\tTD:{}, T2:{}, T1:{}, State: {}'.format(self.TD, self.T2, self.T1, self.state)

    def get_id(self):
        return self.id

    def __repr__(self):
        return('{} [{}] ({}): {}'.format(self.color(self.get_id()), self.desc, self.amount_of_flows, self.state))

    def print_tuple_detected(self):
        """
        Print the tuple. The state is the state since the last detection of the tuple. Not everything
        """
        return('{} [{}] ({}): {}  Detected as: {}'.format(self.color(self.get_id()), self.desc, self.amount_of_flows, self.get_state_detected_last(), self.get_detected_label()))

    def set_color(self, color):
        self.color = color

# Process
class Processor(multiprocessing.Process):
    """ A class process to run the process of the flows """
    def __init__(self, queue, slot_width, get_whois, verbose, amount, dontdetect, threshold, debug, whitelist, sdw_width, config, parsingfunction):
        multiprocessing.Process.__init__(self)
        self.get_whois = get_whois
        self.verbose = verbose
        self.debug = debug
        # The amount of letters requested to print minimum
        self.amount = amount
        self.queue = queue
        self.tuples = {}
        self.tuples_in_this_time_slot = {}
        self.slot_starttime = -1
        self.slot_endtime = -1
        self.slot_width = slot_width
        self.dontdetect = dontdetect
        self.ip_handler = IpHandler(self.verbose, self.debug,self.get_whois)
        self.detection_threshold = threshold;
        # Used to keep track in which time window we are currently in (also total amount of tw)
        self.tw_index = 0
        self.ip_whitelist = whitelist
        #CHANGE THIS
        self.sdw_width = sdw_width
        self.config = config
        self.parsingfunction = parsingfunction

    def get_tuple(self, tuple4):
        """ Get the values and return the correct tuple for them """
        try:
            tuple = self.tuples[tuple4]
            # We already have this connection
        except KeyError:
            # First time for this connection
            tuple = Tuple(tuple4)
            tuple.set_verbose(self.verbose)
            tuple.set_debug(self.debug)
            self.tuples[tuple4] = tuple
        return tuple

    def process_out_of_time_slot(self, column_values, last_tw = False):
        """
        Process the tuples when we are out of the time slot
        last_tw specifies if we know this is the last time window. So we don't add the flow into the 'next' one. There was a problem were we store the last flow twice.
        """
        try:
            # Outside the slot
            if self.verbose > 1:
                print cyan('Time Window Started: {}, finished: {}. ({} connections)'.format(self.slot_starttime, self.slot_endtime, len(self.tuples_in_this_time_slot)))
            for tuple4 in self.tuples:
                tuple = self.get_tuple(tuple4)
                """
                    # Print the tuple and search its whois only if it has more than X amount of letters.
                    # This was the old way of stopping the system of analyzing tuples with less than amount of letters. Now should not be done here.
                    # if tuple.amount_of_flows > self.amount and tuple.should_be_printed:
                    if tuple.should_be_printed:
                        if not tuple.desc and self.get_whois:
                            tuple.get_whois_data()
                        print tuple.print_tuple_detected()
                    # Clear the color because we already print it
                    if tuple.color == red:
                        tuple.set_color(yellow)
                    # After printing the tuple in this time slot, we should not print it again unless we see some of its flows.
                    if tuple.should_be_printed:
                        tuple.dont_print()
                """
            # Print all the addresses in this time window
            self.ip_handler.print_addresses(self.slot_starttime, self.slot_endtime, self.tw_index, self.detection_threshold, self.sdw_width, False)
            # Add 1 to the time window index 
            self.tw_index +=1
            """
            # After each timeslot finishes forget the tuples that are too big. This is useful when a tuple has a very very long state that is not so useful to us. Later we forget it when we detect it or after a long time.
            ids_to_delete = []
            for tuple in self.tuples:
                # We cut the strings of letters regardless of it being detected before.
                if self.tuples[tuple].amount_of_flows > 100:
                    if self.debug > 3:
                           print 'Delete all the letters because there were more than 100 and it was detected. Start again with this tuple.'
                    ids_to_delete.append(self.tuples[tuple].get_id())
            # Actually delete them
            for id in ids_to_delete:
                del self.tuples[id]
            """
            # Move the time window times
            self.slot_starttime = datetime.strptime(column_values[0], timeStampFormat)
            self.slot_endtime = self.slot_starttime + self.slot_width
            #Clear previous TW in ip_handler
            self.ip_handler.close_time_window()

            # If not the last TW. Put the last flow received in the next slot, because it overcome the threshold and it was not processed
            if not last_tw:
                tuple4 = column_values[3]+'-'+column_values[6]+'-'+column_values[7]+'-'+column_values[2]
                tuple = self.get_tuple(tuple4)
                """
                if self.verbose:
                    # If this is the first time this tuple appears in this time window, print it in red.
                    if len(tuple.state) == 0:
                        tuple.set_color(red)
                """
                tuple.add_new_flow(column_values)
                # Detect the first flow of the future timeslot
                self.detect(tuple)
                self.tuples_in_this_time_slot = {}
                flowtime = datetime.strptime(column_values[0], '%Y/%m/%d %H:%M:%S.%f')
                # Ask for the IpAddress object for this source IP
                ip_address = self.ip_handler.get_ip(column_values[3])
                # Store detection result into Ip_address
                ip_address.add_detection(tuple.detected_label, tuple.id, tuple.current_size, flowtime, column_values[6], tuple.get_state_detected_last(), self.tw_index)
        except Exception as inst:
            print 'Problem in process_out_of_time_slot() in class Processor'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            exit(-1)

    def detect(self, tuple):
        """
        Detect behaviors
        """
        try:
            if not self.dontdetect:
                (detected, label, statelen) = __markov_models__.detect(tuple, self.verbose, self.debug)
                if detected:
                    # Change color
                    tuple.set_color(magenta)
                    # Set the detection label
                    tuple.set_detected_label(label)
                    """
                    # Set the detection state len
                    tuple.set_best_model_matching_len(statelen)

                    """
                    #print tuple.state[:statelen]
                    #print tuple.state[len(tuple.state)-statelen:-1]
                    if self.debug > 5:
                        print 'Last flow: Detected with {}'.format(label)
                    # Play sound
                    if args.sound:
                        pygame.mixer.music.play()
                elif not detected:
                    # Not detected by any reason. No model matching but also the state len is too short.
                    tuple.unset_detected_label()
                    if self.debug > 5:
                        print 'Last flow: Not detected'
        except Exception as inst:
            print '\tProblem with detect()'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)

    def run(self):
        try:
            while True:
                line = self.queue.get()
                if 'stop' != line:
                    # Process this flow
                    column_values = self.parsingfunction(line)
                    try:
                        # check if the Ip is not in the whitelist
                        if not column_values[3] in self.ip_whitelist:
                            if 'Start' in column_values[0]:
                                continue
                            # Get some way of not having this if here for every line
                            if self.slot_starttime == -1:
                                # First flow
                                #try:
                                self.slot_starttime = datetime.strptime(column_values[0], timeStampFormat)
                                #except ValueError:
                                #    # This should be a continue because this is the first flow, usually the header
                                #    continue
                                self.slot_endtime = self.slot_starttime + self.slot_width
                            try:
                                flowtime = datetime.strptime(column_values[0], timeStampFormat)
                            except ValueError:
                                logger.error("Invalid timestamp format: {}. Line: {}".format(timeStampFormat, line))
                            if flowtime >= self.slot_starttime and flowtime < self.slot_endtime:
                                # Inside the slot
                                tuple4 = column_values[3]+'-'+column_values[6]+'-'+column_values[7]+'-'+column_values[2]
                                tuple = self.get_tuple(tuple4)
                                self.tuples_in_this_time_slot[tuple.get_id()] = tuple
                                # If this is the first time the tuple appears in this time windows, put it in red
                                if self.verbose:
                                    if len(tuple.state) == 0:
                                        tuple.set_color(red)
                                tuple.add_new_flow(column_values)
                                """
                                tuple.do_print()
                                """
                                # After the flow has been added to the tuple, only work with the ones having more than X amount of flows
                                # Check that this is working correclty comparing it to the old program
                                if len(tuple.state) >= self.amount:
                                    """
                                    tuple.do_print()
                                    """
                                    # Detection
                                    self.detect(tuple)
                                    # Ask for IpAddress object
                                    ip_address = self.ip_handler.get_ip(column_values[3])
                                    # Store detection result into Ip_address
                                    ip_address.add_detection(tuple.detected_label, tuple.id, tuple.current_size, flowtime,column_values[6], tuple.get_state_detected_last(),self.tw_index)
                            elif flowtime > self.slot_endtime:
                                # Out of time slot
                                self.process_out_of_time_slot(column_values, last_tw = False)
                        else:
                            if self.debug:
                                print blue("Skipping flow with whitelisted ip: {}".format(column_values[3]))
                    except UnboundLocalError:
                        print 'Probably empty file.'
                else:
                    try:
                        # Process the last flows in the last time slot
                        self.process_out_of_time_slot(column_values, last_tw = True)
                        # There was an error here that we were calling self.ip_handler.print_addresses. But we should NOT call it here. The last flow was already taken care.
                        # Print final Alerts
                        self.ip_handler.print_alerts()
                    except UnboundLocalError:
                        print 'Probably empty file...'
                        # Here for some reason we still miss the last flow. But since is just one i will let it go for now.
                    # Just Return
                    return True
        except KeyboardInterrupt:
            # Print Summary of detections in the last Time Window
            #self.ip_handler.print_addresses(flowtime, flowtime, self.detection_threshold,self.sdw_width, True)
            # Print final Alerts
            #self.ip_handler.print_alerts()
            return True
        except Exception as inst:
            print '\tProblem with Processor()'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)
import sys
import redis
import os

version = '0.6.1'

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
    parser.add_argument('-N', '--nodejs', help='Use the NodeJS interface.', required=False, default=False, action='store_true')
    parser.add_argument('-b', '--nfdump', help='A binary file from NFDUMP to read. NFDUMP is used to send data to slips.', required=False)
    parser.add_argument('-C', '--curses', help='Use the curses output interface.', required=False, default=False, action='store_true')
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

    # check if redis server running
    server_redis_version = test_redis_database()
    if server_redis_version is None:
        terminate_slips()

    # If we need zeek (bro), test if we can run it.
    if args.pcapfile:
        visible_zeek = test_program('bro --version')
        if visible_zeek is False:
            # If we do not have access to zeek and we want to use it, kill it.
            terminate_slips()

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
    from cursesProcess import CursesProcess
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
    for module_name in __modules__:
        if not module_name in to_ignore:
            module_class = __modules__[module_name]['obj']
            ModuleProcess = module_class(outputProcessQueue, config)
            ModuleProcess.start()
            outputProcessQueue.put('20|main|\t[main] Starting the module {} ({}) [PID {}]'.format(module_name, __modules__[module_name]['description'], ModuleProcess.pid))

    # Get the type of output from the parameters
    # Several combinations of outputs should be able to be used
    if args.nodejs:
        # Create the curses thread
        cursesProcessQueue = Queue()
        cursesProcessThread = CursesProcess(cursesProcessQueue, outputProcessQueue, args.verbose, args.debug, config)
        cursesProcessThread.start()
        outputProcessQueue.put('20|main|Started Curses thread [PID {}]'.format(cursesProcessThread.pid))
    elif not args.nologfiles:
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
    evidenceProcessQueue.close()
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

    profilerProcessQueue.close()
    outputProcessQueue.close()
