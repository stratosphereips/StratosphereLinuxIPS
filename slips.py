#!/usr/bin/python -u
# This file is part of the Stratosphere Linux IPS
# See the file 'LICENSE' for copying permission.
# Author: Sebastian Garcia. eldraco@gmail.com , sebastian.garcia@agents.fel.cvut.cz

import sys
from colors import *
from datetime import datetime
from datetime import timedelta
import argparse
import multiprocessing
from multiprocessing import Queue
import time
from modules.markov_models_1 import __markov_models__
from os import listdir
from os.path import isfile, join

version = '0.3.3alpha'

###################
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

    def get_whois_data(self):
        try:
            import ipwhois
        except ImportError:
            print 'The ipwhois library is not install. pip install ipwhois'
            return False
        # is the ip in the cache
        try:
            self.desc = whois_cache[self.dst_ip]
        except KeyError:
            # Is not, so just ask for it
            try:
                obj = ipwhois.IPWhois(self.dst_ip)
                data = obj.lookup()
                try:
                    self.desc = data['nets'][0]['description'].strip().replace('\n',' ') + ',' + data['nets'][0]['country']
                except AttributeError:
                    # There is no description field
                    self.desc = ""
            except ipwhois.IPDefinedError as e:
                if 'Multicast' in e:
                    self.desc = 'Multicast'
                self.desc = 'Private Use'
            except ipwhois.ipwhois.WhoisLookupError:
                print 'Error looking the whois of {}'.format(self.dst_ip)
                # continue with the work
            except ValueError:
                # Not a real IP, maybe a MAC
                pass
            except IndexError:
                # Some problem with the whois info. Continue
                pass
            # Store in the cache
            whois_cache[self.dst_ip] = self.desc

    def add_new_flow(self, column_values):
        """ Add new stuff about the flow in this tuple """
        # 0:starttime, 1:dur, 2:proto, 3:saddr, 4:sport, 5:dir, 6:daddr: 7:dport, 8:state, 9:stos,  10:dtos, 11:pkts, 12:bytes
        # Store previous
        self.previous_size = self.current_size
        self.previous_duration = self.current_duration
        self.previous_time = self.datetime
        if self.verbose > 2:
            print '\nAdding flow {}'.format(column_values)
        # Get the starttime
        self.datetime = datetime.strptime(column_values[0], '%Y/%m/%d %H:%M:%S.%f')
        # Get the size
        try:
            self.current_size = float(column_values[12])
        except ValueError:
            # It can happen that we dont have this value in the binetflow
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
                if self.verbose > 2:
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
        self.do_print()
        if self.verbose > 1:
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
        if self.verbose > 2:
            print '\tPeriodic: {}'.format(self.periodic)

    def compute_duration(self):
        if self.current_duration <= self.td1:
            self.duration = 1
        elif self.current_duration > self.td1 and self.current_duration <= self.td2:
            self.duration = 2
        elif self.current_duration > self.td2:
            self.duration = 3
        if self.verbose > 2:
            print '\tDuration: {}'.format(self.duration)

    def compute_size(self):
        if self.current_size <= self.ts1:
            self.size = 1
        elif self.current_size > self.ts1 and self.current_size <= self.ts2:
            self.size = 2
        elif self.current_size > self.ts2:
            self.size = 3
        if self.verbose > 2:
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
        if self.verbose > 2:
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

    def dont_print(self):
        if self.verbose > 3:
            print '\tDont print tuple {}'.format(self.get_id())
        self.should_be_printed = False

    def do_print(self):
        self.should_be_printed = True
        if self.verbose > 3:
            print '\tPrint tuple {}'.format(self.get_id())

# Process


class Processor(multiprocessing.Process):
    """ A class process to run the process of the flows """
    def __init__(self, queue, slot_width, get_whois, verbose, amount, dontdetect):
        multiprocessing.Process.__init__(self)
        self.get_whois = get_whois
        self.verbose = verbose
        # The amount of letters requested to print minimum
        self.amount = amount
        self.queue = queue
        self.tuples = {}
        self.tuples_in_this_time_slot = {}
        self.slot_starttime = -1
        self.slot_endtime = -1
        self.slot_width = slot_width
        self.dontdetect = dontdetect

    def get_tuple(self, tuple4):
        """ Get the values and return the correct tuple for them """
        try:
            tuple = self.tuples[tuple4]
            # We already have this connection
        except KeyError:
            # First time for this connection
            tuple = Tuple(tuple4)
            tuple.set_verbose(self.verbose)
            self.tuples[tuple4] = tuple
        return tuple

    def process_out_of_time_slot(self, column_values):
        """
        Process the tuples when we are out of the time slot
        """
        # Outside the slot
        if self.verbose:
            print cyan('Slot Started: {}, finished: {}. ({} connections)'.format(self.slot_starttime, self.slot_endtime, len(self.tuples_in_this_time_slot)))
            for tuple4 in self.tuples:
                tuple = self.get_tuple(tuple4)
                if tuple.amount_of_flows > self.amount and tuple.should_be_printed:
                    if not tuple.desc and self.get_whois:
                        tuple.get_whois_data()
                    print tuple.print_tuple_detected()
                # Clear the color because we already print it
                if tuple.color == red:
                    tuple.set_color(yellow)
                # After printing the tuple in this time slot, we should not print it again unless we see some of its flows.
                if tuple.should_be_printed:
                    tuple.dont_print()
        # After each timeslot finishes forget the tuples that are too big. This is useful when a tuple has a very very long state that is not so useful to us. Later we forget it when we detect it or after a long time.
        ids_to_delete = []
        for tuple in self.tuples:
            # We cut the strings of letters regardless of it being detected before.
            if self.tuples[tuple].amount_of_flows > 100:
                if self.verbose > 3:
                    print 'Delete all the letters because there were more than 100 and it was detected. Start again with this tuple.'
                ids_to_delete.append(self.tuples[tuple].get_id())
        # Actually delete them
        for id in ids_to_delete:
            del self.tuples[id]
        # Move the time slot
        self.slot_starttime = datetime.strptime(column_values[0], '%Y/%m/%d %H:%M:%S.%f')
        self.slot_endtime = self.slot_starttime + self.slot_width

        # Put the last flow received in the next slot, because it overcome the threshold and it was not processed
        tuple4 = column_values[3]+'-'+column_values[6]+'-'+column_values[7]+'-'+column_values[2]
        tuple = self.get_tuple(tuple4)
        if self.verbose:
            if len(tuple.state) == 0:
                tuple.set_color(red)
        tuple.add_new_flow(column_values)
        # Detect the first flow of the future timeslot
        self.detect(tuple)
        # Empty the tuples in this time window
        self.tuples_in_this_time_slot = {}

    def detect(self, tuple):
        """
        Detect behaviors
        """
        try:
            if not self.dontdetect:
                (detected, label, statelen) = __markov_models__.detect(tuple, self.verbose)
                if detected:
                    # Change color
                    tuple.set_color(magenta)
                    # Set the detection label
                    tuple.set_detected_label(label)
                    """
                    # Set the detection state len
                    tuple.set_best_model_matching_len(statelen)
                    """
                    if self.verbose > 5:
                        print 'Last flow: Detected with {}'.format(label)
                    # Play sound
                    if args.sound:
                        pygame.mixer.music.play()
                elif not detected:
                    # Not detected by any reason. No model matching but also the state len is too short.
                    tuple.unset_detected_label()
                    if self.verbose > 5:
                        print 'Last flow: Not detected'
                    tuple.dont_print()
        except Exception as inst:
            print '\tProblem with detect()'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)

    def run(self):
        try:
            while True:
                if not self.queue.empty():
                    line = self.queue.get()
                    if 'stop' != line:
                        # Process this flow
                        nline = ','.join(line.strip().split(',')[:13])
                        try:
                            column_values = nline.split(',')
                            # 0:starttime, 1:dur, 2:proto, 3:saddr, 4:sport, 5:dir, 6:daddr: 7:dport, 8:state, 9:stos,  10:dtos, 11:pkts, 12:bytes
                            if self.slot_starttime == -1:
                                # First flow
                                try:
                                    self.slot_starttime = datetime.strptime(column_values[0], '%Y/%m/%d %H:%M:%S.%f')
                                except ValueError:
                                    continue
                                self.slot_endtime = self.slot_starttime + self.slot_width
                            flowtime = datetime.strptime(column_values[0], '%Y/%m/%d %H:%M:%S.%f')
                            if flowtime >= self.slot_starttime and flowtime < self.slot_endtime:
                                # Inside the slot
                                tuple4 = column_values[3]+'-'+column_values[6]+'-'+column_values[7]+'-'+column_values[2]
                                tuple = self.get_tuple(tuple4)
                                self.tuples_in_this_time_slot[tuple.get_id()] = tuple
                                if self.verbose:
                                    if len(tuple.state) == 0:
                                        tuple.set_color(red)
                                tuple.add_new_flow(column_values)
                                # Detection
                                self.detect(tuple)
                            elif flowtime > self.slot_endtime:
                                # Out of time slot
                                self.process_out_of_time_slot(column_values)
                        except UnboundLocalError:
                            print 'Probable empty file.'
                    else:
                        try:
                            # Process the last flows in the last time slot
                            self.process_out_of_time_slot(column_values)
                        except UnboundLocalError:
                            print 'Probable empty file.'
                            # Here for some reason we still miss the last flow. But since is just one i will let it go for now.
                        # Just Return
                        return True

        except KeyboardInterrupt:
            return True
        except Exception as inst:
            print '\tProblem with Processor()'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)





####################
# Main
####################
print 'Stratosphere Linux IPS. Version {}\n'.format(version)

# Parse the parameters
parser = argparse.ArgumentParser()
parser.add_argument('-a', '--amount', help='Minimum amount of flows that should be in a tuple to be printed.', action='store', required=False, type=int, default=-1)
parser.add_argument('-v', '--verbose', help='Amount of verbosity.', action='store', default=1, required=False, type=int)
parser.add_argument('-w', '--width', help='Width of the time slot used for the analysis. In minutes.', action='store', default=5, required=False, type=int)
parser.add_argument('-d', '--datawhois', help='Get and show the whois info for the destination IP in each tuple', action='store_true', default=False, required=False)
parser.add_argument('-D', '--dontdetect', help='Dont detect the malicious behavior in the flows using the models. Just print the connections.', default=False, action='store_true', required=False)
parser.add_argument('-f', '--folder', help='Folder with models to apply for detection.', action='store', required=False)
parser.add_argument('-s', '--sound', help='Play a small sound when a periodic connections is found.', action='store_true', default=False, required=False)
args = parser.parse_args()

# Global shit for whois cache. The tuple needs to access it but should be shared, so global
whois_cache = {}

if args.dontdetect:
    print 'Warning: No detections will be done. Only the behaviors are printed.'
    print
    # If the folder with models was specified, just ignore it
    args.folder = False

# Do we need sound?
if args.sound:
    import pygame.mixer
    pygame.mixer.init(44100)
    pygame.mixer.music.load('periodic.ogg')


# Read the folder with models if specified
if args.folder:
    onlyfiles = [f for f in listdir(args.folder) if isfile(join(args.folder, f))]
    print 'Detecting malicious behaviors with the following models:'
    for file in onlyfiles:
        __markov_models__.set_model_to_detect(join(args.folder, file))

# Create the queue
queue = Queue()
# Create the thread and start it
processorThread = Processor(queue, timedelta(minutes=args.width), args.datawhois, args.verbose, args.amount, args.dontdetect)
processorThread.start()

# Just put the lines in the queue as fast as possible
for line in sys.stdin:
    queue.put(line)
    #print 'A: {}'.format(queue.qsize())
print 'Finished receiving the input.'
# Shall we wait? Not sure. Seems that not
time.sleep(1)
queue.put('stop')
