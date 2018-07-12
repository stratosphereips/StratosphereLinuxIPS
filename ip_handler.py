#!/usr/bin/python
# Author: Ondrej Lukas - luaksond@fel.cvut.cz
#Description

"""
How is the verdict per IP computed?
Firstly result_per_tuple() function is called to count both all occurences and malicious occurences of each tuple in selected time window.
Return value of result_per_tuple() is tuple (number of malicous occurences, number of all occurences). Next step is counting a weighted score of the IP in selected timewindow.
Function get_weighted_score() is used. First step is to sum values over all  tuples  (get_result_per_tuple() is called for every  tuple). That leads to sum of tuple ratios.
Than percentage of malicous tuples is computed. Malicious tuple is a tuple which contains at leat one connection which was labeled as malicious.
Weighted score(WS) of IP is computed by multiplying sum of tuple ratios with percetage of malicious tuples. This value is stored in the tw_weigthed_scores list. After that, verdict can be computed.
For that sliding detection window (SDW) is used. If width of SDW is N, mean of last N weighted scores is compared to threshold.
If mean od N last WSs is equal or bigger than threshold, IP is labeled as 'Malicious'."""

from datetime import datetime
from time import gmtime, strftime
from colors import *
from utils import WhoisHandler
from alerts import *
import time
import re
from math import *
import ip_blocker

#IP OF FLU VM
flu_ip = '192.168.1.123'

#check if the log directory exists, if not, create it
logdir_path = "./logs"
if not os.path.exists(logdir_path):
    os.makedirs(logdir_path)
#file for logging
filename = logdir_path+"/" + 'log_' + datetime.now().strftime('%Y-%m-%d %H:%M:%S')+'.txt'; 

def timing(f):
    """ Function to measure the time another function takes."""
    def wrap(*args):
        time1 = time.time()
        ret = f(*args)
        time2 = time.time()
        print '%s function took %0.3f ms' % (f.func_name, (time2-time1)*1000.0)
        return ret
    return wrap

class IpAddress(object):
    """IpAddress stores every detection and alerts """
    #TODO: storing ip as string? maybe there is a better way?
    def __init__(self, address, debug):
        self.address = address
        self.tuples = {}
        self.active_tuples = set()
        self.alerts = []
        self.last_time = None
        # What is this variable for? ANSWER: It is used to store weigted scores results indexed by TW index.
        #self.comulative_sum_log_likelihood_ratio = 0;
        self.ws_per_tw = {}
        self.last_tw_result = None
        self.last_verdict = None
        self.debug = debug
        self.blocked = False

        #for mari's experiment
        self.allow_blocking = False

    def add_detection(self, label, tuple, n_chars, input_time, dest_add, state, tw_index):
        """ Stores new detection with timestamp"""
        # The detection structure is a 3-tuple of a label, the number of chars when it was detected and when it was detected
        detection = (label, n_chars, input_time, dest_add, state)
        self.last_time = input_time
        #first time we see this tuple
        if not self.tuples.has_key(tuple):
            self.tuples[tuple] = []
        #add detection to array
        self.tuples[tuple].append(detection)
        self.active_tuples.add(tuple)

    def close_time_window(self):
        """Removes all active tuples in this tw"""
        if self.debug:
            print "#Active tuples in ip:{} = {}".format(self.address,len(self.active_tuples))
        self.active_tuples.clear()
        self.allow_blocking = False

    def result_per_tuple(self, tuple, start_time, end_time):
        """Compute ratio of malicious detection per tuple in timewindow determined by start_time & end_time"""
        try:
            # This counts the amount of times this tuple was detected by any model
            n_malicious = 0
            # This counts the amount of times this tuple was checked
            count = 0
            for detection in self.tuples[tuple]:
                #check if this detection belongs to the TimeWindow
                if (detection[2] >= start_time and detection[2] < end_time):
                    count += 1
                    if detection[0] != False:
                        n_malicious += 1
            if flu_ip in tuple and count > 3:
                self.allow_blocking = True
            return (n_malicious, count)
        except Exception as inst:
            print '\tProblem with result_per_tuple() in ip_handler.py'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)
    
    def print_last_result(self, verbose, start_time, end_time, threshold, use_whois, whois_handler):
        """ 
        Print analysis of this IP in the last time window. Verbosity level modifies amount of information printed.
        """
        try:            
            # Print Malicious IPs
            if self.last_verdict.lower() == 'malicious' and verbose > 0:
                #print red("\t+ {} verdict: {} (Risk: {}) | TW weighted score: {} = {} x {}".format(self.address, self.last_verdict, self.last_risk, self.last_tw_result[0], self.last_tw_result[1], self.last_tw_result[2]))
                # Detection!!! Here we unblock you if you matched the model. So far is a 'normal' model... (file name Malicious thou)
                # Before unblocking you
                if self.address == flu_ip:
                    print cyan('\t\tAt {}, your IP address {} is not blocked'.format(datetime.now(), self.address))
                    file = open('block.log','a')
                    file.write('Real time {}. TW start: {}. TW end: {}. The IP address {} was UNblocked\n'.format(datetime.now(), start_time, end_time, self.address))
                    file.flush()
                    file.close()
                    ip_blocker.remove_reject_rule(self.address)
                    self.blocked = False
        
            elif self.last_verdict.lower() != 'malicious':
                # Not malicious
                # Before blocking check that it is not blocked already. For the adversarial example
                if self.address == flu_ip:
                    if not self.blocked:
                        if self.allow_blocking:
                            print yellow('At {}, your IP address {} is blocked!'.format(datetime.now(), self.address))
                            file = open('block.log','a')
                            file.write('Real time {}. TW start: {}. TW end: {}. The IP address {} was blocked\n'.format(datetime.now(), start_time, end_time, self.address))
                            file.flush()
                            file.close()
                            ip_blocker.add_reject_rule(self.address)
                            self.blocked = True
                        else:
                            print yellow('At {}, NOT ENNOUGH EVIDENCE for your IP address {}'.format(datetime.now(), self.address))
                    elif self.blocked:
                        print cyan('\t\tAt {}, your IP address {} is not blocked BECAUSE you were blocked in the last evaluation'.format(datetime.now(), self.address))
                        file = open('block.log','a')
                        file.write('Real time {}. TW start: {}. TW end: {}. The IP address {} was UNblocked because in the last evaluation it was blocked.\n'.format(datetime.now(), start_time, end_time, self.address))
                        file.flush()
                        file.close()
                        ip_blocker.remove_reject_rule(self.address)
                        self.blocked = False

        except Exception as inst:
            print '\tProblem with print_last_result() in ip_handler.py'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)

    def process_timewindow(self, start_time, end_time, tw_index, sdw_width, swd_threshold):
        """ For this IP, see if we should report a detection or not based on the thresholds and TW"""
        self.last_verdict = 'normal'
        for t in self.active_tuples:
            (malicious, normal) = self.result_per_tuple(t,start_time,end_time)
            if malicious > 0:
                self.last_verdict = 'malicious'
                break
    
    def get_alerts(self):
        """ Returns all the alerts stored in the IP object"""
        return self.alerts

class IpHandler(object):
    """Class which handles all IP actions for slips. Stores every IP object in the session, provides summary, statistics etc."""
    def __init__(self, verbose, debug, whois):
        self.addresses = {}
        self.active_addresses = set()
        self.verbose = verbose
        self.debug = debug
        self.whois = whois
        self.whois_handler = WhoisHandler("WhoisData.txt")
        

    def unblock(self, ip, unblocking_at_start=False):
        """ Unblock this ip """
        print cyan('\t\tAt {}, your IP address {} is not blocked'.format(datetime.now(), ip))
        file = open('block.log','a')
        if unblocking_at_start:
            file.write('Real time {}.The IP address {} UNBLOCKED when SLIPS started\n'.format(datetime.now(),ip))
        else:    
            file.write('Real time {}. The IP address {} was UNblocked because it was blocked in the last TW\n'.format(datetime.now(), ip))
        file.flush()
        file.close()
        ip_blocker.remove_reject_rule(ip)

    # Using this decorator we can measure the time of a function
    # @timing

    def print_addresses(self, start_time, end_time, tw_index, threshold, sdw_width, print_all):
        """ Print information about all the IP addresses in the time window specified in the parameters."""
        if self.debug:
            print "\tTimewindow index:{}, threshold:{},SDW width: {}".format(tw_index,threshold,sdw_width)
        # If we should print all the addresses, because we finish processing.
        if print_all:
            print "\nFinal summary using the complete capture as a unique Time Window (Threshold = %f):" %(threshold)
            # For all the addresses stored in total
            for ip in self.active_addresses:
                #Get the IpAddress object
                address = self.addresses[ip]
                # Process this IP for the time window specified. So we can compute the detection value.
                address.process_timewindow(start_time, end_time, tw_index, 10, threshold)
                # Get a printable version of this IP's data
                address.print_last_result(self.verbose, start_time, end_time, threshold, self.whois, self.whois_handler)
        # If we should NOT print all the addresses, because we are inside a time window
        if not print_all:
            # We should not process all the ips here...
           for ip in self.active_addresses:
                #Get the IpAddress object
                address = self.addresses[ip]
                # Process this IP for the time window specified. So we can compute the detection value.
                address.process_timewindow(start_time, end_time, tw_index, sdw_width, threshold)
                # Get a printable version of this IP's data
                address.print_last_result(self.verbose, start_time, end_time, threshold, self.whois, self.whois_handler)

    def get_ip(self, ip_string):
        """Get the IpAddress object with id 'ip_string'. If it doesn't exists, create it"""
        #Have I seen this IP before?
        ip = None
        if ip_string not in self.addresses.keys():
            ip = IpAddress(ip_string,self.debug)
            self.addresses[ip_string] = ip
        ip = self.addresses[ip_string]
        self.active_addresses.add(ip_string)
        return ip

    def print_alerts(self):
        """ Gater all the alerts in the handler and print them"""
        detected_counter = 0
        self.whois_handler.store_whois_data_in_file()
        print '\nFinal Alerts generated:'
        f = open(filename,"w")
        f.write("DATE:\t{}\nSummary of addresses in this capture:\n\n".format(datetime.now().strftime('%Y/%m/%d %H:%M:%S')))
        f.write('Alerts:\n')
        for ip in self.addresses.values():
            if len(ip.alerts) > 0:
                detected_counter+=1
                print "\t - "+ ip.address
                f.write( '\t - ' + ip.address + '\n')
                for alert in ip.get_alerts():
                    print "\t\t" + str(alert)
                    f.write( '\t\t' + str(alert) + '\n')

        s = "{} IP(s) out of {} detected as malicious.".format(detected_counter,len(self.addresses.keys()))
        f.write(s)
        print s
        f.close()

    def close_time_window(self):
        """Clears all the active objects in the timewindow. Should be called at the end of every TW"""
        #close tw in all active IpAddress objects
        for ip in self.active_addresses:
            self.addresses[ip].close_time_window()
        #clear the active_addresses set
        if self.debug:
            print "# active IPs: {}".format(len(self.active_addresses))
        self.active_addresses.clear()



