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
    def __init__(self, address, verbose, debug):
        self.address = address
        self.tuples = {}
        self.active_tuples = set()
        self.alerts = []
        # What is this variable for? ANSWER: It is used to store weigted scores results indexed by TW index.
        self.ws_per_tw = {}
        self.last_tw_result = None
        self.last_verdict = None
        self.last_time = None
        self.last_SDW_score = -1;
        self.verbose = verbose
        self.debug = debug

    def add_detection(self, label, tuple, n_chars, input_time, dest_add, state, tw_index):
        """ Stores new detection with timestamp"""
        # The detection structure is a 3-tuple of a label, the number of chars when it was detected and when it was detected
        detection = (label, n_chars, input_time, dest_add, state)
        self.last_time = input_time
        #first time we see this tuple
        if(not self.tuples.has_key(tuple)):
            self.tuples[tuple] = []
        #add detection to array
        self.tuples[tuple].append(detection)
        self.active_tuples.add(tuple)

    def close_time_window(self):
        """Removes all active tuples in this tw"""
        if self.debug:
            print "#Active tuples in ip:{} = {}".format(self.address,len(self.active_tuples))
        self.active_tuples.clear()

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
            return (n_malicious, count)
        except Exception as inst:
            print '\tProblem with result_per_tuple() in ip_handler.py'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)

    def get_weighted_score(self, start_time, end_time, tw_index):
        """ This is the main function that computes if the IP should be detected or not based on the tw, the thresholds, the average, etc."""
        """ What is the tuple score: Explain"""
        """ What is the weigthed score: Explain"""
        """ Returns the weighted score for the time windows specified"""
        if self.debug > 0:
            print '\tCompute the detection score for {}'.format(self.address)
        tuple_ratios_sum = 0 
        n_malicious_connections= 0
        n_connections = 0
        n_infected_tuples = 0
        n_tuples_in_tw = 0
        weighted_score = 0
        detected_tuples_perc = 0
        # For each tuple stored for this IP, compute the tuple score.
        for tuple4 in self.active_tuples:

            if self.debug > 1:
                print '\t\tChecking the detection score for tuple {}'.format(tuple4)
            # Get result for this tuple
            (times_detected, times_checked) = self.result_per_tuple(tuple4,start_time,end_time)
            # Increment tuple counter for this TW. This should be done before checking if there are detections
            n_tuples_in_tw += 1
            # if there is at least one detection
            if times_detected != 0: 
                # Compute the ratio of the detections of this tuple - TupleRatio
                tuple_ratio = times_detected / float(times_checked)
                tuple_ratios_sum += tuple_ratio
                if self.debug > 0:
                    print '\t\tTuple: {}, ratio: {} ({}/{})'.format(tuple4, tuple_ratio, times_detected, times_checked)
                # Add 1 to the number of tuples in total for this IP
                n_infected_tuples += 1
        if n_tuples_in_tw > 0:            
            # Comupte percentage of detected tuples in this TW
            detected_tuples_perc = float(n_infected_tuples) / n_tuples_in_tw
            # Compute weigted score of the IP in this TW (WS = tuple_ratios_sum*detected_tuples_perc)
            weighted_score = tuple_ratios_sum * detected_tuples_perc
            self.ws_per_tw[tw_index] = weighted_score
            if self.debug > 0:
                print "\t\t\t#tuples: {}, WS:{} = {} (sum of detected tuple ratios) x {} (percentage of detected tuples over total tuples)".format(n_tuples_in_tw,weighted_score,tuple_ratios_sum,detected_tuples_perc)
        self.last_tw_result = (weighted_score, tuple_ratios_sum, detected_tuples_perc)

    def get_verdict(self, start_time, end_time, tw_index, sdw_width, threshold):
        """This function uses sliding detection window (SDW) to compute mean of last n time windows weighted score"""
        # Get the weighted score
        self.get_weighted_score(start_time,end_time,tw_index)
        if self.ws_per_tw.has_key(tw_index): #traffic in this TW
            startindex = tw_index - sdw_width #compute SDW indices
            if startindex < 0:
                startindex = 0
            sdw = []
            for i in range (startindex+1, tw_index+1): #fill the sdw
                if self.ws_per_tw.has_key(i):
                    sdw.append(self.ws_per_tw[i])
                # If it doesn't have the key? Add a tryf
            mean = sum(sdw) / float(sdw_width)
            if self.debug > 3:
                print '\t' + self.address
                print "\tSDW startindex:{} . SDW endindex:{}".format(startindex, tw_index)
                print "\t\tSliding window:" + str(sdw)
                print "\t\tMean of SDW: {}, THRESHOLD: {}.".format(mean,threshold)
            # Did we detect it?
            if mean < threshold:
                # No
                self.last_verdict = "Normal"
                self.last_SDW_score = mean;
            else:
                # Yes 
                self.alerts.append(IpDetectionAlert(start_time,self.address,mean))
                self.last_verdict = "Malicious"
                self.last_SDW_score = mean
        else:
            #self.last_verdict = None
            self.last_verdict = 'Unknown'

    def print_last_result(self, verbose, start_time, end_time, threshold, use_whois, whois_handler):
        """ 
        Print analysis of this IP in the last time window. Verbosity level modifies amount of information printed.
        """
        try:            
            # Print Malicious IPs
            if self.last_verdict.lower() == 'malicious' and verbose > 0:
                print red("\t+ {} verdict: {} (SDW score: {:.5f}) | TW weighted score: {} = {} x {}".format(self.address, self.last_verdict, self.last_SDW_score, self.last_tw_result[0], self.last_tw_result[1], self.last_tw_result[2]))
                # Print those tuples that have at least 1 detection
                if verbose > 1 and verbose <= 3:
                    for tuple4 in self.tuples.keys():
                        # Here we are checking for all the tuples of this IP in all the capture!! this is veryyy inefficient
                        tuple_result = self.result_per_tuple(tuple4, start_time, end_time)
                        # Is at least one tuple detected?
                        if tuple_result[0] != 0:
                            #Shall we use whois?
                            if use_whois:
                                whois = whois_handler.get_whois_data(self.tuples[tuple4][0][3])
                                print "\t\t{} [{}] ({}/{})".format(tuple4,whois,tuple_result[0],tuple_result[1])
                            else:
                                print "\t\t{} ({}/{})".format(tuple4,tuple_result[0],tuple_result[1])
                            if verbose > 2:
                                for detection in self.tuples[tuple4]:
                                    #check if detection fits in the TW
                                    if (detection[2] >= start_time and detection[2] < end_time):
                                        print("\t\t\tDstIP: {}, Label:{:>40} , Detection Time:{}, State(100 max): {}").format(detection[3], detection[0], detection[2], detection[4][:100])
                # Print those tuples that have at least 1 detection and also the ones that were not detected
                elif verbose > 3:
                    for tuple4 in self.tuples.keys():
                        tuple_result = self.result_per_tuple(tuple4,start_time,end_time)
                        # Shall we use whois?
                        if use_whois:
                            whois = whois_handler.get_whois_data(self.tuples[tuple4][0][3])
                            print "\t\t{} [{}] ({}/{})".format(tuple4,whois,tuple_result[0],tuple_result[1])
                        else:
                            print "\t\t{} ({}/{})".format(tuple4,tuple_result[0],tuple_result[1])
                        if verbose > 2:
                            for detection in self.tuples[tuple4]:
                                #check if detection fits in the TW
                                if (detection[2] >= start_time and detection[2] < end_time):
                                    print("\t\t\tDstIP: {}, Label:{:>40} , Detection Time:{}, State(100 max): {}").format(detection[3], detection[0], detection[2], detection[4][:100])
            # Print normal IPs
            elif verbose > 3:
                # Since the value of self.last_tw_result can be None of a 3-tuple of strings, we need to check before
                try: 
                    last_tw_result_0 = self.last_tw_result[0]
                except TypeError:
                    last_tw_result_0 = ""
                try: 
                    last_tw_result_1 = self.last_tw_result[1]
                except TypeError:
                    last_tw_result_1 = ""
                try: 
                    last_tw_result_2 = self.last_tw_result[2]
                except TypeError:
                    last_tw_result_2 = ""

                print green("\t+{} verdict: {} (SDW score: {:.5f}) | TW weighted score: {} = {} x {}".format(self.address, self.last_verdict, self.last_SDW_score, last_tw_result_0, last_tw_result_1, last_tw_result_2))
                if verbose > 4:
                    for tuple4 in self.tuples.keys():
                        tuple_result = self.result_per_tuple(tuple4,start_time,end_time)
                        # Is at least one tuple checked?
                        if tuple_result[1] != 0:
                            #Shall we use whois?
                            if use_whois:
                                whois = whois_handler.get_whois_data(self.tuples[tuple4][0][3])
                                print "\t\t{} [{}] ({}/{})".format(tuple4,whois,tuple_result[0],tuple_result[1])
                            else:
                                print "\t\t{} ({}/{})".format(tuple4,tuple_result[0],tuple_result[1])
                            if verbose > 5:
                                for detection in self.tuples[tuple4]:
                                    #check if detection fits in the TW
                                    if (detection[2] >= start_time and detection[2] < end_time):
                                        print("\t\t\tDstIP: {}, Label:{:>40} , Detection Time:{}, State(100 max): {}").format(detection[3], detection[0], detection[2], detection[4][:100])
        except Exception as inst:
            print '\tProblem with print_last_result() in ip_handler.py'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)

    def process_timewindow(self, start_time, end_time, tw_index, sdw_width, swd_threshold,):
        """ For this IP, see if we should report a detection or not based on the thresholds and TW"""
        self.get_verdict(start_time, end_time, tw_index, sdw_width, swd_threshold)

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
                #print "***********************"

    def get_ip(self, ip_string):
        """Get the IpAddress object with id 'ip_string'. If it doesn't exists, create it"""
        #Have I seen this IP before?
        try:
            ip = self.addresses[ip_string]
        # No, create it
        except KeyError:
            ip = IpAddress(ip_string, self.verbose, self.debug)
            self.addresses[ip_string] = ip
        #register ip as active in this TW
        self.active_addresses.add(ip_string)
        return ip

    def print_alerts(self):
        """ Gater all the alerts in the handler and print them"""
        detected_counter = 0
        self.whois_handler.store_whois_data_in_file()
        print '\nFinal Alerts generated:'
        f = open(filename,"w")
        f.write("DATE:\t{}\nSummary of adresses in this capture:\n\n".format(datetime.now().strftime('%Y/%m/%d %H:%M:%S')))
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
