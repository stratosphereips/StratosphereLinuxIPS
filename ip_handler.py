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

#check if the log directory exists, if not, create it
logdir_path = "./logs"
if not os.path.exists(logdir_path):
    os.makedirs(logdir_path)
#file for logging
filename = logdir_path+"/" + 'log_' + datetime.now().strftime('%Y-%m-%d %H:%M:%S')+'.txt'; 

class IpAddress(object):
    """docstring for IPAdress"""
    #TODO: storing ip as string? maybe there is a better way?
    def __init__(self, address, verbose, debug):
        self.address = address

        self.tuples = {}
        self.alerts = []
        self.ws_per_tw = {}

        self.last_tw_result = None
        self.last_verdict = None
        self.last_time = None
        self.last_SDW_score = -1;
        self.verbose = verbose
        self.debug = debug

    def get_whois_data(self, ip):
        """ Get the whois data. This should be an independent function"""
        try:
            import ipwhois
        except ImportError:
            print 'The ipwhois library is not install. pip install ipwhois'
            return False
        # is the ip in the cache
        try:
            self.desc = whois_cache[ip]
            return self.desc
        except KeyError:
            # Is not, so just ask for it
            try:
                obj = ipwhois.IPWhois(ip)
                data = obj.lookup_whois()
                try:
                    self.desc = data['nets'][0]['description'].strip().replace('\n',' ') + ',' + data['nets'][0]['country']
                except AttributeError:
                    # There is no description field
                    self.desc = ""
            except ValueError:
                # Not a real IP, maybe a MAC
                pass
            except IndexError:
                # Some problem with the whois info. Continue
                pass        
            except ipwhois.IPDefinedError as e:
                if 'Multicast' in e:
                    self.desc = 'Multicast'
                self.desc = 'Private Use'
            except ipwhois.ipwhois.WhoisLookupError:
                print 'Error looking the whois of {}'.format(ip)
                # continue with the work\
                pass
            # Store in the cache
            whois_cache[ip] = self.desc
            return self.desc

    def add_detection(self, label, tuple, n_chars, input_time, dest_add, state, tw_index):
        # The detection structure is a 3-tuple of a label, the number of chars when it was detected and when it was detected
        detection = (label, n_chars, input_time,dest_add,state)
        self.last_time = input_time
        #first time we see this tuple
        if(not self.tuples.has_key(tuple)):
            self.tuples[tuple] = []
        #add detection to array
        self.tuples[tuple].append(detection)

    def result_per_tuple(self, tuple, start_time, end_time):       
        try:
            n_malicious = 0
            count = 0
            for detection in self.tuples[tuple]:
                #check this detection belongs to the TimeWindow
                if (detection[2] >= start_time and detection[2] < end_time):
                    count += 1
                    if detection[0] != False:
                        n_malicious += 1
            if count == 0:
                return None
            else:
                return (n_malicious, count)
        except Exception as inst:
            print '\tProblem with result_per_tuple() in ip_handler.py'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)

    def tuple_occured_in_tw(self,start_time,end_time,tuple4):
        for detection in self.tuples[tuple4]:
            if (detection[2] >= start_time and detection[2] < end_time):
                return True
        return False

    def get_weighted_score(self, start_time, end_time, tw_index):
        """ This is the main function that computes if the IP should be detected or not based on the tw, the thresholds, the average, etc."""
        """ What is the tuple score: Explain"""
        """ What is the weigthed score: Explain"""
        """ Returns the weighted score for the time windows specified"""
        tuple_ratios_sum = 0 
        n_malicious_connections= 0
        n_connections = 0
        n_infected_tuples = 0
        n_tuples_in_tw= 0
        # For each tuple stored for this IP, compute the tuple score.
        for tuple4 in self.tuples.keys():
            #get result for this tuple
            tuple_result = self.result_per_tuple(tuple4,start_time,end_time)
            if tuple_result != None: #There is at least one detection
                #Increment tuple counter in fro this TW
                n_tuples_in_tw +=1
                #Compute the ratio of the detections of this tuple - TupleRatio
                tuple_ratio = tuple_result[0]/ float(tuple_result[1])
                tuple_ratios_sum += tuple_ratio
                if self.debug > 1:
                    print '\t\tTuple: {}, ratio: {} ({}/{})'.format(tuple4, tuple_ratio, tuple_result[0], tuple_result[1])
                if tuple_ratio > 0: #There was at least one positive detection in this tuple
                    n_infected_tuples += 1
        if n_tuples_in_tw > 0:            
            #Comupte percentage of detected tuples in this TW
            detected_tuples_perc = float(n_infected_tuples) / n_tuples_in_tw
            #Compute weigted score of the IP in this TW (WS = tuple_ratios_sum*detected_tuples_perc)
            weighted_score = tuple_ratios_sum*detected_tuples_perc
            self.ws_per_tw[tw_index] = weighted_score
            self.last_tw_result = (weighted_score,tuple_ratios_sum,detected_tuples_perc)
            if self.debug:
                print "#tuples: {}, WS:{} = {}(tuple ratios sum) x {} (detected tuple percentage)".format(n_tuples_in_tw,weighted_score,tuple_ratios_sum,detected_tuples_perc)
        else:
            if True or debug:
                self.last_tw_result = None
                "No detections in this TW"

    def get_verdict(self, start_time, end_time, tw_index, sdw_width, threshold):
        """This function uses sliding detection window (SDW) to compute mean of last n time windows weighted score"""
        #compute weighted score for the last TW
        self.get_weighted_score(start_time,end_time,tw_index)
        
        if self.ws_per_tw.has_key(tw_index): #traffic in this TW
            startindex = tw_index-sdw_width #compute SDW indices
            if startindex < 0:
                startindex = 0
            sdw = []
            for i in range (startindex,tw_index+1): #fill the sdw
                if self.ws_per_tw.has_key(i):
                    sdw.append(self.ws_per_tw[i])
                # If it doesn't have the key? Add a try
            mean = sum(sdw) / float(sdw_width)
            if self.debug > 3:
                print self.address
                print "\tSDW startindex:{}. SDW endindex:{}.".format(startindex, tw_index)
                print "\t\t " +str(sdw)
                print "\t\tMean of SDW:{}, THRESHOLD:{}.".format(mean,threshold)
            # Did we detect it?
            if mean < threshold:
                # No
                self.last_verdict = "Normal"
                self.last_SDW_score = mean;
            else:
                # Yes 
                self.alerts.append(IpDetectionAlert(datetime.now(),self.address,mean))
                self.last_verdict = "Malicious"
                self.last_SDW_score = mean
        else:
            self.last_verdict = None

    def print_last_result(self, verbose, start_time, end_time, threshold, use_whois, whois_handler):
        """ Print information about the IPs. Both during the time window and at the end. Do the verbose printings better"""
        try:            
            if self.last_verdict != None:
                #print Malicious IPs
                if verbose > 0 and self.last_verdict.lower() == 'malicious':
                    print red("\t+{} verdict:{} (SDW score: {:.5f}) | TW weighted score: {} = {} x {}".format(self.address, self.last_verdict, self.last_SDW_score, self.last_tw_result[0], self.last_tw_result[1], self.last_tw_result[2]))                      
                    if verbose > 1:
                        for tuple4 in self.tuples.keys():
                            tuple_result = self.result_per_tuple(tuple4,start_time,end_time)
                            if tuple_result != None:
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
                                            print("\t\t\t"+ str(detection))
                #print normal IPs
                if verbose > 3 and self.last_verdict.lower() != 'malicious':
                    print green("\t+{} verdict:{} (SDW score: {:.5f}) | TW weighted score: {} = {} x {}".format(self.address, self.last_verdict, self.last_SDW_score, self.last_tw_result[0], self.last_tw_result[1], self.last_tw_result[2]))                      
                    if verbose > 4:
                        for tuple4 in self.tuples.keys():
                            tuple_result = self.result_per_tuple(tuple4,start_time,end_time)
                            if tuple_result != None:
                                #Shall we use whois?
                                if use_whois:
                                    whois = self.get_whois_data(self.tuples[tuple4][0][3])
                                    print "\t\t{} [{}] ({}/{})".format(tuple4,whois,tuple_result[0],tuple_result[1])
                                else:
                                    print "\t\t{} ({}/{})".format(tuple4,tuple_result[0],tuple_result[1])
                                if verbose > 5:
                                    for detection in self.tuples[tuple4]:
                                        #check if detection fits in the TW
                                        if (detection[2] >= start_time and detection[2] < end_time):
                                            print("\t\t\t"+ str(detection))
        except Exception as inst:
            print '\tProblem with print_last_result() in ip_handler.py'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)

    def process_timewindow(self, start_time, end_time, tw_index, sdw_width, swd_threshold,):
        """ For this IP, see if we should report a detection or not based on the thresholds and TW"""
        self.get_weighted_score(start_time, end_time, tw_index)
        self.get_verdict(start_time, end_time, tw_index, sdw_width, swd_threshold)

    def get_alerts(self):
        """ Returns all the alerts stored in the IP object"""
        return self.alerts

class IpHandler(object):
    """Class which handles all IP actions for slips. Stores every IP object in the session, provides summary, statistics etc."""
    def __init__(self, verbose, debug, whois):
        self.addresses = {}
        self.verbose = verbose
        self.debug = debug
        self.whois = whois
        self.whois_handler = WhoisHandler("WhoisData.txt")

    def print_addresses(self, start_time, end_time, tw_index, threshold, sdw_width, print_all):
        """ Print information about all the IP addresses in the time window specified in the parameters."""
        if self.debug:
            print "Timewindow index:{}, threshold:{},SDW width: {}".format(tw_index,threshold,sdw_width)
        if print_all:
            print "\nFinal summary using the complete capture as a unique Time Window (Threshold = %f):" %(threshold)
        # For all the addresses stored in total
        for address in self.addresses.values():
           # print "********BEGINNIG {} *******".format(address.address)
            # Process this IP for the time window specified. So we can compute the detection value.
            address.process_timewindow(start_time, end_time, tw_index, 10, threshold)
            # Get a printable version of this IP's data
            #string = address.print_last_result(self.verbose, start_time, end_time, threshold,self.whois, print_all, True)
            address.print_last_result(self.verbose, start_time, end_time, threshold,self.whois,self.whois_handler)
            #print "***********************"

    def get_ip(self, ip_string):
        """ TODO put description here"""
        #Have I seen this IP before?
        try:
            ip = self.addresses[ip_string]
        # No, create it
        except KeyError:
            ip = IpAddress(ip_string, self.verbose, self.debug)
            self.addresses[ip_string] = ip
        return ip

    def print_alerts(self):
        """ TODO put description here"""
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
