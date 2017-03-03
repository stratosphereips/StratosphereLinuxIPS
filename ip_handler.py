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

filename = 'log.txt'
sw_width = 10
# Global shit for whois cache. The tuple needs to access it but should be shared, so global
whois_cache = {}

class Alert(object):
    """docstring for Alert"""
    def __init__(self, time,source):
        self.time = time
        self.source = source
    def __str__(self):
        print "function print_alert() has to be implemented in derived class!"
        return  NotImplemented

class IpDetectionAlert(Alert):
    """docstring for IpDetectionAlert"""
    def __init__(self, time, source, score):
        super(IpDetectionAlert, self).__init__(time,source)
        self.score = score
    def __str__(self):
        return yellow('*{} detected with score {}\ttime: {}*'.format(self.source,self.score,self.time.strftime('%Y/%m/%d %H:%M:%S.%f')))

class TupleDetectionAlert(object):
    """docstring for TupleDetectionAlert"""
    def __init__(self, time, source,model):
        super(TupleDetectionAlert, self).__init__(time,source)
        self.model = model            

class IpAddress(object):
    """docstring for IPAdress"""
    #TODO: storing ip as string? maybe there is a better way?
    def __init__(self, address, verbose, debug):
        self.address = address
        self.tuples = {}
        self.alerts = []
        self.ws_per_tw = {}
        self.last_result = None
        self.last_verdict = None
        self.last_time = None
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

    def add_detection(self, label, tuple, n_chars, input_time, dest_add):
        # The detection structure is a 3-tuple of a label, the number of chars when it was detected and when it was detected
        detection = (label, n_chars, input_time,dest_add)
        self.last_time = input_time
        #first time we see this tuple
        if(not self.tuples.has_key(tuple)):
            self.tuples[tuple] = []
        #add detection to array
        self.tuples[tuple].append(detection)

    def result_per_tuple(self, tuple, start_time, end_time, use_all=False):       
        try:
            n_malicious = 0
            count = 0
            for detection in self.tuples[tuple]:
                if (detection[2] >= start_time and detection[2] < end_time) or use_all:
                    count += 1
                    if detection[0] != False:
                        n_malicious += 1
                else:
                    continue
            return (n_malicious, count)
        except Exception as inst:
            print '\tProblem with result_per_tuple() in ip_handler.py'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)

    def get_weighted_score(self, start_time, end_time, tw_index, use_all=False):
        """ This is the main function that computes if the IP should be detected or not based on the tw, the thresholds, the average, etc."""
        """ What is the tuple score: Explain"""
        """ What is the weigthed score: Explain"""
        """ Returns the weighted score for the time windows specified"""
        try:
            result = 0;
            n_malicious = 0;
            count = 0
            total_infected_tuples = 0
            # For each tuple stored for this IP, compute the tuple score.
            for key in self.tuples.keys():
                tuple_result = self.result_per_tuple(key, start_time, end_time, use_all)
                n_malicious += tuple_result[0]
                count += tuple_result[1]
                try:
                    # Compute the ratio of the detections per tuple. This is the score of the tuple.
                    tuple_ratio = tuple_result[0] / float(tuple_result[1])
                    # Also sum up all the scores of all the different tuples for this ip
                    result += tuple_ratio
                except ZeroDivisionError:
                    #print 'Warning! trying to divide by zero. We should not be here. Ignore and continue'
                    tuple_ratio = False
                    pass
                if self.debug > 1:
                    print '\t\tTuple: {}, Score: {}, ({}/{})'.format(key, tuple_ratio, tuple_result[0], tuple_result[1])
                # If the last tuple was detected at least once, then count it.
                if tuple_result[0] > 0:
                    total_infected_tuples += 1
                tuples_dect_perc = float(total_infected_tuples) / len(self.tuples.keys())
                # Compute the weighted result
                weighted_score = float(tuples_dect_perc) * result
            if self.debug > 2:
                print '\t\t\t- Number of Tuples:{}, Tuples Score: {}, ({}/{}). Detection Score: {} ({}/{}). Weighted Score: {}'.format(len(self.tuples.keys()), result, n_malicious, count, tuples_dect_perc, total_infected_tuples, len(self.tuples.keys()), weighted_score)
            # Store the weighted_score for this TW 
            self.ws_per_tw[tw_index] = weighted_score
            self.last_result = (result, n_malicious, count, weighted_score, tuples_dect_perc, total_infected_tuples, len(self.tuples.keys()))
            return weighted_score
        except Exception as inst:
            print '\tProblem with get_weighted_score() in ip_handler.py'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)

    def get_verdict(self, start_time, end_time, tw_index, sdw_width, threshold, use_all=False):
        """This function uses sliding detection window (SDW) to compute mean of last n time windows weighted score"""
        #compute weighted score for the last TW
        #self.get_weighted_score(start_time,end_time,tw_index,use_all)
        sdw = []
        for i in range (tw_index, tw_index-sdw_width, -1):
            if i < 0:
                break
            if self.ws_per_tw.has_key(i):
                sdw.append(self.ws_per_tw[i])
            # If it doesn't have the key? Add a try
        mean = sum(sdw) / float(sdw_width)
        if self.debug > 3:
            print "\tSDW startindex:{}. SDW endindex:{}.".format(tw_index-sdw_width, tw_index)
            print "\t\t " +str(sdw)
            print "\t\tMean of SDW:{}.".format(mean)
        # Did we detect it?
        if mean < threshold:
            # No
            self.last_verdict = "Normal"
            return 'Normal'
        else:
            # Yes
            self.alerts.append(IpDetectionAlert(datetime.now(),self.address,mean))
            #print "\tSlide window width:{}, mean of SW:{}".format(sdw_width,mean)
            self.last_verdict = "Malicious"


    def to_string(self, verbose, start_time, end_time, threshold, print_all=False, colors=True):
        """ Print information about the IPs. Both during the time window and at the end. Do the verbose printings better"""
        sb= []
        try:
            if (self.last_time >= start_time and self.last_time < end_time) or print_all:
                verdict = self.last_verdict
                res = self.last_result
                # Check independently of the case
                if verbose > 0 and verdict.lower() == 'malicious':
                    if colors:
                        sb.append(red('\t+ {} (Tuple Score: {:.5f}) Verdict: {} ({} of {} detections). Weighted Score: {} considering Detection Score: {}'.format(self.address,res[0], verdict, res[1], res[2], res[3], res[4])))
                    else:
                        sb.append('\t+ {}(Tuple Score: {:.5f}) Verdict: {} ({} of {} detections). Weighted Score: {} considering Detection Score: {}'.format(self.address,res[0], verdict, res[1], res[2], res[3], res[4]))
                    if verbose > 1:
                        for key in self.tuples.keys():
                            tuple_res = self.result_per_tuple(key, start_time, end_time, print_all)
                            if tuple_res[0] > 0:
                                # Get whois
                                whois = self.get_whois_data(self.tuples[key][0][3])
                                sb.append("\n\t\t%s [%s] (%d/%d)" %(key, whois, tuple_res[0], tuple_res[1]))
                                if verbose > 2:
                                    for detection in self.tuples[key]:
                                        if (detection[2] >= start_time and detection[2] < end_time) or print_all:
                                            # Only print when it was positively detected
                                            if detection[0] != False:
                                                sb.append('\n\t\t\tLabel: {}, #chars: {}, Detection time: {}'.format(detection[0], detection[1], detection[2].strftime('%Y/%m/%d %H:%M:%S.%f')))
                if verbose > 3 and verdict.lower() != 'malicious':
                    if colors:
                        sb.append(green("\t+ %s %d/%d (%f) Verdict:%s" %(self.address, res[1],res[2],res[0],verdict)))
                    else:
                        sb.append("\t+ %s %d/%d (%f) Verdict:%s" %(self.address, res[1],res[2],res[0],verdict))
                    if verbose > 4:
                        for key in self.tuples.keys():
                            tuple_res = self.result_per_tuple(key,start_time,end_time,print_all)
                            if(tuple_res[1] > 0):
                                sb.append("\n\t\t%s (%d/%d)" %(key,tuple_res[0],tuple_res[1]))
                                if verbose > 5:
                                    for detection in self.tuples[key]:
                                        if (detection[2] >= start_time and detection[2] < end_time) or print_all:
                                            sb.append("\n\t\t\t"+ str(detection))
                                            
            return ''.join(sb)  
        except Exception as inst:
            print '\tProblem with to_string() in ip_handler.py'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)

    def process_timewindow(self, start_time, end_time, tw_index, sdw_width, swd_threshold, verbose, use_all=False):
        """ For this IP, see if we should report a detection or not based on the thresholds and TW"""
        score = self.get_weighted_score(start_time, end_time, tw_index, use_all)
        self.get_verdict(start_time, end_time, tw_index, sdw_width, swd_threshold, use_all)

    def get_alerts(self):
        """ TODO put description here"""
        return self.alerts

class IpHandler(object):
    """Class which handles all IP actions for slips. Stores every IP object in the session, provides summary, statistics etc."""
    def __init__(self, verbose, debug):
        self.addresses = {}
        self.verbose = verbose
        self.debug = debug

    def print_addresses(self, start_time, end_time, tw_index, threshold,sdw_width, print_all):
        """ Print information about all the IP addresses in the time window specified in the parameters."""
        if self.debug:
            print "Timewindow index:{}, threshold:{},SDW width: {}".format(tw_index,threshold,sdw_width)
        if print_all:
            print "\nFinal summary using the complete capture as a unique Time Window (Threshold = %f):" %(threshold)
        # For all the addresses stored in total
        for address in self.addresses.values():
            # Process this IP for the time window specified. So we can compute the detection value.
            address.process_timewindow(start_time, end_time, tw_index, 10, threshold, print_all, True)
            # Get a printable version of this IP's data
            string = address.to_string(self.verbose, start_time, end_time, threshold, print_all, True)
            if(len(string) > 0):
                print string

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
        # Open the file for the log
        print '\nFinal Alerts generated:'
        f = open(filename,"w")
        f.write("DATE:\t{}\nSummary of adresses in this capture:\n\n".format(datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')))
        f.write('Alerts:\n')
        for ip in self.addresses.values():
            if len(ip.alerts) > 0:
                print "\t - "+ ip.address
                f.write( '\t - ' + ip.address + '\n')
                for alert in ip.get_alerts():
                    print "\t\t" + str(alert)
                    f.write( '\t\t' + str(alert) + '\n')
        f.close()
