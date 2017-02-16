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


global filename
filename = 'log.txt'
global sw_width
sw_width = 10
class Alert(object):
    """docstring for Alert"""
    def __init__(self, time,source):
            self.time = time
            self.source = source
    def print_alert(self):
            print "function print_alert() has to be implemented in derived class!"
            return  NotImplemented


class IpDetectionAlert(Alert):
    """docstring for IpDetectionAlert"""
    def __init__(self, time, source, score):
            super(IpDetectionAlert, self).__init__(time,source)
            self.score = score
    def print_alert(self):
            print  yellow('\t*{} detected with score {}\ttime: {}*'.format(self.source,self.score,self.time.strftime('%Y/%m/%d %H:%M:%S.%f')))

class TupleDetectionAlert(object):
    """docstring for TupleDetectionAlert"""
    def __init__(self, time, source,model):
            super(TupleDetectionAlert, self).__init__(time,source)
            self.model = model            
        





class IpAddress(object):
    """docstring for IPAdress"""

    #TODO: storing ip as string? maybe there is a better way?
    
    def __init__(self, address):
            self.address = address
            self.tuples = {}
            self.alerts = []
            self.tw_weighted_score = []
            self.last_result = None
            self.last_verdict = None
            self.last_time = None

    def add_detection(self, label,tuple,n_chars,input_time):
            #TODO:  
            #alerts
            # The detection structure is a 3-tuple of a label, the number of chars when it was detected and when it was detected
            detection = (label, n_chars, input_time)
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

    def get_weighted_score(self,start_time,end_time,use_all,debug=False):
            #threshold - sum of over all tuples
            try:
                result = 0;
                n_malicious = 0;
                count = 0
                total_infected_tuples = 0
                for key in self.tuples.keys():
                    tuple_result = self.result_per_tuple(key,start_time,end_time,use_all)
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
                    if debug:
                        print '\t\tTuple:{}, Score: {}, ({}/{})'.format(key, tuple_ratio, tuple_result[0], tuple_result[1])
                    # If the last tuple was detected at least once, then count it.
                    if tuple_result[0] > 0:
                        total_infected_tuples += 1
                    tuples_dect_perc = float(total_infected_tuples) / len(self.tuples.keys())
                    # Compute the weighted result
                    weighted_score = float(tuples_dect_perc) * result
                    if debug:
                        print '\t#Tuples:{}, Tuples Score: {}, ({}/{}). Detection Score: {} ({}/{}). Weighted Score: {}'.format(len(self.tuples.keys()), result, n_malicious, count, tuples_dect_perc, total_infected_tuples, len(self.tuples.keys()), weighted_score)
                #self.tw_weighted_score.append((start_time,end_time,weighted_score))
                self.tw_weighted_score.append(weighted_score)
                self.last_result = (result, n_malicious, count, weighted_score, tuples_dect_perc, total_infected_tuples, len(self.tuples.keys()))
                return weighted_score
            except Exception as inst:




                print '\tProblem with get_weighted_score() in ip_handler.py'
                print type(inst)     # the exception instance
                print inst.args      # arguments stored in .args
                print inst           # __str__ allows args to printed directly
                sys.exit(1)

    def get_verdict(self,start_time,end_time,offset,threshold,use_all=False,debug=False):
            ws = self.get_weighted_score(start_time,end_time,use_all,debug)
            if len(self.tw_weighted_score) < offset:
                slide_window = self.tw_weighted_score
            else:
                slide_window = self.tw_weighted_score[len(self.tw_weighted_score)-offset:]
            mean = sum(slide_window)/float(offset)
            if debug:
                print "Mean of the slide window:{}.".format(mean)
            if mean < threshold:
                self.last_verdict = "Normal"
                return 'Normal'
            else:
                self.alerts.append(IpDetectionAlert(datetime.now(),self.address,ws))
                print "\tSlide window width:{}, mean of SW:{}".format(offset,mean)
                self.last_verdict = "Malicious"
                return 'Malicious'

    def to_string(self, verbose, debug, start_time, end_time, threshold, print_all=False,colors=True):
            """ Print information about the IPs. Both during the time window and at the end. Do the verbose printings better"""
            sb= []

            try:
                if (self.last_time >= start_time and self.last_time < end_time) or print_all:
                    if debug:
                        sb.append('Analyzing IP {}\n'.format(self.address))
                    verdict = self.get_verdict(start_time,end_time,sw_width,threshold,print_all,debug)
                    res = self.last_result
                    # Check independently of the case
                    if verbose > 0 and verdict.lower() == 'malicious':
                        if colors:
                            sb.append(red('\t+ {} (Tuple Score: {:.5f}) verdict: {} ({} of {} detections). Weighted Score: {} considering Detection Score: {}\n'.format(self.address, res[0], verdict, res[1], res[2], res[3], res[4])))
                        else:
                            sb.append('\t+ {} (Tuple Score: {:.5f}) verdict: {} ({} of {} detections). Weighted Score: {} considering Detection Score: {}\n'.format(self.address, res[0], verdict, res[1], res[2], res[3], res[4]))
                        if verbose > 1:
                            for key in self.tuples.keys():
                                tuple_res = self.result_per_tuple(key, start_time, end_time, print_all)
                                if tuple_res[0] > 0:
                                    sb.append("\t\t%s (%d/%d)\n" %(key,tuple_res[0],tuple_res[1]))
                                    if verbose > 2:
                                        for detection in self.tuples[key]:
                                            if (detection[2] >= start_time and detection[2] < end_time) or print_all:
                                                # Only print when it was positively detected
                                                if detection[0] != False:
                                                    sb.append('\t\t\tLabel: {}, #chars: {}, Detection time: {}\n'.format(detection[0], detection[1], detection[2].strftime('%Y/%m/%d %H:%M:%S.%f')))
                    if verbose > 3 and verdict.lower() != 'malicious':
                        if colors:
                            sb.append(green("\t+ %s %d/%d (%f) verdict:%s\n" %(self.address, res[1],res[2],res[0],verdict)))
                        else:
                            sb.append("\t+ %s %d/%d (%f) verdict:%s\n" %(self.address, res[1],res[2],res[0],verdict))
                        if verbose > 4:
                            for key in self.tuples.keys():
                                tuple_res = self.result_per_tuple(key,start_time,end_time,print_all)
                                if(tuple_res[1] > 0):
                                    sb.append("\t\t%s (%d/%d)\n" %(key,tuple_res[0],tuple_res[1]))
                                    if verbose > 5:
                                        for detection in self.tuples[key]:
                                            if (detection[2] >= start_time and detection[2] < end_time) or print_all:
                                                sb.append("\t\t\t"+ str(detection) + '\n')
                                                
                return ''.join(sb)  
            except Exception as inst:
                print '\tProblem with to_string() in ip_handler.py'
                print type(inst)     # the exception instance
                print inst.args      # arguments stored in .args
                print inst           # __str__ allows args to printed directly
                sys.exit(1)

    def proccess_timewindow(self,start_time,end_time,sdw_width,swd_threshold,verbose,use_all=False,debug=False):
            verdict = get_verdict(start_time,end_time,sdw_width,swd_threshold,use_all,debug)
            print to_string(verbose,debug,start_time,end_time,swd_threshold,use_all)

    


    def get_alerts(self):
            return self.alerts

class IpHandler(object):
    """Class which handles all IP actions for slips. Stores every IP object in the session, provides summary, statistics etc."""
    def __init__(self, verbose, debug):
            self.addresses = {}
            self.verbose = verbose
            self.debug = debug
            self.time_threshold = 0.5
            self.impact_threshold = 0.5

    def print_addresses(self, start_time, end_time, threshold, print_all):
            if print_all:
                f = open(filename,"w")
                f.write("DATE:\t{}\nTHRESHOLD:\t{}\nSummary of adresses in this capture:\n\n".format(datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f'),threshold))
                f.close()
                print "Final summary of addresses in this capture (t=%f):" %(threshold)
            else:
                print "Detections in this timewindow (t=%f):" %(threshold)
            for address in self.addresses.values():
                #address.print_ip(self.verbose, self.debug, start_time, end_time, threshold, print_all)
                string = address.to_string(self.verbose, self.debug, start_time, end_time, threshold, print_all,True)
                if(len(string) > 0):
                    print string

    def get_ip(self,ip_string):
            #Have I seen this IP before?
            try:
                ip = self.addresses[ip_string]
            #no, create it
            except KeyError:
                ip = IpAddress(ip_string)
                self.addresses[ip_string] = ip
                #print yellow("\tAdding %s to the dictionary." %(ip_string))
            return ip

        # Call IpAddress.add_detection instead?
    def add_detection_result(self, ip_string,label,tuple,n_chars):
            if not self.addresses.has_key(ip_string):
                print "Invalid argument! No such ip has been stored!"
            else:
                self.addresses[ip_string].add_detection(label,tuple,n_chars)

    def print_alerts(self):
            print "ALERTS:"
            for ip in self.addresses.values():
                for alert in ip.get_alerts():
                    alert.print_alert()



