#!/usr/bin/python
# Author: Ondrej Lukas - luaksond@fel.cvut.cz
from datetime import datetime
from time import gmtime, strftime
from colors import *

class IpAddress(object):
	"""docstring for IPAdress"""

	#TODO: storing ip as string? maybe there is a better way?
	
	def __init__(self, address):
            self.address = address
            self.last_label = False
            self.tuples = {}
            self.last_time = -1

	def add_detection(self, label,tuple,n_chars,input_time):
            #TODO: 	
            #alerts
            #check if the detection has changed
            """if self.last_label != label:
                    #yep, send alert
                    print("Detection label of %s CHANGED %s -> %s",(self.address,str(self.last_label),str(label)))
            self.last_label = label
            """
            # The detection structure is a 3-tuple of a label, the number of chars when it was detected and when it was detected
            detection = (label, n_chars, input_time)
            self.last_time = input_time

            #first time we see this tuple
            if(not self.tuples.has_key(tuple)):
                    self.tuples[tuple] = []
            #add detection to array
            self.tuples[tuple].append(detection)

	def result_per_tuple(self, tuple, start_time, end_time, use_all):		
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

	def get_result(self, start_time, end_time, threshold, use_all, verbose, debug):
		result = 0;
		n_malicious = 0;
		count = 0
                total_infected_tuples = 0
		for key in self.tuples.keys():
                    tuple_result = self.result_per_tuple(key,start_time,end_time,use_all)
                    n_malicious += tuple_result[0]
                    count += tuple_result[1]
                    #if tuple_result[1] != 0:
                    try:
                        # Compute the ratio of the detections per tuple. This is the score of the tuple.
                        # Also sum up all the scores of all the different tuples for this ip
                        tuple_ratio = tuple_result[0] / float(tuple_result[1])
                        result += tuple_ratio
                        if debug:
                            print '\t\tTuple:{}, Score: {}, ({}/{})'.format(key, tuple_ratio, tuple_result[0], tuple_result[1])
                        # If the last tuple was detected at least once, then count it.
                        if tuple_result[0] > 0:
                            total_infected_tuples += 1
                    except ZeroDivisionError:
                        print 'Warning! trying to divide by zero. We should not be here.'
                        result = False
                tuples_dect_perc = float(total_infected_tuples) / len(self.tuples.keys())
                # Compute the weighted result
                weighted_score = float(tuples_dect_perc) * result
                if debug:
                    print '\t#Tuples:{}, Tuples Score: {}, ({}/{}). Detection Score: {} ({}/{}). Weighted Score: {}'.format(len(self.tuples.keys()), result, n_malicious, count, tuples_dect_perc, total_infected_tuples, len(self.tuples.keys()), weighted_score)
                # Compute the verdict
		if result >= threshold:
                    verdict = 'Malicious'
		else:
                    verdict = 'Normal'
                return (verdict, result, n_malicious, count, weighted_score, tuples_dect_perc, total_infected_tuples, len(self.tuples.keys()))

	def print_ip(self, verbose, debug, start_time, end_time, threshold, print_all):
            """ Print information about the IPs. Both during the time window and at the end. Do the verbose printings better"""
            if (self.last_time >= start_time and self.last_time < end_time) or print_all:
                if debug:
                    print 'Analyzing IP {}'.format(self.address)
                res = self.get_result(start_time, end_time, threshold, print_all, verbose, debug)
                # Check independently of the case
                if verbose > 0 and res[0].lower() == 'malicious':
                    print red('\t+ {} (Tuple Score: {:.5f}) verdict: {} ({} of {} detections). Weighted Score: {}'.format(self.address, res[1], res[0], res[2], res[3], res[4]))
                    if verbose > 1:
                        for key in self.tuples.keys():
                            tuple_res = self.result_per_tuple(key, start_time, end_time, print_all)
                            #if tuple_res[1] > 0:
                            if tuple_res[0] > 0:
                                print "\t\t%s (%d/%d)" %(key,tuple_res[0],tuple_res[1])
                                if verbose > 2:
                                    for detection in self.tuples[key]:
                                        if (detection[2] >= start_time and detection[2] < end_time) or print_all:
                                            # Only print when it was positively detected
                                            if detection[0] != False:
                                                print '\t\t\tLabel: {}, #chars: {}, Detection time: {}'.format(detection[0], detection[1], detection[2].strftime('%Y/%m/%d %H:%M:%S.%f'))
                if verbose > 3 and res[0].lower() != 'malicious':
                    print green("\t+ %s %d/%d (%f) verdict:%s" %(self.address, res[2],res[3],res[1],res[0]))
                    if verbose > 4:
                        for key in self.tuples.keys():
                            tuple_res = self.result_per_tuple(key,start_time,end_time,print_all)
                            if(tuple_res[1] > 0):
                                print "\t\t%s (%d/%d)" %(key,tuple_res[0],tuple_res[1])
                                if verbose > 5:
                                    for detection in self.tuples[key]:
                                        if (detection[2] >= start_time and detection[2] < end_time) or print_all:
                                            print "\t\t\t"+ str(detection)

class IpHandler(object):
	"""Class which handles all IP actions for slips. Stores every IP object in the session, provides summary, statistics etc."""
	def __init__(self, verbose, debug):
            self.addresses = {}
            self.verbose = verbose
            self.debug = debug

	def print_addresses(self, start_time, end_time, threshold, print_all):
            if print_all:
                print
                print "Final summary of addresses in this capture (t=%f):" %(threshold)
            else:
                print "Detections in this timewindow (t=%f):" %(threshold)
            for address in self.addresses.values():
                address.print_ip(self.verbose, self.debug, start_time, end_time, threshold, print_all)

	def get_ip(self,ip_string):
            #Have I seen this IP before?
            try:
                ip = self.addresses[ip_string]
            #no, create it
            except KeyError:
                #TODO:
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

