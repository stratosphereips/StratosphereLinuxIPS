#!/usr/bin/python
#authot Ondrej Lukas - luaksond@fel.cvut.cz
#cat /home/ondrej/Dokumenty/flows/2016-07-29_win.binetflow | ./slips.py -w 6000 -v 2 -D -f ./models | less -R
import datetime
from time import gmtime, strftime
import time
from colors import *

class IpAddress(object):
	"""docstring for IPAdress"""

	#TODO: storing ip as string? maybe there is a better way?
	
	def __init__(self, address):
		self.address =address
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
		detection = (label,n_chars,input_time)
		self.last_time = input_time

		#first time we see this tuple
		if(not self.tuples.has_key(tuple)):
			self.tuples[tuple] = []
		#add detection to array
		self.tuples[tuple].append(detection)


	def result_per_tuple(self,tuple,start_time,end_time,use_all):		
		n_malicious = 0
		count = 0
		for detection in self.tuples[tuple]:
			if (detection[2] >= start_time and detection[2] < end_time) or use_all:
				count += 1
				if(detection[0] != False):
					n_malicious += 1
			else:
				continue

		return (n_malicious,count)

	def get_result(self,start_time,end_time,threshold,use_all):
		result= 0;
		n_malicious = 0;
		count = 0
		for key in self.tuples.keys():
			tuple_result = self.result_per_tuple(key,start_time,end_time,use_all)
			n_malicious += tuple_result[0]
			count += tuple_result[1]

			if tuple_result[1] != 0:
				result+= (tuple_result[0]/float(tuple_result[1]))
		if result >= threshold:
			return ("MALICIOUS",result,n_malicious,count)
		else:
			return ("NORMAL",result,n_malicious,count)

	def print_ip(self, verb,start_time, end_time,threshold,print_all):
		if (self.last_time >= start_time and self.last_time < end_time) or print_all:
			res = self.get_result(start_time,end_time,threshold,print_all)
			if verb > 0:
				if(res[0] =='MALICIOUS'):
					print red("\t+ %s %d/%d (%f) verdict:%s" %(self.address, res[2],res[3],res[1],res[0]))
				else:
					if verb > 1 or print_all:	
						print green("\t+ %s %d/%d (%f) verdict:%s" %(self.address, res[2],res[3],res[1],res[0]))
			if verb > 1:
				for key in self.tuples.keys():
					tuple_res = self.result_per_tuple(key,start_time,end_time,print_all)
					if(tuple_res[1] > 0):
						print "\t\t%s(%d/%d)" %(key,tuple_res[0],tuple_res[1])
						if verb > 2:
							for detection in self.tuples[key]:
								if (detection[2] >= start_time and detection[2] < end_time) or print_all:
									print "\t\t\t"+ str(detection)

class IpHandler(object):
	"""Class which handles all IP actions for slips. Stores every IP object in the session, provides summary, statistics etc."""
	def __init__(self,verbose):
		self.addresses = {}
		self.verbose =verbose
		print "Handler created"


	def print_addresses(self,verb,start_time,end_time,threshold,print_all):
		if print_all:
		    print "Summary of registered addresses (t=%f):" %(threshold)
		else:
			if verb > 1:
				print "Addresses registered in this timewindow (t=%f):" %(threshold)
			else:
				print " Malicious addresses registered in this timewindow (t=%f):" %(threshold)
		for address in self.addresses.values():
			address.print_ip(verb,start_time,end_time,threshold,print_all)

	def get_ip(self,ip_string):
		#Have I seen this IP before?
		try:
			ip = self.addresses[ip_string]
		#no, create it
		except KeyError:
			#TODO:
			ip = IpAddress(ip_string)
			self.addresses[ip_string] = ip
			if self.verbose > 1:
				print yellow("\tAdding %s to the dictionary." %(ip_string))
		return ip

# 	call IpAddress.add_detection instead?
	def add_detection_result(self, ip_string,label,tuple,n_chars):
		if not self.addresses.has_key(ip_string):
			print "Invalid argument! No such ip has been stored!"
		else:
			self.addresses[ip_string].add_detection(label,tuple,n_chars)

