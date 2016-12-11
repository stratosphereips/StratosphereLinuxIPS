#!/usr/bin/python
#authot Ondrej Lukas - luaksond@fel.cvut.cz
#cat /home/ondrej/Dokumenty/flows/2016-07-29_win.binetflow | ./slips.py -w 6000 -v 2 -D -f ./models | less -R
import datetime
from time import gmtime, strftime
import time

class IpAddress(object):
	"""docstring for IPAdress"""

	#TODO: storing ip as string? maybe there is a better way?
	
	def __init__(self, adress):
		self.adress =adress
		self.whois_data = None 
		self.lastDetectedRuling = False
		self.lastDetectedTime = -1
		self.detections = {}

	def to_string(self):
		return "<" + self.adress + ">(detected " + str(len(self.detections))  + "x)" + " last detected as: " + str(self.lastDetectedRuling) + " (W="+ str(self.detections[self.lastDetectedTime][1]) +")"

	def add_detection(self, detection,time,weight):
		#TODO: 	
		#check timeformat?
		#alerts

		#check if the detection has changed
		if self.lastDetectedRuling != detection:
			#yep, send alert
			print "Detection label of <" + self.adress + "> CHANGED  " + str(self.lastDetectedRuling)  + " -> "  + str(detection) + " at " + str(time)
		self.detections[time] = (detection,weight);
		self.lastDetectedTime = time;
		self.lastDetectedRuling = detection;

	def get_result(self):
		"""
		det_count ={}
		weights = {}
		for detections in self.detections.values():
			#count
			if det_count.has_key(detection[0]):
				det_count[detection[0]] +=1
			else:
				det_count[detection[0]] = 1

			#weights
			if weights.has_key(detection[0]):
				weights[detection[0]] += detection[1]
			else:
				weights[detection[0]] = detection[1]

		res = None
		res_weight = -1
		for detections in self.detections.values():
		"""
		#TODO: better way of 
		n_malicious = 0;
		n_harmless = 0;
		for detection in self.detections.values():
			if(detection[0] == False):
				n_harmless += 1
			else:
				n_malicious += 1
		if n_harmless >= n_malicious:
			return "OK"
		else:
			return "Malicious"

	#WHOIS	
	def find_whois(self):
		#Check access to ipwhois library
		try:
			import ipwhois
		except ImportError:
			print 'The ipwhois library is not installed. pip install ipwhois'
			return False



	def get_whois(self):
		if self.whois_data == None:
			find_whois(self)
		return self.whois_data


class IpHandler(object):
	"""Class which handles all IP actions for slips. Stores every IP object in the session, provides summary, statistics etc."""
	def __init__(self):
		self.addresses = {}
		print "Handler created"


	def to_string(self):
		return self.adresses.values();

	def print_addresses(self):
		print "ADDRESSES STORED:"
		for address in self.addresses.values():
			print address.to_string() + " RESULT: " + address.get_result()


	def get_ip(self,ip_string):
		#Have I seen this IP before?
		try:
			ip = self.addresses[ip_string]
		#no, create it
		except KeyError:
			#TODO:
			#check files?
			ip = IpAddress(ip_string)
			self.addresses[ip_string] = ip
			print "Adding " + ip_string + " to the dictionary."
		return ip

# 	call IpAddress.add_detection instead?
	def add_detection_result(self, ip_string,result,time,weight):
		if not self.addresses.has_key(ip_string):
			print "Invalid argument! No such ip has been stored!"
		else:
			self.addresses[ip_string].add_detection(result,time,weight)


if __name__ == '__main__':
	handler = IpHandler()
	ip1 = handler.get_ip('127.0.0.1')
	handler.add_detection_result('127.0.0.1',"Malware", datetime.datetime.now(),1)

	time.sleep(0.0051)
	handler.add_detection_result('127.0.0.1',"Ransomware", datetime.datetime.now(),2)
	time.sleep(0.001)
	ip2 = handler.get_ip('192.168.0.1')
	handler.add_detection_result('192.168.0.1',"Troyan", datetime.datetime.now(),3)

	time.sleep(0.001)
	handler.add_detection_result('192.168.0.1',False, datetime.datetime.now(),4)
	time.sleep(0.001)
	handler.add_detection_result('192.168.0.1',False, datetime.datetime.now(),5)
	print handler.print_addresses()