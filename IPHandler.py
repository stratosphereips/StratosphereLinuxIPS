#!/usr/bin/python
#authot Ondrej Lukas - luaksond@fel.cvut.cz
import datetime
from time import gmtime, strftime
import time

class IPAdress(object):
	"""docstring for IPAdress"""

	#TODO: storing ip as string? maybe there is a better way?
	
	def __init__(self, adress):
		self.adress =adress
		self.lastDetectedRuling = False
		self.lastDetectedTime = -1
		self.detections = {}

	def to_string(self):
		return "<" + self.adress + ">" + str(self.get_detections())

	def set_detection(self, detection,time):
		#TODO: check timeformat?
		#check if the detection has changed
		if self.lastDetectedRuling != detection:
			#yep, send alert
			print "LABEL OF <" + self.adress + "> CHANGED  " + str(self.lastDetectedRuling)  + " -> "  + str(detection) + " at " + str(time)
		self.lastDetectedTime = time;
		self.lastDetectedRuling = detection;

	def get_detections(self):
		return self.detections;


class IpHandler(object):
	"""Class which handles all IP actions for slips. Stores every IP object in the session, provides summary, statistics etc."""
	def __init__(self):
		self.adresses = {}


	def to_string(self):
		return self.adresses.items();


	def get_ip(self,ip_string):
		#Have I seen this IP before?
		if not self.adresses.has_key(ip_string):
			self.adresses[ip_string] = IPAdress(ip_string)
			print "Adding " + ip_string + " to the dictionary."
		return self.adresses[ip_string]

	def add_detection_result(self, ip_string,result,time):
		if not self.adresses.has_key(ip_string):
			print "Invalid argument! No such ip has been stored!"
		else:
			self.adresses[ip_string].set_detection(result,time)



if __name__ == '__main__':
	handler = IpHandler()
	ip1 = handler.get_ip('127.0.0.1')
	handler.add_detection_result('127.0.0.1',"Malware", datetime.datetime.now())
	time.sleep(0.0051)
	handler.add_detection_result('127.0.0.1',"Ransomware", datetime.datetime.now())
	time.sleep(0.001)
	ip2 = handler.get_ip('192.168.0.1')
	handler.add_detection_result('192.168.0.1',"Troyan", datetime.datetime.now())
	time.sleep(0.001)
	handler.add_detection_result('192.168.0.1',False, datetime.datetime.now())
	print ip1.to_string()
	print ip2.to_string()
		
