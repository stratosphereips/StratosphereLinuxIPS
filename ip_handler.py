#!/usr/bin/python
#authot Ondrej Lukas - luaksond@fel.cvut.cz
#cat /home/ondrej/Dokumenty/flows/2016-07-29_win.binetflow | ./slips.py -w 6000 -v 2 -D -f ./models | less -R
import datetime
from time import gmtime, strftime
import time

class IpAdress(object):
	"""docstring for IPAdress"""

	#TODO: storing ip as string? maybe there is a better way?
	
	def __init__(self, adress):
		self.adress =adress
		self.whois_data = None 
		self.lastDetectedRuling = False
		self.lastDetectedTime = -1
		self.detections = {}

	def to_string(self):
		return "<" + self.adress + ">(" + str(len(self.detections))  + ")" + " last detected as: " + str(self.lastDetectedRuling)

	def add_detection(self, detection,time):
		#TODO: 	
		#check timeformat?
		#alerts

		#check if the detection has changed
		if self.lastDetectedRuling != detection:
			#yep, send alert
			print "Detection label of <" + self.adress + "> CHANGED  " + str(self.lastDetectedRuling)  + " -> "  + str(detection) + " at " + str(time)
		self.lastDetectedTime = time;
		self.lastDetectedRuling = detection;

	def get_detections(self):
		return self.detections;


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
		self.adresses = {}
		print "Handler created"


	def to_string(self):
		return self.adresses.values();

	def print_adresses(self):
		print "Adresses in the Handler:"
		for adress in self.adresses.values():
			print adress.to_string()


	def get_ip(self,ip_string):
		#Have I seen this IP before?
		try:
			ip = self.adresses[ip_string]
		#no, create it
		except KeyError:
			#TODO:
			#check files?
			ip = IpAdress(ip_string)
			self.adresses[ip_string] = ip
			print "Adding " + ip_string + " to the dictionary."
		return ip

# 	call IpAdress.add_detection instead?
	def add_detection_result(self, ip_string,result,time):
		if not self.adresses.has_key(ip_string):
			print "Invalid argument! No such ip has been stored!"
		else:
			self.adresses[ip_string].add_detection(result,time)

	def statistic_for_ip(self,ip_string):
		harmless = len(self.adresses[ip_string].detections[False]);
		print "Result for <%s>\nDetected as malicious:%dx\nDetected as harmless:%d" %{ip_string,harmless,len(self.adresses[ip_string].detection) - harmless}


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
	time.sleep(0.001)
	handler.add_detection_result('192.168.0.1',False, datetime.datetime.now())
