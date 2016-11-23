#!/usr/bin/python
#authot Ondrej Lukas - luaksond@fel.cvut.cz


class IPAdress(object):
	"""docstring for IPAdress"""
	def __init__(self, adress):
		self.adress  =adress
		self.lastDetectedRuling = False
		self.lastDetectedTime = 0
		self.n_malicious_detections = 0
		self.n_good_detections = 0

	def to_string(self):
		return "<" + self.adress + ">" + "Detected:" + self.lastDetected

	def set_detection(self, detection,time):
		#TODO:
		#	timeformat
		if detection:
			self.n_good_detections+=1
		else:
			self.n_malicious_detections+=1

		if detection == self.lastDetectedRuling:
			self.lastDetectedTime = time
		else:
			self.lastDetectedRuling = detection
			self.lastDetectedTime  = time
			#Something changed -> sent Alert
			#TODO parameters for amount of printed information?
			print "DETECTION OF <" + self.adress + "> CHANGED  " + str(not self.lastDetectedRuling)  + " -> "  + str(self.lastDetectedRuling) + " at " + str(self.lastDetectedTime)

		





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
			print "Adding" + ip_string + "to the dictionary."
		return self.adresses[ip_string]

	def add_detection_result(self, ip_string,result):
		if not self.adresses.has_key(ip_string):
			print "Invalid argument! No such ip has been stored!"
		else:
			self.adresses[ip_string]




if __name__ == '__main__':
	#handler = IpHandler()
	#handler.get_ip('127.0.0.1');
	#print handler.to_string();
	ip = IPAdress("127.0.0.1")
	ip.set_detection(True,12.2354)
		
