import sys
import datetime, time
import socket
import threading


flow = '0.000000,udp,127.0.0.1,546,   ->,31.13.91.6,6666,INT,0,,1,189,189,,,'
host = 'localhost'
port = 9000
timeformat = "%Y/%m/%d %H:%M:%S.%f"
next_call = time.time()

def ping():
	global next_call
	s = socket.socket()
	s.connect((host,port))
	s.sendall("{},{}\n".format((datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime(timeformat),flow))
	s.close()
	print "[{}] ping...".format(datetime.datetime.now())
	next_call = next_call+1
	threading.Timer(next_call - time.time(), ping).start()

if __name__ == '__main__':
	print "Pinger started at: {}".format(datetime.datetime.now())
	try:
		"""
		while True:
				s = socket.socket()
				s.connect((host,port))
				s.sendall("{},{}\n".format((datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime(timeformat),flow))
				s.close()
				print "[{}] ping...".format(datetime.datetime.now())
				time.sleep(1)
		"""
		ping()
	except KeyboardInterrupt:
		print "\nLeaving pinger"
