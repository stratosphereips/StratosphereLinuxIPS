from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__
import time
import json

# Port Scan Detector Process
class PortScanProcess(Module, multiprocessing.Process):
    """ 
    A class process to find port scans
    This should be converted into a module that wakesup alone when a new alert arrives
    """
    name = 'PortscanDetector1'
    description = 'Port scan detector to detect XX scan'
    authors = ['Sebastian Garcia']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        self.outputqueue = outputqueue
        self.config = config
        # Get from the database the separator used to separate the IP and the word profile
        self.fieldseparator = __database__.getFieldSeparator()
        # To which channels do you wnat to subscribe? When a message arrives on the channel the module will wakeup
        self.c1 = __database__.subscribe('tw_modified')

    def print(self, text, verbose=1, debug=0):
        """ 
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the prcocesses into account

        Input
         verbose: is the minimum verbosity level required for this text to be printed
         debug: is the minimum debugging level required for this text to be printed
         text: text to print. Can include format like 'Test {}'.format('here')
        
        If not specified, the minimum verbosity level required is 1, and the minimum debugging level is 0
        """

        vd_text = str(int(verbose) * 10 + int(debug))
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + text)

    def run(self):
        try:
            while True:
                # Wait for a message from the channel that a TW was modified
                message = self.c1.get_message(timeout=None)
                #self.print('Message received from channel {} with data {}'.format(message['channel'], message['data']), 0, 1)
                if message['channel'] == 'tw_modified':
                    # 'profile_147.32.81.134:timewindow0'
                    # Get the profileid and twid
                    try:
                        profileid = message['data'].split(':')[0]
                        twid = message['data'].split(':')[1]
                    except AttributeError:
                        # When the channel is created the data '1' is sent
                        continue

                # Start of the port scan detection
                self.print('Running the detection of portscans in profile {} TW {}'.format(profileid, twid), 5, 0)
                # For port scan detection, we will measure different things:
                # 1. Vertical port scan:
                #  - When 1 srcip contacts (established or not) > 3 ports in the same dstip (any number of packets)
                # 2. Horizontal port scan:
                #  - When 1 srcip contacts (established or not) the same port in > 3 different dstip (any number of packets)
                # Other things to detect may be
                # 4. If a dstip is port scanned by a src ip
                # 3. The same srcip connecting to the same dst port in the same ip > 3 packets as not established
                # 5. Slow port scan. Same as the others but distributed in multiple time windows
                
                ###
                # To detect 2. and 3. togethe we can use the ClientDstPortTCPNotEstablished
                # Get the ClientDstPortTCPNotEstablished
                data = __database__.getDstPortClientTCPNotEstablishedFromProfileTW(profileid, twid)
                for dport in data.keys():
                    totalpkts = int(data[dport]['totalpkt'])
                    # Fixed threshold for now.
                    if totalpkts > 3:
                        if totalpkts >= 10:
                            confidence = 1
                        else:
                            confidence = totalpkts / 10.0
                        # very stupid port scan
                        type_detection = 'Too many not established TCP conn to the same port'
                        threat_level = 50
                        __database__.setEvidenceForTW(profileid, twid, type_detection, threat_level, confidence)
                        
                        self.print('Too Many Not Estab TCP to same port {} from IP: {}. Amount: {}'.format(dport, profileid.split('_')[1], totalpkts),4,0)
        except KeyboardInterrupt:
            self.print('Stopping the process', 0, 1)
            return True
        except Exception as inst:
            self.print('Error in run() of ', 0, 1)
            self.print(type(inst), 0, 1)
            self.print(inst, 0, 1)

