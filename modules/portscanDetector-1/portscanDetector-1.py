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
    description = 'Port scan detector to detect Horizonal and Vertical scans'
    authors = ['Sebastian Garcia']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        self.outputqueue = outputqueue
        self.config = config
        # Get from the database the separator used to separate the IP and the word profile
        self.fieldseparator = __database__.getFieldSeparator()
        # To which channels do you wnat to subscribe? When a message arrives on the channel the module will wakeup
        self.c1 = __database__.subscribe('tw_modified')
        self.separator = '_'

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
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

    def run(self):
        try:
            while True:
                # Wait for a message from the channel that a TW was modified
                message = self.c1.get_message(timeout=-1)
                #self.print('Message received from channel {} with data {}'.format(message['channel'], message['data']), 0, 1)
                if message['channel'] == 'tw_modified':
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
                # - 1 srcip sends not established flows to > 3 dst ports in the same dst ip. Any number of packets
                # 2. Horizontal port scan:
                # - 1 srcip sends not established flows to the same dst ports in > 3 dst ip. 
                # 3. Too many connections???:
                # - 1 srcip sends not established flows to the same dst ports, > 3 pkts, to the same dst ip
                # 4. Slow port scan. Same as the others but distributed in multiple time windows

                # Remember that in slips all these port scans can happen for traffic going IN to an IP or going OUT from the IP.


                
                # data = __database__.getSrcDstPortTCPNotEstablishedFromProfileTW(profileid, twid, 'Client')
                hash_key = profileid + self.separator + twid
                data = __database__.get_data_from_profile_tw(hash_key, 'DstPortClientTCPEstablished')
                # For each port, see if the amount is over the threshold
                for dport in data.keys():
                    """
                    ###
                    # PortScan Type 3. Direction OUT
                    # Considering all the flows in this TW, for all the Dst IP, get the sum of all the pkts send to each dst port TCP No tEstablished
                    totalpkts = int(data[dport]['totalpkt'])
                    # If for each port, more than X amount of packets were sent, report an evidence
                    if totalpkts > 3:
                        # Type of evidence
                        type_evidence = 'PortScanType3'
                        # Key
                        key = 'dport' + ':' + dport + ':' + type_evidence
                        # Description
                        description = 'Too Many Not Estab TCP to same port {} from IP: {}. Amount: {}'.format(dport, profileid.split('_')[1], totalpkts)
                        # Threat level
                        threat_level = 50
                        # Confidence. By counting how much we are over the threshold. 
                        if totalpkts >= 10:
                            # 10 pkts or more, receive the max confidence
                            confidence = 1
                        else:
                            # Between 3 and 10 pkts compute a kind of linear grow
                            confidence = totalpkts / 10.0
                        __database__.setEvidenceForTW(profileid, twid, type_evidence, threat_level, confidence)
                        self.print('Too Many Not Estab TCP to same port {} from IP: {}. Amount: {}'.format(dport, profileid.split('_')[1], totalpkts),6,0)

                    """
                    ### PortScan Type 2. Direction OUT
                    dstips = data[dport]['dstips']
                    amount_of_dips = len(dstips)
                    # If we contacted more than 3 dst IPs on this port with not established connections.. we have evidence
                    if amount_of_dips > 3:
                        # Type of evidence
                        type_evidence = 'PortScanType2'
                        # Key
                        key = 'dport' + ':' + dport + ':' + type_evidence
                        # Threat level
                        threat_level = 50
                        # Compute the confidence
                        pkts_sent = 0
                        for dip in dstips:
                            # Get the total amount of pkts sent to the same port to all IPs
                            pkts_sent += dstips[dip]
                        if pkts_sent > 10:
                            confidence = 1
                        else:
                            # Between 3 and 10 pkts compute a kind of linear grow
                            confidence = pkts_sent / 10.0
                        # Description
                        description = 'Horizontal Port Scan to port {}. Not Estab TCP from IP: {}. Tot pkts sent all IPs: {}'.format(dport, profileid.split(self.fieldseparator)[1], pkts_sent, confidence)
                        __database__.setEvidenceForTW(profileid, twid, key, threat_level, confidence, description)
                        self.print(description ,3,0)


                # Get the list of dstips that we connected as client using TCP not established, and their ports
                # data = __database__.getClientTCPNotEstablishedFromProfileTW('DstIP', profileid, twid)
                hash_key = profileid + self.separator + twid
                data = __database__.get_data_from_profile_tw(hash_key, 'DstIPClientTCPEstablished')
                # For each dstip, see if the amount of ports connections is over the threshold
                #self.print(str(data),4,0)
                for dstip in data.keys():
                    ### PortScan Type 1. Direction OUT
                    # dstports is a dict
                    dstports = data[dstip]['dstports']
                    amount_of_dports = len(dstports)
                    # If we contacted more than 3 dst ports on this ip with not established connections.. we have evidence
                    if amount_of_dports > 3:
                        # Type of evidence
                        type_evidence = 'PortScanType1'
                        # Key
                        key = 'dstip' + ':' + dstip + ':' + type_evidence
                        # Threat level
                        threat_level = 50
                        # Compute the confidence
                        pkts_sent = 0
                        for dport in dstports:
                            # Get the total amount of pkts sent to the same port to all IPs
                            pkts_sent += dstports[dport]
                        if pkts_sent > 10:
                            confidence = 1
                        else:
                            # Between 3 and 10 pkts compute a kind of linear grow
                            confidence = pkts_sent / 10.0
                        # Description
                        description = 'Vertical Port Scan to IP {} from {}. Total {} dst ports. Not Estab TCP. Tot pkts sent all ports: {}'.format(dstip, profileid.split(self.fieldseparator)[1], amount_of_dports, pkts_sent, confidence)
                        __database__.setEvidenceForTW(profileid, twid, key, threat_level, confidence, description)
                        self.print(description, 3, 0)


        except KeyboardInterrupt:
            self.print('Stopping the process', 0, 1)
            return True
        except Exception as inst:
            self.print('Error in run() of {}'.format(inst), 0, 1)
            self.print(type(inst), 0, 1)
            self.print(inst, 0, 1)
