from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__
import time
import json
import platform

# Port Scan Detector Process
class PortScanProcess(Module, multiprocessing.Process):
    """ 
    A class process to find port scans
    This should be converted into a module that wakesup alone when a new alert arrives
    """
    name = 'portscandetector-1'
    description = 'Port scan detector to detect Horizonal and Vertical scans'
    authors = ['Sebastian Garcia']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        self.outputqueue = outputqueue
        self.config = config
        # Start the DB
        __database__.start(self.config)
        # Set the output queue of our database instance
        __database__.setOutputQueue(self.outputqueue)
        # Get from the database the separator used to separate the IP and the word profile
        self.fieldseparator = __database__.getFieldSeparator()
        # To which channels do you wnat to subscribe? When a message arrives on the channel the module will wakeup
        self.c1 = __database__.subscribe('tw_modified')
        # We need to know that after a detection, if we receive another flow that does not modify the count for the detection, we are not
        # re-detecting again only becase the threshold was overcomed last time.
        self.cache_det_thresholds = {}
        # Retrieve malicious/benigh labels
        self.normal_label = __database__.normal_label
        self.malicious_label = __database__.malicious_label
        # Set the timeout based on the platform. This is because the pyredis lib does not have officially recognized the timeout=None as it works in only macos and timeout=-1 as it only works in linux
        if platform.system() == 'Darwin':
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            self.timeout = None
        else:
            #??
            self.timeout = None
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
        while True:
            try:
                # Wait for a message from the channel that a TW was modified
                message = self.c1.get_message(timeout=self.timeout)
                #print('Message received from channel {} with data {}'.format(message['channel'], message['data']))
                if message['data'] == 'stop_process':
                    # Confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True
                elif message['channel'] == 'tw_modified':
                    # Get the profileid and twid
                    try:
                        profileid = message['data'].split(':')[0]
                        twid = message['data'].split(':')[1]

                        # Start of the port scan detection
                        self.print('Running the detection of portscans in profile {} TW {}'.format(profileid, twid), 6, 0)
                        # For port scan detection, we will measure different things:
                        # 1. Vertical port scan:
                        # - 1 srcip sends not established flows to > 3 dst ports in the same dst ip. Any number of packets
                        # 2. Horizontal port scan:
                        # - 1 srcip sends not established flows to the same dst ports in > 3 dst ip.
                        # 3. Too many connections???:
                        # - 1 srcip sends not established flows to the same dst ports, > 3 pkts, to the same dst ip
                        # 4. Slow port scan. Same as the others but distributed in multiple time windows

                        # Remember that in slips all these port scans can happen for traffic going IN to an IP or going OUT from the IP.


                        # Get the list of dports that we connected as client using TCP not established
                        direction = 'Dst'
                        state = 'NotEstablished'
                        protocol = 'TCP'
                        role = 'Client'
                        type_data = 'Ports'
                        data = __database__.getDataFromProfileTW(profileid, twid, direction, state, protocol, role, type_data)
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
                                __database__.setEvidence(profileid, twid, type_evidence, threat_level, confidence)
                                self.print('Too Many Not Estab TCP to same port {} from IP: {}. Amount: {}'.format(dport, profileid.split('_')[1], totalpkts),6,0)
    
                            """
                            ### PortScan Type 2. Direction OUT
                            dstips = data[dport]['dstips']
                            # Remove dstips that have DNS resolution already
                            for dip in dstips:
                                dns_resolution = __database__.get_dns_resolution(dip)
                                if dns_resolution:
                                    dstips.remove(dip)
                            amount_of_dips = len(dstips)
                            # If we contacted more than 3 dst IPs on this port with not established connections.. we have evidence
                            #self.print('Horizontal Portscan check. Amount of dips: {}. Threshold=3'.format(amount_of_dips), 3, 0)

                            # Type of evidence
                            type_evidence = 'PortScanType2'
                            # Key
                            type_detection = 'dport'
                            detection_info = dport
                            key = 'dport' + ':' + dport + ':' + type_evidence
                            # Threat level
                            threat_level = 25
                            # Compute the confidence
                            pkts_sent = 0
                            # We detect a scan every Threshold. So we detect when there is 3, 6, 9, 12, etc. dips per port.
                            # The idea is that after X dips we detect a connection. And then we 'reset' the counter until we see again X more.
                            cache_key = profileid + ':' + twid + ':' + key
                            try:
                                prev_amount_dips = self.cache_det_thresholds[cache_key]
                            except KeyError:
                                prev_amount_dips = 0
                            #self.print('Key: {}. Prev dips: {}, Current: {}'.format(cache_key, prev_amount_dips, amount_of_dips))
                            if amount_of_dips % 3 == 0 and prev_amount_dips < amount_of_dips:
                                for dip in dstips:
                                    # Get the total amount of pkts sent to the same port to all IPs
                                    pkts_sent += dstips[dip]
                                if pkts_sent > 10:
                                    confidence = 1
                                else:
                                    # Between 3 and 10 pkts compute a kind of linear grow
                                    confidence = pkts_sent / 10.0
                                # Description
                                description = 'New horizontal port scan detected to port {}. Not Estab TCP from IP: {}. Tot pkts sent all IPs: {}'.format(dport, profileid.split(self.fieldseparator)[1], pkts_sent, confidence)
                                __database__.setEvidence(type_detection, detection_info,type_evidence,
                                                         threat_level, confidence, description, profileid=profileid, twid=twid)
                                # Set 'malicious' label in the detected profile
                                __database__.set_profile_module_label(profileid, type_evidence, self.malicious_label)
                                self.print(description, 3, 0)
                                # Store in our local cache how many dips were there:
                                self.cache_det_thresholds[cache_key] = amount_of_dips

                        # Get the list of dstips that we connected as client using TCP not established, and their ports

                        direction = 'Dst'
                        state = 'NotEstablished'
                        protocol = 'TCP'
                        role = 'Client'
                        type_data = 'IPs'
                        data = __database__.getDataFromProfileTW(profileid, twid, direction, state, protocol, role, type_data)

                        # For each dstip, see if the amount of ports connections is over the threshold
                        for dstip in data.keys():
                            ### PortScan Type 1. Direction OUT
                            # dstports is a dict
                            dstports = data[dstip]['dstports']
                            amount_of_dports = len(dstports)
                            #self.print('Vertical Portscan check. Amount of dports: {}. Threshold=3'.format(amount_of_dports), 3, 0)
                            # Type of evidence
                            type_detection = 'dstip'
                            detection_info = dstip
                            type_evidence = 'PortScanType1'
                            # Key
                            key = 'dstip' + ':' + dstip + ':' + type_evidence
                            # Threat level
                            threat_level = 25
                            # We detect a scan every Threshold. So we detect when there is 3, 6, 9, 12, etc. dports per dip.
                            # The idea is that after X dips we detect a connection. And then we 'reset' the counter until we see again X more.
                            cache_key = profileid + ':' + twid + ':' + key
                            try:
                                prev_amount_dports = self.cache_det_thresholds[cache_key]
                            except KeyError:
                                prev_amount_dports = 0
                            #self.print('Key: {}, Prev dports: {}, Current: {}'.format(cache_key, prev_amount_dports, amount_of_dports))
                            if amount_of_dports % 3 == 0 and prev_amount_dports < amount_of_dports:
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
                                description = 'New vertical port scan detected to IP {} from {}. Total {} dst ports. Not Estab TCP. Tot pkts sent all ports: {}'.format(dstip, profileid.split(self.fieldseparator)[1], amount_of_dports, pkts_sent, confidence)
                                __database__.setEvidence(type_detection, detection_info, type_evidence,
                                                         threat_level, confidence, description, profileid=profileid, twid=twid)
                                # Set 'malicious' label in the detected profile
                                __database__.set_profile_module_label(profileid, type_evidence, self.malicious_label)
                                self.print(description, 3, 0)
                                # Store in our local cache how many dips were there:
                                self.cache_det_thresholds[cache_key] = amount_of_dports

                    except AttributeError:
                        # When the channel is created the data '1' is sent
                        continue
            except KeyboardInterrupt:
                # On KeyboardInterrupt, slips.py sends a stop_process msg to all modules, so continue to receive it
                continue
            except Exception as inst:
                self.print('Error in run() of {}'.format(inst), 0, 1)
                self.print(type(inst), 0, 1)
                self.print(inst, 0, 1)
