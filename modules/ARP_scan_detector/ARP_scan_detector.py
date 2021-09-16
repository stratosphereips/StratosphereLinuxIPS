# Ths is a template module for you to copy and create your own slips module
# Instructions
# 1. Create a new folder on ./modules with the name of your template. Example:
#    mkdir modules/anomaly_detector
# 2. Copy this template file in that folder.
#    cp modules/template/template.py modules/anomaly_detector/anomaly_detector.py
# 3. Make it a module
#    touch modules/template/__init__.py
# 4. Change the name of the module, description and author in the variables
# 5. The file name of the python module (template.py) MUST be the same as the name of the folder (template)
# 6. The variable 'name' MUST have the public name of this module. This is used to ignore the module
# 7. The name of the class MUST be 'Module', do not change it.

# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
import platform

# Your imports
import json
import time
import datetime

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'ARPScanDetector'
    description = 'Module to detect ARP scans.'
    authors = ['Alya Gomaa']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue.
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for
        # your own configurations
        self.config = config
        # Start the DB
        __database__.start(self.config)
        # To which channels do you wnat to subscribe? When a message
        # arrives on the channel the module will wakeup
        # The options change, so the last list is on the
        # slips/core/database.py file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added
        # Remember to subscribe to this channel in database.py
        self.pubsub = __database__.r.pubsub()
        self.pubsub.subscribe('new_arp')
        self.pubsub.subscribe('tw_closed')
        self.timeout = None
        # this dict will categorize arp requests by profileid_twid
        self.cache_arp_requests = {}

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by
        taking all the prcocesses into account

        Input
         verbose: is the minimum verbosity level required for this text to
         be printed
         debug: is the minimum debugging level required for this text to be
         printed
         text: text to print. Can include format like 'Test {}'.format('here')

        If not specified, the minimum verbosity level required is 1, and the
        minimum debugging level is 0
        """

        vd_text = str(int(verbose) * 10 + int(debug))
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

    def check_arp_scan(self, flow):
        # to test this module run sudo arp-scan  --localnet
        ts = flow['ts']
        profileid = flow['profileid']
        twid = flow['twid']
        src_mac = flow['src_mac']
        dst_mac = flow['dst_mac']
        daddr = flow['daddr']
        saddr = flow['saddr']
        uid = flow['uid']
        try:
            # cached_requests is a list, append this request to it
            # if ip x sends more than 10 arp requests to any ip within 0.015 seconds, then this is x doing arp scan
            # the key f'{profileid}_{twid} is used to group rquests from the same saddr
            cached_requests = self.cache_arp_requests[f'{profileid}_{twid}']
            cached_requests.append({'uid' : uid,
                                    'daddr': daddr,
                                    'saddr': saddr,
                                    'src_mac': src_mac ,
                                    'dst_mac': dst_mac ,
                                    'ts' : ts})

            #todo do we need mac addresses?
            if len(cached_requests) >= 10:
                # check if these requests happened within 30 secs
                # get the first and the last request of the 10
                starttime = cached_requests[0]['ts']
                endtime = cached_requests[-1]['ts']
                # get the time of each one in seconds
                starttime = datetime.datetime.fromtimestamp(starttime)
                endtime = datetime.datetime.fromtimestamp(endtime)
                # get the difference between them in seconds
                self.diff = float(str(endtime - starttime).split(':')[-1])
                if self.diff <= 30.00:
                    # we are sure this is an arp scan
                    confidence = 1
                    threat_level = 60
                    description = f'ARP Scan Detected to destination address: {daddr}'
                    type_evidence = 'ARPScan'
                    type_detection = 'dstip'
                    detection_info = daddr
                    __database__.setEvidence(type_detection, detection_info, type_evidence,
                                         threat_level, confidence, description, ts, profileid=profileid, twid=twid, uid=uid)
                    # after we set evidence, clear the dict so we can detect if it does another scan
                    self.cache_arp_requests.pop(f'{profileid}_{twid}')
                    return True
        except KeyError:
            # create the key if it doesn't exist
            self.cache_arp_requests[f'{profileid}_{twid}'] = [{'uid' : uid,
                                                                'daddr': daddr,
                                                                'saddr': saddr,
                                                                'src_mac': src_mac,
                                                                'dst_mac': dst_mac,
                                                                'ts' : ts}]
        return False

    def run(self):
        # Main loop function
        while True:
            try:
                message = self.pubsub.get_message(timeout=None)
                if message and message['data'] == 'stop_process':
                    # Confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True

                if message and message['channel'] == 'new_arp' and type(message['data'])==str:
                    flow = json.loads(message['data'])
                    self.check_arp_scan(flow)

                # if the tw is closed, remove all its entries from the cache dict
                if message and message['channel'] == 'tw_closed' and type(message['data'])==str:
                    profileid_tw = message['data']
                    # when a tw is closed, this means that it's too old so we don't check for arp scan in this time range anymore
                    # this copy is made to avoid dictionary changed size during iteration err
                    cache_copy = self.cache_arp_requests.copy()
                    for key in cache_copy:
                        if profileid_tw in key:
                            self.cache_arp_requests.pop(key)
                            # don't break , keep looking for more keys that belong to the same tw
            except KeyboardInterrupt:
                # On KeyboardInterrupt, slips.py sends a stop_process msg to all modules, so continue to receive it
                continue
            except Exception as inst:
                self.print('Problem on the run()', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True
