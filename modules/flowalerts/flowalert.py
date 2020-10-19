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
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__
import platform

# Your imports
import json
import configparser



class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'flowalerts'
    description = 'Alerts about flows: long connection'
    authors = ['Kamila Babayeva']

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
        # Read the configuration
        self.read_configuration()
        # To which channels do you wnat to subscribe? When a message
        # arrives on the channel the module will wakeup
        # The options change, so the last list is on the
        # slips/core/database.py file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added
        self.c1 = __database__.subscribe('new_flow')
        # Set the timeout based on the platform. This is because the
        # pyredis lib does not have officially recognized the
        # timeout=None as it works in only macos and timeout=-1 as it only works in linux
        if platform.system() == 'Darwin':
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            # linux
            self.timeout = None
        else:
            # Other systems
            self.timeout = None

    def read_configuration(self):
        """ Read the configuration file for what we need """
        # Get the pcap filter
        try:
            self.long_connection_threshold = self.config.get('parameters', 'long_connection_threshold')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.long_connection_threshold = 1500

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

    def set_evidence_long_connection(self, ip, duration, profileid, twid):
        '''
        Set an evidence for long connection in the tw
        If profileid is None, do not set an Evidence
        Returns nothing
        '''
        type_evidence = 'LongConnection'
        key = 'ip' + ':' + ip + ':' + type_evidence
        threat_level = 50
        confidence = 1
        description = 'Long Connection ' + str(duration)
        if not twid:
            twid = ''
        __database__.setEvidence(key, threat_level, confidence, description, profileid=profileid, twid=twid)

    def check_long_connection(self, dur, daddr, saddr, profileid, twid):
        """
        Function to generate alert if the new connection's duration if above the threshold (more than 25mins by default).
        """
        # If duration is above threshold, we should set Evidence
        if dur > self.long_connection_threshold:
            # If the flow is 'in' feature, then we set source address in the evidence
            if daddr == profileid.split('_')[-1]:
                self.set_evidence_long_connection(saddr, dur, profileid, twid)
            # If the flow is as 'out' feature, then we set dst address as evidence
            else:
                self.set_evidence_long_connection(daddr, dur, profileid, twid)


    def run(self):
        try:
            # Main loop function
            while True:
                message = self.c1.get_message(timeout=self.timeout)
                # Check that the message is for you. Probably unnecessary...
                if message['data'] == 'stop_process':
                    return True
                if message['channel'] == 'new_flow':
                    data = message['data']
                    if type(data) == str:
                        # Convert from json to dict
                        data = json.loads(data)
                        profileid = data['profileid']
                        twid = data['twid']
                        # Get flow as a json
                        flow = data['flow']
                        timestamp = data['stime']
                        # Convert flow to a dict
                        flow = json.loads(flow)
                        # Convert the common fields to something that can be interpreted
                        uid = next(iter(flow))
                        flow_dict = json.loads(flow[uid]) #dur, stime, saddr, sport, daddr, dport, proto, state, pkts, allbytes
                        dur = flow_dict['dur']
                        stime = flow_dict['ts']
                        saddr = flow_dict['saddr']
                        sport = flow_dict['sport']
                        daddr = flow_dict['daddr']
                        dport = flow_dict['dport']
                        proto = flow_dict['proto']
                        state = flow_dict['state']
                        pkts = flow_dict['pkts']
                        allbytes = flow_dict['allbytes']

                        self.check_long_connection(dur, daddr, saddr,profileid, twid)




        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
