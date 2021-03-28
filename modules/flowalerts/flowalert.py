# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__
import platform

# Your imports
import json
import configparser
from ipaddress import ip_address
import time


class Module(Module, multiprocessing.Process):
    name = 'flowalerts'
    description = 'Alerts about flows: long connection, successful ssh'
    authors = ['Kamila Babayeva', 'Sebastian Garcia']

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
        # Retrieve the labels
        self.normal_label = __database__.normal_label
        self.malicious_label = __database__.malicious_label
        # To which channels do you wnat to subscribe? When a message
        # arrives on the channel the module will wakeup
        # The options change, so the last list is on the
        # slips/core/database.py file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added
        self.c1 = __database__.subscribe('new_flow')
        self.c2 = __database__.subscribe('new_ssh')
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
            self.long_connection_threshold = int(self.config.get('flowalerts', 'long_connection_threshold'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.long_connection_threshold = 1500
        try:
            self.ssh_succesful_detection_threshold = int(self.config.get('flowalerts', 'ssh_succesful_detection_threshold'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.ssh_succesful_detection_threshold = 4290

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

    def set_evidence_ssh_successful(self, profileid, twid, saddr, daddr, size, by, ip_state='ip'):
        """
        Set an evidence for a successful SSH login.
        This is not strictly a detection, but we don't have
        a better way to show it.
        The threat_level is 0.01 to show that this is not a detection
        """
        type_evidence = 'SSHSuccessful-by-' + by
        key = 'ip:' + saddr + ':' + type_evidence
        threat_level = 0.01
        confidence = 0.5
        description = 'SSH Successful to IP :' + daddr + '. From IP ' + saddr + '. Size: ' + str(size) + '. Detection Model ' + by
        if not twid:
            twid = ''
        __database__.setEvidence(key, threat_level, confidence, description, profileid=profileid, twid=twid)

    def set_evidence_long_connection(self, ip, duration, profileid, twid, ip_state='ip'):
        '''
        Set an evidence for a long connection.
        '''
        type_evidence = 'LongConnection'
        key = ip_state + ':' + ip + ':' + type_evidence
        threat_level = 10
        confidence = 0.5
        description = 'Long Connection ' + str(duration)
        if not twid:
            twid = ''
        __database__.setEvidence(key, threat_level, confidence, description, profileid=profileid, twid=twid)

    def check_long_connection(self, dur, daddr, saddr, profileid, twid, uid):
        """
        Function to generate an evidence if a duration of the connection is
        above the threshold (more than 25 minutess by default).
        """
        if type(dur) == str:
            dur = float(dur)
        # If duration is above threshold, we should set an evidence
        if dur > self.long_connection_threshold:
            # If the flow is 'in' feature, then we set source address (saddr) in
            # the evidence
            if daddr == profileid.split('_')[-1]:
                self.set_evidence_long_connection(saddr, dur, profileid, twid, ip_state='srcip')
            # If the flow is 'out' feature, then we set destination address (daddr)
            # the evidence
            else:
                self.set_evidence_long_connection(daddr,
                                                  dur,
                                                  profileid,
                                                  twid,
                                                  ip_state='dstip')

                # set "flowalerts-long-connection:malicious" label in the flow (needed for Ensembling module)
                module_name = "flowalerts-long-connection"
                module_label = self.malicious_label
                __database__.set_module_label_to_flow(profileid,
                                                      twid,
                                                      uid,
                                                      module_name,
                                                      module_label)
        else:
            # set "flowalerts-long-connection:normal" label in the flow (needed for Ensembling module)
            module_name = "flowalerts-long-connection"
            module_label = self.normal_label
            __database__.set_module_label_to_flow(profileid,
                                                  twid,
                                                  uid,
                                                  module_name,
                                                  module_label)

    def run(self):
        try:
            # Main loop function
            while True:
                message = self.c1.get_message(timeout=0.01)
                # if timewindows are not updated for a long time, Slips is stopped automatically.
                if message and message['data'] == 'stop_process':
                    return True
                if message and message['channel'] == 'new_flow':
                    data = message['data']
                    if type(data) == str:
                        # Convert from json to dict
                        data = json.loads(data)
                        profileid = data['profileid']
                        twid = data['twid']
                        # Get flow as a json
                        flow = data['flow']
                        # Convert flow to a dict
                        flow = json.loads(flow)
                        # Convert the common fields to something that can
                        # be interpreted
                        uid = next(iter(flow))
                        flow_dict = json.loads(flow[uid])
                        dur = flow_dict['dur']
                        saddr = flow_dict['saddr']
                        daddr = flow_dict['daddr']
                        # stime = flow_dict['ts']
                        # sport = flow_dict['sport']
                        # timestamp = data['stime']
                        # dport = flow_dict['dport']
                        # proto = flow_dict['proto']
                        # state = flow_dict['state']
                        # pkts = flow_dict['pkts']
                        # allbytes = flow_dict['allbytes']

                        # Do not check the duration of the flow if the daddr or
                        # saddr is a  multicast.
                        if not ip_address(daddr).is_multicast and not ip_address(saddr).is_multicast:
                            self.check_long_connection(dur, daddr, saddr, profileid, twid, uid)

                message = self.c2.get_message(timeout=0.01)
                if message and message['data'] == 'stop_process':
                    return True
                if message and message['channel'] == 'new_ssh':
                    data = message['data']
                    if type(data) == str:
                        # Convert from json to dict
                        data = json.loads(data)
                        profileid = data['profileid']
                        twid = data['twid']
                        # Get flow as a json
                        flow = data['flow']
                        # Convert flow to a dict
                        flow_dict = json.loads(flow)
                        uid = flow_dict['uid']
                        # Try Zeek method to detect if SSh was successful or not.
                        auth_success = flow_dict['auth_success']
                        if auth_success:
                            time.sleep(10)    # This logic should be fixed, it stops the whole module.
                            original_ssh_flow = __database__.get_flow(profileid, twid, uid)
                            original_flow_uid = next(iter(original_ssh_flow))
                            if original_ssh_flow[original_flow_uid]:
                                ssh_flow_dict = json.loads(original_ssh_flow[original_flow_uid])
                                daddr = ssh_flow_dict['daddr']
                                saddr = ssh_flow_dict['saddr']
                                size = ssh_flow_dict['allbytes']
                                self.set_evidence_ssh_successful(profileid, twid, saddr, daddr, size, by='Zeek')
                        else:
                            # Try Slips method to detect if SSH was successful.
                            time.sleep(10) # This logic should be fixed, it stops the whole module.
                            original_ssh_flow = __database__.get_flow(profileid, twid, uid)
                            original_flow_uid = next(iter(original_ssh_flow))
                            if original_ssh_flow[original_flow_uid]:
                                ssh_flow_dict = json.loads(original_ssh_flow[original_flow_uid])
                                daddr = ssh_flow_dict['daddr']
                                saddr = ssh_flow_dict['saddr']
                                size = ssh_flow_dict['allbytes']
                                if size > self.ssh_succesful_detection_threshold:
                                    # Set the evidence because there is no
                                    # easier way to show how Slips detected
                                    # the successful ssh and not Zeek
                                    self.set_evidence_ssh_successful(profileid, twid, saddr, daddr, size, by='Slips')
                                else:
                                    # self.print(f'NO Successsul SSH recived: {data}', 1, 0)
                                    pass
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
