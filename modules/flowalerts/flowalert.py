# This is a template module for you to copy and create your own slips module
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
import ipaddress

class Module(Module, multiprocessing.Process):
    name = 'flowalerts'
    description = 'Alerts about flows: long connection, successful ssh'
    authors = ['Kamila Babayeva', 'Sebastian Garcia','Alya Gomaa']

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
        self.c3 = __database__.subscribe('new_notice')
        self.c4 = __database__.subscribe('new_ssl')
        self.c6 = __database__.subscribe('tw_closed')
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
        # todo is there more ranges that i should ignore?
        # ignore default LAN IP address, loopback addr, dns servers, ...etc
        self.ignored_ips = ('192.168.0.1' ,'192.168.1.1', '127.0.0.1', '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112',
                            '208.67.222.222', '208.67.220.220', '185.228.168.9', '185.228.169.9','76.76.19.19', '76.223.122.150', '94.140.14.14',
                            '94.140.15.15','193.159.232.5', '82.103.129.72', '103.113.200.10','77.68.45.252', '117.53.46.10', '103.11.98.187',
                           '160.19.155.51', '31.204.180.44', '169.38.73.5', '104.152.211.99', '177.20.178.12', '185.43.51.84', '79.175.208.28',
                           '223.31.121.171','169.53.182.120')
        self.ignored_ranges = ('172.16.0.0/12',)
        # store them as network objects
        self.ignored_ranges = list(map(ipaddress.ip_network,self.ignored_ranges))

    def is_ignored_ip(self, ip) -> bool:
        ip_obj =  ipaddress.ip_address(ip)
        if ip_obj.is_multicast or ip in self.ignored_ips or ip.endswith('255'):
            return True
        for network_range in self.ignored_ranges:
            if ip_obj in network_range:
                # ip found in one of the ranges, ignore it
                return True
        return False

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

        type_detection = 'ip'
        detection_info = saddr
        type_evidence = 'SSHSuccessful-by-' + by
        threat_level = 0.01
        confidence = 0.5
        description = 'SSH Successful to IP :' + daddr + '. From IP ' + saddr + '. Size: ' + str(size) + '. Detection Model ' + by
        if not twid:
            twid = ''
        __database__.setEvidence(type_detection, detection_info, type_evidence,
                                 threat_level, confidence, description, profileid=profileid, twid=twid)

    def set_evidence_long_connection(self, ip, duration, profileid, twid, ip_state='ip'):
        '''
        Set an evidence for a long connection.
        '''
        type_detection = ip_state
        detection_info = ip
        type_evidence = 'LongConnection'
        threat_level = 10
        confidence = 0.5
        description = 'Long Connection ' + str(duration)
        if not twid:
            twid = ''
        __database__.setEvidence(type_detection, detection_info, type_evidence, threat_level, confidence, description, profileid=profileid, twid=twid)

    def set_evidence_self_signed_certificates(self, profileid, twid, ip, description,  ip_state='ip'):
        '''
        Set evidence for self signed certificates.
        '''
        confidence = 0.5
        threat_level = 30
        type_detection = 'dstip'
        type_evidence = 'SelfSignedCertificate'
        detection_info = ip
        if not twid:
            twid = ''
        __database__.setEvidence(type_detection, detection_info, type_evidence, threat_level, confidence, description, profileid=profileid, twid=twid)

    def set_evidence_for_invalid_certificates(self,profileid, twid, ip, description):
        '''
        Set evidence for Invalid SSL certificates.
        '''
        confidence = 0.5
        threat_level = 20
        type_detection  = 'dstip'
        type_evidence = 'InvalidCertificate'
        detection_info = ip
        if not twid:
            twid = ''
        __database__.setEvidence(type_detection, detection_info, type_evidence, threat_level, confidence, description, profileid=profileid, twid=twid)

    def check_long_connection(self, dur, daddr, saddr, profileid, twid, uid):
        """
        Check if a duration of the connection is
        above the threshold (more than 25 minutess by default).
        """
        if type(dur) == str:
            dur = float(dur)
        # If duration is above threshold, we should set an evidence
        if dur > self.long_connection_threshold:
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

    def check_connection_without_dns(self, daddr, twid, profileid):
        """ Checks if there's a flow to a dstip that has no DNS answer """
        resolved = False
        answers_dict = __database__.get_dns_answers()
        # answers dict is a dict {profileid_tw: {query:serialized answers list}}
        for answer in answers_dict.values():
            # convert from str to list
            answer = json.loads(answer)
            if daddr in answer:
                resolved = True
                return

        # IP has no dns answer, alert.
        if not resolved:
            confidence = 1
            threat_level = 30
            type_detection  = 'dstip'
            type_evidence = 'ConnectionWithoutDNS'
            detection_info = daddr
            description = f'IP address connection without DNS resolution: {daddr}'
            if not twid:
                twid = ''
            __database__.setEvidence(type_detection, detection_info, type_evidence, threat_level, confidence,
                                     description, profileid=profileid, twid=twid)

    def check_ununsed_DNS_resolution(self, contacted_ips, answers, profileid, twid):
        """
         Checks if ip in cached DNS answers
        :param contacted_ips: list of ips used in a specific tw
        :param answers: dict {query: serialized answers list}
        """
        pass

    def run(self):
        try:
            # Main loop function
            while True:
                # ---------------------------- new_flow channel
                message = self.c1.get_message(timeout=0.01)
                # if timewindows are not updated for a long time, Slips is stopped automatically.
                if message and message['data'] == 'stop_process':
                    return True
                if message and message['channel'] == 'new_flow' and type(message['data']) is not int:
                    data = message['data']
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
                    daddr_obj = ipaddress.ip_address(daddr)
                    saddr_obj = ipaddress.ip_address(saddr)
                    # don't check for multicast IPs
                    if not daddr_obj.is_multicast and not saddr_obj.is_multicast:
                        self.check_long_connection(dur, daddr, saddr, profileid, twid, uid)

                        # Check if daddr has a dns answer
                        if not self.is_ignored_ip(daddr):
                            self.check_connection_without_dns(daddr, twid, profileid)

                # ---------------------------- new_ssh channel
                message = self.c2.get_message(timeout=0.01)
                if message and message['data'] == 'stop_process':
                    return True
                if message and message['channel'] == 'new_ssh'  and type(message['data']) is not int:
                    data = message['data']

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
                        # time.sleep(10) # This logic should be fixed, it stops the whole module.
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
                        # time.sleep(10) # This logic should be fixed, it stops the whole module.
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

                # ---------------------------- new_notice channel
                # Check for self signed certificates in new_notice channel (notice.log)
                message = self.c3.get_message(timeout=0.01)
                if message and message['data'] == 'stop_process':
                    return True
                if message and message['channel'] == 'new_notice':
                    """ Checks for self signed certificates in the notice data """
                    data = message['data']
                    if type(data) == str:
                        # Convert from json to dict
                        data = json.loads(data)
                        # Get flow as a json
                        flow = data['flow']
                        # Convert flow to a dict
                        flow = json.loads(flow)
                        msg = flow['msg']
                        # We're looking for self signed certs in the 'msg' field
                        if 'self signed' in msg or 'self-signed' in msg:
                            profileid = data['profileid']
                            twid = data['twid']
                            ip = flow['daddr']
                            description = 'Self-signed certificate. Destination IP: {}'.format(ip)
                            self.set_evidence_self_signed_certificates(profileid,twid, ip, description)
                            self.print(description, 3, 0)
                        if 'SSL certificate validation failed' in msg:
                            profileid = data['profileid']
                            twid = data['twid']
                            ip = flow['daddr']
                            # get the description inside parenthesis
                            description = msg + ' Destination IP: {}'.format(ip)
                            self.set_evidence_for_invalid_certificates(profileid,twid, ip, description)
                            self.print(description, 3, 0)
                # ---------------------------- new_ssl channel
                message = self.c4.get_message(timeout=0.01)
                if message and message['data'] == 'stop_process':
                    return True
                if message and message['channel'] == 'new_ssl':
                    # Check for self signed certificates in new_ssl channel (ssl.log)
                    data = message['data']
                    if type(data) == str:
                        # Convert from json to dict
                        data = json.loads(data)
                        # Get flow as a json
                        flow = data['flow']
                        # Convert flow to a dict
                        flow = json.loads(flow)
                        if 'self signed' in flow['validation_status']:
                            profileid = data['profileid']
                            twid = data['twid']
                            ip = flow['daddr']
                            server_name = flow.get('server_name') # returns None if not found
                            if server_name is not None:
                                description = 'Self-signed certificate. Destination: {}. IP: {}'.format(server_name,ip)
                            else:
                                description = 'Self-signed certificate. Destination IP: {}'.format(ip)
                            self.set_evidence_self_signed_certificates(profileid,twid, ip, description)
                            self.print(description, 3, 0)
                # ---------------------------- tw_closed channel
                message = self.c6.get_message(timeout=0.01)
                if message and message['data'] == 'stop_process':
                    return True
                if message and message['channel'] == 'tw_closed' and type(message['data']) == str:
                    pass
                    data = message["data"]
                    # Get an updated list of dns answers
                    answers = __database__.get_dns_answers()
                    # data example: profile_192.168.1.1_timewindow1
                    data = data.split('_')
                    profileid = f'{data[0]}_{data[1]}'
                    twid = data[2]
                    # get all flows in the tw
                    flows = __database__.get_all_flows_in_profileid_twid(profileid, twid)
                    # a list of contacte dips in this tw
                    contacted_ips = []
                    # flows is a dict of uids as keys and actual flows as values
                    for flow in flows.values():
                        flow = json.loads(flow)
                        contacted_ip = flow.get('daddr','')
                        # append ipv4 addresses only to ths list
                        if not ':' in contacted_ip and not self.is_ignored_ip(contacted_ip) :
                            contacted_ips.append(contacted_ip)
                    # set evidence if we have an answer that isn't used in the contacted ips
                    self.check_ununsed_DNS_resolution(set(contacted_ips), answers, profileid, twid )


        #todo fix [VirusTotal] Problem on the run()
        # [VirusTotal] <class 'KeyError'>
        # [VirusTotal] ('profileid',)
        # [VirusTotal] 'profileid'

        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
