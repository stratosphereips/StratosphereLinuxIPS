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
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
import platform

# Your imports
import json
import configparser
from ipaddress import ip_address
import datetime

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
        self.timeout = None
        # this dict will store connections on port 0 {'srcips':[(ts,dstip)]}
        self.scans = {}

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

    def set_evidence_ssh_successful(self, profileid, twid, saddr, daddr, size, uid, timestamp, by='', ip_state='ip'):
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
                                 threat_level, confidence, description, timestamp, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_long_connection(self, ip, duration, profileid, twid, uid, ip_state='ip'):
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
        __database__.setEvidence(type_detection, detection_info, type_evidence, threat_level,
                                 confidence, description, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_self_signed_certificates(self, profileid, twid, ip, description, uid, timestamp, ip_state='ip'):
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
        __database__.setEvidence(type_detection, detection_info, type_evidence, threat_level, confidence,
                                 description, timestamp, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_for_multiple_reconnection_attempts(self,profileid, twid, ip, description, uid, timestamp):
        '''
        Set evidence for Reconnection Attempts.
        '''
        confidence = 0.5
        threat_level = 20
        type_detection  = 'dstip'
        type_evidence = 'MultipleReconnectionAttempts'
        detection_info = ip
        if not twid:
            twid = ''
        __database__.setEvidence(type_detection, detection_info, type_evidence, threat_level,
                                 confidence, description, timestamp, profileid=profileid, twid=twid, uid=uid)


    def set_evidence_for_connection_to_multiple_ports(self,profileid, twid, ip, description, uid, timestamp):
        '''
        Set evidence for connection to multiple ports.
        '''
        confidence = 0.5
        threat_level = 20
        type_detection  = 'dstip'
        type_evidence = 'ConnectionToMultiplePorts'
        detection_info = ip
        if not twid:
            twid = ''
        __database__.setEvidence(type_detection, detection_info, type_evidence, threat_level,
                                 confidence, description, timestamp, profileid=profileid, twid=twid, uid=uid)

    def set_evidence_for_invalid_certificates(self,profileid, twid, ip, description, uid, timestamp):
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
        __database__.setEvidence(type_detection, detection_info, type_evidence, threat_level,
                                 confidence, description, timestamp, profileid=profileid, twid=twid, uid=uid)

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

    def set_evidence_for_port_0_scanning(self, saddr, diff, profileid, twid, uid, timestamp):
        confidence = 0.8
        threat_level = 20
        type_detection  = 'srcip'
        type_evidence = 'Port0Scanning'
        detection_info = saddr
        # get a unique list of dstips:
        dest_ips = []
        for scan in self.scans[saddr]:
            daddr = scan[1]
            if daddr not in dest_ips: dest_ips.append(daddr)
        description = f'Port 0 is scanned in the following destination IPs: {dest_ips}'
        if not twid:
            twid = ''
        __database__.setEvidence(type_detection, detection_info, type_evidence, threat_level,
                                 confidence, description, timestamp, profileid=profileid, twid=twid, uid=uid)
        # remove this saddr from the scans dict so the dict won't be growing forever
        self.scans.pop(saddr)

    def run(self):
        # Main loop function
        while True:
            try:

                # ---------------------------- new_flow channel
                message = self.c1.get_message(timeout=0.01)
                # if timewindows are not updated for a long time, Slips is stopped automatically.
                if message and message['data'] == 'stop_process':
                    # confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
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
                    origstate = flow_dict['origstate']
                    dport = flow_dict['dport']
                    proto = flow_dict['proto']
                    state = flow_dict['state']
                    timestamp = data['stime']
                    # stime = flow_dict['ts']
                    sport = flow_dict['sport']
                    # pkts = flow_dict['pkts']
                    # allbytes = flow_dict['allbytes']
                    # Do not check the duration of the flow if the daddr or
                    # saddr is a  multicast.
                    if not ip_address(daddr).is_multicast and not ip_address(saddr).is_multicast:
                        self.check_long_connection(dur, daddr, saddr, profileid, twid, uid)

                    # Multiple Reconnection attempts
                    key = saddr + '-' + daddr + ':' + str(dport)
                    if dport != 0 and origstate == 'REJ':
                        current_reconnections = __database__.getReconnectionsForTW(profileid,twid)
                        current_reconnections[key] = current_reconnections.get(key, 0) + 1
                        __database__.setReconnections(profileid, twid, current_reconnections)
                        for key, count_reconnections in current_reconnections.items():
                            if count_reconnections > 1:
                                description = "Multiple reconnection attempts to Destination IP: {} from IP: {}".format(daddr,saddr)
                                self.set_evidence_for_multiple_reconnection_attempts(profileid, twid, daddr, description, uid, timestamp)

                    if sport == 0:
                        # is this an ip scanning another one through port 0?
                        try:
                            self.scans[saddr].append((timestamp,daddr))
                            if len(self.scans[saddr]) >=3:
                                # this is the same srcip scanning 1 or more daddr through port 0
                                # is it in a short period of time?
                                # get first and last tuples
                                first_scan = self.scans[saddr][0]
                                last_scan = self.scans[saddr][-1]
                                # get first and last ts
                                time_of_first_scan = datetime.datetime.fromtimestamp(first_scan[0])
                                time_of_last_scan = datetime.datetime.fromtimestamp(last_scan[0])
                                # get the difference between them in seconds
                                diff = float(str(time_of_last_scan - time_of_first_scan).split(':')[-1])
                                if diff <= 30.00:
                                    self.set_evidence_for_port_0_scanning(saddr, diff, profileid, twid, uid, timestamp)
                        except KeyError:
                            self.scans[saddr] = [(timestamp,daddr)]

                    # Connection to multiple ports
                    if proto == 'tcp' and state == 'Established':
                        dport_name = flow_dict.get('appproto','')
                        if not dport_name:
                            dport_name = __database__.get_port_info(str(dport) + '/' + proto.lower())
                            if dport_name:
                                dport_name = dport_name.upper()
                        # Consider only unknown services
                        else:
                            dport_name = dport_name.upper()
                        # Consider only unknown services
                        if not dport_name:
                            # Connection to multiple ports to the destination IP
                            if profileid.split('_')[1] == saddr:
                                direction = 'Dst'
                                state = 'Established'
                                protocol = 'TCP'
                                role = 'Client'
                                type_data = 'IPs'
                                dst_IPs_ports = __database__.getDataFromProfileTW(profileid, twid, direction, state, protocol, role, type_data)
                                dstports = list(dst_IPs_ports[daddr]['dstports'])
                                if len(dstports) > 1:
                                    description = "Connection to multiple ports {} of Destination IP: {}".format(dstports, daddr)
                                    self.set_evidence_for_connection_to_multiple_ports(profileid, twid, daddr, description, uid, timestamp)
                            # Connection to multiple port to the Source IP. Happens in the mode 'all'
                            elif profileid.split('_')[1] == daddr:
                                direction = 'Src'
                                state = 'Established'
                                protocol = 'TCP'
                                role = 'Server'
                                type_data = 'IPs'
                                src_IPs_ports = __database__.getDataFromProfileTW(profileid, twid, direction, state, protocol, role, type_data)
                                dstports = list(src_IPs_ports[saddr]['dstports'])
                                if len(dstports) > 1:
                                    description = "Connection to multiple ports {} of Source IP: {}".format(dstports, saddr)
                                    self.set_evidence_for_connection_to_multiple_ports(profileid, twid, daddr, description, uid, timestamp)


                # ---------------------------- new_ssh channel
                message = self.c2.get_message(timeout=0.01)
                if message and message['data'] == 'stop_process':
                    # Confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
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
                    timestamp = flow_dict['stime']
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
                            self.set_evidence_ssh_successful(profileid, twid, saddr, daddr, size, uid, timestamp, by='Zeek')
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
                                self.set_evidence_ssh_successful(profileid, twid, saddr, daddr, size, uid, timestamp, by='Slips')
                            else:
                                # self.print(f'NO Successsul SSH recived: {data}', 1, 0)
                                pass

                # ---------------------------- new_notice channel
                # Check for self signed certificates in new_notice channel (notice.log)
                message = self.c3.get_message(timeout=0.01)
                if message and message['data'] == 'stop_process':
                    # Confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True
                if message and message['channel'] == 'new_notice':
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
                        timestamp = flow['stime']
                        uid = data['uid']
                        msg = flow['msg']
                        note = flow['note']
                        # We're looking for self signed certs in notice.log in the 'msg' field
                        if 'self signed' in msg or 'self-signed' in msg:
                            ip = flow['daddr']
                            description = 'Self-signed certificate. Destination IP: {}'.format(ip)
                            confidence = 0.5
                            threat_level = 30
                            type_detection = 'dstip'
                            type_evidence = 'SelfSignedCertificate'
                            detection_info = ip
                            __database__.setEvidence(type_detection, detection_info, type_evidence,
                                                     threat_level, confidence, description, timestamp, profileid=profileid, twid=twid, uid=uid)
                            self.print(description, 3, 0)

                        # We're looking for port scans in notice.log in the note field
                        if 'Port_Scan' in note:
                            # Vertical port scan
                            # confidence = 1 because this detection is comming from a zeek file so we're sure it's accurate
                            confidence = 1
                            threat_level = 60
                            # msg example: 192.168.1.200 has scanned 60 ports of 192.168.1.102
                            description = 'Zeek: Vertical port scan. ' + msg
                            type_evidence = 'PortScanType1'
                            type_detection = 'dstip'
                            detection_info = flow.get('scanning_ip','')
                            __database__.setEvidence(type_detection, detection_info, type_evidence,
                                                 threat_level, confidence, description, timestamp, profileid=profileid, twid=twid, uid=uid)
                            self.print(description, 3, 0)
                        if 'SSL certificate validation failed' in msg:
                            profileid = data['profileid']
                            twid = data['twid']
                            ip = flow['daddr']
                            # get the description inside parenthesis
                            description = msg + ' Destination IP: {}'.format(ip)
                            self.set_evidence_for_invalid_certificates(profileid,twid, ip, description, uid, timestamp)
                            self.print(description, 3, 0)

                        if 'Address_Scan' in note:
                            # Horizontal port scan
                            confidence = 1
                            threat_level = 60
                            description = 'Zeek: Horizontal port scan. ' + msg
                            type_evidence = 'PortScanType2'
                            type_detection = 'dport'
                            detection_info = flow.get('scanned_port','')
                            __database__.setEvidence(type_detection, detection_info, type_evidence,
                                                 threat_level, confidence, description, timestamp, profileid=profileid, twid=twid, uid=uid)
                            self.print(description, 3, 0)

                # ---------------------------- new_ssl channel
                message = self.c4.get_message(timeout=0.01)
                if message and message['data'] == 'stop_process':
                    # Confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
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
                        uid = flow['uid']
                        timestamp = flow['stime']
                        if 'self signed' in flow['validation_status']:
                            profileid = data['profileid']
                            twid = data['twid']
                            ip = flow['daddr']
                            server_name = flow.get('server_name') # returns None if not found
                            # if server_name is not None or not empty
                            if not server_name:
                                description = 'Self-signed certificate. Destination IP: {}'.format(ip)
                            else:
                                description = 'Self-signed certificate. Destination IP: {}, SNI: {}'.format(ip, server_name)
                            self.set_evidence_self_signed_certificates(profileid,twid, ip, description, uid, timestamp)
                            self.print(description, 3, 0)
            except KeyboardInterrupt:
                return True
            except Exception as inst:
                self.print('Problem on the run()', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True
