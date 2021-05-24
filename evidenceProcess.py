# Stratosphere Linux IPS. A machine-learning Intrusion Detection System
# Copyright (C) 2021 Sebastian Garcia

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# Contact: eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz, stratosphere@aic.fel.cvut.cz
import multiprocessing
from slips.core.database import __database__
import json
from datetime import datetime
import configparser
import platform
from colorama import init
from os import path
from colorama import Fore, Back, Style
import validators
import ipaddress
import socket

# Evidence Process
class EvidenceProcess(multiprocessing.Process):
    """
    A class to process the evidence from the alerts and update the threat level
    It only work on evidence for IPs that were profiled
    This should be converted into a module
    """
    def __init__(self, inputqueue, outputqueue, config):
        self.name = 'Evidence'
        multiprocessing.Process.__init__(self)
        self.inputqueue = inputqueue
        self.outputqueue = outputqueue
        self.config = config
        # Start the DB
        __database__.start(self.config)
        self.separator = __database__.separator
        # Read the configuration
        self.read_configuration()
        # Subscribe to channel 'tw_modified'
        self.c1 = __database__.subscribe('evidence_added')
        self.logfile = self.clean_evidence_log_file()
        self.jsonfile = self.clean_evidence_json_file()
        # Set the timeout based on the platform. This is because the pyredis lib does not have officially recognized the timeout=None as it works in only macos and timeout=-1 as it only works in linux
        if platform.system() == 'Darwin':
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            # now linux also needs to be non-negative
            self.timeout = None
        else:
            self.timeout = None

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

        # self.name = f'{Style.DIM}{Fore.RED}{self.name}{Style.RESET_ALL}'
        vd_text = str(int(verbose) * 10 + int(debug))
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

    def read_configuration(self):
        """ Read the configuration file for what we need """
        # Get the format of the time in the flows
        try:
            self.timeformat = self.config.get('timestamp', 'format')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.timeformat = '%Y/%m/%d %H:%M:%S.%f'

        # Read the width of the TW
        try:
            data = self.config.get('parameters', 'time_window_width')
            self.width = float(data)
        except ValueError:
            # Its not a float
            if 'only_one_tw' in data:
                # Only one tw. Width is 10 9s, wich is ~11,500 days, ~311 years
                self.width = 9999999999
        except configparser.NoOptionError:
            # By default we use 300 seconds, 5minutes
            self.width = 300.0
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.width = 300.0
        # Limit any width to be > 0. By default we use 300 seconds, 5minutes
        if self.width < 0:
            self.width = 300.0

        # Get the detection threshold
        try:
            self.detection_threshold = float(self.config.get('detection', 'evidence_detection_threshold'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified, by default...
            self.detection_threshold = 2
        self.print(f'Detection Threshold: {self.detection_threshold} attacks per minute ({self.detection_threshold * self.width / 60} in the current time window width)')

    def print_evidence(self, profileid, twid, ip, detection_module, detection_type, detection_info, description):
        '''
        Function to display evidence according to the detection module.
        :return : string with a correct evidence displacement
        '''
        evidence_string = ''
        dns_resolution_detection_info = __database__.get_dns_resolution(detection_info)
        dns_resolution_detection_info_final = dns_resolution_detection_info[0:3] if dns_resolution_detection_info else ''
        dns_resolution_ip = __database__.get_dns_resolution(ip)
        dns_resolution_ip_final = dns_resolution_ip[0:3] if dns_resolution_detection_info else ''

        if detection_module == 'ThreatIntelligenceBlacklistIP':
            if detection_type == 'dstip':
                evidence_string = f'Infected IP {ip} connected to blacklisted IP {detection_info} {dns_resolution_detection_info_final} due to {description}.'

            elif detection_type == 'srcip':
                evidence_string = f'Detected blacklisted IP {detection_info} {dns_resolution_detection_info_final} due to {description}. '

        elif detection_module == 'ThreatIntelligenceBlacklistDomain':
            evidence_string = f'Detected domain: {detection_info} due to {description}.'

        elif detection_module == 'LongConnection':
            evidence_string = f'Detected IP {detection_info} {dns_resolution_detection_info_final} due to a {description}.'

        elif detection_module == 'SSHSuccessful':
            evidence_string = f'IP: {ip} did a successful SSH. {description}.'
        else:
            evidence_string = f'Detected IP: {ip} {dns_resolution_ip_final} due to {description}.'

        return evidence_string

    def clean_evidence_log_file(self):
        '''
        Clear the file if exists for evidence log
        '''
        if path.exists('alerts.log'):
            open('alerts.log', 'w').close()
        return open('alerts.log', 'a')

    def clean_evidence_json_file(self):
        '''
        Clear the file if exists for evidence log
        '''
        if path.exists('alerts.json'):
            open('alerts.json', 'w').close()
        return open('alerts.json', 'a')


    def addDataToJSONFile(self, data):
        """
        Add a new evidence line to the file.
        """
        try:
            data_json = json.dumps(data)
            self.jsonfile.write(data_json)
            self.jsonfile.write('\n')
            self.jsonfile.flush()
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Error in addDataToJSONFile()')
            self.print(type(inst))
            self.print(inst)

    def addDataToLogFile(self, data):
        """
        Add a new evidence line to the file.
        """
        try:
            self.logfile.write(data)
            self.logfile.write('\n')
            self.logfile.flush()
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Error in addDataToLogFile()')
            self.print(type(inst))
            self.print(inst)

    def ip2int(self,ip):
        """ Convert IP address to integer """

        # convert ipv4address object to str ip
        ip = str(ip)
        # convert each octet to int
        integer_ip = list(map(int, ip.split('.')))
        res = (16777216 * integer_ip[0]) + (65536 * integer_ip[1]) + (256 * integer_ip[2]) + integer_ip[3]
        return res

    def is_whitelisted(self, data, type_detection) -> bool:
        """
        Checks if IP is whitelisted
        data: (detection_info) can be ip, domain, tuple(ip:port:proto)
        type_detection: 'sip', 'dip', 'sport', 'dport', 'inTuple', 'outTuple', 'dstdomain'
        """

        whitelist = __database__.get_whitelist()
        max_tries = 10
        # if this module is loaded before profilerProcess or before we're done processing the whitelist in general
        # the database won't return the whitelist
        # so we need to try several times until the db returns the populated whitelist
        # empty dicts evaluate to False
        while bool(whitelist) is False and max_tries!=0:
            # try max 10 times to get the whitelist, if it's still empty then it's not empty by mistake
            max_tries -=1
            whitelist = __database__.get_whitelist()
        if max_tries is 0:
            # we tried 10 times to get the whitelist, it's probably empty.
            return False

        try:
            # Convert each list from str to dict
            whitelisted_IPs = json.loads(whitelist['IPs'])
            whitelisted_domains = json.loads(whitelist['domains'])
            whitelisted_organizations = json.loads(whitelist['organizations'])
        except IndexError:
            pass

        # Set data type
        if 'domain' in type_detection:
            data_type = 'domain'
        elif 'outTuple' in type_detection:
            # for example: ip:port:proto
            # get the ip
            data = data.split(":")[0]
            data_type = 'ip'
        else:
            # it's probably one of the following:  'sip', 'dip', 'sport', 'dport'
            data_type = 'ip'
        #---------------------------------------- Check domains
        if data_type is 'domain' :
            # is domain in whitelisted domains?
            if data in whitelisted_domains:
                # ignore flows or alerts?
                what_to_ignore = whitelisted_domains[data] # alerts or flows
                ignore_alerts = 'alerts' in what_to_ignore or 'both' in what_to_ignore
                if ignore_alerts:
                    return True
            # domain not in whitelisted domains.
            # resolve this domain and check if it's in whitelisted ips or whitelisted orgs
            try:
                resolved_domain = socket.gethostbyname(data)
                data = resolved_domain
                data_type = 'ip'
            except socket.gaierror:
                # the given host name is invalid
                return False
        # Is it a srcip or a dstip??
        is_srcip = type_detection in ('sip', 'srcip', 'sport', 'inTuple')
        is_dstip = type_detection in ('dip', 'dstip', 'dport', 'outTuple','domain')
        ip = data
        if data_type is 'ip' and ip in whitelisted_IPs:
            # Check if we should ignore src or dst alerts from this ip
            # from_ can be: src, dst, both
            # what_to_ignore can be: alerts or flows or both
            from_, what_to_ignore = whitelisted_IPs[ip]
            ignore_alerts = 'alerts' in what_to_ignore or 'both' in what_to_ignore
            ignore_alerts_from_ip = ignore_alerts and is_srcip and ('src' in from_ or 'both' in from_)
            ignore_alerts_to_ip = ignore_alerts and is_dstip and ('dst' in from_ or 'both' in from_)
            if ignore_alerts_from_ip or ignore_alerts_to_ip:
                return True
        #---------------------------------------- Check orgs
        # Did the user specify any whitelisted orgs??
        elif whitelisted_organizations:
            # Check if ip belongs to a whitelisted organization
            for org in whitelisted_organizations:
                from_ =  whitelisted_organizations[org]['from']
                what_to_ignore = whitelisted_organizations[org]['what_to_ignore']
                ignore_alerts = 'alerts' in what_to_ignore or 'both' in what_to_ignore
                ignore_alerts_from_ip = ignore_alerts and is_srcip and ('src' in from_ or 'both' in from_)
                ignore_alerts_to_ip = ignore_alerts and is_dstip and ('dst' in from_ or 'both' in from_)
                if ignore_alerts_from_ip or ignore_alerts_to_ip:
                    IPs_dict = whitelisted_organizations[org]['IPs']
                    # Now start searching for this ip in the list of org IPs
                    ip_octets = ip.split(".")
                    try:
                        first_2_octets = f'{ip_octets[0]}.{ip_octets[1]}'
                        for subnet, ip_range in IPs_dict.items():
                            # if our ip belongs to this subnet, search the hosts of this subnet,
                            # if not move to the next subnet and repeat
                            if first_2_octets in subnet:
                                first_ip_in_subnet = ip_range[0]
                                last_ip_in_subnet = ip_range[1]
                                int_ip = self.ip2int(ip)
                                # if it's in the stored range, it's whitelisted, ignore it
                                return int_ip >= first_ip_in_subnet and int_ip <= last_ip_in_subnet
                    except (IndexError, AttributeError) as e:
                        # IndexError this ip isn't ipv4, ignore it
                        # AttributeError IPs_dict is empty, ignore it
                        return False
        return False

    def run(self):
        try:
            # Adapt this process to process evidence from only IPs and not profileid or twid
            while True:
                # Wait for a message from the channel that a TW was modified
                message = self.c1.get_message(timeout=self.timeout)
                # if timewindows are not updated for a long time (see at logsProcess.py), we will stop slips automatically.The 'stop_process' line is sent from logsProcess.py.
                if message['data'] == 'stop_process':
                    self.logfile.close()
                    self.jsonfile.close()
                    return True
                elif message['channel'] == 'evidence_added' and type(message['data']) is not int:
                    # Data sent in the channel as a json dict, it needs to be deserialized first
                    data = json.loads(message['data'])
                    profileid = data.get('profileid')
                    ip = profileid.split(self.separator)[1]
                    twid = data.get('twid')
                    # Key data
                    key = data.get('key')
                    type_detection = key.get('type_detection') # example: dstip srcip dport sport dstdomain
                    detection_info = key.get('detection_info') # example: ip, port, inTuple, outTuple, domain
                    type_evidence = key.get('type_evidence') # example: PortScan, ThreatIntelligence, etc..
                    # Ignore alert if ip is whitelisted
                    if self.is_whitelisted(detection_info, type_detection):
                        # All evidence are added to the db and to kalipso because before reaching this module
                        # Remove evidence from db so it will be completely ignored from kalipso and the terminal
                        __database__.deleteEvidence(profileid, twid, key)
                        continue
                    # evidence data
                    evidence_data = data.get('data')
                    description = evidence_data.get('description')
                    evidence_to_log = self.print_evidence(profileid,
                                                          twid,
                                                          ip,
                                                          type_evidence,
                                                          type_detection,
                                                          detection_info,
                                                          description)
                    # timestamp
                    now = datetime.now()
                    current_time = now.strftime('%Y-%m-%d %H:%M:%S')

                    evidence_dict = {'timestamp': current_time,
                                     'detected_ip': ip,
                                     'detection_module':type_evidence,
                                     'detection_info':type_detection + ' ' + detection_info,
                                     'description':description}

                    self.addDataToLogFile(current_time + ' ' + evidence_to_log)
                    self.addDataToJSONFile(evidence_dict)

                    evidence = __database__.getEvidenceForTW(profileid, twid)
                    # Important! It may happen that the evidence is not related to a profileid and twid.
                    # For example when the evidence is on some src IP attacking our home net, and we are not creating
                    # profiles for attackers
                    if evidence:
                        evidence = json.loads(evidence)
                        # self.print(f'Evidence: {evidence}. Profileid {profileid}, twid {twid}')
                        # The accumulated threat level is for all the types of evidence for this profile
                        accumulated_threat_level = 0.0
                        # CONTINUE HERE
                        ip = profileid.split(self.separator)[1]
                        for key in evidence:
                            # Deserialize key data
                            key_json = json.loads(key)
                            type_detection = key_json.get('type_detection')
                            detection_info = key_json.get('detection_info')
                            type_evidence = key_json.get('type_evidence')

                            # Deserialize evidence data
                            data = evidence[key]
                            confidence = data.get('confidence')
                            threat_level = data.get('threat_level')
                            description = data.get('description')

                            # Compute the moving average of evidence
                            new_threat_level = threat_level * confidence
                            self.print('\t\tWeighted Threat Level: {}'.format(new_threat_level), 5, 0)
                            accumulated_threat_level += new_threat_level
                            self.print('\t\tAccumulated Threat Level: {}'.format(accumulated_threat_level), 5, 0)

                        # This is the part to detect if the accumulated evidence was enough for generating a detection
                        # The detection should be done in attacks per minute. The parameter in the configuration is attacks per minute
                        # So find out how many attacks corresponds to the width we are using
                        # 60 because the width is specified in seconds
                        detection_threshold_in_this_width = self.detection_threshold * self.width / 60
                        if accumulated_threat_level >= detection_threshold_in_this_width:
                            # if this profile was not already blocked in this TW
                            if not __database__.checkBlockedProfTW(profileid, twid):
                                # Differentiate the type of evidence for different detections
                                evidence_to_print = self.print_evidence(profileid, twid, ip, type_evidence, type_detection,detection_info, description)
                                self.print(f'{Fore.RED}\t{evidence_to_print}{Style.RESET_ALL}', 1, 0)
                                __database__.publish('new_blocking', ip)
                                __database__.markProfileTWAsBlocked(profileid, twid)
        except KeyboardInterrupt:
            self.logfile.close()
            self.jsonfile.close()
            self.outputqueue.put('01|evidence|[Evidence] Stopping the Evidence Process')
            return True
        except Exception as inst:
            self.outputqueue.put('01|evidence|[Evidence] Error in the Evidence Process')
            self.outputqueue.put('01|evidence|[Evidence] {}'.format(type(inst)))
            self.outputqueue.put('01|evidence|[Evidence] {}'.format(inst))
            return True
