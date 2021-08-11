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
from slips_files.core.database import __database__
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
    def __init__(self, inputqueue, outputqueue, config, output_folder, logs_folder):
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
        self.logfile = self.clean_evidence_log_file(output_folder)
        self.jsonfile = self.clean_evidence_json_file(output_folder)
        # If logs enabled, write alerts to the log folder as well
        if logs_folder:
            self.logs_logfile = self.clean_evidence_log_file(logs_folder+'/')
            self.logs_jsonfile =  self.clean_evidence_json_file(logs_folder+'/')
        else:
            self.logs_logfile = False
            self.logs_jsonfile = False

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

    def print_alert(self, profileid, twid, score):
        '''
        Function to print alert about the blocked profileid and twid
        '''
        alert_to_print = "{} {} is blocked with a score: {}.".format(profileid, twid, score)
        return alert_to_print

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
                evidence_string = f'{profileid}_{twid}: Infected IP {ip} connected to blacklisted IP {detection_info} {dns_resolution_detection_info_final} due to {description}.'

            elif detection_type == 'srcip':
                evidence_string = f'{profileid}_{twid}: Detected blacklisted IP {detection_info} {dns_resolution_detection_info_final} due to {description}. '

        elif detection_module == 'ThreatIntelligenceBlacklistDomain':
            evidence_string = f'{profileid}_{twid}: Detected domain {detection_info} due to {description}.'

        elif detection_module == 'SSHSuccessful':
            evidence_string = f'{profileid}_{twid}: IP {ip} did a successful SSH. {description}.'
        else:
            evidence_string = f'{profileid}_{twid}: Detected IP {ip} {dns_resolution_ip_final} due to {description}.'

        return evidence_string

    def clean_evidence_log_file(self, output_folder):
        '''
        Clear the file if exists for evidence log
        '''
        if path.exists(output_folder  + 'alerts.log'):
            open(output_folder  + 'alerts.log', 'w').close()
        return open(output_folder + 'alerts.log', 'a')

    def clean_evidence_json_file(self, output_folder):
        '''
        Clear the file if exists for evidence log
        '''
        if path.exists(output_folder  + 'alerts.json'):
            open(output_folder  + 'alerts.json', 'w').close()
        return open(output_folder + 'alerts.json', 'a')


    def addDataToJSONFile(self, data):
        """
        Add a new evidence line to the file.
        """
        try:
            data_json = json.dumps(data)
            self.jsonfile.write(data_json)
            self.jsonfile.write('\n')
            self.jsonfile.flush()
            # If logs folder are enabled, write alerts in the folder as well
            if self.logs_jsonfile:
                self.logs_jsonfile.write(data_json)
                self.logs_jsonfile.write('\n')
                self.logs_jsonfile.flush()
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
            # If logs are enabled, write alerts in the folder as well
            if self.logs_logfile:
                self.logs_logfile.write(data)
                self.logs_logfile.write('\n')
                self.logs_logfile.flush()
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Error in addDataToLogFile()')
            self.print(type(inst))
            self.print(inst)

    def get_domains_of_flow(self, flow:dict):
        """ Returns the domains of each ip (src and dst) that appeard in this flow """
        # These separate lists, hold the domains that we should only check if they are SRC or DST. Not both
        flow = json.loads(list(flow.values())[0])
        domains_to_check_src = []
        domains_to_check_dst = []
        try:
            #self.print(f"IPData of src IP {self.column_values['saddr']}: {__database__.getIPData(self.column_values['saddr'])}")
            domains_to_check_src.append(__database__.getIPData(flow['saddr']).get('SNI',[{}])[0].get('server_name'))
        except (KeyError, TypeError):
            pass
        try:
            #self.print(f"DNS of src IP {self.column_values['saddr']}: {__database__.get_dns_resolution(self.column_values['saddr'])}")
            src_dns_domains = __database__.get_dns_resolution(flow['saddr'])
            for dns_domain in src_dns_domains:
                domains_to_check_src.append(dns_domain)
        except (KeyError, TypeError):
            pass
        try:
            # self.print(f"IPData of dst IP {self.column_values['daddr']}: {__database__.getIPData(self.column_values['daddr'])}")
            domains_to_check_dst.append(__database__.getIPData(flow['daddr']).get('SNI',[{}])[0].get('server_name'))
        except (KeyError, TypeError):
            pass

        return domains_to_check_dst, domains_to_check_src

    def is_whitelisted(self, srcip: str, data, type_detection, description, flow: dict) -> bool:
        """
        Checks if IP is whitelisted
        :param srcip: Src IP that generated the evidence
        :param data: This is what was detected in the evidence. (detection_info) can be ip, domain, tuple(ip:port:proto).
        :param type_detection: 'sip', 'dip', 'sport', 'dport', 'inTuple', 'outTuple', 'dstdomain'
        :param description: may contain IPs if the evidence is coming from portscan module
        :param flow: used to get the domains associated with each flow
        """

        #self.print(f'Checking the whitelist of {srcip}: {data} {type_detection} {description} ')

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
        except IndexError:
            pass
        try:
            whitelisted_domains = json.loads(whitelist['domains'])
        except IndexError:
            pass
        try:
            whitelisted_orgs = json.loads(whitelist['organizations'])
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
        elif 'dport' in type_detection:
            # is coming from portscan module
            try:
                # data coming from portscan module contains the port and not the ip, we need to extract
                # the ip from the description
                data = description.split('. Tot')[0].split(': ')[1]
                data_type = 'ip'
            except (IndexError,ValueError):
                # not coming from portscan module , data is a dport, do nothing
                pass
        else:
            # it's probably one of the following:  'sip', 'dip', 'sport'
            data_type = 'ip'

        # Check that the srcip of the flow that generated this alert is whitelisted
        is_srcip = type_detection in ('sip', 'srcip', 'sport', 'inTuple')
        ip = srcip
        if ip in whitelisted_IPs:
            # Check if we should ignore src or dst alerts from this ip
            # from_ can be: src, dst, both
            # what_to_ignore can be: alerts or flows or both
            from_ = whitelisted_IPs[ip]['from']
            what_to_ignore = whitelisted_IPs[ip]['what_to_ignore']
            ignore_alerts = 'alerts' in what_to_ignore or 'both' in what_to_ignore
            ignore_alerts_from_ip = ignore_alerts and is_srcip and ('src' in from_ or 'both' in from_)
            if ignore_alerts_from_ip:
                #self.print(f'Whitelisting src IP {srcip} for generating an alert related to {data} in {description}')
                return True

        # Check IPs
        if data_type is 'ip':
            # Check that the IP in the content of the alert is whitelisted
            # Was the evidence coming as a src or dst?
            is_srcip = type_detection in ('sip', 'srcip', 'sport', 'inTuple')
            is_dstip = type_detection in ('dip', 'dstip', 'dport', 'outTuple')
            ip = data
            if ip in whitelisted_IPs:
                # Check if we should ignore src or dst alerts from this ip
                # from_ can be: src, dst, both
                # what_to_ignore can be: alerts or flows or both
                from_ = whitelisted_IPs[ip]['from']
                what_to_ignore = whitelisted_IPs[ip]['what_to_ignore']
                ignore_alerts = 'alerts' in what_to_ignore or 'both' in what_to_ignore
                ignore_alerts_from_ip = ignore_alerts and is_srcip and ('src' in from_ or 'both' in from_)
                ignore_alerts_to_ip = ignore_alerts and is_dstip and ('dst' in from_ or 'both' in from_)
                if ignore_alerts_from_ip or ignore_alerts_to_ip:
                    #self.print(f'Whitelisting src IP {srcip} for evidence about {ip}, due to a connection related to {data} in {description}')
                    return True

        # Check domains
        elif data_type is 'domain':
            is_srcdomain = type_detection in ('srcdomain')
            is_dstdomain = type_detection in ('dstdomain')
            domain = data
            # is domain in whitelisted domains?
            for domain_in_whitelist in whitelisted_domains:
                # We go one by one so we can match substrings in the domains
                sub_domain = domain[-len(domain_in_whitelist):]
                if domain_in_whitelist in sub_domain:
                    # Ignore src or dst
                    from_ = whitelisted_domains[sub_domain]['from']
                    # Ignore flows or alerts?
                    what_to_ignore = whitelisted_domains[sub_domain]['what_to_ignore'] # alerts or flows
                    ignore_alerts = 'alerts' in what_to_ignore or 'both' in what_to_ignore
                    ignore_alerts_from_domain = ignore_alerts and is_srcdomain and ('src' in from_ or 'both' in from_)
                    ignore_alerts_to_domain = ignore_alerts and is_dstdomain and ('dst' in from_ or 'both' in from_)
                    if ignore_alerts_from_domain or ignore_alerts_to_domain:
                        #self.print(f'Whitelisting evidence about {domain_in_whitelist}, due to a connection related to {data} in {description}')
                        return True

        # Check orgs
        if whitelisted_orgs:
            # Check if the IP in the alert belongs to a whitelisted organization
            if data_type is 'ip':
                is_srcorg = type_detection in ('sip', 'srcip', 'sport', 'inTuple', 'srcdomain')
                is_dstorg = type_detection in ('dip', 'dstip', 'dport', 'outTuple', 'dstdomain')
                ip = data
                for org in whitelisted_orgs:
                    from_ =  whitelisted_orgs[org]['from']
                    what_to_ignore = whitelisted_orgs[org]['what_to_ignore']
                    ignore_alerts = 'alerts' in what_to_ignore or 'both' in what_to_ignore
                    ignore_alerts_from_org = ignore_alerts and is_srcorg and ('src' in from_ or 'both' in from_)
                    ignore_alerts_to_org = ignore_alerts and is_dstorg and ('dst' in from_ or 'both' in from_)
                    
                    if ignore_alerts_from_org or ignore_alerts_to_org:
                        # Method 1: using asn
                        # Check if the IP in the content of the alert has ASN info in the db
                        ip_data = __database__.getIPData(ip)
                        ip_asn = ip_data.get('asn',{'asnorg':''})

                        # make sure the asn field contains a value
                        if (ip_asn['asnorg'] not in ('','Unknown')
                                and (org.lower() in ip_asn['asnorg'].lower()
                                        or ip_asn['asnorg'] in whitelisted_orgs[org]['asn'])):
                            # this ip belongs to a whitelisted org, ignore alert
                            #self.print(f'Whitelisting evidence sent by {srcip} about {ip} due to ASN of {ip} related to {org}. {data} in {description}')
                            return True

                        # method 2 using the organization's list of ips
                        # ip doesn't have asn info, search in the list of organization IPs
                        try:
                            org_subnets = json.loads(whitelisted_orgs[org]['IPs'])
                            ip = ipaddress.ip_address(ip)
                            for network in org_subnets:
                                # check if ip belongs to this network
                                if ip in ipaddress.ip_network(network):
                                    #self.print(f'Whitelisting evidence sent by {srcip} about {ip}, due to {ip} being in the range of {org}. {data} in {description}')
                                    return True
                        except (KeyError,TypeError):
                            # comes here if the whitelisted org doesn't have info in slips/organizations_info (not a famous org)
                            # and ip doesn't have asn info.
                            pass

                        # Method 3 Check if the domains of this flow belong to this org
                        domains_to_check_dst, domains_to_check_src = self.get_domains_of_flow(flow)
                        # which list of the above should be used? src or dst or both?
                        if ignore_alerts_to_org and ignore_alerts_from_org: domains_to_check = domains_to_check_src + domains_to_check_dst
                        elif ignore_alerts_from_org : domains_to_check = domains_to_check_src
                        elif ignore_alerts_to_org : domains_to_check = domains_to_check_dst
                        try:
                            org_domains = json.loads(whitelisted_orgs[org]['domains'])
                            for domain in org_domains:
                                # domains to check are usually 1 or 2 domains
                                for flow_domain in domains_to_check:
                                    # match subdomains too
                                    if domain in flow_domain:
                                        return True
                        except (KeyError,TypeError):
                            # comes here if the whitelisted org doesn't have domains in slips/organizations_info (not a famous org)
                            # and ip doesn't have asn info.
                            # so we don't know how to link this ip to the whitelisted org!
                            pass
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
                    # evidence data
                    evidence_data = data.get('data')
                    description = evidence_data.get('description')
                    timestamp = data.get('stime')
                    uid = data.get('uid')

                    # Ignore alert if ip is whitelisted
                    flow = __database__.get_flow(profileid,twid,uid)
                    if self.is_whitelisted(ip, detection_info, type_detection, description, flow):
                        # Modules add evidence to the db before reaching this point, so
                        # remove evidence from db so it will be completely ignored
                        __database__.deleteEvidence(profileid, twid, key)
                        continue

                    if timestamp and (isinstance(timestamp, datetime) or type(timestamp)==float):
                        flow_datetime = datetime.fromtimestamp(timestamp)
                        flow_datetime = flow_datetime.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        flow_datetime = timestamp


                    evidence_to_log = self.print_evidence(profileid,
                                                          twid,
                                                          ip,
                                                          type_evidence,
                                                          type_detection,
                                                          detection_info,
                                                          description)

                    evidence_dict = {'type': 'evidence',
                                     'profileid': profileid,
                                     'twid': twid,
                                     'timestamp': flow_datetime,
                                     'detected_ip': ip,
                                     'detection_module':type_evidence,
                                     'detection_info':str(type_detection) + ' ' + str(detection_info),
                                     'description':description}

                    self.addDataToLogFile(flow_datetime + ' ' + evidence_to_log)
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
                                # Set an alert about the evidence being blocked
                                alert_to_log = self.print_alert(profileid,
                                                                      twid,
                                                                      accumulated_threat_level
                                                                      )

                                alert_dict = {'type':'alert',
                                              'profileid': profileid,
                                              'twid': twid,
                                              'threat_level':accumulated_threat_level
                                                }

                                self.addDataToLogFile(alert_to_log)
                                self.addDataToJSONFile(alert_dict)

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
