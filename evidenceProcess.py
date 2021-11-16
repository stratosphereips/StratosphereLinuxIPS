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
from os import path
from colorama import Fore, Style
import ipaddress
import sys

#import requests
import subprocess
import socket
import re
import platform
import os
import notify2

# Evidence Process
class EvidenceProcess(multiprocessing.Process):
    """
    A class to process the evidence from the alerts and update the threat level
    It only work on evidence for IPs that were profiled
    This should be converted into a module
    """
    def __init__(self, inputqueue, outputqueue, config, output_folder, logs_folder):
        self.name = 'EvidenceProcess'
        multiprocessing.Process.__init__(self)
        self.inputqueue = inputqueue
        self.outputqueue = outputqueue
        self.config = config
        # Start the DB
        __database__.start(self.config)
        self.separator = __database__.separator
        # Read the configuration
        self.read_configuration()
        # Subscribe to channel 'evidence_added'
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
        self.timeout = None
        # this list will have our local and public ips
        self.our_ips = self.get_IP()

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        self.outputqueue.put(f"{levels}|{self.name}|{text}")

    def get_IP(self):
        """ Returns a list of our local and public IPs"""
        IPs = []
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            IPs.append(s.getsockname()[0])
        except Exception:
            IPs.append('127.0.0.1')
        finally:
            s.close()
        # get public ip
        #IPs.append(requests.get('http://ipinfo.io/json').json()['ip'])
        command = f'curl -m 5 -s http://ipinfo.io/json'
        result = subprocess.run(command.split(), capture_output=True)
        text_output = result.stdout.decode("utf-8").replace('\n','')
        if text_output:
            public_ip = json.loads(text_output)['ip']
            IPs.append(public_ip)
        return IPs

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
        self.print(f'Detection Threshold: {self.detection_threshold} attacks per minute ({self.detection_threshold * self.width / 60} in the current time window width)', 2, 0)

        try:
            self.popup_alerts = self.config.get('detection', 'popup_alerts')
            self.popup_alerts = True if 'yes' in self.popup_alerts else False
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified, by default...
            self.popup_alerts = False

    def print_alert(self, profileid, twid, flow_datetime):
        '''
        Function to print alert about the blocked profileid and twid
        '''
        try:
            now = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
            ip = profileid.split("_")[-1].strip()
            alert_to_print = f'{flow_datetime}: Src IP {ip:15}. Blocked given enough evidence on timewindow {twid.split("timewindow")[1]}. (real time {now})'
            return alert_to_print
        except Exception as inst:
            self.print('Error in print_alert()')
            self.print(type(inst))
            self.print(inst)

    def print_evidence(self, profileid, twid, ip, detection_module, detection_type, detection_info, description):
        '''
        Function to display evidence according to the detection module.
        :return : string with a correct evidence displacement
        '''
        evidence_string = ''
        dns_resolution_detection_info = __database__.get_dns_resolution(detection_info)
        dns_resolution_detection_info_final = dns_resolution_detection_info[0:3] if dns_resolution_detection_info else ''
        dns_resolution_ip = __database__.get_dns_resolution(ip)
        if len(dns_resolution_ip) >= 1:
            dns_resolution_ip = dns_resolution_ip[0]
        elif len(dns_resolution_ip) == 0:
            dns_resolution_ip = ''
        dns_resolution_ip_final = f' DNS: {dns_resolution_ip[0:3]}. ' if (dns_resolution_detection_info and len(dns_resolution_ip[0:3]) > 0) else '. '
        srcip = profileid.split('_')[1]

        if detection_module == 'ThreatIntelligenceBlacklistIP':
            evidence_string = f'Detected {description}.'
            if detection_type == 'srcip':
                ip = srcip

        elif detection_module == 'ThreatIntelligenceBlacklistDomain':
            ip = srcip
            evidence_string = f'Detected {description}.'

        elif detection_module == 'SSHSuccessful':
            evidence_string = f'Did a successful SSH. {description}.'
        else:
            evidence_string = f'Detected {description}.'

        # Add the srcip to the evidence
        #evidence_string = f'IP: {ip} (DNS:{dns_resolution_ip}). ' + evidence_string
        evidence_string = f'Src IP {ip:15}. ' + evidence_string

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
        """ Returns the domains of each ip (src and dst) that appeared in this flow """
        # These separate lists, hold the domains that we should only check if they are SRC or DST. Not both
        try:
            flow = json.loads(list(flow.values())[0])
        except TypeError:
            # sometimes this function is called before the flow is add to our database
            return [],[]
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

        whitelist = __database__.get_all_whitelist()
        max_tries = 10
        # if this module is loaded before profilerProcess or before we're done processing the whitelist in general
        # the database won't return the whitelist
        # so we need to try several times until the db returns the populated whitelist
        # empty dicts evaluate to False
        while bool(whitelist) is False and max_tries!=0:
            # try max 10 times to get the whitelist, if it's still empty then it's not empty by mistake
            max_tries -=1
            whitelist = __database__.get_all_whitelist()
        if max_tries is 0:
            # we tried 10 times to get the whitelist, it's probably empty.
            return False

        try:
            # Convert each list from str to dict
            whitelisted_IPs = json.loads(whitelist['IPs'])
        except KeyError:
            pass
        try:
            whitelisted_domains = json.loads(whitelist['domains'])
        except KeyError:
            pass
        try:
            whitelisted_orgs = json.loads(whitelist['organizations'])
        except KeyError:
            pass
        try:
            whitelisted_mac = json.loads(whitelist['organizations'])
        except KeyError:
            pass


        # Set data type
        if 'domain' in type_detection:
            data_type = 'domain'
        elif 'outTuple' in type_detection:
            # for example: ip:port:proto
            # check if ipv6 or v4
            data = data.split(':')
            if len(data) > 3:
                # outtuples can contain ipv6 like this 2a00:1450:400c:c05::be:443:tcp
                # we're sure this is an ipv6, extract it
                data = data[:-2]  # remove port and proto
                data = "".join(i+':' for i in data)[:-1]
            else:
                # is ipv4
                data = data[0]
            data_type = 'ip'

        elif 'dport' in type_detection:
            # is coming from portscan module
            try:
                # data coming from portscan module contains the port and not the ip, we need to extract
                # the ip from the description
                ip_regex = r'[0-9]+.[0-9]+.[0-9]+.[0-9]+'
                match = re.search(ip_regex, description)
                if match:
                    data = match.group()
                    data_type = 'ip'
                else:
                    # can't get the ip from the description!!
                    return False

            except (IndexError,ValueError):
                # not coming from portscan module , data is a dport, do nothing
                data_type = ''
                pass
        else:
            # it's probably one of the following:  'sip', 'dip', 'sport'
            data_type = 'ip'

        # Check IPs
        if data_type is 'ip':
            # Check that the IP in the content of the alert is whitelisted
            # Was the evidence coming as a src or dst?
            ip = data
            is_srcip = type_detection in ('sip', 'srcip', 'sport', 'inTuple')
            is_dstip = type_detection in ('dip', 'dstip', 'dport', 'outTuple')
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

                # Now we know this ipv4 or ipv6 isn't whitelisted
                # is the mac address of this ip whitelisted?
                if whitelisted_mac:
                    # getthe mac addr of this ip from our db
                    # this mac can be src or dst mac, based on the type of ip (is_srcip or is_dstip)
                    mac = __database__.get_mac_addr_from_profile(f'profile_{ip}')[0]
                    if mac and mac in list(whitelisted_mac.keys()):
                        # src or dst and
                        from_ = whitelisted_mac[mac]['from']
                        what_to_ignore = whitelisted_mac[mac]['what_to_ignore']
                        # do we want to whitelist alerts?
                        if ('flows' in what_to_ignore or 'both' in what_to_ignore):
                            if is_srcip and ('src' in from_ or 'both' in from_) :
                                return True
                            if is_dstip and ('dst' in from_ or 'both' in from_):
                                return True

        # Check domains
        if data_type is 'domain':
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
                        if ip_data:
                            ip_asn = ip_data.get('asn',{'asnorg':''})

                            # make sure the asn field contains a value
                            if (ip_asn['asnorg'] not in ('','Unknown')
                                and (org.lower() in ip_asn['asnorg'].lower()
                                        or ip_asn['asnorg'] in whitelisted_orgs[org].get('asn',''))):
                                # this ip belongs to a whitelisted org, ignore alert
                                #self.print(f'Whitelisting evidence sent by {srcip} about {ip} due to ASN of {ip} related to {org}. {data} in {description}')
                                return True

                        # Method 2 using the organization's list of ips
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

                        # Method 3 Check if the domains of this flow belong to this org domains
                        domains_to_check_dst, domains_to_check_src = self.get_domains_of_flow(flow)
                        # which list of the above should be used? src or dst or both?
                        if ignore_alerts_to_org and ignore_alerts_from_org: domains_to_check = domains_to_check_src + domains_to_check_dst
                        elif ignore_alerts_from_org : domains_to_check = domains_to_check_src
                        elif ignore_alerts_to_org : domains_to_check = domains_to_check_dst
                        try:
                            org_domains = json.loads(whitelisted_orgs[org].get('domains','{}'))
                            # domains to check are usually 1 or 2 domains
                            for flow_domain in domains_to_check:
                                if org in flow_domain:
                                    return True
                                for domain in org_domains:
                                    # match subdomains too
                                    if domain in flow_domain:
                                        return True
                        except (KeyError,TypeError):
                            # comes here if the whitelisted org doesn't have domains in slips/organizations_info (not a famous org)
                            # and ip doesn't have asn info.
                            # so we don't know how to link this ip to the whitelisted org!
                            pass
        return False

    def show_popup(self, alert_to_log: str):
        pass

    def run(self):
        while True:
            try:
            # Adapt this process to process evidence from only IPs and not profileid or twid

                # Wait for a message from the channel that a TW was modified
                message = self.c1.get_message(timeout=self.timeout)
                # if timewindows are not updated for a long time (see at logsProcess.py), we will stop slips automatically.The 'stop_process' line is sent from logsProcess.py.
                if message['data'] == 'stop_process':
                    self.logfile.close()
                    self.jsonfile.close()
                    __database__.publish('finished_modules','EvidenceProcess')
                    return True

                elif message['channel'] == 'evidence_added' and type(message['data']) is not int:
                    # Data sent in the channel as a json dict, it needs to be deserialized first
                    data = json.loads(message['data'])
                    profileid = data.get('profileid')
                    srcip = profileid.split(self.separator)[1]
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
                    # in case of blacklisted ip evidence, we add the tag to the description like this [tag]
                    tag = data.get('tags',False)

                    # Ignore alert if ip is whitelisted
                    flow = __database__.get_flow(profileid,twid,uid)
                    if flow and self.is_whitelisted(srcip, detection_info, type_detection, description, flow):
                        # Modules add evidence to the db before reaching this point, so
                        # remove evidence from db so it will be completely ignored
                        __database__.deleteEvidence(profileid, twid, key)
                        continue

                    if timestamp and (isinstance(timestamp, datetime) or type(timestamp)==float):
                        flow_datetime = datetime.fromtimestamp(timestamp)
                        flow_datetime = flow_datetime.strftime('%Y/%m/%d %H:%M:%S')
                    else:
                        try:
                            # for timestamps like 2021-06-07T12:44:56.654854+0200
                            flow_datetime = timestamp.split('T')[0] +' '+ timestamp.split('T')[1][:8]
                        except IndexError:
                            #  for timestamps like 2018-03-09 22:57:44.781449+02:00
                            flow_datetime = timestamp[:19]
                        #  change the date separator to /
                        flow_datetime = flow_datetime.replace('-','/')

                    # Print the evidence in the outprocess
                    evidence_to_log = self.print_evidence(profileid,
                                                          twid,
                                                          srcip,
                                                          type_evidence,
                                                          type_detection,
                                                          detection_info,
                                                          description)

                    evidence_dict = {'type': 'evidence',
                                     'profileid': profileid,
                                     'twid': twid,
                                     'timestamp': flow_datetime,
                                     'detected_ip': srcip,
                                     'detection_module':type_evidence,
                                     'detection_info':str(type_detection) + ' ' + str(detection_info),
                                     'description':description
                                     }

                    # What tag is this??? TI tag?
                    if tag:
                        # remove the tag from the description
                        description = description[:description.index('[')][:-5]
                        # add a key in the json evidence with tag
                        evidence_dict.update({'tags':tag.replace("'",''), 'description': description})

                    # Add the evidence to the log files
                    self.addDataToLogFile(flow_datetime + ': ' + evidence_to_log)
                    self.addDataToJSONFile(evidence_dict)


                    #
                    # Analysis of evidence for blocking or not
                    # This is done every time we receive 1 new evidence
                    # 

                    # Get all the evidence for the TW
                    evidence = __database__.getEvidenceForTW(profileid, twid)

                    # Important! It may happen that the evidence is not related to a profileid and twid.
                    # For example when the evidence is on some src IP attacking our home net, and we are not creating
                    # profiles for attackers
                    if evidence:
                        evidence = json.loads(evidence)
                        # self.print(f'Evidence: {evidence}. Profileid {profileid}, twid {twid}')
                        # The accumulated threat level is for all the types of evidence for this profile
                        accumulated_threat_level = 0.0
                        srcip = profileid.split(self.separator)[1]
                        for key in evidence:
                            # Deserialize key data
                            key_json = json.loads(key)
                            type_detection = key_json.get('type_detection')
                            detection_info = key_json.get('detection_info')
                            type_evidence = key_json.get('type_evidence')

                            # Deserialize evidence data
                            data = evidence[key]
                            confidence = float(data.get('confidence'))
                            threat_level = data.get('threat_level')
                            description = data.get('description')

                            # Compute the moving average of evidence
                            new_threat_level = threat_level * confidence
                            self.print('\t\tWeighted Threat Level: {}'.format(new_threat_level), 3, 0)
                            accumulated_threat_level += new_threat_level
                            self.print('\t\tAccumulated Threat Level: {}'.format(accumulated_threat_level), 3, 0)

                        # This is the part to detect if the accumulated evidence was enough for generating a detection
                        # The detection should be done in attacks per minute. The parameter in the configuration is attacks per minute
                        # So find out how many attacks corresponds to the width we are using
                        # 60 because the width is specified in seconds
                        detection_threshold_in_this_width = self.detection_threshold * self.width / 60
                        if accumulated_threat_level >= detection_threshold_in_this_width:
                            # if this profile was not already blocked in this TW
                            if not __database__.checkBlockedProfTW(profileid, twid):
                                # Differentiate the type of evidence for different detections
                                # when printing alerts to the terminal print the profileid_twid that generated this alert too
                                #evidence_to_print = f'{profileid}_{twid} '
                                evidence_to_print = f'{flow_datetime}: '
                                evidence_to_print += self.print_evidence(profileid, twid, srcip, type_evidence, type_detection,detection_info, description)
                                self.print(f'{Fore.RED}{evidence_to_print}{Style.RESET_ALL}', 1, 0)
                                # Set an alert about the evidence being blocked
                                alert_to_log = self.print_alert(profileid, twid, flow_datetime)
                                alert_dict = {'type':'alert',
                                              'profileid': profileid,
                                              'twid': twid,
                                              'threat_level':accumulated_threat_level
                                                }

                                self.addDataToLogFile(alert_to_log)
                                self.addDataToJSONFile(alert_dict)

                                if self.popup_alerts:
                                    self.show_popup(alert_to_log)

                                # check that the dst ip isn't our own IP
                                if type_detection=='dstip' and detection_info not in self.our_ips:
                                    #  TODO: edit the options in blocking_data, by default it'll block all traffic to or from this ip
                                    # blocking_data = {
                                    #     'ip':str(detection_info),
                                    #     'block' : True,
                                    # }
                                    # blocking_data = json.dumps(blocking_data)
                                    # # If the blocking module is loaded after this module this line won't work!!!
                                    # __database__.publish('new_blocking', blocking_data)
                                    pass
                                __database__.markProfileTWAsBlocked(profileid, twid)
            except KeyboardInterrupt:
                self.logfile.close()
                self.jsonfile.close()
                # self.outputqueue.put('01|evidence|[Evidence] Stopping the Evidence Process')
                continue
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.outputqueue.put(f'01|[Evidence] Error in the Evidence Process line {exception_line}')
                self.outputqueue.put('01|[Evidence] {}'.format(type(inst)))
                self.outputqueue.put('01|[Evidence] {}'.format(inst))
                return True
