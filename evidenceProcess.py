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
from slips_files.common.slips_utils import utils
import json
from datetime import datetime, timedelta
import configparser
from os import path
from colorama import Fore, Style
import ipaddress
import sys

import subprocess
import socket
import re
import platform
import os
import psutil
import pwd
from git import Repo


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
        # If logs enabled, write alerts to the log folder as well
        self.clear_logs_dir(logs_folder)

        if self.popup_alerts:
            # The way we send notifications differ depending on the user and the OS
            self.setup_notifications()

        # Subscribe to channel 'evidence_added'
        self.c1 = __database__.subscribe('evidence_added')

        # clear alerts.log
        self.logfile = self.clean_evidence_log_file(output_folder)
        # clear alerts.json
        self.jsonfile = self.clean_evidence_json_file(output_folder)

        self.timeout = 0.0000001
        # this list will have our local and public ips
        self.our_ips = self.get_IP()
        # all evidence slips detects has threat levels of strings
        # each string should have a corresponding int value to be able to calculate
        # the accumulated threat level and alert
        self.threat_levels = {
            'info': 0,
            'low' : 0.2,
            'medium': 0.5,
            'high': 0.8,
            'critical': 1
        }
        # flag to only add commit and hash to the firs alert in alerts.json
        self.is_first_alert = True

    def clear_logs_dir(self, logs_folder):
        self.logs_logfile = False
        self.logs_jsonfile = False
        if logs_folder:
            # these json files are inside the logs dir, not the output/ dir
            self.logs_logfile = self.clean_evidence_log_file(logs_folder+'/')
            self.logs_jsonfile = self.clean_evidence_json_file(logs_folder+'/')

    def get_branch_info(self):
        """
        Returns a tuple containing (commit,branch)
        """
        try:
            repo = Repo('.')
        except:
            # when in docker, we copy the repo instead of clone it so there's no .git files
            # we can't add repo metadata
            return False
        # add branch name and commit
        branch = repo.active_branch.name
        commit = repo.active_branch.commit.hexsha
        return (commit, branch)


    def setup_notifications(self):
        """
        Get the used display, the user using this display and the uid of this user in case of using Slips as root on linux
        """
        # in linux, if the user's not root, notifications command will need extra configurations
        if platform.system() != 'Linux' or os.geteuid() != 0:
            self.notify_cmd = 'notify-send -t 5000 '
            return False

        # Get the used display (if the user has only 1 screen it will be set to 0), if not we should know which screen is slips running on.
        # A "display" is the address for your screen. Any program that wants to write to your screen has to know the address.
        used_display = psutil.Process().environ()['DISPLAY']

        # when you login as user x in linux, no user other than x is authorized to write to your display, not even root
        # now that we're running as root, we dont't have acess to the used_display
        # get the owner of the used_display, there's no other way than running the 'who' command
        command = f'who | grep "({used_display})" '
        cmd_output = os.popen(command).read()

        # make sure we found the user of this used display
        if len(cmd_output) < 5:
            # we don't know the user of this display!!, try getting it using psutil
            # user 0 is the one that owns tty1
            user = str(psutil.users()[0].name)
        else:
            # get the first user from the 'who' command
            user = cmd_output.split("\n")[0].split()[0]

        # get the uid
        uid = pwd.getpwnam(user).pw_uid
        # run notify-send as user using the used_display and give it the dbus addr
        self.notify_cmd = f'sudo -u {user} DISPLAY={used_display} DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus notify-send -t 5000 '

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
        command = f'curl -m 5 -s http://ipinfo.io/json'
        result = subprocess.run(command.split(), capture_output=True)
        text_output = result.stdout.decode("utf-8").replace('\n','')
        if not text_output or 'Connection timed out' in text_output:
            self.print('Error getting local and public IPs', 0, 1)
        else:
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
            self.popup_alerts = self.config.get('detection', 'popup_alerts').lower()
            self.popup_alerts = True if 'yes' in self.popup_alerts else False

            # In docker, disable alerts no matter what slips.conf says
            if os.environ.get('IS_IN_A_DOCKER_CONTAINER', False):
                self.popup_alerts = False

        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified, by default...
            self.popup_alerts = False

    def format_blocked_srcip_evidence(self, profileid, twid, flow_datetime):
        '''
        Function to prepare evidence about the blocked profileid and twid
        This evidence will be written in alerts.log, it won't be displayed in the terminal
        '''
        try:
            now = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
            ip = profileid.split("_")[-1].strip()
            alert_to_print = f'{flow_datetime}: Src IP {ip:26}. Blocked given enough evidence on timewindow {twid.split("timewindow")[1]}. (real time {now})'
            return alert_to_print
        except Exception as inst:
            self.print('Error in print_alert()')
            self.print(type(inst))
            self.print(inst)

    def format_evidence_string(self, profileid, twid, ip, detection_module, detection_type, detection_info, description):
        '''
        Function to format each evidence and enrich it with more data, to be displayed according to each detection module.
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
            evidence_string = f'Detected {description}'
            if detection_type == 'srcip':
                ip = srcip

        elif detection_module == 'ThreatIntelligenceBlacklistDomain':
            ip = srcip
            evidence_string = f'Detected {description}'

        elif detection_module == 'SSHSuccessful':
            evidence_string = f'Did a successful SSH. {description}'
        else:
            evidence_string = f'Detected {description}'

        # Add the srcip to the evidence
        # evidence_string = f'IP: {ip} (DNS:{dns_resolution_ip}). ' + evidence_string
        # evidence_string = f'Src IP {ip:15}. ' + evidence_string

        return f'{evidence_string}'

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

    def addDataToJSONFile(self, IDEA_dict: dict):
        """
        Add a new evidence line to our alerts.json file in json IDEA format.
        :param IDEA_dict: dict containing 1 alert
        """
        try:
            json_alert = '{ '
            for key_,val in IDEA_dict.items():
                if type(val)==str:
                    # strings in json should be in double quotes instead of single quotes
                   json_alert += f'"{key_}": "{val}", '
                else:
                    # int and float values should be printed as they are
                    json_alert += f'"{key_}": {val}, '
            # remove the last comma and close the dict
            json_alert = json_alert[:-2] + ' }\n'
            # make sure all alerts are in json format (using double quotes)
            json_alert = json_alert.replace("'",'"')
            self.jsonfile.write(json_alert)
            self.jsonfile.flush()
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Error in addDataToJSONFile()')
            self.print(type(inst))
            self.print(inst)

    def addDataToLogFile(self, data):
        """
        Add a new evidence line to the alerts.log and other log files if logging is enabled.
        """
        try:
            # write to alerts.log
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
        except (IndexError, KeyError):
            whitelisted_IPs = {}

        try:
            whitelisted_domains = json.loads(whitelist['domains'])
        except (IndexError, KeyError):
            whitelisted_domains = {}
        try:
            whitelisted_orgs = json.loads(whitelist['organizations'])
        except (IndexError, KeyError):
            whitelisted_orgs = {}
        try:
            whitelisted_mac = json.loads(whitelist['mac'])
        except (IndexError, KeyError):
            whitelisted_mac = {}


        # Set data type
        if 'domain' in type_detection:
            data_type = 'domain'
        elif 'outTuple' in type_detection:
            # for example: ip:port:proto
            data = data.split('-')[0]
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
        if data_type == 'ip':
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
                        if ('alerts' in what_to_ignore or 'both' in what_to_ignore):
                            if is_srcip and ('src' in from_ or 'both' in from_) :
                                return True
                            if is_dstip and ('dst' in from_ or 'both' in from_):
                                return True

        # Check domains
        if data_type == 'domain':
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
            is_src = type_detection in ('sip', 'srcip', 'sport', 'inTuple', 'srcdomain')
            is_dst = type_detection in ('dip', 'dstip', 'dport', 'outTuple', 'dstdomain')
            for org in whitelisted_orgs:
                from_ =  whitelisted_orgs[org]['from']
                what_to_ignore = whitelisted_orgs[org]['what_to_ignore']
                ignore_alerts = 'alerts' in what_to_ignore or 'both' in what_to_ignore
                ignore_alerts_from_org = ignore_alerts and is_src and ('src' in from_ or 'both' in from_)
                ignore_alerts_to_org = ignore_alerts and is_dst and ('dst' in from_ or 'both' in from_)

                # Check if the IP in the alert belongs to a whitelisted organization
                if data_type == 'ip':
                    ip = data
                    if ignore_alerts_from_org or ignore_alerts_to_org:
                        # Method 1: using asn
                        # Check if the IP in the content of the alert has ASN info in the db
                        ip_data = __database__.getIPData(ip)
                        if ip_data:
                            ip_asn = ip_data.get('asn',{'asnorg':''})['asnorg']
                            # make sure the asn field contains a value
                            if (ip_asn not in ('','Unknown')
                                and (org.lower() in ip_asn.lower()
                                        or ip_asn in whitelisted_orgs[org].get('asn',''))):
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
                    except (KeyError, TypeError):
                        # comes here if the whitelisted org doesn't have info in slips/organizations_info (not a famous org)
                        # and ip doesn't have asn info.
                        pass
                if data_type == 'domain':
                    flow_domain = data
                    flow_TLD = flow_domain.split(".")[-1]
                    # Method 3 Check if the domains of this flow belong to this org domains
                    try:
                        org_domains = json.loads(whitelisted_orgs[org].get('domains','{}'))
                        if org in flow_domain:
                            # self.print(f"The domain of this flow ({flow_domain}) belongs to the domains of {org}")
                            return True

                        for org_domain in org_domains:
                            org_domain_TLD = org_domain.split(".")[-1]
                            # make sure the 2 domains have the same same top level domain
                            if flow_TLD != org_domain_TLD: continue

                            # match subdomains
                            # if org has org.com, and the flow_domain is xyz.org.com whitelist it
                            if org_domain in flow_domain:
                                print(f"The src domain of this flow ({flow_domain}) is "
                                           f"a subdomain of {org} domain: {org_domain}")
                                return True
                            # if org has xyz.org.com, and the flow_domain is org.com whitelist it
                            if flow_domain in org_domain :
                                print(f"The domain of {org} ({org_domain}) is a subdomain of "
                                      f"this flow domain ({flow_domain})")
                                return True

                    except (KeyError,TypeError):
                        # comes here if the whitelisted org doesn't have domains in slips/organizations_info (not a famous org)
                        # and ip doesn't have asn info.
                        # so we don't know how to link this ip to the whitelisted org!
                        pass
        return False

    def show_popup(self, alert_to_log: str):
        """
        Function to display a popup with the alert depending on the OS
        """
        if platform.system() == 'Linux':
            #  is notify_cmd is set in setup_notifications function depending on the user
            os.system(f'{self.notify_cmd} "Slips" "{alert_to_log}"')
        elif platform.system() == 'Darwin':
            os.system(f"osascript -e 'display notification \"{alert_to_log}\" with title \"Slips\"' ")

    def get_ts_format(self, timestamp):
        """
        returns the appropriate format of the given ts
        """
        if '+' in timestamp:
            # timestamp contains UTC offset, set the new format accordingly
            newformat = "%Y-%m-%d %H:%M:%S%z"
        else:
            # timestamp doesn't contain UTC offset, set the new format accordingly
            newformat = "%Y-%m-%d %H:%M:%S"

        # is the seconds field a float?
        if '.' in timestamp:
            # append .f to the seconds field
            newformat = newformat.replace('S','S.%f')
        return newformat



    def add_to_log_folder(self, data):
        # If logs folder is enabled (using -l), write alerts in the folder as well
        if not self.logs_jsonfile:
            return False
        data_json = json.dumps(data)
        self.logs_jsonfile.write(data_json)
        self.logs_jsonfile.write('\n')
        self.logs_jsonfile.flush()


    def format_evidence_causing_this_alert(self, all_evidence, profileid, twid, flow_datetime) -> str:
        """
        Function to format the string with all evidence causing an alert
        flow_datetime: time of the last evidence received
        """
        # alerts in slips consists of several evidence, each evidence has a threat_level
        # once we reach a certain threshold of accumulated threat_levels, we produce an alert
        # Now instead of printing the last evidence only, we print all of them
        try:
            twid_num = twid.split('timewindow')[1]
            srcip = profileid.split(self.separator)[1]
            # Get the start time of this TW
            twid_start_time = None
            while twid_start_time==None:
                # give the database time to retreive the time
                twid_start_time = __database__.getTimeTW(profileid, twid)

            tw_start_time_str = utils.format_timestamp(float(twid_start_time))
            tw_start_time_datetime = datetime.strptime(tw_start_time_str, self.get_ts_format(tw_start_time_str).replace(' ','T'))
            # Convert the tw width to deltatime
            tw_width_in_seconds_delta = timedelta(seconds=int(self.width))
            # Get the stop time of the TW
            tw_stop_time_datetime = tw_start_time_datetime + tw_width_in_seconds_delta
            tw_stop_time_str = tw_stop_time_datetime.strftime("%Y-%m-%dT%H:%M:%S.%f%z")

            hostname = __database__.get_hostname_from_profile(profileid)
            # if there's no hostname, set it as ' '
            hostname = hostname or ''
            if hostname:
                hostname = f'({hostname})'

            alert_to_print = f'{Fore.RED}IP {srcip} {hostname} detected as infected in timewindow {twid_num} ' \
                             f'(start {tw_start_time_str}, stop {tw_stop_time_str}) given the following evidence:{Style.RESET_ALL}\n'
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on format_evidence_causing_this_alert() line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True

 
        for evidence in all_evidence.values():
            # Deserialize evidence
            evidence = json.loads(evidence)
            type_detection = evidence.get('type_detection')
            detection_info = evidence.get('detection_info')
            type_evidence = evidence.get('type_evidence')
            description = evidence.get('description')

            # format the string of this evidence only: for example Detected C&C channels detection, destination IP:xyz
            evidence_string = self.format_evidence_string(profileid, twid, srcip, type_evidence, type_detection, detection_info, description)
            alert_to_print += f'\t{Fore.CYAN}• {evidence_string}{Style.RESET_ALL}\n'

        # Add the timestamp to the alert. The datetime printed will be of the last evidence only
        if '.' in flow_datetime:
            format = '%Y-%m-%dT%H:%M:%S.%f%z'
        else:
            # e.g  2020-12-18T03:11:09+02:00
            format = '%Y-%m-%dT%H:%M:%S%z'
        human_readable_datetime = datetime.strptime(flow_datetime, format).strftime("%Y/%m/%d %H:%M:%S")
        alert_to_print = f'{Fore.RED}{human_readable_datetime}{Style.RESET_ALL} {alert_to_print}'
        return alert_to_print



    def run(self):
        # add metadata to alerts.log
        branch_info = self.get_branch_info()
        if branch_info != False:
            # it's false when we're in docker because there's no .git/ there
            commit, branch = branch_info[0], branch_info[1]
            now = datetime.now()
            self.logfile.write(f'Using {branch} - {commit} - {now}\n\n')

        while True:
            try:
            # Adapt this process to process evidence from only IPs and not profileid or twid

                # Wait for a message from the channel that a TW was modified
                message = self.c1.get_message(timeout=self.timeout)
                # if timewindows are not updated for a long time (see at logsProcess.py), we will stop slips automatically.The 'stop_process' line is sent from logsProcess.py.
                if message and message['data'] == 'stop_process':
                    self.logfile.close()
                    self.jsonfile.close()
                    __database__.publish('finished_modules','EvidenceProcess')
                    return True

                if utils.is_msg_intended_for(message, 'evidence_added'):
                    # Data sent in the channel as a json dict, it needs to be deserialized first
                    data = json.loads(message['data'])
                    profileid = data.get('profileid')
                    srcip = profileid.split(self.separator)[1]
                    twid = data.get('twid')
                    type_detection = data.get('type_detection') # example: dstip srcip dport sport dstdomain
                    detection_info = data.get('detection_info') # example: ip, port, inTuple, outTuple, domain
                    type_evidence = data.get('type_evidence') # example: PortScan, ThreatIntelligence, etc..
                    # evidence data
                    description = data.get('description')
                    timestamp = data.get('stime')
                    uid = data.get('uid')
                    # in case of blacklisted ip evidence, we add the tag to the description like this [tag]
                    tags = data.get('tags',False)
                    confidence = data.get('confidence', False)
                    threat_level = data.get('threat_level', False)
                    category = data.get('category',False)
                    conn_count = data.get('conn_count',False)
                    port = data.get('port',False)
                    proto = data.get('proto',False)
                    source_target_tag = data.get('source_target_tag', False)

                    # Ignore alert if IP is whitelisted
                    flow = __database__.get_flow(profileid, twid, uid)
                    if flow and self.is_whitelisted(srcip, detection_info, type_detection, description, flow):
                        # Modules add evidence to the db before reaching this point, so
                        # remove evidence from db so it will be completely ignored
                        __database__.deleteEvidence(profileid, twid, description)
                        continue

                    # Format the time to a common style given multiple type of time variables
                    flow_datetime = utils.format_timestamp(timestamp)

                    # prepare evidence for text log file
                    evidence = self.format_evidence_string(profileid,
                                                           twid,
                                                           srcip,
                                                           type_evidence,
                                                           type_detection,
                                                           detection_info,
                                                           description)
                    # prepare evidence for json log file
                    IDEA_dict = utils.IDEA_format(srcip,
                                    type_evidence,
                                    type_detection,
                                    detection_info,
                                    description,
                                    confidence,
                                    category,
                                    conn_count,
                                    source_target_tag,
                                    port,
                                    proto)


                    # to keep the alignment of alerts.json ip + hostname combined should take no more than 26 chars
                    alert_to_log = f'{flow_datetime}: Src IP {srcip:26}. {evidence}'
                    # sometimes slips tries to get the hostname of a profile before ip_info stores it in the db
                    # there's nothing we can do about it
                    hostname = __database__.get_hostname_from_profile(profileid)
                    if hostname:
                        srcip = f'{srcip} ({hostname})'
                        # fill the rest of the 26 characters with spaces to keep the alignment
                        srcip =  f'{srcip}{" "*(26-len(srcip))}'
                        alert_to_log = f'{flow_datetime}: Src IP {srcip}. {evidence}'
                    # Add the evidence to the log files
                    self.addDataToLogFile(alert_to_log)
                    # add to alerts.json
                    if self.is_first_alert and branch_info != False:
                        # only add commit and hash to the firs alert in alerts.json
                        self.is_first_alert = False
                        IDEA_dict.update({'commit': commit, 'branch': branch })
                    self.addDataToJSONFile(IDEA_dict)
                    self.add_to_log_folder(IDEA_dict)

                    #
                    # Analysis of evidence for blocking or not
                    # This is done every time we receive 1 new evidence
                    #

                    # Get all the evidence for the TW
                    tw_evidence = __database__.getEvidenceForTW(profileid, twid)

                    # Important! It may happen that the evidence is not related to a profileid and twid.
                    # For example when the evidence is on some src IP attacking our home net, and we are not creating
                    # profiles for attackers
                    if tw_evidence:
                        tw_evidence = json.loads(tw_evidence)

                        # self.print(f'Evidence: {tw_evidence}. Profileid {profileid}, twid {twid}')
                        # The accumulated threat level is for all the types of evidence for this profile
                        accumulated_threat_level = 0.0
                        srcip = profileid.split(self.separator)[1]
                        # to store all the ids causing this alerts in the database
                        IDs_causing_an_alert = []
                        for evidence in tw_evidence.values():
                            # Deserialize evidence
                            evidence = json.loads(evidence)

                            type_detection = evidence.get('type_detection')
                            detection_info = evidence.get('detection_info')
                            type_evidence = evidence.get('type_evidence')
                            confidence = float(evidence.get('confidence'))
                            threat_level = evidence.get('threat_level')
                            description = evidence.get('description')
                            ID = evidence.get('ID')
                            IDs_causing_an_alert.append(ID)

                            # each threat level is a string, get the numerical value of it
                            try:
                                threat_level = self.threat_levels[threat_level.lower()]
                            except KeyError:
                                self.print(f"Error: Evidence of type {type_evidence} has an invalid threat level {threat_level}", 0 , 1)
                                self.print(f"Description: {description}")
                                threat_level = 0


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
                                # store the alert in our database
                                # the alert ID is profileid_twid + the ID of the last evidence causing this alert
                                alert_ID = f'{profileid}_{twid}_{ID}'
                                # todo we can just publish in new_alert, do we need to save it in the db??
                                __database__.set_evidence_causing_alert(alert_ID, IDs_causing_an_alert)
                                __database__.publish('new_alert', alert_ID)

                                # print the alert
                                alert_to_print = self.format_evidence_causing_this_alert(tw_evidence, profileid, twid, flow_datetime)
                                self.print(f'{alert_to_print}', 1, 0)

                                # Add to log files that this srcip is being blocked
                                blocked_srcip_to_log = self.format_blocked_srcip_evidence(profileid, twid, flow_datetime)
                                blocked_srcip_dict = {'type':'alert',
                                              'profileid': profileid,
                                              'twid': twid,
                                              'threat_level':accumulated_threat_level
                                                }

                                self.addDataToLogFile(blocked_srcip_to_log)
                                # alerts.json should only contain alerts in idea format,
                                # blocked srcips should only be printed in alerts.log
                                # self.addDataToJSONFile(blocked_srcip_dict)
                                self.add_to_log_folder(blocked_srcip_dict)

                                if self.popup_alerts:
                                    # remove the colors from the aletss before printing
                                    alert_to_print = alert_to_print.replace(Fore.RED, '').replace(Fore.CYAN, '').replace(Style.RESET_ALL,'')
                                    self.show_popup(alert_to_print)

                                # Send to the blocking module.
                                # Check that the dst ip isn't our own IP
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
