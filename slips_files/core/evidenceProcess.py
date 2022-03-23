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
from .database import __database__
from slips_files.common.slips_utils import utils
from .notify import Notify
import json
from datetime import datetime, timedelta
import configparser
from os import path
from colorama import Fore, Style
import ipaddress
import sys
import re
import os
from .whitelist import Whitelist

# Evidence Process
class EvidenceProcess(multiprocessing.Process):
    """
    A class to process the evidence from the alerts and update the threat level
    It only work on evidence for IPs that were profiled
    This should be converted into a module
    """
    def __init__(self, inputqueue, outputqueue,
                 config, output_folder, logs_folder):
        self.name = 'EvidenceProcess'
        multiprocessing.Process.__init__(self)
        self.inputqueue = inputqueue
        self.outputqueue = outputqueue
        self.config = config
        self.whitelist = Whitelist(outputqueue, config)
        # Start the DB
        __database__.start(self.config)
        self.separator = __database__.separator
        # Read the configuration
        self.read_configuration()
        # If logs enabled, write alerts to the log folder as well
        self.clear_logs_dir(logs_folder)
        if self.popup_alerts:
            self.notify = Notify()
            # The way we send notifications differ depending on the user and the OS
            self.notify.setup_notifications()

        # Subscribe to channel 'evidence_added'
        self.c1 = __database__.subscribe('evidence_added')

        # clear alerts.log
        self.logfile = self.clean_file(output_folder , 'alerts.log')

        # clear alerts.json
        self.jsonfile = self.clean_file(output_folder , 'alerts.json')

        self.timeout = 0.0000001
        # this list will have our local and public ips
        self.our_ips = utils.get_own_IPs()
        if not self.our_ips:
            self.print('Error getting local and public IPs', 0, 1)
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
            self.logs_jsonfile = self.clean_file(logs_folder+'/' , 'alerts.json')
            self.logs_logfile = self.clean_file(logs_folder+'/' , 'alerts.log')

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
        dns_resolution_detection_info = dns_resolution_detection_info.get('domains', [])
        dns_resolution_detection_info = dns_resolution_detection_info[0:3] if dns_resolution_detection_info else ''
        dns_resolution_ip = __database__.get_dns_resolution(ip)
        dns_resolution_ip = dns_resolution_ip.get('domains', [])
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

    def clean_file(self, output_folder, file_to_clean):
        '''
        Clear the file if exists and return an open handle to it
        '''
        logfile_path = f'{output_folder}{file_to_clean}'
        if path.exists(logfile_path):
            open(logfile_path, 'w').close()
        return open(logfile_path, 'a')

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

    def shutdown_gracefully(self):
        self.logfile.close()
        self.jsonfile.close()
        __database__.publish('finished_modules','EvidenceProcess')

    def run(self):
        # add metadata to alerts.log
        branch_info = utils.get_branch_info()
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
                    self.shutdown_gracefully()
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
                    if flow and self.whitelist.is_whitelisted_evidence(srcip,
                                                                       detection_info,
                                                                       type_detection,
                                                                       description):
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
                                    self.notify.show_popup(alert_to_print)

                                # Send to the blocking module.
                                # Check that the dst ip isn't our own IP
                                if type_detection == 'dstip' \
                                        and detection_info not in self.our_ips:
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
                self.shutdown_gracefully()
                # self.outputqueue.put('01|evidence|[Evidence] Stopping the Evidence Process')
                return True
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.outputqueue.put(f'01|[Evidence] Error in the Evidence Process line {exception_line}')
                self.outputqueue.put('01|[Evidence] {}'.format(type(inst)))
                self.outputqueue.put('01|[Evidence] {}'.format(inst))
                return True
