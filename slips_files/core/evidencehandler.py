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
from slips_files.common.imports import *
from slips_files.core.helpers.whitelist import Whitelist
from slips_files.core.helpers.notify import Notify
from slips_files.common.abstracts.core import ICore
import json
from typing import Union, List, Tuple, Dict
from datetime import datetime
from os import path
from colorama import Fore, Style
import sys
import os
import time
import platform
import traceback
from slips_files.core.evidence_structure.evidence import dict_to_evidence, \
    Evidence
IS_IN_A_DOCKER_CONTAINER = os.environ.get('IS_IN_A_DOCKER_CONTAINER', False)

# Evidence Process
class EvidenceHandler(ICore):
    """
    A class to process the evidence from the alerts and update the threat level
    It only work on evidence for IPs that were profiled
    This should be converted into a module
    """
    name = 'Evidence'

    def init(self):
        self.whitelist = Whitelist(self.logger, self.db)
        self.separator = self.db.get_separator()
        self.read_configuration()
        self.detection_threshold_in_this_width = self.detection_threshold * self.width / 60
        self.running_non_stop = self.is_running_on_interface()
        # to keep track of the number of generated evidence
        self.db.init_evidence_number()
        if self.popup_alerts:
            self.notify = Notify()
            if self.notify.bin_found:
                # The way we send notifications differ depending on the user and the OS
                self.notify.setup_notifications()
            else:
                self.popup_alerts = False

        self.c1 = self.db.subscribe('evidence_added')
        self.c2 = self.db.subscribe('new_blame')
        self.channels = {
            'evidence_added': self.c1,
            'new_blame': self.c2,
        }

        # clear output/alerts.log
        self.logfile = self.clean_file(self.output_dir, 'alerts.log')
        utils.change_logfiles_ownership(self.logfile.name, self.UID, self.GID)

        self.is_interface = self.is_running_on_interface()

        # clear output/alerts.json
        self.jsonfile = self.clean_file(self.output_dir, 'alerts.json')
        utils.change_logfiles_ownership(self.jsonfile.name, self.UID, self.GID)

        self.print(f'Storing Slips logs in {self.output_dir}')
        # this list will have our local and public ips when using -i
        self.our_ips = utils.get_own_IPs()
        self.discarded_bc_never_processed = {}

    def read_configuration(self):
        conf = ConfigParser()
        self.width = conf.get_tw_width_as_float()
        self.detection_threshold = conf.evidence_detection_threshold()
        self.print(
            f'Detection Threshold: {self.detection_threshold} '
            f'attacks per minute ({self.detection_threshold * int(self.width) / 60} '
            f'in the current time window width)',2,0,
        )
        self.GID = conf.get_GID()
        self.UID = conf.get_UID()

        self.popup_alerts = conf.popup_alerts()
        # In docker, disable alerts no matter what slips.conf says
        if IS_IN_A_DOCKER_CONTAINER:
            self.popup_alerts = False

    def format_evidence_string(
            self, ip, detection_module, attacker, description) -> str:
        """
        Function to add the dns resolution of the src and dst ips of
         each evidence
        :return : string with a correct evidence displacement
        """
        evidence_string = ''
        dns_resolution_attacker = self.db.get_dns_resolution(attacker)
        dns_resolution_attacker = dns_resolution_attacker.get(
            'domains', []
        )
        dns_resolution_attacker = dns_resolution_attacker[
                                        :3] if dns_resolution_attacker else ''

        dns_resolution_ip = self.db.get_dns_resolution(ip)
        dns_resolution_ip = dns_resolution_ip.get('domains', [])
        if len(dns_resolution_ip) >= 1:
            dns_resolution_ip = dns_resolution_ip[0]
        elif len(dns_resolution_ip) == 0:
            dns_resolution_ip = ''

        # dns_resolution_ip_final = f' DNS: {dns_resolution_ip[:3]}. ' if dns_resolution_attacker and len(
        #     dns_resolution_ip[:3]
        #     ) > 0 else '. '


        return f'{evidence_string}'
    
    
    def line_wrap(self, txt):
        """
        is called for evidence that are goinng to be printed in the terminal
        line wraps the given text so it looks nice
        """
        # max chars per line
        wrap_at = 155

        wrapped_txt = ''
        for indx in range(0, len(txt), wrap_at):
            wrapped_txt += txt[indx:indx+wrap_at]
            wrapped_txt += f'\n{" "*10}'

        # remove the \n at the end
        wrapped_txt = wrapped_txt[:-11]
        if wrapped_txt.endswith('\n'):
            wrapped_txt = wrapped_txt[:-1]

        return wrapped_txt
        
    
    def clean_file(self, output_dir, file_to_clean):
        """
        Clear the file if exists and return an open handle to it
        """
        logfile_path = os.path.join(output_dir, file_to_clean)
        if path.exists(logfile_path):
            open(logfile_path, 'w').close()
        return open(logfile_path, 'a')

    def add_to_json_log_file(
             self,
             IDEA_dict: dict,
             all_uids: list,
             timewindow: str,
             accumulated_threat_level: float =0
        ):
        """
        Add a new evidence line to our alerts.json file in json format.
        :param IDEA_dict: dict containing 1 alert
        :param all_uids: the uids of the flows causing this evidence
        """
        try:
            # we add extra fields to alerts.json that are not in the IDEA format
            IDEA_dict.update({
                'uids': all_uids,
                'accumulated_threat_level': accumulated_threat_level,
                'timewindow': int(timewindow.replace('timewindow', '')),
            })
            json.dump(IDEA_dict, self.jsonfile)
            self.jsonfile.write('\n')
        except KeyboardInterrupt:
            return True
        except Exception:
            self.print('Error in addDataToJSONFile()')
            self.print(traceback.print_exc(), 0, 1)

    def add_to_log_file(self, data):
        """
        Add a new evidence line to the alerts.log and other log files if logging is enabled.
        """
        try:
            # write to alerts.log
            self.logfile.write(data)
            self.logfile.write('\n')
            self.logfile.flush()
        except KeyboardInterrupt:
            return True
        except Exception:
            self.print('Error in addDataToLogFile()')
            self.print(traceback.print_exc(),0,1)

    def get_domains_of_flow(self, flow: dict):
        """Returns the domains of each ip (src and dst) that appeared in this flow"""
        # These separate lists, hold the domains that we should only check if they are SRC or DST. Not both
        try:
            flow = json.loads(list(flow.values())[0])
        except TypeError:
            # sometimes this function is called before the flow is add to our database
            return [], []
        domains_to_check_src = []
        domains_to_check_dst = []
        try:
            domains_to_check_src.append(
                self.db.get_ip_info(flow['saddr'])
                .get('SNI', [{}])[0]
                .get('server_name')
            )
        except (KeyError, TypeError):
            pass
        try:
            # self.print(f"DNS of src IP {self.column_values['saddr']}:
            # {self.db.get_dns_resolution(self.column_values['saddr'])}")
            src_dns_domains = self.db.get_dns_resolution(flow['saddr'])
            src_dns_domains = src_dns_domains.get('domains', [])

            domains_to_check_src.extend(iter(src_dns_domains))
        except (KeyError, TypeError):
            pass
        try:
            domains_to_check_dst.append(
                self.db.get_ip_info(flow['daddr'])
                .get('SNI', [{}])[0]
                .get('server_name')
            )
        except (KeyError, TypeError):
            pass

        return domains_to_check_dst, domains_to_check_src

    def show_popup(self, alert_to_log: str):
        """
        Function to display a popup with the alert depending on the OS
        """
        if platform.system() == 'Linux':
            #  is notify_cmd is set in setup_notifications function depending on the user
            os.system(f'{self.notify_cmd} "Slips" "{alert_to_log}"')
        elif platform.system() == 'Darwin':
            os.system(
                f'osascript -e \'display notification "{alert_to_log}" '
                f'with title "Slips"\' '
            )


    def format_evidence_causing_this_alert(
            self,
            all_evidence: Dict[str, dict],
            profileid: str,
            twid: str,
            flow_datetime: str
    ) -> str:
        """
        Function to format the string with all evidence causing an alert
        flow_datetime: time of the last evidence received
        """
        # alerts in slips consists of several evidence,
        # each evidence has a threat_level
        # once we reach a certain threshold of accumulated
        # threat_levels, we produce an alert
        # Now instead of printing the last evidence only,
        # we print all of them
        try:
            twid_num = twid.split('timewindow')[1]
            srcip = profileid.split(self.separator)[1]
            # Get the start time of this TW
            twid_start_time = None
            while twid_start_time is None:
                # give the database time to retreive the time
                twid_start_time = self.db.getTimeTW(profileid, twid)

            tw_start_time_str = utils.convert_format(twid_start_time,
                                                     '%Y/%m/%d %H:%M:%S')
            # datetime obj
            tw_start_time_datetime = utils.convert_to_datetime(tw_start_time_str)

            # Convert the tw width to deltatime
            # tw_width_in_seconds_delta = timedelta(seconds=int(self.width))
            delta_width = utils.to_delta(self.width)

            # Get the stop time of the TW
            tw_stop_time_datetime = (tw_start_time_datetime + delta_width)

            tw_stop_time_str = utils.convert_format(
                tw_stop_time_datetime,
                 '%Y/%m/%d %H:%M:%S'
            )

            hostname = self.db.get_hostname_from_profile(profileid)
            # if there's no hostname, set it as ' '
            hostname = hostname or ''
            if hostname:
                hostname = f'({hostname})'

            alert_to_print = (
                f'{Fore.RED}IP {srcip} {hostname} detected as malicious in timewindow {twid_num} '
                f'(start {tw_start_time_str}, stop {tw_stop_time_str}) \n'
                f'given the following evidence:{Style.RESET_ALL}\n'
            )
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f'Problem on format_evidence_causing_this_alert() '
                f'line {exception_line}',0,1,
            )
            self.print(traceback.print_exc(),0,1)
            return True

        for evidence in all_evidence.values():
            evidence: dict
            description: str = evidence.get('description')

            evidence_string = f'Detected {description}'
            evidence_string = self.line_wrap(evidence_string)

            alert_to_print += (
                f'\t{Fore.CYAN}- {evidence_string}{Style.RESET_ALL}\n'
            )

        # Add the timestamp to the alert. The datetime printed will be of the last evidence only
        readable_datetime = utils.convert_format(flow_datetime, utils.alerts_format)
        alert_to_print = f'{Fore.RED}{readable_datetime}{Style.RESET_ALL} {alert_to_print}'
        return alert_to_print

    def is_running_on_interface(self):
        return '-i' in sys.argv or self.db.is_growing_zeek_dir()


    def decide_blocking(self, profileid) -> bool:
        """
        Decide whether to block or not and send to the blocking module
        :param ip: IP to block
        """

        # now since this source ip(profileid) caused an alert,
        # it means it caused so many evidence(attacked others a lot)
        # that we decided to alert and block it
        #todo if by default we don't block everything from/to this ip anymore, remember to update the CYST module

        ip_to_block = profileid.split('_')[-1]

        # Make sure we don't block our own IP
        if ip_to_block in self.our_ips:
            return False

        #  TODO: edit the options in blocking_data, by default it'll block
        #  TODO: all traffic to or from this ip
        blocking_data = {
            'ip': ip_to_block,
            'block': True,
        }
        blocking_data = json.dumps(blocking_data)
        self.db.publish('new_blocking', blocking_data)
        return True

    def mark_as_blocked(
            self, profileid,
            twid,
            flow_datetime,
            accumulated_threat_level,
            IDEA_dict,
            blocked=False
    ):
        """
        Marks the profileid and twid as blocked and logs it to alerts.log
        we don't block when running slips on files, we log it in alerts.log only
        :param blocked: bool. if the ip was blocked by the blocking module, we should say so
                    in alerts.log, if not, we should say that we generated an alert
        :param IDEA_dict: the last evidence of this alert, used for logging the blocking
        """
        now = datetime.now()
        now = utils.convert_format(now, utils.alerts_format)
        ip = profileid.split('_')[-1].strip()
        msg = f'{flow_datetime}: Src IP {ip:26}. '
        if blocked:
            self.db.markProfileTWAsBlocked(profileid, twid)
            # Add to log files that this srcip is being blocked
            msg += 'Blocked '
        else:
            msg += 'Generated an alert '

        msg += f'given enough evidence on timewindow {twid.split("timewindow")[1]}. (real time {now})'

        # log in alerts.log
        self.add_to_log_file(msg)

        # Add a json field stating that this ip is blocked in alerts.json
        # replace the evidence description with slips msg that this is a
        # blocked profile
        IDEA_dict['Format'] = 'Json'
        IDEA_dict['Category'] = 'Alert'
        IDEA_dict['profileid'] = profileid
        IDEA_dict['threat_level'] = accumulated_threat_level
        IDEA_dict['Attach'][0]['Content'] = msg

        # add to alerts.json
        self.add_to_json_log_file(
            IDEA_dict,
            [],
            twid,
            profileid
        )


    def shutdown_gracefully(self):
        self.logfile.close()
        self.jsonfile.close()

    def get_evidence_that_were_part_of_a_past_alert(
            self, profileid: str, twid: str) -> List[str]:

        past_alerts: dict = self.db.get_profileid_twid_alerts(profileid, twid)
        try:
            past_evidence_ids = list(past_alerts.values())[0]
            past_evidence_ids: List[str] = json.loads(past_evidence_ids)
        except IndexError:
            # no past evidence
            past_evidence_ids = []
        return past_evidence_ids

    def is_evidence_done_by_others(self, evidence: dict) -> bool:
        # given all the tw evidence, we should only
        # consider evidence that makes this given
        # profile malicious, aka evidence of this profile attacking others.
        attacker_direction: str = evidence.get('attacker_direction', '')
        # the following type detections are the ones
        # expected to be seen when we are attacking others
        # marking this profileid (srcip) as malicious
        if attacker_direction in ('srcip', 'sport', 'srcport'):
            return False
        return True

    def get_evidence_for_tw(self, profileid: str, twid: str) \
            -> Dict[str, dict]:
        """
        filters and returns all the evidence for this profile in this TW
        returns the dict with filtered evidence
        """
        tw_evidence: str = self.db.get_twid_evidence(profileid, twid)
        if not tw_evidence:
            return False

        # format of this is {ev_id, json_serialized(ev_details)}
        tw_evidence: dict = json.loads(tw_evidence)

        past_evidence_ids: List[str] = \
            self.get_evidence_that_were_part_of_a_past_alert(profileid, twid)

        # to store all the ids causing this alert in the database
        self.IDs_causing_an_alert = []
        filtered_evidence = {}

        for id, evidence in tw_evidence.items():
            id: str
            evidence: str

            evidence: dict = json.loads(evidence)

            if self.is_filtered_evidence(
                evidence,
                past_evidence_ids
                ):
                continue

            whitelisted: bool = self.db.is_whitelisted_evidence(id)
            if whitelisted:
                continue

            # delete not processed evidence
            # sometimes the db has evidence that didn't come yet to evidence.py
            # and they are alerted without checking the whitelist!
            # to fix this, we keep track of processed evidence
            # that came to new_evidence channel and were processed by it.
            # so they are ready to be a part of an alert
            processed: bool = self.db.is_evidence_processed(id)
            if not processed:
                continue

            id: str = evidence.get('ID')
            # we keep track of these IDs to be able to label the flows of these
            # evidence later if this was detected as an alert
            # now this should be done in its' own function but this is more
            # optimal so we don't loop through all evidence again. i'll
            # just leave it like that:D
            self.IDs_causing_an_alert.append(id)

            filtered_evidence[id] = evidence

        return filtered_evidence


    def is_filtered_evidence(self,
                             evidence: dict,
                             past_evidence_ids: List[str]):
        """
        filters the following
        * evidence that were part of a past alert in this same profileid
        twid (past_evidence_ids)
        * evidence that weren't done by the given profileid
        """

        # delete already alerted evidence
        # if there was an alert in this tw before, remove the evidence that
        # were part of the past alert from the current evidence.

        # when blocking is not enabled, we can alert on a
        # single profile many times
        # when we get all the tw evidence from the db, we get the once we
        # alerted, and the new once we need to alert
        # this method removes the already alerted evidence to avoid duplicates
        if id in past_evidence_ids:
            return True

        if self.is_evidence_done_by_others(evidence):
            return True

        return False


    def get_threat_level(
            self,
            evidence: dict,
            ) -> float:
        """
        return the threat level of the given evidence * confidence
        """
        evidence_type: str = evidence.get('evidence_type')
        confidence: float = float(evidence.get('confidence'))
        threat_level: float = evidence.get('threat_level')
        description: str = evidence.get('description')

        # each threat level is a string, get the numerical value of it
        try:
            threat_level: float = \
                utils.threat_levels[threat_level.lower()]
        except KeyError:
            self.print(
                f'Error: Evidence of type {evidence_type} has '
                f'an invalid threat level {threat_level}', 0, 1
            )
            self.print(f'Description: {description}', 0, 1)
            threat_level = 0

        # Compute the moving average of evidence
        evidence_threat_level: float = threat_level * confidence
        self.print(f'\t\tWeighted Threat Level: {evidence_threat_level}', 3, 0)
        return evidence_threat_level

    def get_last_evidence_ID(self, tw_evidence: dict) -> str:
        return list(tw_evidence.keys())[-1]

    def send_to_exporting_module(self, tw_evidence: Dict[str, str]):
        for evidence in tw_evidence.values():
            self.db.publish('export_evidence', json.dumps(evidence))

    def is_blocking_module_enabled(self) -> bool:
        """
        returns true if slips is running in an interface or growing zeek dir with -p
        or if slips is using custom flows. meaning slips is reading the flows by a custom module not by
        inputprocess. there's no need for -p to enable the blocking
        """

        custom_flows = '-im' in sys.argv or '--input-module' in sys.argv
        return (self.is_running_on_interface() and '-p' not in sys.argv) or custom_flows

    def handle_new_alert(self, alert_ID: str, tw_evidence: dict):
        """
        saves alert details in the db and informs exporting modules about it
        """
        profile, srcip, twid, _ = alert_ID.split('_')
        profileid = f'{profile}_{srcip}'
        self.db.set_evidence_causing_alert(
            profileid,
            twid,
            alert_ID,
            self.IDs_causing_an_alert
        )
        # when an alert is generated , we should set the threat level of the
        # attacker's profile to 1(critical) and confidence 1
        # so that it gets reported to other peers with these numbers
        self.db.update_threat_level(profileid, 'critical', 1)

        alert_details = {
            'alert_ID': alert_ID,
            'profileid': profileid,
            'twid': twid,
        }
        self.db.publish('new_alert', json.dumps(alert_details))

        #store the alerts in the alerts table in sqlite db
        alert_details.update(
            {'time_detected': utils.convert_format(datetime.now(),
                                                   'unixtimestamp'),
             'label': 'malicious'})
        self.db.add_alert(alert_details)
        self.db.label_flows_causing_alert(self.IDs_causing_an_alert)
        self.send_to_exporting_module(tw_evidence)
        # reset the accumulated threat level now that an alert is generated
        self.db.set_accumulated_threat_level(profileid, twid, 0)

    def get_evidence_to_log(
                self,
                srcip: str,
                description: str,
                twid: str,
                flow_datetime: str,
                profileid: str,
        ) -> str:
            timewindow_number: int = twid.replace("timewindow", '')

            # to keep the alignment of alerts.json ip + hostname
            # combined should take no more than 26 chars
            evidence = f'{flow_datetime} (TW {timewindow_number}): Src IP' \
                       f' {srcip:26}. Detected {description}'

            # sometimes slips tries to get the hostname of a
            # profile before ip_info stores it in the db
            # there's nothing we can do about it
            hostname: str = self.db.get_hostname_from_profile(profileid)
            if not hostname:
                return evidence

            padding_len = 26 - len(srcip) - len(hostname) - 3
            # fill the rest of the 26 characters with spaces to keep the alignment
            evidence = f'{flow_datetime} (TW {timewindow_number}): Src IP' \
                       f' {srcip} ({hostname}) {" "*padding_len}. ' \
                       f'Detected {description}'

            return evidence

    def increment_attack_counter(
            self,
            attacker: str,
            victim: str,
            evidence_type: str
            ):
        """
        increments the number of attacks of this type from the given
        attacker-> the given victim
        used for displaying alert summary
        """
        # this method is here instead of the db bc here we check
        # if the evidence is whitelisted, alerted before, etc. before we
        # consider it as  valid evidence. this filtering is not done in the db
        self.db.increment_attack_counter(
            attacker,
            victim,
            evidence_type
            )


    def update_accumulated_threat_level(self, evidence: dict) -> float:
        """
        update the accumulated threat level of the profileid and twid of
        the given evidence and return the updated value
        """
        profileid: str = evidence['profileid']
        twid: str = evidence['twid']
        evidence_threat_level: float = self.get_threat_level(evidence)

        self.db.update_accumulated_threat_level(
            profileid, twid, evidence_threat_level
        )
        accumulated_threat_level: float = \
            self.db.get_accumulated_threat_level(
                profileid, twid
            )
        return accumulated_threat_level

    def show_popup(self, alert: str):
        # remove the colors from the alerts before printing
        alert = (
            alert.replace(Fore.RED, '')
            .replace(Fore.CYAN, '')
            .replace(Style.RESET_ALL, '')
        )
        self.notify.show_popup(alert)

    def main(self):
        while not self.should_stop():
            if msg := self.get_msg('evidence_added'):
                msg['data'] : str
                evidence: dict = json.loads(msg['data'])
                evidence: Evidence = dict_to_evidence(evidence)
                profileid = evidence.get('profileid')
                srcip = profileid.split(self.separator)[1]
                twid = evidence.get('twid')
                attacker_direction = evidence.get(
                    'attacker_direction'
                )   # example: dstip srcip dport sport dstdomain
                attacker = evidence.get(
                    'attacker'
                )   # example: ip, port, inTuple, outTuple, domain
                evidence_type: str = evidence.get(
                    'evidence_type'
                )   # example: PortScan, ThreatIntelligence, etc..
                description = evidence.get('description')
                timestamp = evidence.get('stime')
                # this is all the uids of the flows that cause this evidence
                all_uids = evidence.get('uid')
                confidence = evidence.get('confidence', False)
                category = evidence.get('category', False)
                conn_count = evidence.get('conn_count', False)
                port = evidence.get('port', False)
                proto = evidence.get('proto', False)
                source_target_tag = evidence.get('source_target_tag', False)
                evidence_ID = evidence.get('ID', False)
                victim: str = evidence.get('victim', '')

                # FP whitelisted alerts happen when the db returns an evidence
                # that isn't processed in this channel, in the tw_evidence
                # below.
                # to avoid this, we only alert about processed evidence
                self.db.mark_evidence_as_processed(evidence_ID)

                # Ignore alert if IP is whitelisted
                if self.whitelist.is_whitelisted_evidence(
                    srcip, attacker, attacker_direction, description, victim
                ):
                    self.db.cache_whitelisted_evidence_ID(evidence_ID)
                    # Modules add evidence to the db before
                    # reaching this point, now remove evidence from db so
                    # it could be completely ignored
                    self.db.deleteEvidence(
                        profileid, twid, evidence_ID
                    )
                    continue


                # convert time to local timezone
                if self.running_non_stop:
                    timestamp: datetime = utils.convert_to_local_timezone(timestamp)
                flow_datetime = utils.convert_format(timestamp, 'iso')

                evidence_to_log: str = self.get_evidence_to_log(
                    srcip,
                    description,
                    twid,
                    flow_datetime,
                    profileid
                )
                # Add the evidence to alerts.log
                self.add_to_log_file(evidence_to_log)
                self.increment_attack_counter(
                    profileid,
                    victim,
                    evidence_type
                    )

                past_evidence_ids: List[str] = \
                    self.get_evidence_that_were_part_of_a_past_alert(
                        profileid,
                        twid
                        )
                if not self.is_filtered_evidence(evidence, past_evidence_ids):
                    accumulated_threat_level: float = \
                        self.update_accumulated_threat_level(evidence)
                else:
                    accumulated_threat_level: float = \
                        self.db.get_accumulated_threat_level(
                            profileid,
                            twid
                        )
                # prepare evidence for json log file
                IDEA_dict: dict = utils.IDEA_format(
                    srcip,
                    evidence_type,
                    attacker_direction,
                    attacker,
                    description,
                    confidence,
                    category,
                    conn_count,
                    source_target_tag,
                    port,
                    proto,
                    evidence_ID
                )
                # add to alerts.json
                self.add_to_json_log_file(
                      IDEA_dict,
                      all_uids,
                      twid,
                      accumulated_threat_level,
                    )

                self.db.set_evidence_for_profileid(IDEA_dict)
                self.db.publish('report_to_peers', json.dumps(evidence))


                # if the profile was already blocked in
                # this twid, we shouldn't alert
                profile_already_blocked = \
                    self.db.checkBlockedProfTW(profileid, twid)

                # This is the part to detect if the accumulated
                # evidence was enough for generating a detection
                # The detection should be done in attacks per minute.
                # The parameter in the configuration
                # is attacks per minute
                # So find out how many attacks corresponds
                # to the width we are using
                if (
                    accumulated_threat_level >= self.detection_threshold_in_this_width
                    and not profile_already_blocked
                ):
                    tw_evidence: Dict[str, dict] = \
                        self.get_evidence_for_tw(
                            profileid, twid
                        )
                    if tw_evidence:
                        id: str = self.get_last_evidence_ID(tw_evidence)
                        # store the alert in our database
                        # the alert ID is profileid_twid + the ID of
                        # the last evidence causing this alert
                        alert_id: str = f'{profileid}_{twid}_{id}'

                        self.handle_new_alert(alert_id, tw_evidence)

                        # print the alert
                        alert_to_print: str = \
                            self.format_evidence_causing_this_alert(
                                tw_evidence,
                                profileid,
                                twid,
                                flow_datetime,
                            )

                        self.print(f'{alert_to_print}', 1, 0)

                        if self.popup_alerts:
                            self.show_popup(alert_to_print)


                        blocked = False
                        # send ip to the blocking module
                        if (
                                self.is_blocking_module_enabled()
                                and self.decide_blocking(profileid)
                        ):
                            blocked = True

                        self.mark_as_blocked(
                            profileid,
                            twid,
                            flow_datetime,
                            accumulated_threat_level,
                            IDEA_dict,
                            blocked=blocked
                        )

            if msg := self.get_msg('new_blame'):
                self.msg_received = True
                data = msg['data']
                try:
                    data = json.loads(data)
                except json.decoder.JSONDecodeError:
                    self.print(
                        'Error in the report received from p2ptrust module'
                    )
                    return
                # The available values for the following variables are defined in go_director

                # available key types: "ip"
                key_type = data['key_type']

                # if the key type is ip, the ip is validated
                key = data['key']

                # available evaluation types: 'score_confidence'
                evaluation_type = data['evaluation_type']

                # this is the score_confidence received from the peer
                evaluation = data['evaluation']
                # {"key_type": "ip", "key": "1.2.3.40",
                # "evaluation_type": "score_confidence",
                # "evaluation": { "score": 0.9, "confidence": 0.6 }}
                ip_info = {
                    'p2p4slips': evaluation
                }
                ip_info['p2p4slips'].update({'ts': time.time()})
                self.db.store_blame_report(key, evaluation)

                blocking_data = {
                    'ip': key,
                    'block': True,
                    'to': True,
                    'from': True,
                    'block_for': self.width * 2,  # block for 2 timewindows
                }
                blocking_data = json.dumps(blocking_data)
                self.db.publish('new_blocking', blocking_data)

