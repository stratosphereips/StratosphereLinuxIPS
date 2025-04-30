# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301, USA.
# Contact: eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz,
# stratosphere@aic.fel.cvut.cz

import json
from typing import (
    List,
    Dict,
    Optional,
)
from datetime import datetime
from os import path
import sys
import os
import time
import traceback

from slips_files.common.idmefv2 import IDMEFv2
from slips_files.common.style import (
    green,
)
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.helpers.whitelist.whitelist import Whitelist
from slips_files.core.helpers.notify import Notify
from slips_files.common.abstracts.core import ICore
from slips_files.core.structures.evidence import (
    dict_to_evidence,
    Evidence,
    Victim,
    EvidenceType,
)
from slips_files.core.structures.alerts import (
    Alert,
)
from slips_files.core.text_formatters.evidence import EvidenceFormatter

IS_IN_A_DOCKER_CONTAINER = os.environ.get("IS_IN_A_DOCKER_CONTAINER", False)


# Evidence Process
class EvidenceHandler(ICore):
    name = "EvidenceHandler"

    def init(self):
        self.whitelist = Whitelist(self.logger, self.db)
        self.idmefv2 = IDMEFv2(self.logger, self.db)
        self.separator = self.db.get_separator()
        self.read_configuration()
        self.detection_threshold_in_this_width = (
            self.detection_threshold * self.width / 60
        )
        # to keep track of the number of generated evidence
        self.db.init_evidence_number()
        if self.popup_alerts:
            self.notify = Notify()
            if self.notify.bin_found:
                # The way we send notifications differ depending
                # on the user and the OS
                self.notify.setup_notifications()
            else:
                self.popup_alerts = False

        self.c1 = self.db.subscribe("evidence_added")
        self.c2 = self.db.subscribe("new_blame")
        self.channels = {
            "evidence_added": self.c1,
            "new_blame": self.c2,
        }

        # clear output/alerts.log
        self.logfile = self.clean_file(self.output_dir, "alerts.log")
        utils.change_logfiles_ownership(self.logfile.name, self.UID, self.GID)

        self.is_running_non_stop = self.db.is_running_non_stop()

        # clear output/alerts.json
        self.jsonfile = self.clean_file(self.output_dir, "alerts.json")
        utils.change_logfiles_ownership(self.jsonfile.name, self.UID, self.GID)
        # this list will have our local and public ips when using -i
        self.our_ips = utils.get_own_ips()
        self.formatter = EvidenceFormatter(self.db)
        # thats just a tmp value, this variable will be set and used when
        # the
        # module is stopping.
        self.last_msg_received_time = time.time()

    def read_configuration(self):
        conf = ConfigParser()
        self.width: float = conf.get_tw_width_as_float()
        self.detection_threshold = conf.evidence_detection_threshold()
        self.print(
            f"Detection Threshold: {self.detection_threshold} "
            f"attacks per minute "
            f"({self.detection_threshold * int(self.width) / 60} "
            f"in the current time window width)",
            2,
            0,
        )
        self.GID = conf.get_GID()
        self.UID = conf.get_UID()

        self.popup_alerts = conf.popup_alerts()
        # In docker, disable alerts no matter what slips.yaml says
        if IS_IN_A_DOCKER_CONTAINER:
            self.popup_alerts = False

    def clean_file(self, output_dir, file_to_clean):
        """
        Clear the file if exists and return an open handle to it
        """
        logfile_path = os.path.join(output_dir, file_to_clean)
        if path.exists(logfile_path):
            open(logfile_path, "w").close()
        return open(logfile_path, "a")

    def handle_unable_to_log(self):
        self.print("Error logging evidence/alert.")

    def add_alert_to_json_log_file(self, alert: Alert):
        """
        Add a new alert/event line to our alerts.json file in json format.
        """
        idmef_alert: dict = self.idmefv2.convert_to_idmef_alert(alert)
        if not idmef_alert:
            self.handle_unable_to_log()
            return

        try:
            json.dump(idmef_alert, self.jsonfile)
            self.jsonfile.write("\n")
        except KeyboardInterrupt:
            return True
        except Exception:
            self.handle_unable_to_log()

    def add_evidence_to_json_log_file(
        self,
        evidence,
        accumulated_threat_level: float = 0,
    ):
        """
        Add a new evidence line to our alerts.json file in json format.
        """
        idmef_evidence: dict = self.idmefv2.convert_to_idmef_event(evidence)
        if not idmef_evidence:
            self.handle_unable_to_log()
            return

        try:
            idmef_evidence.update(
                {
                    "Note": json.dumps(
                        {
                            # this is all the uids of the flows that cause
                            # this evidence
                            "uids": evidence.uid,
                            "accumulated_threat_level": accumulated_threat_level,
                            "threat_level": str(evidence.threat_level),
                            "timewindow": evidence.timewindow.number,
                        }
                    )
                }
            )
            json.dump(idmef_evidence, self.jsonfile)
            self.jsonfile.write("\n")
        except KeyboardInterrupt:
            return True
        except Exception:
            self.handle_unable_to_log()

    def add_to_log_file(self, data):
        """
        Add a new evidence line to the alerts.log and other log files if
        logging is enabled.
        """
        try:
            # write to alerts.log
            self.logfile.write(data)
            if not data.endswith("\n"):
                self.logfile.write("\n")
            self.logfile.flush()
        except KeyboardInterrupt:
            return True
        except Exception:
            self.print("Error in add_to_log_file()")
            self.print(traceback.format_exc(), 0, 1)

    def log_alert(self, alert: Alert, blocked=False):
        """
        constructs the alert descript ion from the given alert and logs it
        to alerts.log and alerts.json
        :param blocked: bool. if the ip was blocked by the blocking module,
                we should say so in alerts.log, if not, we should say that
                we generated an alert
        """
        now = utils.get_human_readable_datetime()

        alert_description = (
            f"{alert.last_flow_datetime}: " f"Src IP {alert.profile.ip:26}. "
        )
        if blocked:
            # Add to log files that this srcip is being blocked
            alert_description += "Is blocked "
        else:
            alert_description += "Generated an alert "

        alert_description += (
            f"given enough evidence on timewindow "
            f"{alert.timewindow.number}. (real time {now})"
        )
        # log to alerts.log
        self.add_to_log_file(alert_description)
        # log to alerts.json
        self.add_alert_to_json_log_file(alert)

    def shutdown_gracefully(self):
        self.logfile.close()
        self.jsonfile.close()

    def get_evidence_that_were_part_of_a_past_alert(
        self, profileid: str, twid: str
    ) -> List[str]:
        """
        returns a list of evidence <ids that were part of an alert in the
        given timewindow
        """
        past_alerts: dict = self.db.get_profileid_twid_alerts(profileid, twid)
        try:
            past_evidence_ids = list(past_alerts.values())[0]
            past_evidence_ids: List[str] = json.loads(past_evidence_ids)
        except IndexError:
            # no past evidence
            past_evidence_ids = []
        return past_evidence_ids

    def is_evidence_done_by_others(self, evidence: Evidence) -> bool:
        # given all the tw evidence, we should only
        # consider evidence that makes this given
        # profile malicious, aka evidence of this profile(srcip) attacking
        # others.
        return evidence.attacker.direction != "SRC"

    def get_evidence_for_tw(
        self, profileid: str, twid: str
    ) -> Optional[Dict[str, Evidence]]:
        """
        filters and returns all the evidence for this profile in this TW
        returns the dict with filtered evidence
        """
        tw_evidence: Dict[str, dict] = self.db.get_twid_evidence(
            profileid, twid
        )
        if not tw_evidence:
            return

        past_evidence_ids: List[str] = (
            self.get_evidence_that_were_part_of_a_past_alert(profileid, twid)
        )

        filtered_evidence = {}

        for id, evidence in tw_evidence.items():
            id: str
            evidence: str
            evidence: dict = json.loads(evidence)
            evidence: Evidence = dict_to_evidence(evidence)

            if self.is_filtered_evidence(evidence, past_evidence_ids):
                continue

            if self.db.is_whitelisted_evidence(id):
                continue

            # delete not processed evidence
            # sometimes the db has evidence that didn't come yet to evidence.py
            # and they are alerted without checking the whitelist!
            # to fix this, we keep track of processed evidence
            # that came to new_evidence channel and were processed by it.
            # so they are ready to be a part of an alert
            if not self.db.is_evidence_processed(id):
                continue

            filtered_evidence[evidence.id] = evidence

        return filtered_evidence

    def is_filtered_evidence(
        self, evidence: Evidence, past_evidence_ids: List[str]
    ):
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
        if evidence.id in past_evidence_ids:
            return True

        if self.is_evidence_done_by_others(evidence):
            return True

        return False

    def get_threat_level(
        self,
        evidence: Evidence,
    ) -> float:
        """
        return the threat level of the given evidence * confidence
        """
        confidence: float = evidence.confidence
        threat_level: float = evidence.threat_level.value

        # Compute the moving average of evidence
        evidence_threat_level: float = threat_level * confidence
        self.print(
            f"\t\tWeighted Threat Level: " f"{evidence_threat_level}", 3, 0
        )
        return evidence_threat_level

    def send_to_exporting_module(self, tw_evidence: Dict[str, Evidence]):
        """
        sends all given evidence to export_evidence channel
        :param tw_evidence: all evidence that happened in a certain
        timewindow
        format is {evidence_id (str) :  Evidence obj}
        """
        for evidence in tw_evidence.values():
            evidence: Evidence
            evidence: dict = utils.to_dict(evidence)
            self.db.publish("export_evidence", json.dumps(evidence))

    def is_blocking_module_supported(self) -> bool:
        """
        returns true if slips is running in an interface or growing
         zeek dir with -p
        or if slips is using custom flows (meaning slips is reading the
        flows by a custom module not by input.py).
        """
        custom_flows = "-im" in sys.argv or "--input-module" in sys.argv
        blocking_module_enabled = "-p" in sys.argv
        return (
            self.is_running_non_stop or custom_flows
        ) and blocking_module_enabled

    def handle_new_alert(
        self, alert: Alert, evidence_causing_the_alert: Dict[str, Evidence]
    ):
        """
        saves alert details in the db and informs exporting modules about it
        """
        self.db.set_alert(alert, evidence_causing_the_alert)
        self.send_to_exporting_module(evidence_causing_the_alert)
        alert_to_print: str = self.formatter.format_evidence_for_printing(
            alert, evidence_causing_the_alert
        )

        self.print(f"{alert_to_print}", 1, 0)

        if self.popup_alerts:
            self.show_popup(alert)

        is_blocked: bool = self.decide_blocking(alert.profile.ip)
        if is_blocked:
            self.db.mark_profile_and_timewindow_as_blocked(
                str(alert.profile), str(alert.timewindow)
            )
        self.log_alert(alert, blocked=is_blocked)

    def decide_blocking(self, ip_to_block: str) -> bool:
        """
        Decide whether to block or not and send to the blocking module
         returns True if the given IP was blocked by Slips blocking module
        """
        # send ip to the blocking module
        if not self.is_blocking_module_supported():
            return False
        # now since this source ip(profileid) caused an alert,
        # it means it caused so many evidence(attacked others a lot)
        # that we decided to alert and block it

        # First, Make sure we don't block our own IP
        if ip_to_block in self.our_ips:
            return False

        #  TODO: edit the options here. by default it'll block
        #   all traffic to or from this ip
        # PS: if by default we don't block everything from/to this ip anymore,
        # remember to update the CYST module
        blocking_data = {
            "ip": ip_to_block,
            "block": True,
        }
        blocking_data = json.dumps(blocking_data)
        self.db.publish("new_blocking", blocking_data)
        return True

    def increment_attack_counter(
        self,
        attacker: str,
        victim: Optional[Victim],
        evidence_type: EvidenceType,
    ):
        """
        increments the number of attacks of this type from the given
        attacker-> the given victim
        used for displaying alert summary
        """
        # this method is here instead of the db bc here we check
        # if the evidence is whitelisted, alerted before, etc. before we
        # consider it as  valid evidence. this filtering is not done in the db
        self.db.increment_attack_counter(attacker, victim, evidence_type.name)

    def update_accumulated_threat_level(self, evidence: Evidence) -> float:
        """
        update the accumulated threat level of the profileid and twid of
        the given evidence and return the updated value
        """
        evidence_threat_level: float = self.get_threat_level(evidence)
        return self.db.update_accumulated_threat_level(
            str(evidence.profile),
            str(evidence.timewindow),
            evidence_threat_level,
        )

    def show_popup(self, alert: Alert):
        alert_description: str = self.formatter.get_printable_alert(alert)
        self.notify.show_popup(alert_description)

    def should_stop(self) -> bool:
        """
        Overrides imodule's should_stop() to make sure thi smodule only
        stops after 1 minute of the last received evidence.
        """
        if not self.termination_event.is_set():
            return False

        if self.is_msg_received_in_any_channel():
            self.last_msg_received_time = time.time()
            return False

        # no new msgs are received in any of the channels here
        # wait an extra 1 minute for new evidence to arrive
        # without this, slips has problems processing the last evidence
        # set by some of the modules.
        if time.time() - self.last_msg_received_time < 60:
            # one minute didnt pass yet
            return False

        # 1 min passed since the last evidence with no new msgs. stop.
        return True

    def pre_main(self):
        self.print(f"Using threshold: {green(self.detection_threshold)}")

    def main(self):
        while not self.should_stop():
            if msg := self.get_msg("evidence_added"):
                msg["data"]: str
                evidence: dict = json.loads(msg["data"])
                evidence: Evidence = dict_to_evidence(evidence)
                profileid: str = str(evidence.profile)
                twid: str = str(evidence.timewindow)
                evidence_type: EvidenceType = evidence.evidence_type
                timestamp: str = evidence.timestamp

                # FP whitelisted alerts happen when the db returns an evidence
                # that isn't processed in this channel, in the tw_evidence
                # below.
                # to avoid this, we only alert about processed evidence
                self.db.mark_evidence_as_processed(evidence.id)
                # Ignore evidence if IP is whitelisted
                if self.whitelist.is_whitelisted_evidence(evidence):
                    self.db.cache_whitelisted_evidence_id(evidence.id)
                    # Modules add evidence to the db before
                    # reaching this point, now remove evidence from db so
                    # it could be completely ignored
                    self.db.delete_evidence(profileid, twid, evidence.id)
                    continue

                # convert time to local timezone
                if self.is_running_non_stop:
                    timestamp: datetime = utils.convert_to_local_timezone(
                        timestamp
                    )
                flow_datetime = utils.convert_format(timestamp, "iso")

                evidence: Evidence = (
                    self.formatter.add_threat_level_to_evidence_description(
                        evidence
                    )
                )

                evidence_to_log: str = self.formatter.get_evidence_to_log(
                    evidence,
                    flow_datetime,
                )
                # Add the evidence to alerts.log
                self.add_to_log_file(evidence_to_log)

                self.increment_attack_counter(
                    evidence.profile.ip, evidence.victim, evidence_type
                )

                past_evidence_ids: List[str] = (
                    self.get_evidence_that_were_part_of_a_past_alert(
                        profileid, twid
                    )
                )
                # filtered evidence dont add to the acc threat level
                if not self.is_filtered_evidence(evidence, past_evidence_ids):
                    accumulated_threat_level: float = (
                        self.update_accumulated_threat_level(evidence)
                    )
                else:
                    accumulated_threat_level: float = (
                        self.db.get_accumulated_threat_level(profileid, twid)
                    )

                # add to alerts.json
                self.add_evidence_to_json_log_file(
                    evidence,
                    accumulated_threat_level,
                )

                evidence_dict: dict = utils.to_dict(evidence)
                self.db.publish("report_to_peers", json.dumps(evidence_dict))

                # if the profile was already blocked in
                # this twid, we shouldn't alert
                profile_already_blocked = self.db.is_blocked_profile_and_tw(
                    profileid, twid
                )
                # This is the part to detect if the accumulated
                # evidence was enough for generating a detection
                # The detection should be done in attacks per minute.
                # The parameter in the configuration
                # is attacks per minute
                # So find out how many attacks corresponds
                # to the width we are using
                if (
                    accumulated_threat_level
                    >= self.detection_threshold_in_this_width
                    and not profile_already_blocked
                ):
                    tw_evidence: Dict[str, Evidence]
                    tw_evidence = self.get_evidence_for_tw(profileid, twid)
                    if tw_evidence:
                        tw_start, tw_end = self.db.get_tw_limits(
                            profileid, twid
                        )
                        evidence.timewindow.start_time = tw_start
                        evidence.timewindow.end_time = tw_end

                        alert: Alert = Alert(
                            profile=evidence.profile,
                            timewindow=evidence.timewindow,
                            last_evidence=evidence,
                            accumulated_threat_level=accumulated_threat_level,
                            correl_id=list(tw_evidence.keys()),
                        )
                        self.handle_new_alert(alert, tw_evidence)

            if msg := self.get_msg("new_blame"):
                data = msg["data"]
                try:
                    data = json.loads(data)
                except json.decoder.JSONDecodeError:
                    self.print(
                        "Error in the report received from p2ptrust module"
                    )
                    return
                # The available values for the following variables are
                # defined in go_director

                # available key types: "ip"
                # key_type = data['key_type']

                # if the key type is ip, the ip is validated
                key = data["key"]

                # available evaluation types: 'score_confidence'
                # evaluation_type = data['evaluation_type']

                # this is the score_confidence received from the peer
                evaluation = data["evaluation"]
                # {"key_type": "ip", "key": "1.2.3.40",
                # "evaluation_type": "score_confidence",
                # "evaluation": { "score": 0.9, "confidence": 0.6 }}
                ip_info = {"p2p4slips": evaluation}
                ip_info["p2p4slips"].update({"ts": time.time()})
                self.db.store_blame_report(key, evaluation)

                blocking_data = {
                    "ip": key,
                    "block": True,
                    "to": True,
                    "from": True,
                    "block_for": self.width * 2,  # block for 2 timewindows
                }
                blocking_data = json.dumps(blocking_data)
                self.db.publish("new_blocking", blocking_data)
