# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# Stratosphere Linux IPS. A machine-learning Intrusion Detection System
# Copyright (C) 2021 Sebastian Garcia

import json
import os
import queue
import sys
from multiprocessing import Queue
from typing import Dict, List, Optional

from slips_files.common.abstracts.imodule import IModule
from slips_files.common.idmefv2 import IDMEFv2
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.common.style import green
from slips_files.core.helpers.notify import Notify
from slips_files.core.helpers.whitelist.whitelist import Whitelist
from slips_files.core.structures.alerts import Alert
from slips_files.core.structures.evidence import (
    Evidence,
    ThreatLevel,
    TimeWindow,
    dict_to_evidence,
)
from slips_files.core.text_formatters.evidence_formatter import (
    EvidenceFormatter,
)

IS_IN_A_DOCKER_CONTAINER = os.environ.get("IS_IN_A_DOCKER_CONTAINER", False)


class EvidenceHandlerWorker(IModule):
    name = "EvidenceHandlerWorker"

    def init(
        self,
        name: str,
        evidence_queue: Queue,
        evidence_logger_q: Queue,
    ):
        self.name = name
        self.evidence_queue = evidence_queue
        self.evidence_logger_q = evidence_logger_q
        self.whitelist = Whitelist(self.logger, self.db, self.bloom_filters)
        self.idmefv2 = IDMEFv2(self.logger, self.db)
        self.read_configuration()
        self.detection_threshold_in_this_width = (
            self.detection_threshold * self.width / 60
        )
        if self.popup_alerts:
            self.notify = Notify()
            if self.notify.bin_found:
                self.notify.setup_notifications()
            else:
                self.popup_alerts = False

        self.is_running_non_stop = self.db.is_running_non_stop()
        self.blocking_modules_supported = self.is_blocking_modules_supported()
        self.our_ips: List[str] = utils.get_own_ips(ret="List")
        self.formatter = EvidenceFormatter(self.db, self.args)
        self.slips_start_time = self.db.get_slips_start_time()
        self.first_flow_pcap_time = None

    def subscribe_to_channels(self):
        self.channels = {}

    def read_configuration(self):
        conf = ConfigParser()
        self.width: float = conf.get_tw_width_in_seconds()
        self.detection_threshold = conf.evidence_detection_threshold()
        self.print(
            f"Detection Threshold: {self.detection_threshold} "
            f"attacks per minute "
            f"({self.detection_threshold * int(self.width) / 60} "
            f"in the current time window width)",
            2,
            0,
        )
        self.popup_alerts = conf.popup_alerts()
        self.use_p2p: bool = conf.use_local_p2p() or conf.use_global_p2p()
        self.exporting_modules_enabled: bool = (
            conf.export_to() or conf.send_to_warden()
        )
        if IS_IN_A_DOCKER_CONTAINER:
            self.popup_alerts = False

    def handle_unable_to_log(self, failed_log, error=None):
        self.print(f"Error logging evidence/alert: {error}. {failed_log}.")

    def add_alert_to_json_log_file(self, alert: Alert):
        idmef_alert: dict = self.idmefv2.convert_to_idmef_alert(alert)
        if not idmef_alert:
            self.handle_unable_to_log(alert, "Can't convert to IDMEF alert")
            return

        self.evidence_logger_q.put(
            {
                "to_log": idmef_alert,
                "where": "alerts.json",
            }
        )

    def add_evidence_to_json_log_file(
        self,
        evidence: Evidence,
        accumulated_threat_level: float = 0,
    ):
        idmef_evidence: dict = self.idmefv2.convert_to_idmef_event(evidence)
        if not idmef_evidence:
            self.handle_unable_to_log(
                evidence, "Can't convert to IDMEF evidence"
            )
            return

        try:
            idmef_evidence.update(
                {
                    "Note": json.dumps(
                        {
                            "uids": evidence.uid,
                            "accumulated_threat_level": accumulated_threat_level,
                            "threat_level": str(evidence.threat_level),
                            "timewindow": evidence.timewindow.number,
                        }
                    )
                }
            )
            self.add_latency_to_csv(idmef_evidence)
            self.evidence_logger_q.put(
                {
                    "to_log": idmef_evidence,
                    "where": "alerts.json",
                }
            )
        except KeyboardInterrupt:
            return True
        except Exception as error:
            self.handle_unable_to_log(evidence, error)

    def add_latency_to_csv(self, idmef_evidence: dict):
        start_time = idmef_evidence.get("StartTime")
        create_time = idmef_evidence.get("CreateTime")
        evidence_id = idmef_evidence.get("ID")
        if not (start_time and create_time and evidence_id):
            return

        if self.first_flow_pcap_time is None:
            self.first_flow_pcap_time = float(self.db.get_first_flow_time())

        try:
            start_unix = utils.convert_ts_format(start_time, "unixtimestamp")
            create_unix = utils.convert_ts_format(create_time, "unixtimestamp")

            if self.is_running_non_stop:
                latency = float(create_unix) - float(start_unix)
            else:
                wall_elapsed = float(create_unix) - float(
                    self.slips_start_time
                )
                pcap_elapsed = float(start_unix) - float(
                    self.first_flow_pcap_time
                )
                latency = wall_elapsed - pcap_elapsed
                if latency < 0:
                    latency = 0

            latency = round(latency)
        except Exception as error:
            print(f"@@@@@@@@@@@@@@@@ {error}")
            return

        self.evidence_logger_q.put(
            {
                "to_log": {
                    "ts": create_unix,
                    "evidence_id": evidence_id,
                    "latency": latency,
                },
                "where": "latency.csv",
            }
        )

    def add_to_log_file(self, data: str):
        self.evidence_logger_q.put({"to_log": data, "where": "alerts.log"})

    def log_alert(self, alert: Alert, blocked=False):
        now = utils.get_human_readable_datetime()

        alert_description = (
            f"{alert.last_flow_datetime}: " f"Src IP {alert.profile.ip:26}. "
        )
        if blocked:
            alert_description += "Is blocked "
        else:
            alert_description += "Generated an alert "

        alert_description += (
            f"given enough evidence on timewindow "
            f"{alert.timewindow.number}. (real time {now})"
        )
        self.add_to_log_file(alert_description)
        self.add_alert_to_json_log_file(alert)

    def get_evidence_that_were_part_of_a_past_alert(
        self, profileid: str, twid: str
    ) -> List[str]:
        past_alerts: dict = self.db.get_profileid_twid_alerts(profileid, twid)

        past_evidence_ids = []
        if past_alerts:
            for evidence_id_list in list(past_alerts.values()):
                evidence_id_list: List[str] = json.loads(evidence_id_list)
                past_evidence_ids += evidence_id_list

        return past_evidence_ids

    def is_evidence_done_by_others(self, evidence: Evidence) -> bool:
        return evidence.attacker.direction != "SRC"

    def get_evidence_for_tw(
        self, profileid: str, twid: str
    ) -> Optional[Dict[str, Evidence]]:
        tw_evidence: Dict[str, dict] = self.db.get_twid_evidence(
            profileid, twid
        )
        if not tw_evidence:
            return None

        past_evidence_ids = self.get_evidence_that_were_part_of_a_past_alert(
            profileid, twid
        )
        filtered_evidence = {}

        for evidence_id, raw_evidence in tw_evidence.items():
            evidence = dict_to_evidence(json.loads(raw_evidence))

            if self.is_filtered_evidence(evidence, past_evidence_ids):
                continue

            if self.db.is_whitelisted_evidence(evidence_id):
                continue

            profileid = str(evidence.profile)
            if not self.db.is_evidence_processed(evidence_id, profileid, twid):
                continue

            filtered_evidence[evidence.id] = evidence

        return filtered_evidence

    def is_filtered_evidence(
        self, evidence: Evidence, past_evidence_ids: List[str]
    ):
        if evidence.id in past_evidence_ids:
            return True

        if self.is_evidence_done_by_others(evidence):
            return True

        return False

    def get_threat_level(self, evidence: Evidence) -> float:
        evidence_threat_level = (
            evidence.threat_level.value * evidence.confidence
        )
        self.print(f"\t\tWeighted Threat Level: {evidence_threat_level}", 3, 0)
        return evidence_threat_level

    def send_to_exporting_module(self, tw_evidence: Dict[str, Evidence]):
        if not self.exporting_modules_enabled:
            return

        for evidence in tw_evidence.values():
            evidence_dict: dict = utils.to_dict(evidence)
            self.print(
                f"[EvidenceHandler] Exporting evidence {evidence_dict.get('id')} "
                f"type={evidence_dict.get('evidence_type')} via export_evidence.",
                2,
                0,
            )
            self.db.publish("export_evidence", json.dumps(evidence_dict))

    def give_evidence_to_exporting_modules(self, evidence: Evidence):
        if not self.exporting_modules_enabled:
            return

        evidence_dict: dict = utils.to_dict(evidence)
        self.print(
            f"[EvidenceHandler] Export streaming {evidence_dict.get('id')} "
            f"type={evidence_dict.get('evidence_type')} via export_evidence.",
            2,
            0,
        )
        self.db.publish("export_evidence", json.dumps(evidence_dict))

    def is_blocking_modules_supported(self) -> bool:
        custom_flows = "-im" in sys.argv or "--input-module" in sys.argv
        blocking_module_enabled = "-p" in sys.argv
        return (
            self.is_running_non_stop or custom_flows
        ) and blocking_module_enabled

    def handle_new_alert(
        self,
        alert: Alert,
        evidence_causing_the_alert,
    ):
        self.db.set_alert(alert, evidence_causing_the_alert)
        is_blocked: bool = self.decide_blocking(
            alert.profile.ip, alert.timewindow
        )
        profile_already_blocked: bool = self.db.is_blocked_profile_and_tw(
            str(alert.profile), str(alert.timewindow)
        )
        if profile_already_blocked:
            return

        self.send_to_exporting_module(evidence_causing_the_alert)
        alert_to_print: str = self.formatter.format_evidence_for_printing(
            alert, evidence_causing_the_alert
        )
        self.print(f"{alert_to_print}", 1, 0)

        if self.popup_alerts:
            self.show_popup(alert)

        if is_blocked:
            self.db.mark_profile_and_timewindow_as_blocked(
                str(alert.profile), str(alert.timewindow)
            )

        self.log_alert(alert, blocked=is_blocked)

    def decide_blocking(
        self,
        ip_to_block: str,
        timewindow: TimeWindow,
    ) -> bool:
        if not self.blocking_modules_supported:
            return False

        if ip_to_block in self.our_ips:
            return False

        blocking_data = {
            "ip": ip_to_block,
            "block": True,
            "tw": timewindow.number,
            "interface": utils.get_interface_of_ip(
                ip_to_block, self.db, self.args
            ),
        }
        self.db.publish("new_blocking", json.dumps(blocking_data))
        return True

    def update_accumulated_threat_level(self, evidence: Evidence) -> float:
        evidence_threat_level = self.get_threat_level(evidence)
        return self.db.update_accumulated_threat_level(
            str(evidence.profile),
            str(evidence.timewindow),
            evidence_threat_level,
        )

    def show_popup(self, alert: Alert):
        alert_description = self.formatter.get_printable_alert(alert)
        self.notify.show_popup(alert_description)

    def get_accumulated_threat_level(
        self, profileid, twid, evidence: Evidence
    ) -> float:
        if evidence.threat_level == ThreatLevel.INFO:
            return self.db.get_accumulated_threat_level(profileid, twid)

        past_evidence_ids = self.get_evidence_that_were_part_of_a_past_alert(
            profileid, twid
        )
        if not self.is_filtered_evidence(evidence, past_evidence_ids):
            return self.update_accumulated_threat_level(evidence)

        return self.db.get_accumulated_threat_level(profileid, twid)

    def get_msg_from_queue(self, q: Queue):
        try:
            return q.get(timeout=1)
        except queue.Empty:
            return None
        except Exception:
            return None

    def is_stop_msg(self, msg) -> bool:
        return msg == "stop"

    def pre_main(self):
        worker_number = self.name.split("_")[-1]
        self.print(
            f"Started Evidence Handler Worker {green(worker_number)} "
            f"[PID {green(os.getpid())}]"
        )

    def should_stop(self) -> bool:
        return False

    def handle_evidence_added_message(self, msg: dict):
        evidence = json.loads(msg["data"])
        try:
            evidence = dict_to_evidence(evidence)
        except Exception as error:
            self.print(f"Problem converting {evidence} to dict: {error}", 0, 1)
            return

        profileid = str(evidence.profile)
        twid = str(evidence.timewindow)
        timestamp = evidence.timestamp

        self.db.mark_evidence_as_processed(evidence.id, profileid, twid)

        if self.whitelist.is_whitelisted_evidence(evidence):
            self.db.cache_whitelisted_evidence_id(evidence.id)
            self.db.delete_evidence(profileid, twid, evidence.id)
            self.print(f"{self.whitelist.get_bloom_filters_stats()}", 2, 0)
            return

        if self.is_running_non_stop:
            timestamp = utils.convert_to_local_timezone(timestamp)
        flow_datetime = utils.convert_ts_format(timestamp, "iso")

        evidence = self.formatter.add_threat_level_to_evidence_description(
            evidence
        )
        evidence_to_log = self.formatter.get_evidence_to_log(
            evidence,
            flow_datetime,
        )
        self.add_to_log_file(evidence_to_log)

        accumulated_threat_level = self.get_accumulated_threat_level(
            profileid, twid, evidence
        )
        self.add_evidence_to_json_log_file(
            evidence,
            accumulated_threat_level,
        )
        self.give_evidence_to_exporting_modules(evidence)

        if self.use_p2p:
            self.db.publish(
                "report_to_peers", json.dumps(utils.to_dict(evidence))
            )

        if accumulated_threat_level < self.detection_threshold_in_this_width:
            return

        tw_evidence = self.get_evidence_for_tw(profileid, twid)
        if not tw_evidence:
            return

        tw_start, tw_end = self.db.get_tw_limits(profileid, twid)
        evidence.timewindow.start_time = tw_start
        evidence.timewindow.end_time = tw_end

        alert = Alert(
            profile=evidence.profile,
            timewindow=evidence.timewindow,
            last_evidence=evidence,
            accumulated_threat_level=accumulated_threat_level,
            correl_id=list(tw_evidence.keys()),
        )
        self.handle_new_alert(alert, tw_evidence)

    def handle_new_blame_message(self, msg: dict):
        data = msg["data"]
        try:
            data = json.loads(data)
        except json.decoder.JSONDecodeError:
            self.print("Error in the report received from p2ptrust module")
            return

        key = data["key"]
        evaluation = data["evaluation"]
        self.db.store_blame_report(key, evaluation)

        blocking_data = {
            "ip": key,
            "block": True,
            "to": True,
            "from": True,
            "interface": utils.get_interface_of_ip(key, self.db, self.args),
        }
        self.db.publish("new_blocking", json.dumps(blocking_data))

    def main(self):
        """runs in a loop defined in IModule"""
        task = self.get_msg_from_queue(self.evidence_queue)
        if not task:
            return

        if self.is_stop_msg(task):
            self.print("Received stop signal. Stopping.")
            return 1

        channel = task["channel"]
        msg = task["message"]

        if channel == "evidence_added":
            self.handle_evidence_added_message(msg)
        elif channel == "new_blame":
            self.handle_new_blame_message(msg)
