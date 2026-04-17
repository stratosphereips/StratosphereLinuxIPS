# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import json
import math
import re
from dataclasses import dataclass, field
from typing import Dict, List

from slips_files.common.abstracts.imodule import IModule
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
    Attacker,
    Direction,
    Evidence,
    EvidenceType,
    IoCType,
    ProfileID,
    Proto,
    ThreatLevel,
    TimeWindow,
    Victim,
)


AUTOMATION_BANNER_TOKENS = (
    "libssh",
    "libssh2",
    "paramiko",
    "hydra",
    "medusa",
    "ncrack",
    "net::ssh",
    "net-ssh",
    "asyncssh",
    "jsch",
    "sshj",
)

KNOWN_CLIENT_BANNER_TOKENS = (
    "openssh",
    "putty",
    "dropbear",
    "winscp",
)


@dataclass
class SSHBruteforceCampaign:
    profileid: str
    twid: str
    saddr: str
    daddr: str
    dport: str
    first_timestamp: str
    last_timestamp: str
    attempts: int = 0
    uids: List[str] = field(default_factory=list)
    reported_bucket: int = -1


class BruteforceDetector(IModule):
    name = "brute_force_detector"
    description = (
        "Detect SSH brute forcing using ssh.log, software.log, and Zeek "
        "notices."
    )
    authors = ["Sebastian Garcia"]
    ssh_full_confidence_attempts = 30

    def init(self):
        self.classifier = FlowClassifier()
        self.campaigns: Dict[str, SSHBruteforceCampaign] = {}
        self.client_software: Dict[str, Dict[str, str]] = {}
        self.zeek_confirmations: Dict[str, Dict[str, str]] = {}
        self.read_configuration()

    def subscribe_to_channels(self):
        self.c1 = self.db.subscribe("new_ssh")
        self.c2 = self.db.subscribe("new_software")
        self.c3 = self.db.subscribe("new_notice")
        self.c4 = self.db.subscribe("tw_closed")
        self.channels = {
            "new_ssh": self.c1,
            "new_software": self.c2,
            "new_notice": self.c3,
            "tw_closed": self.c4,
        }

    def pre_main(self):
        utils.drop_root_privs_permanently()

    def read_configuration(self):
        conf = ConfigParser()
        self.ssh_attempt_threshold = conf.ssh_brute_force_detector_threshold()

    @staticmethod
    def _campaign_key(
        profileid: str, twid: str, daddr: str, dport: str
    ) -> str:
        return f"{profileid}_{twid}:dst:{daddr}:dport:{dport}"

    @staticmethod
    def _source_tw_key(profileid: str, twid: str) -> str:
        return f"{profileid}_{twid}"

    @staticmethod
    def _is_successful_ssh(flow) -> bool:
        return str(flow.auth_success).lower() in ("true", "t")

    @staticmethod
    def _is_failed_ssh(flow) -> bool:
        return str(flow.auth_success).lower() in ("false", "f")

    @staticmethod
    def _get_twid_number(twid: str) -> int:
        return int(str(twid).replace("timewindow", ""))

    @staticmethod
    def _format_client_banner(software_name: str, version: str) -> str:
        parts = []
        if software_name:
            parts.append(software_name)
        if version and version not in parts:
            parts.append(version)
        return " ".join(parts).strip()

    def _parse_attempt_increment(self, flow) -> int:
        try:
            auth_attempts = int(flow.auth_attempts or 0)
        except (TypeError, ValueError):
            auth_attempts = 0

        if self._is_successful_ssh(flow):
            return 0

        if auth_attempts <= 0:
            # Some SSH bruteforce tools trigger repeated SSH sessions where
            # Zeek does not record auth attempts or auth_success. Count each
            # non-successful session as one suspected password attempt.
            return 1

        if self._is_failed_ssh(flow):
            return auth_attempts

        # If Zeek observed auth attempts but did not mark the session as
        # successful, treat them as failed attempts.
        return auth_attempts

    def _get_reporting_bucket(self, attempts: int) -> int:
        if attempts < self.ssh_attempt_threshold:
            return -1
        # Emit frequently near the threshold, then increasingly sparsely.
        return int(
            math.log2(max(1, attempts - self.ssh_attempt_threshold + 1))
        )

    def _get_banner_bonus(self, banner: str, source: str) -> float:
        if not banner:
            return 0.0

        bonus = 0.0
        if source == "software.log":
            bonus += 0.03

        normalized_banner = banner.lower()
        if any(
            token in normalized_banner for token in AUTOMATION_BANNER_TOKENS
        ):
            bonus += 0.07
        elif any(
            token in normalized_banner for token in KNOWN_CLIENT_BANNER_TOKENS
        ):
            bonus += 0.02

        return min(0.1, bonus)

    def _get_banner_context(self, flow) -> Dict[str, str]:
        software_info = self.client_software.get(flow.saddr, {})
        if software_info:
            return {
                "banner": software_info["banner"],
                "source": "software.log",
            }

        banner = flow.client or ""
        return {"banner": banner, "source": "ssh.log" if banner else ""}

    def _calculate_confidence(
        self,
        attempts: int,
        banner: str,
        banner_source: str,
        confirmed_attempts: int = 0,
    ) -> float:
        effective_attempts = max(attempts, confirmed_attempts)
        full_confidence_attempts = max(
            self.ssh_attempt_threshold,
            self.ssh_full_confidence_attempts,
        )

        if effective_attempts >= full_confidence_attempts:
            return 1.0

        attempts_ratio = min(
            1.0,
            max(0, effective_attempts - self.ssh_attempt_threshold)
            / max(
                1,
                full_confidence_attempts - self.ssh_attempt_threshold,
            ),
        )
        confidence = 0.5 + (0.4 * attempts_ratio)
        confidence += self._get_banner_bonus(banner, banner_source)
        return round(min(0.99, confidence), 2)

    @staticmethod
    def _parse_confirmed_attempts(value) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    def _parse_port(self, port) -> int:
        try:
            return int(port)
        except (TypeError, ValueError):
            return None

    def _get_port_label(self, dport: str) -> str:
        if not dport:
            return ""
        portproto = f"{dport}/tcp"
        port_info = self.db.get_port_info(portproto) or ""
        return f"{port_info} {portproto}".strip()

    def _build_campaign_description(
        self,
        campaign: SSHBruteforceCampaign,
        banner: str,
        banner_source: str,
        confidence: float,
        zeek_confirmed: bool,
    ) -> str:
        port_label = self._get_port_label(campaign.dport)
        target = campaign.daddr or "an SSH server"
        destination = f"{target} on {port_label}" if port_label else target
        description = (
            f"SSH brute force detector from {campaign.saddr} to {destination}. "
            f"Attempts observed: {campaign.attempts}."
        )
        if banner:
            description += (
                f" Client banner: {banner}"
                f"{f' from {banner_source}' if banner_source else ''}."
            )
        if zeek_confirmed:
            description += " Confirmed by Zeek notice.log."
        description += f" Confidence: {confidence}. by Slips"
        return description

    def _set_campaign_evidence(
        self,
        campaign: SSHBruteforceCampaign,
        banner: str,
        banner_source: str,
    ):
        source_key = self._source_tw_key(campaign.profileid, campaign.twid)
        confirmation = self.zeek_confirmations.get(source_key, {})
        zeek_confirmed = bool(confirmation)
        confirmed_attempts = self._parse_confirmed_attempts(
            confirmation.get("attempts")
        )
        confidence = self._calculate_confidence(
            campaign.attempts,
            banner,
            banner_source,
            confirmed_attempts=confirmed_attempts,
        )
        description = self._build_campaign_description(
            campaign, banner, banner_source, confidence, zeek_confirmed
        )

        evidence = Evidence(
            evidence_type=EvidenceType.PASSWORD_GUESSING,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=campaign.saddr,
            ),
            victim=(
                Victim(
                    direction=Direction.DST,
                    ioc_type=IoCType.IP,
                    value=campaign.daddr,
                )
                if utils.is_valid_ip(campaign.daddr)
                else False
            ),
            threat_level=ThreatLevel.MEDIUM,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=campaign.saddr),
            timewindow=TimeWindow(number=self._get_twid_number(campaign.twid)),
            uid=campaign.uids,
            timestamp=campaign.last_timestamp,
            proto=Proto.TCP,
            dst_port=self._parse_port(campaign.dport),
        )
        self.db.set_evidence(evidence)

    def _set_notice_evidence(self, profileid: str, twid: str, flow):
        srcip = flow.saddr
        description = (
            f"SSH brute force detector. {flow.msg}. "
            f"Confirmed by Zeek notice.log. Confidence: 1.0. by Zeek"
        )
        evidence = Evidence(
            evidence_type=EvidenceType.PASSWORD_GUESSING,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=srcip,
            ),
            threat_level=ThreatLevel.MEDIUM,
            confidence=1.0,
            description=description,
            profile=ProfileID(ip=srcip),
            timewindow=TimeWindow(number=self._get_twid_number(twid)),
            uid=[flow.uid],
            timestamp=flow.starttime,
        )
        self.db.set_evidence(evidence)
        self.zeek_confirmations[self._source_tw_key(profileid, twid)][
            "reported"
        ] = "true"

    @staticmethod
    def _parse_notice_attempts(msg: str) -> int:
        match = re.search(r"seen in (\d+) connections", msg or "")
        if not match:
            return 0
        return int(match.group(1))

    def _cache_client_software(self, flow):
        if flow.software != "SSH::CLIENT":
            return

        banner = self._format_client_banner(
            flow.software_name, flow.unparsed_version
        )
        if not banner:
            return

        self.client_software[flow.saddr] = {
            "banner": banner,
            "software_name": flow.software_name,
            "unparsed_version": flow.unparsed_version,
        }

    def _handle_software(self, flow):
        if not utils.is_valid_ip(flow.saddr):
            return
        self._cache_client_software(flow)

    def _handle_notice(self, profileid: str, twid: str, flow):
        if "Password_Guessing" not in flow.note:
            return

        if not utils.is_valid_ip(flow.saddr):
            return

        profileid = f"profile_{flow.saddr}"

        source_key = self._source_tw_key(profileid, twid)
        confirmation = self.zeek_confirmations.setdefault(
            source_key,
            {
                "msg": flow.msg,
                "attempts": str(self._parse_notice_attempts(flow.msg)),
                "reported": "false",
            },
        )
        confirmation["msg"] = flow.msg
        confirmation["attempts"] = str(
            max(
                int(confirmation["attempts"]),
                self._parse_notice_attempts(flow.msg),
            )
        )

        if confirmation["reported"] != "true":
            self._set_notice_evidence(profileid, twid, flow)

    def _handle_ssh(self, profileid: str, twid: str, flow):
        if not utils.is_valid_ip(flow.saddr):
            return

        profileid = f"profile_{flow.saddr}"

        attempt_increment = self._parse_attempt_increment(flow)
        if attempt_increment <= 0:
            return

        if not flow.daddr:
            return

        dport = str(flow.dport or "")
        campaign_key = self._campaign_key(profileid, twid, flow.daddr, dport)
        campaign = self.campaigns.get(campaign_key)
        if not campaign:
            campaign = SSHBruteforceCampaign(
                profileid=profileid,
                twid=twid,
                saddr=flow.saddr,
                daddr=flow.daddr,
                dport=dport,
                first_timestamp=flow.starttime,
                last_timestamp=flow.starttime,
            )
            self.campaigns[campaign_key] = campaign

        campaign.attempts += attempt_increment
        campaign.last_timestamp = flow.starttime
        if flow.uid:
            campaign.uids.append(flow.uid)

        bucket = self._get_reporting_bucket(campaign.attempts)
        if bucket <= campaign.reported_bucket:
            return

        campaign.reported_bucket = bucket
        banner_context = self._get_banner_context(flow)
        self._set_campaign_evidence(
            campaign,
            banner_context["banner"],
            banner_context["source"],
        )

    def cleanup_cache_dicts(self, profile_tw: List[str]):
        profile_tw = "_".join(profile_tw)
        self.campaigns = {
            key: value
            for key, value in self.campaigns.items()
            if profile_tw not in key
        }
        self.zeek_confirmations = {
            key: value
            for key, value in self.zeek_confirmations.items()
            if profile_tw not in key
        }

    def main(self):
        if msg := self.get_msg("new_software"):
            data = json.loads(msg["data"])
            flow = self.classifier.convert_to_flow_obj(data["flow"])
            self._handle_software(flow)

        if msg := self.get_msg("new_notice"):
            data = json.loads(msg["data"])
            profileid = data["profileid"]
            twid = data["twid"]
            flow = self.classifier.convert_to_flow_obj(data["flow"])
            self._handle_notice(profileid, twid, flow)

        if msg := self.get_msg("new_ssh"):
            data = json.loads(msg["data"])
            profileid = data["profileid"]
            twid = data["twid"]
            flow = self.classifier.convert_to_flow_obj(data["flow"])
            self._handle_ssh(profileid, twid, flow)

        if msg := self.get_msg("tw_closed"):
            self.cleanup_cache_dicts(utils.get_msg_payload(msg).split("_"))
