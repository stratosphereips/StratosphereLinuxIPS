# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json

from slips_files.common.abstracts.iflowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
    Evidence,
    EvidenceType,
    IoCType,
    ProfileID,
    Direction,
    ThreatLevel,
    TimeWindow,
    Victim,
    Attacker,
)


class Login(IFlowalertsAnalyzer):
    """Detects Zeek login.log entries and records them as evidence."""

    name = "login_analyzer"

    def init(self) -> None:
        self.classifier = FlowClassifier()

    def get_login_status(self, flow) -> str:
        if flow.success:
            return "successful"
        if flow.confused:
            return "confused"
        return "failed"

    def set_evidence_login(self, flow, twid: str) -> bool:
        """Set informational evidence for a login.log entry.

        Parameters:
        flow: Login flow converted from a Zeek login.log line.
        twid: Time window id for the flow.

        Return:
        True if evidence was sent to the database, False otherwise.
        """
        if not utils.is_valid_ip(flow.daddr):
            return False

        twid_number = int(twid.replace("timewindow", ""))
        status = self.get_login_status(flow)

        # can be (telnet, rlogin, or rsh)
        proto = flow.proto or "login"
        # username given for login attempt
        user = f" for user {flow.user}" if flow.user else ""
        description = (
            f"{status} {proto} login. {user} destination IP: {flow.daddr}."
        )

        evidence = Evidence(
            evidence_type=EvidenceType.LOGIN,
            attacker=Attacker(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=flow.daddr,
            ),
            victim=Victim(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            threat_level=ThreatLevel.INFO,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow.uid],
            timestamp=flow.starttime,
            confidence=1.0,
            src_port=flow.sport,
            dst_port=flow.dport,
        )
        self.db.set_evidence(evidence)
        return True

    def analyze(self, msg: dict) -> bool:
        """Analyze a new_login message.

        Parameters:
        msg: Redis message from the new_login channel.

        Return:
        True if evidence was set, False otherwise.
        """
        if not utils.is_msg_intended_for(msg, "new_login"):
            return False

        data = json.loads(msg["data"])
        flow = self.classifier.convert_to_flow_obj(data["flow"])
        return self.set_evidence_login(flow, data["twid"])
