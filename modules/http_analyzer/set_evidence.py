# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from uuid import uuid4
from slips_files.common.slips_utils import utils
from slips_files.core.flows.zeek import Weird
from slips_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    TimeWindow,
    Victim,
    Attacker,
    ThreatLevel,
    EvidenceType,
    IoCType,
    Direction,
)


class SetEvidenceHelper:
    def __init__(self, db):
        self.db = db

    def weird_http_method(
        self, twid: str, weird_flow: Weird, flow: dict
    ) -> None:
        confidence = 0.9
        threat_level: ThreatLevel = ThreatLevel.MEDIUM
        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            ioc_type=IoCType.IP,
            value=flow["saddr"],
        )

        victim: Victim = Victim(
            direction=Direction.DST,
            ioc_type=IoCType.IP,
            value=flow["daddr"],
        )

        description: str = (
            f"Weird HTTP method {weird_flow.addl} to IP: "
            f'{flow["daddr"]}. by Zeek.'
        )

        twid_number: int = int(twid.replace("timewindow", ""))

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.WEIRD_HTTP_METHOD,
            attacker=attacker,
            victim=victim,
            threat_level=threat_level,
            description=description,
            profile=ProfileID(ip=flow["saddr"]),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow["uid"]],
            timestamp=weird_flow.starttime,
            confidence=confidence,
        )

        self.db.set_evidence(evidence)

    def pastebin_downloads(self, flow, twid):
        confidence: float = 1
        threat_level: ThreatLevel = ThreatLevel.INFO
        response_body_len = int(flow.response_body_len)
        response_body_len = utils.convert_to_mb(response_body_len)
        description: str = (
            f"A downloaded file from pastebin.com. "
            f"Size: {response_body_len} MBs"
        )
        attacker = Attacker(
            direction=Direction.SRC, ioc_type=IoCType.IP, value=flow.saddr
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.PASTEBIN_DOWNLOAD,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[flow.uid],
            timestamp=flow.starttime,
        )

        self.db.set_evidence(evidence)

    def multiple_user_agents_in_a_row(self, flow, ua, twid):
        description: str = (
            f"Using multiple user-agents:" f' "{ua}" then "{flow.user_agent}"'
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.MULTIPLE_USER_AGENT,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            threat_level=ThreatLevel.INFO,
            confidence=1,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[flow.uid],
            timestamp=flow.starttime,
        )

        self.db.set_evidence(evidence)

    def multiple_empty_connections(self, flow, host, uids, twid):
        confidence: float = 1
        description: str = f"Multiple empty HTTP connections to {host}"
        twid_number = twid.replace("timewindow", "")
        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.EMPTY_CONNECTIONS,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            threat_level=ThreatLevel.MEDIUM,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=int(twid_number)),
            uid=uids,
            timestamp=flow.starttime,
        )

        self.db.set_evidence(evidence)

    def suspicious_user_agent(self, flow, profileid, twid):
        confidence: float = 1
        saddr = profileid.split("_")[1]
        description: str = (
            f"Suspicious user-agent: "
            f"{flow.user_agent} while "
            f"connecting to {flow.host}{flow.uri}"
        )
        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.SUSPICIOUS_USER_AGENT,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=saddr,
            ),
            threat_level=ThreatLevel.HIGH,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[flow.uid],
            timestamp=flow.starttime,
        )

        self.db.set_evidence(evidence)

    def non_http_port_80_conn(self, twid, flow) -> None:
        twid_number: int = int(twid.replace("timewindow", ""))
        # to add a correlation between the 2 evidence in alerts.json
        evidence_id_of_dstip_as_the_attacker = str(uuid4())
        evidence_id_of_srcip_as_the_attacker = str(uuid4())
        evidence: Evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=[evidence_id_of_dstip_as_the_attacker],
            evidence_type=EvidenceType.NON_HTTP_PORT_80_CONNECTION,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            victim=Victim(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=flow.daddr,
            ),
            threat_level=ThreatLevel.LOW,
            description=(
                f"non-HTTP established connection to port 80. "
                f"destination IP: {flow.daddr}"
            ),
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow.uid],
            timestamp=flow.starttime,
            confidence=0.8,
            src_port=flow.sport,
            dst_port=flow.dport,
        )
        self.db.set_evidence(evidence)

        evidence: Evidence = Evidence(
            id=evidence_id_of_dstip_as_the_attacker,
            rel_id=[evidence_id_of_srcip_as_the_attacker],
            evidence_type=EvidenceType.NON_HTTP_PORT_80_CONNECTION,
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
            threat_level=ThreatLevel.MEDIUM,
            description=(
                f"non-HTTP established connection to port 80. "
                f"from IP: {flow.saddr}"
            ),
            profile=ProfileID(ip=flow.daddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow.uid],
            timestamp=flow.starttime,
            confidence=0.8,
            src_port=flow.sport,
            dst_port=flow.dport,
        )

        self.db.set_evidence(evidence)

    def http_traffic(self, twid, flow):
        confidence: float = 1
        description = (
            f"Unencrypted HTTP traffic from {flow.saddr} to" f" {flow.daddr}."
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.HTTP_TRAFFIC,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            threat_level=ThreatLevel.INFO,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[flow.uid],
            timestamp=flow.starttime,
            victim=Victim(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=flow.daddr,
            ),
        )

        self.db.set_evidence(evidence)

        return True

    def incompatible_user_agent(self, twid, flow, user_agent, vendor):

        os_type: str = user_agent.get("os_type", "").lower()
        os_name: str = user_agent.get("os_name", "").lower()
        browser: str = user_agent.get("browser", "").lower()
        user_agent: str = user_agent.get("user_agent", "")
        description: str = (
            f"using incompatible user-agent ({user_agent}) "
            f"that belongs to OS: {os_name} "
            f"type: {os_type} browser: {browser}. "
            f"while connecting to {flow.host}{flow.uri}. "
            f"IP has MAC vendor: {vendor.capitalize()}"
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.INCOMPATIBLE_USER_AGENT,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            threat_level=ThreatLevel.HIGH,
            confidence=1,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[flow.uid],
            timestamp=flow.starttime,
        )

        self.db.set_evidence(evidence)

    def executable_mime_type(self, twid, flow):
        description: str = (
            f"Download of an executable with MIME type: {flow.resp_mime_types} "
            f"by {flow.saddr} from {flow.daddr}."
        )
        twid_number = int(twid.replace("timewindow", ""))
        # to add a correlation between the 2 evidence in alerts.json
        evidence_id_of_dstip_as_the_attacker = str(uuid4())
        evidence_id_of_srcip_as_the_attacker = str(uuid4())
        evidence: Evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=[evidence_id_of_dstip_as_the_attacker],
            evidence_type=EvidenceType.EXECUTABLE_MIME_TYPE,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            threat_level=ThreatLevel.LOW,
            confidence=1,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow.uid],
            timestamp=flow.starttime,
        )

        self.db.set_evidence(evidence)

        evidence: Evidence = Evidence(
            id=evidence_id_of_dstip_as_the_attacker,
            rel_id=[evidence_id_of_srcip_as_the_attacker],
            evidence_type=EvidenceType.EXECUTABLE_MIME_TYPE,
            attacker=Attacker(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=flow.daddr,
            ),
            threat_level=ThreatLevel.LOW,
            confidence=1,
            description=description,
            profile=ProfileID(ip=flow.daddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow.uid],
            timestamp=flow.starttime,
        )

        self.db.set_evidence(evidence)
