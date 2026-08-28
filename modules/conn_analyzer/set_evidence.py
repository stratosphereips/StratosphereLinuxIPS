# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from typing import Any, List
from uuid import uuid4
from datetime import datetime
from slips_files.common.slips_utils import utils
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

ESTAB = "Established"


class SetEvidenceHelper:
    def __init__(self, db):
        self.db = db

    def different_localnet_usage(self, twid, flow, ip_outside_localnet=""):
        """
        :param ip_outside_localnet: was the
        'srcip' outside the localnet or the 'dstip'?
        """
        # the attacker here is the IP found to be
        # private and outside the localnet
        if ip_outside_localnet == "srcip":
            attacker = Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            )
            victim = Victim(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=flow.daddr,
            )
            threat_level = ThreatLevel.LOW
            description = (
                f"A connection from a private IP ({flow.saddr}) on port "
                f"{flow.dport}/{flow.proto} "
                f"outside of the used local network "
                f"{self.db.get_local_network(flow.interface)}. To IP:"
                f" {flow.daddr} "
            )
        else:
            attacker = Attacker(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=flow.daddr,
            )
            victim = Victim(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            )
            threat_level = ThreatLevel.HIGH
            description = (
                f"A connection to a private IP ({flow.daddr}) on port"
                f" {flow.dport}/{flow.proto} "
                f"outside of the used local network "
                f"{self.db.get_local_network(flow.interface)}. "
                f"From IP: {flow.saddr} "
            )
            proto = flow.proto.lower()
            description += (
                "using ARP"
                if "arp" in proto
                else f"on destination port: {flow.dport}/{flow.proto.upper()}"
            )

        confidence = 1.0

        twid_number = int(twid.replace("timewindow", ""))
        evidence = Evidence(
            evidence_type=EvidenceType.DIFFERENT_LOCALNET,
            attacker=attacker,
            threat_level=threat_level,
            description=description,
            victim=victim,
            profile=ProfileID(ip=attacker.value),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow.uid],
            timestamp=flow.starttime,
            confidence=confidence,
            src_port=flow.sport,
            dst_port=flow.dport,
        )
        self.db.set_evidence(evidence)

    def device_changing_ips(self, twid, flow, old_ip: str):
        confidence = 0.8
        threat_level = ThreatLevel.MEDIUM
        description = (
            f"A device changing IPs. IP {flow.saddr} was found "
            f"with MAC address {flow.smac} but the MAC belongs "
            f"originally to IP: {old_ip}. "
        )
        twid_number = int(twid.replace("timewindow", ""))

        evidence = Evidence(
            evidence_type=EvidenceType.DEVICE_CHANGING_IP,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            threat_level=threat_level,
            description=description,
            victim=None,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow.uid],
            timestamp=flow.starttime,
            confidence=confidence,
        )

        self.db.set_evidence(evidence)

    def non_ssl_port_443_conn(self, twid, flow) -> None:
        confidence: float = 0.8
        description: str = (
            f"non-SSL established connection to port 443. "
            f"destination IP: {flow.daddr}"
        )

        twid_number: int = int(twid.replace("timewindow", ""))

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.NON_SSL_PORT_443_CONNECTION,
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
            threat_level=ThreatLevel.MEDIUM,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow.uid],
            timestamp=flow.starttime,
            confidence=confidence,
            src_port=flow.sport,
            dst_port=flow.dport,
        )

        self.db.set_evidence(evidence)

    def conn_without_dns(self, twid, flow) -> None:
        confidence: float = 0.8
        threat_level: ThreatLevel = ThreatLevel.INFO

        attacker: Attacker = Attacker(
            direction=Direction.SRC, ioc_type=IoCType.IP, value=flow.saddr
        )

        # The first 5 hours the confidence of connection w/o DNS
        # is 0.1 in case of interface only, until slips learns all the DNS
        start_time: str = self.db.get_slips_start_time()
        now = datetime.now()
        if self.db.is_running_non_stop():
            diff: float = utils.get_time_diff(
                start_time, now, return_type="hours"
            )
            if diff < 5:
                confidence = 0.1

        description: str = (
            f"A connection without DNS resolution to Destination IP: "
            f"{flow.daddr}"
        )

        twid_number: int = int(twid.replace("timewindow", ""))
        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.CONNECTION_WITHOUT_DNS,
            attacker=attacker,
            threat_level=threat_level,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow.uid],
            timestamp=flow.starttime,
            confidence=confidence,
            src_port=flow.sport,
            dst_port=flow.dport,
        )

        self.db.set_evidence(evidence)

    def tor_exit_node(self, twid: str, flow: Any) -> None:
        """
        Set evidence for a connection to a Tor exit node.

        Parameters:
        twid: Time window ID.
        flow: Connection flow whose destination is a Tor exit node.

        Return:
        None.
        """
        twid_number: int = int(twid.replace("timewindow", ""))
        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.TOR_EXIT_NODE,
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
            description=f"A connection to TOR exit node {flow.daddr}.",
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow.uid],
            timestamp=flow.starttime,
            confidence=1.0,
            src_port=flow.sport,
            dst_port=flow.dport,
        )

        self.db.set_evidence(evidence)

    def unknown_port(self, twid, flow) -> None:
        confidence: float = 1.0
        twid_number: int = int(twid.replace("timewindow", ""))
        description: str = (
            f"Connection to unknown destination port {flow.dport}/"
            f"{flow.proto.upper()} destination IP {flow.daddr}."
        )
        if flow.interpreted_state == ESTAB:
            threat_level = ThreatLevel.HIGH
        else:
            threat_level = ThreatLevel.MEDIUM

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.UNKNOWN_PORT,
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
            threat_level=threat_level,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow.uid],
            timestamp=flow.starttime,
            confidence=confidence,
            src_port=flow.sport,
            dst_port=flow.dport,
        )

        self.db.set_evidence(evidence)

    def conn_to_private_ip(self, twid, flow) -> None:
        confidence: float = 1.0
        twid_number: int = int(twid.replace("timewindow", ""))
        description: str = f"Connecting to private IP: {flow.daddr} "

        if flow.proto.lower() == "arp" or flow.dport == "":
            pass
        elif flow.proto.lower() == "icmp":
            description += "protocol: ICMP"
        else:
            description += f"on destination port: {flow.dport}"

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.CONNECTION_TO_PRIVATE_IP,
            attacker=Attacker(
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
            confidence=confidence,
            victim=Victim(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=flow.daddr,
            ),
            src_port=flow.sport,
            dst_port=flow.dport,
        )

        self.db.set_evidence(evidence)

    def long_connection(self, twid, flow) -> None:
        """
        Set an evidence for a long connection.
        """
        twid: int = int(twid.replace("timewindow", ""))
        # Confidence depends on how long the connection.
        # Scale the confidence from 0 to 1; 1 means 24 hours long.
        confidence: float = 1 / (3600 * 24) * (flow.dur - 3600 * 24) + 1
        # ensure it doesnt exceed 1
        confidence: float = min(1, confidence)
        confidence = round(confidence, 2)
        # Get the duration in minutes.
        if isinstance(flow.dur, str):
            dur = float(flow.dur)
        else:
            dur = flow.dur
        duration_minutes: int = int(dur / 60)
        description: str = (
            f"Long Connection. Connection from {flow.saddr} "
            f"to destination address: {flow.daddr} "
            f"took {duration_minutes} mins"
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.LONG_CONNECTION,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            threat_level=ThreatLevel.LOW,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=twid),
            uid=[flow.uid],
            timestamp=flow.starttime,
            victim=Victim(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=flow.daddr,
            ),
            src_port=flow.sport,
            dst_port=flow.dport,
        )

        self.db.set_evidence(evidence)

    def multiple_telnet_reconnection_attempts(
        self, twid, flow, reconnections, uids: List[str]
    ):
        """
        Set evidence for 4+ telnet unsuccessful attempts.
        """
        confidence: float = 0.5
        threat_level: ThreatLevel = ThreatLevel.MEDIUM

        twid: int = int(twid.replace("timewindow", ""))

        description = (
            f"Multiple Telnet reconnection attempts from IP: {flow.saddr} "
            f"to Destination IP: {flow.daddr}  "
            f"reconnections: {reconnections}"
        )
        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.MULTIPLE_RECONNECTION_ATTEMPTS,
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
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=twid),
            uid=uids,
            timestamp=flow.starttime,
        )

        self.db.set_evidence(evidence)

    def multiple_reconnection_attempts(
        self, twid, flow, reconnections, uids: List[str]
    ) -> None:
        """
        Set evidence for Reconnection Attempts.
        """
        confidence: float = 0.5
        threat_level: ThreatLevel = ThreatLevel.MEDIUM

        twid: int = int(twid.replace("timewindow", ""))

        description = (
            f"Multiple reconnection attempts from IP: {flow.saddr} to "
            f"destination IP: {flow.daddr} "
            f"reconnections: {reconnections}."
        )
        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.MULTIPLE_RECONNECTION_ATTEMPTS,
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
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=twid),
            uid=uids,
            timestamp=flow.starttime,
        )

        self.db.set_evidence(evidence)

    def connection_to_multiple_ports(
        self,
        profileid,
        twid,
        flow,
        victim: str,
        attacker: str,
        dstports,
        uids: List[str],
    ) -> None:
        """
        Set evidence for connection to multiple ports.
        """
        confidence: float = 0.5
        twid: int = int(twid.replace("timewindow", ""))
        description = (
            f"Connection to multiple ports {dstports} from {attacker} to "
            f"{victim}. "
        )

        if attacker in profileid:
            attacker_direction = Direction.SRC
            victim_direction = Direction.DST
            profile_ip = attacker
        else:
            attacker_direction = Direction.DST
            victim_direction = Direction.SRC
            profile_ip = victim

        evidence = Evidence(
            evidence_type=EvidenceType.CONNECTION_TO_MULTIPLE_PORTS,
            attacker=Attacker(
                direction=attacker_direction,
                ioc_type=IoCType.IP,
                value=attacker,
            ),
            victim=Victim(
                direction=victim_direction,
                ioc_type=IoCType.IP,
                value=victim,
            ),
            threat_level=ThreatLevel.INFO,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=profile_ip),
            timewindow=TimeWindow(number=twid),
            uid=uids,
            timestamp=flow.starttime,
        )

        self.db.set_evidence(evidence)

    def port_0_connection(
        self, profileid, twid, flow, victim: str, attacker: str
    ) -> None:
        confidence: float = 0.8
        threat_level: ThreatLevel = ThreatLevel.HIGH

        if attacker in profileid:
            attacker_direction = Direction.SRC
            victim_direction = Direction.DST
            profile_ip = attacker
        else:
            attacker_direction = Direction.DST
            victim_direction = Direction.SRC
            profile_ip = victim

        description: str = (
            f"Connection on port 0 from {flow.saddr}:{flow.sport} "
            f"to {flow.daddr}:{flow.dport}."
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.PORT_0_CONNECTION,
            attacker=Attacker(
                direction=attacker_direction,
                ioc_type=IoCType.IP,
                value=attacker,
            ),
            victim=Victim(
                direction=victim_direction,
                ioc_type=IoCType.IP,
                value=victim,
            ),
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=profile_ip),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[flow.uid],
            timestamp=flow.starttime,
            src_port=flow.sport,
            dst_port=flow.dport,
        )

        self.db.set_evidence(evidence)

    def data_exfiltration(
        self,
        daddr: str,
        src_mbs: float,
        profileid: str,
        twid: str,
        uids: List[str],
        timestamp,
    ) -> None:
        saddr: str = profileid.split("_")[-1]
        description: str = f"Large data upload. {src_mbs} MBs sent to {daddr}"
        timestamp: str = utils.convert_ts_format(
            timestamp, utils.alerts_format
        )
        twid_number = int(twid.replace("timewindow", ""))
        # to add a correlation the 2 evidence in alerts.json
        evidence_id_of_dstip_as_the_attacker = str(uuid4())
        evidence_id_of_srcip_as_the_attacker = str(uuid4())
        evidence: Evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=[evidence_id_of_dstip_as_the_attacker],
            evidence_type=EvidenceType.DATA_UPLOAD,
            attacker=Attacker(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=saddr
            ),
            threat_level=ThreatLevel.INFO,
            confidence=0.6,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=uids,
            timestamp=timestamp,
        )

        self.db.set_evidence(evidence)

        evidence: Evidence = Evidence(
            id=evidence_id_of_dstip_as_the_attacker,
            rel_id=[evidence_id_of_srcip_as_the_attacker],
            evidence_type=EvidenceType.DATA_UPLOAD,
            attacker=Attacker(
                direction=Direction.DST, ioc_type=IoCType.IP, value=daddr
            ),
            threat_level=ThreatLevel.HIGH,
            confidence=0.6,
            description=description,
            profile=ProfileID(ip=daddr),
            timewindow=TimeWindow(number=twid_number),
            uid=uids,
            timestamp=timestamp,
        )

        self.db.set_evidence(evidence)
