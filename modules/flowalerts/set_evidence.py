# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from typing import List
from uuid import uuid4
from datetime import datetime
from slips_files.common.slips_utils import utils
from slips_files.core.flows.zeek import SMTP
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

    def cn_url_mismatch(self, twid, cn, flow):
        twid_number: int = int(twid.replace("timewindow", ""))
        confidence: float = 0.8
        description: str = (
            f"a CN mismatch. The common name (CN) '{cn}' in the SSL "
            f"certificate for the domain '{flow.server_name}' does not match "
            f"the server's domain."
        )

        # to add a correlation between the 2 evidence in alerts.json
        evidence_id_of_dstip_as_the_attacker = str(uuid4())
        evidence_id_of_srcip_as_the_attacker = str(uuid4())
        evidence: Evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=[evidence_id_of_dstip_as_the_attacker],
            evidence_type=EvidenceType.CN_URL_MISMATCH,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            victim=Victim(
                direction=Direction.DST,
                ioc_type=IoCType.DOMAIN,
                value=flow.server_name,
            ),
            threat_level=ThreatLevel.LOW,
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

        evidence: Evidence = Evidence(
            id=evidence_id_of_dstip_as_the_attacker,
            rel_id=[evidence_id_of_srcip_as_the_attacker],
            evidence_type=EvidenceType.CN_URL_MISMATCH,
            attacker=Attacker(
                direction=Direction.DST,
                ioc_type=IoCType.DOMAIN,
                value=flow.server_name,
            ),
            victim=Victim(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            threat_level=ThreatLevel.MEDIUM,
            description=description,
            profile=ProfileID(ip=flow.daddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow.uid],
            timestamp=flow.starttime,
            confidence=confidence,
            src_port=flow.sport,
            dst_port=flow.dport,
        )

        self.db.set_evidence(evidence)

    def doh(self, twid, flow):
        twid_number: int = int(twid.replace("timewindow", ""))
        description: str = f"using DNS over HTTPs. DNS server: {flow.daddr} "
        evidence = Evidence(
            evidence_type=EvidenceType.DIFFERENT_LOCALNET,
            attacker=Attacker(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=flow.daddr,
            ),
            threat_level=ThreatLevel.INFO,
            description=description,
            victim=Victim(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            profile=ProfileID(ip=flow.daddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow.uid],
            timestamp=flow.starttime,
            confidence=0.9,
            src_port=flow.sport,
            dst_port=flow.dport,
        )
        self.db.set_evidence(evidence)

    def young_domain(self, twid, flow, age, ips_in_answer: List[str]):
        twid_number: int = int(twid.replace("timewindow", ""))
        description: str = (
            f"connection to a young domain: {flow.query} "
            f"registered {age} days ago."
        )

        evidence_id_of_srcip_as_the_attacker = str(uuid4())
        uuids_list = [evidence_id_of_srcip_as_the_attacker]
        # set evidence for all the young domain dns answers
        for attacker in ips_in_answer:
            attacker: str
            evidence_id = str(uuid4())
            evidence = Evidence(
                id=evidence_id,
                rel_id=uuids_list,
                evidence_type=EvidenceType.YOUNG_DOMAIN,
                attacker=Attacker(
                    direction=Direction.DST,
                    ioc_type=IoCType.IP,
                    value=attacker,
                ),
                threat_level=ThreatLevel.LOW,
                description=description,
                profile=ProfileID(ip=attacker),
                timewindow=TimeWindow(number=twid_number),
                uid=[flow.uid],
                timestamp=flow.starttime,
                confidence=1.0,
            )
            self.db.set_evidence(evidence)
            # to relate all the evidence generated by this function together
            uuids_list.append(evidence_id)

        # we dont wanna relate this evidence with itself right?
        uuids_list.remove(evidence_id_of_srcip_as_the_attacker)
        evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=uuids_list,
            evidence_type=EvidenceType.YOUNG_DOMAIN,
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
            confidence=1.0,
        )
        self.db.set_evidence(evidence)

    def multiple_ssh_versions(
        self,
        flow,
        cached_versions: str,
        current_versions: str,
        twid: str,
        uids: List[str],
        role: str = "",
    ):
        """
        :param cached_versions: major.minor
        :param current_versions: major.minor
        :param role: can be 'SSH::CLIENT' or
            'SSH::SERVER' as seen in zeek software.log flows
        """
        role = "client" if "CLIENT" in role.upper() else "server"
        description = (
            f"SSH {role} version changing from "
            f"{cached_versions} to {current_versions}"
        )

        evidence = Evidence(
            evidence_type=EvidenceType.MULTIPLE_SSH_VERSIONS,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            threat_level=ThreatLevel.MEDIUM,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(int(twid.replace("timewindow", ""))),
            uid=uids,
            timestamp=flow.starttime,
            confidence=0.9,
        )
        self.db.set_evidence(evidence)

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
                f"{self.db.get_local_network()}. To IP: {flow.daddr} "
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
                f"{self.db.get_local_network()}. "
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

    def incompatible_cn(self, twid, flow, org: str) -> None:
        confidence: float = 0.9
        description: str = (
            f"Incompatible certificate CN to IP: {flow.daddr} domain: "
            f"{flow.server_name}. The certificate is "
            f"claiming to belong to {org.capitalize()}."
        )

        twid_number: int = int(twid.replace("timewindow", ""))
        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.INCOMPATIBLE_CN,
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

    def dga(self, twid, flow, nxdomains: int, uids: List[str]) -> None:
        # for each non-existent domain beyond the threshold of 100,
        # the confidence score is increased linearly.
        # +1 ensures that the minimum confidence score is 1.
        confidence: float = max(0, (1 / 100) * (nxdomains - 100) + 1)
        confidence = round(confidence, 2)  # for readability
        description = (
            f"Possible DGA or domain scanning. {flow.saddr} "
            f"failed to resolve {nxdomains} different domains"
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.DGA_NXDOMAINS,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            threat_level=ThreatLevel.HIGH,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=uids,
            timestamp=flow.starttime,
            confidence=confidence,
        )

        self.db.set_evidence(evidence)

    def dns_without_conn(self, twid, flow):
        # WARNING
        #  The approach we use to detect "dns without connection" evidence will
        #  cause the evidence to be set after 30 mins of the dns flow,
        #  and the timewindow of that evidence may have been closed,
        #  that would cause us to detect the tw as malicious way after it
        #  ends.
        #  but this doesnt matter since the threat level of it is info.
        #
        # this will be an issue if we ever decide to increase the threat level
        # of this evidence

        description: str = f"domain {flow.query} resolved with no connection"
        twid_number: int = int(twid.replace("timewindow", ""))

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.DNS_WITHOUT_CONNECTION,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            victim=Victim(
                direction=Direction.DST,
                ioc_type=IoCType.DOMAIN,
                value=flow.query,
            ),
            threat_level=ThreatLevel.INFO,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow.uid],
            timestamp=flow.starttime,
            confidence=0.8,
        )

        self.db.set_evidence(evidence)

    def pastebin_download(
        self, twid, flow: dict, bytes_downloaded: int
    ) -> bool:
        confidence: float = 1.0
        response_body_len: float = utils.convert_to_mb(bytes_downloaded)
        description: str = (
            f"A downloaded file from pastebin.com. "
            f"size: {response_body_len} MBs"
        )

        twid_number: int = int(twid.replace("timewindow", ""))
        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.PASTEBIN_DOWNLOAD,
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
            src_port=flow.sport,
            dst_port=flow.dport,
        )

        self.db.set_evidence(evidence)
        return True

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
            f"A connection without DNS resolution to IP: " f"{flow.daddr}"
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

    def dns_arpa_scan(
        self, twid, flow, arpa_scan_threshold: int, uids: List[str]
    ) -> bool:
        threat_level = ThreatLevel.MEDIUM
        confidence = 0.7
        description = (
            f"Doing DNS ARPA scan. Scanned {arpa_scan_threshold}"
            f" hosts within 2 seconds."
        )

        # Create Evidence object using local variables
        evidence = Evidence(
            evidence_type=EvidenceType.DNS_ARPA_SCAN,
            description=description,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            threat_level=threat_level,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=uids,
            timestamp=flow.starttime,
            confidence=confidence,
        )

        # Store evidence in the database
        self.db.set_evidence(evidence)

        return True

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

    def pw_guessing(self, twid, flow) -> None:
        # 222.186.30.112 appears to be guessing SSH passwords
        # (seen in 30 connections)
        # confidence = 1 because this detection is comming
        # from a zeek file so we're sure it's accurate
        confidence: float = 1.0
        twid_number: int = int(twid.replace("timewindow", ""))
        scanning_ip: str = flow.msg.split(" appears")[0]

        description: str = f"password guessing. {flow.msg}. Detected by zeek."

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.PASSWORD_GUESSING,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=scanning_ip,
            ),
            threat_level=ThreatLevel.HIGH,
            description=description,
            profile=ProfileID(ip=scanning_ip),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow.uid],
            timestamp=flow.starttime,
            confidence=confidence,
        )

        self.db.set_evidence(evidence)

    def ssh_pw_guessing(self, flow, twid, uids: List[str]):
        confidence: float = 1.0
        description = (
            f"SSH password guessing to IP {flow.daddr}. Detected " f"by Slips"
        )
        twid_number: int = int(twid.replace("timewindow", ""))
        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.PASSWORD_GUESSING,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            threat_level=ThreatLevel.HIGH,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=uids,
            timestamp=flow.starttime,
            confidence=confidence,
        )

        self.db.set_evidence(evidence)

    def horizontal_portscan(self, profileid, twid, flow) -> None:
        confidence: float = 1.0
        twid_number: int = int(twid.replace("timewindow", ""))
        saddr = profileid.split("_")[-1]

        description: str = f"horizontal port scan by Zeek engine. {flow.msg}"

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.HORIZONTAL_PORT_SCAN,
            attacker=Attacker(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=saddr
            ),
            threat_level=ThreatLevel.HIGH,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow.uid],
            timestamp=flow.starttime,
            confidence=confidence,
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

    def gre_tunnel(self, twid, flow) -> None:
        confidence: float = 1.0
        threat_level: ThreatLevel = ThreatLevel.LOW
        twid_number: int = int(twid.replace("timewindow", ""))

        description: str = (
            f"GRE tunnel from {flow.saddr} "
            f"to {flow.daddr} tunnel action: {flow.action}"
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.GRE_TUNNEL,
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
        )

        self.db.set_evidence(evidence)

    def gre_scan(self, twid, flow) -> None:
        confidence: float = 1.0
        threat_level: ThreatLevel = ThreatLevel.LOW
        twid_number: int = int(twid.replace("timewindow", ""))

        description: str = (
            f"GRE scan from {flow.saddr} "
            f"to {flow.daddr} tunnel action: {flow.action}"
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.GRE_SCAN,
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
        )

        self.db.set_evidence(evidence)

    def vertical_portscan(self, twid, flow) -> None:
        # confidence = 1 because this detection is coming
        # from a Zeek file so we're sure it's accurate
        confidence: float = 1.0
        twid: int = int(twid.replace("timewindow", ""))
        # msg example: 192.168.1.200 has scanned 60 ports of 192.168.1.102
        description: str = f"vertical port scan by Zeek engine. {flow.msg}"
        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.VERTICAL_PORT_SCAN,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.scanning_ip,
            ),
            victim=Victim(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=flow.msg.split("ports of host ")[-1].split(" in")[0],
            ),
            threat_level=ThreatLevel.HIGH,
            description=description,
            profile=ProfileID(ip=flow.scanning_ip),
            timewindow=TimeWindow(number=twid),
            uid=[flow.uid],
            timestamp=flow.starttime,
            confidence=confidence,
        )

        self.db.set_evidence(evidence)

    def ssh_successful(
        self, twid, saddr, daddr, size, uid, timestamp, by=""
    ) -> None:
        """
        Set an evidence for a successful SSH login.
        This is not strictly a detection, but we don't have
        a better way to show it.
        The threat_level is 0.01 to show that this is not a detection
        """
        confidence: float = 0.8
        threat_level: ThreatLevel = ThreatLevel.INFO
        twid: int = int(twid.replace("timewindow", ""))

        description: str = (
            f"SSH successful to IP {daddr}. "
            f"From IP {saddr}. Sent bytes: {size}. Detection model {by}. "
            f"Confidence {confidence}"
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.SSH_SUCCESSFUL,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=saddr,
            ),
            victim=Victim(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=daddr,
            ),
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid),
            uid=[uid],
            timestamp=timestamp,
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

    def self_signed_certificates(self, twid, flow) -> None:
        """
        Set evidence for self-signed certificates.
        """
        confidence: float = 0.5
        twid: int = int(twid.replace("timewindow", ""))
        attacker: Attacker = Attacker(
            direction=Direction.SRC, ioc_type=IoCType.IP, value=flow.saddr
        )

        description = f"Self-signed certificate. Destination IP: {flow.daddr}."

        if flow.server_name:
            description += f" SNI: {flow.server_name}."

        # to add a correlation between the 2 evidence in alerts.json
        evidence_id_of_dstip_as_the_attacker = str(uuid4())
        evidence_id_of_srcip_as_the_attacker = str(uuid4())

        evidence: Evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=[evidence_id_of_dstip_as_the_attacker],
            evidence_type=EvidenceType.SELF_SIGNED_CERTIFICATE,
            attacker=attacker,
            threat_level=ThreatLevel.LOW,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=twid),
            uid=[flow.uid],
            timestamp=flow.starttime,
            src_port=flow.sport,
            dst_port=flow.dport,
        )
        self.db.set_evidence(evidence)

        attacker: Attacker = Attacker(
            direction=Direction.DST, ioc_type=IoCType.IP, value=flow.daddr
        )
        evidence: Evidence = Evidence(
            id=evidence_id_of_dstip_as_the_attacker,
            rel_id=[evidence_id_of_srcip_as_the_attacker],
            evidence_type=EvidenceType.SELF_SIGNED_CERTIFICATE,
            attacker=attacker,
            threat_level=ThreatLevel.LOW,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=flow.daddr),
            timewindow=TimeWindow(number=twid),
            uid=[flow.uid],
            timestamp=flow.starttime,
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
            f"Multiple reconnection attempts to Destination IP: "
            f"{flow.daddr} from IP: {flow.saddr} "
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
            f"Connection to multiple ports {dstports} of " f"IP: {attacker}. "
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

    def suspicious_dns_answer(
        self, twid, flow, entropy: float, sus_answer: str
    ) -> None:
        confidence: float = 0.6
        twid: int = int(twid.replace("timewindow", ""))

        description: str = (
            f"A DNS TXT answer with high entropy. "
            f'query: {flow.query} answer: "{sus_answer}" '
            f"entropy: {round(entropy, 2)} "
        )
        # to add a correlation between the 2 evidence in alerts.json
        evidence_id_of_dstip_as_the_attacker = str(uuid4())
        evidence_id_of_srcip_as_the_attacker = str(uuid4())
        evidence: Evidence = Evidence(
            id=evidence_id_of_dstip_as_the_attacker,
            rel_id=[evidence_id_of_srcip_as_the_attacker],
            evidence_type=EvidenceType.HIGH_ENTROPY_DNS_ANSWER,
            attacker=Attacker(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=flow.daddr,
            ),
            threat_level=ThreatLevel.MEDIUM,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=flow.daddr),
            timewindow=TimeWindow(number=twid),
            uid=[flow.uid],
            timestamp=flow.starttime,
        )

        self.db.set_evidence(evidence)

        evidence: Evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=[evidence_id_of_dstip_as_the_attacker],
            evidence_type=EvidenceType.HIGH_ENTROPY_DNS_ANSWER,
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
        )
        self.db.set_evidence(evidence)

    def invalid_dns_answer(self, twid, flow, invalid_answer) -> None:
        confidence: float = 0.8
        twid: int = int(twid.replace("timewindow", ""))

        description: str = (
            f"Invalid DNS answer. The DNS query {flow.query} was resolved to "
            f"the private IP: {invalid_answer}"
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.INVALID_DNS_RESOLUTION,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            victim=Victim(
                direction=Direction.DST,
                ioc_type=IoCType.DOMAIN,
                value=flow.query,
            ),
            threat_level=ThreatLevel.INFO,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=twid),
            uid=[flow.uid],
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

    def malicious_ja3s(self, twid, flow, malicious_ja3_dict: dict) -> None:
        ja3_info: dict = json.loads(malicious_ja3_dict[flow.ja3s])

        threat_level: str = ja3_info["threat_level"].upper()
        threat_level: ThreatLevel = ThreatLevel[threat_level]

        tags: str = ja3_info.get("tags", "")
        ja3_description: str = ja3_info["description"]

        description = (
            f"Malicious JA3s: (possible C&C server): {flow.ja3s} "
            f"to server {flow.daddr}."
        )
        if ja3_description != "None":
            description += f" description: {ja3_description}."
        if tags:
            description += f" tags: {tags}"

        confidence: float = 1
        twid_number: int = int(twid.replace("timewindow", ""))
        # to add a correlation between the 2 evidence in alerts.json
        evidence_id_of_dstip_as_the_attacker = str(uuid4())
        evidence_id_of_srcip_as_the_attacker = str(uuid4())
        evidence: Evidence = Evidence(
            id=evidence_id_of_dstip_as_the_attacker,
            rel_id=[evidence_id_of_srcip_as_the_attacker],
            evidence_type=EvidenceType.MALICIOUS_JA3S,
            attacker=Attacker(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=flow.daddr,
            ),
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=flow.daddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow.uid],
            timestamp=flow.starttime,
            src_port=flow.sport,
            dst_port=flow.dport,
        )

        self.db.set_evidence(evidence)
        evidence: Evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=[evidence_id_of_dstip_as_the_attacker],
            evidence_type=EvidenceType.MALICIOUS_JA3S,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            threat_level=ThreatLevel.LOW,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow.uid],
            timestamp=flow.starttime,
            src_port=flow.sport,
            dst_port=flow.dport,
        )

        self.db.set_evidence(evidence)

    def malicious_ja3(self, twid, flow, malicious_ja3_dict: dict) -> None:
        ja3_info: dict = json.loads(malicious_ja3_dict[flow.ja3])
        threat_level: str = ja3_info["threat_level"].upper()
        threat_level: ThreatLevel = ThreatLevel[threat_level]

        tags: str = ja3_info.get("tags", "")
        ja3_description: str = ja3_info["description"]

        description = (
            f"Malicious JA3: {flow.ja3} from source address {flow.saddr} "
            f"to {flow.daddr}."
        )
        if ja3_description != "None":
            description += f" description: {ja3_description}."
        if tags:
            description += f" tags: {tags}"

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.MALICIOUS_JA3,
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
            confidence=1,
            description=description,
            profile=ProfileID(ip=flow.saddr),
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
        timestamp: str = utils.convert_format(timestamp, utils.alerts_format)
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

    def bad_smtp_login(self, twid, flow: SMTP) -> None:
        confidence: float = 1.0
        threat_level: ThreatLevel = ThreatLevel.HIGH

        description: str = f"doing bad SMTP login to {flow.daddr} "

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.BAD_SMTP_LOGIN,
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
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[flow.uid],
            timestamp=flow.starttime,
        )

        self.db.set_evidence(evidence)

    def smtp_bruteforce(
        self,
        flow,
        twid,
        smtp_bruteforce_threshold: int,
        uids: List[str],
    ) -> None:
        confidence: float = 1.0
        threat_level: ThreatLevel = ThreatLevel.HIGH

        description: str = (
            f"doing SMTP login bruteforce to {flow.daddr}. "
            f"{smtp_bruteforce_threshold} logins in 10 seconds. "
        )
        attacker: Attacker = Attacker(
            direction=Direction.SRC, ioc_type=IoCType.IP, value=flow.saddr
        )
        victim = Victim(
            direction=Direction.DST, ioc_type=IoCType.IP, value=flow.daddr
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.SMTP_LOGIN_BRUTEFORCE,
            attacker=attacker,
            victim=victim,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=uids,
            timestamp=flow.starttime,
        )

        self.db.set_evidence(evidence)

    def malicious_ssl(self, twid, flow, ssl_info_from_db: str) -> None:
        ssl_info_from_db: dict = json.loads(ssl_info_from_db)
        tags: str = ssl_info_from_db["tags"]
        cert_description: str = ssl_info_from_db["description"]

        confidence: float = 1.0
        threat_level: float = utils.threat_levels[
            ssl_info_from_db["threat_level"]
        ]
        threat_level: ThreatLevel = ThreatLevel(threat_level)

        description: str = (
            f"Malicious SSL certificate to server {flow.daddr}. "
            f"description: {cert_description} {tags}"
        )
        # to add a correlation between the 2 evidence in alerts.json
        evidence_id_of_dstip_as_the_attacker = str(uuid4())
        evidence_id_of_srcip_as_the_attacker = str(uuid4())
        evidence: Evidence = Evidence(
            id=evidence_id_of_dstip_as_the_attacker,
            rel_id=[evidence_id_of_srcip_as_the_attacker],
            evidence_type=EvidenceType.MALICIOUS_SSL_CERT,
            attacker=Attacker(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=flow.daddr,
            ),
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=flow.daddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[flow.uid],
            timestamp=flow.starttime,
        )

        self.db.set_evidence(evidence)

        evidence: Evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=[evidence_id_of_dstip_as_the_attacker],
            evidence_type=EvidenceType.MALICIOUS_SSL_CERT,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            threat_level=ThreatLevel.LOW,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[flow.uid],
            timestamp=flow.starttime,
        )

        self.db.set_evidence(evidence)
