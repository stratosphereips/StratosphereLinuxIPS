# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
Contains evidence dataclass that is used in slips
"""

import ipaddress
from dataclasses import dataclass, field
from enum import Enum, auto
from pprint import pformat
from uuid import uuid4
from typing import (
    List,
    Optional,
    Dict,
)

from slips_files.common.slips_utils import utils


# IMPORTANT: remember to update dict_to_evidence() function based on the
# field you add to the evidence class, or any class used by the evidence
# class.


def validate_ip(ip):
    ipaddress.ip_address(ip)


def validate_timestamp(ts) -> str:
    """
    the ts of all evidence should be in
     the alerts time format, if not, raise an exception
    """
    if utils.get_time_format(ts) == utils.alerts_format:
        return ts
    else:
        raise ValueError(
            f"Invalid timestamp format: {ts}. "
            f"Expected format: '%Y/%m/%d %H:%M:%S.%f%z'."
        )


class EvidenceType(Enum):
    """
    These are the types of evidence slips can detect
    """

    ARP_SCAN = auto()
    ARP_OUTSIDE_LOCALNET = auto()
    UNSOLICITED_ARP = auto()
    MITM_ARP_ATTACK = auto()
    YOUNG_DOMAIN = auto()
    MULTIPLE_SSH_VERSIONS = auto()
    DIFFERENT_LOCALNET = auto()
    DEVICE_CHANGING_IP = auto()
    NON_HTTP_PORT_80_CONNECTION = auto()
    NON_SSL_PORT_443_CONNECTION = auto()
    WEIRD_HTTP_METHOD = auto()
    INCOMPATIBLE_CN = auto()
    CN_URL_MISMATCH = auto()
    DGA_NXDOMAINS = auto()
    DNS_WITHOUT_CONNECTION = auto()
    PASTEBIN_DOWNLOAD = auto()
    CONNECTION_WITHOUT_DNS = auto()
    DNS_ARPA_SCAN = auto()
    UNKNOWN_PORT = auto()
    PASSWORD_GUESSING = auto()
    HORIZONTAL_PORT_SCAN = auto()
    CONNECTION_TO_PRIVATE_IP = auto()
    GRE_TUNNEL = auto()
    GRE_SCAN = auto()
    VERTICAL_PORT_SCAN = auto()
    SSH_SUCCESSFUL = auto()
    LONG_CONNECTION = auto()
    SELF_SIGNED_CERTIFICATE = auto()
    MULTIPLE_RECONNECTION_ATTEMPTS = auto()
    CONNECTION_TO_MULTIPLE_PORTS = auto()
    HIGH_ENTROPY_DNS_ANSWER = auto()
    INVALID_DNS_RESOLUTION = auto()
    PORT_0_CONNECTION = auto()
    MALICIOUS_JA3 = auto()
    MALICIOUS_JA3S = auto()
    DATA_UPLOAD = auto()
    BAD_SMTP_LOGIN = auto()
    SMTP_LOGIN_BRUTEFORCE = auto()
    MALICIOUS_SSL_CERT = auto()
    MALICIOUS_FLOW = auto()
    SUSPICIOUS_USER_AGENT = auto()
    EMPTY_CONNECTIONS = auto()
    INCOMPATIBLE_USER_AGENT = auto()
    EXECUTABLE_MIME_TYPE = auto()
    MULTIPLE_USER_AGENT = auto()
    HTTP_TRAFFIC = auto()
    MALICIOUS_JARM = auto()
    NETWORK_GPS_LOCATION_LEAKED = auto()
    ICMP_TIMESTAMP_SCAN = auto()
    ICMP_ADDRESS_SCAN = auto()
    ICMP_ADDRESS_MASK_SCAN = auto()
    DHCP_SCAN = auto()
    MALICIOUS_IP_FROM_P2P_NETWORK = auto()
    P2P_REPORT = auto()
    COMMAND_AND_CONTROL_CHANNEL = auto()
    THREAT_INTELLIGENCE_BLACKLISTED_ASN = auto()
    THREAT_INTELLIGENCE_FROM_BLACKLISTED_IP = auto()
    THREAT_INTELLIGENCE_TO_BLACKLISTED_IP = auto()
    THREAT_INTELLIGENCE_BLACKLISTED_DNS_ANSWER = auto()
    THREAT_INTELLIGENCE_BLACKLISTED_DOMAIN = auto()
    MALICIOUS_DOWNLOADED_FILE = auto()
    THREAT_INTELLIGENCE_MALICIOUS_URL = auto()

    def __str__(self):
        return self.name


class Direction(Enum):
    DST = auto()
    SRC = auto()


class IoCType(Enum):
    IP = auto()
    URL = auto()
    DOMAIN = auto()
    MD5 = auto()


class ThreatLevel(Enum):
    """determines the importance of the evidence"""

    INFO = 0
    LOW = 0.2
    MEDIUM = 0.5
    HIGH = 0.8
    CRITICAL = 1

    def __str__(self):
        return self.name.lower()


class Proto(Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"


@dataclass
class Victim:
    direction: Direction
    ioc_type: IoCType
    value: str  # like the actual ip/domain/url check if value is reserved
    # if the victim is part of a TI feed that slips knows  about,
    # the feed name goes here
    TI: str = field(default=None)
    # autonomous system
    # has {"org": org, "number": number}
    AS: Dict[str, str] = field(default=None)
    rDNS: str = field(default=None)
    SNI: str = field(default=None)
    # if the attacker  is a domain, and that domain was found in any queyr,
    # this would be the answers to that query
    DNS_resolution: List[str] = field(default=None)
    # if the attacker is an IP, and that IP was found as an answer to any
    # query this would be that query
    queries: List[str] = field(default=None)
    # useful if the victim is a domain
    CNAME: List[str] = field(default=None)

    def __post_init__(self):
        if self.ioc_type == IoCType.IP:
            validate_ip(self.value)


@dataclass
class ProfileID:
    ip: str

    def __setattr__(self, name, value):
        if name == "ip":
            assert ipaddress.ip_address(value)
        self.__dict__[name] = value

    def __repr__(self):
        return f"profile_{self.ip}"


@dataclass
class Attacker:
    direction: Direction
    ioc_type: IoCType
    value: str  # like the actual ip/domain/url check if value is reserved
    profile: ProfileID = ""
    # if the victim is part of a TI feed that slips knows  about,
    # the feed name goes here
    TI: str = field(default=None)
    # autonomous system
    # has {"org": org, "number": number}
    AS: Dict[str, str] = field(default=None)
    rDNS: str = field(default=None)
    SNI: str = field(default=None)
    # if the attacker is a domain, and that domain was found in any query,
    # this would be the answers to that query
    DNS_resolution: List[str] = field(default=None)
    # if the attacker is an IP, and that IP was found as an answer to any
    # query this would be that query
    queries: List[str] = field(default=None)
    # useful if the attacker is a domain
    CNAME: List[str] = field(default=None)

    def __post_init__(self):
        if self.ioc_type == IoCType.IP:
            validate_ip(self.value)
        # each attacker should have a profile if it's an IP
        if self.ioc_type == IoCType.IP:
            self.profile = ProfileID(ip=self.value)


@dataclass
class TimeWindow:
    number: int
    start_time: Optional[str] = field(default="")
    end_time: Optional[str] = field(default="")

    def __post_init__(self):
        for timestamp in [self.start_time, self.end_time]:
            if timestamp and not utils.is_iso_format(timestamp):
                raise ValueError(
                    f"Invalid ISO format for start_time: " f"{timestamp}"
                )

        if not isinstance(self.number, int):
            raise ValueError(
                f"timewindow number must be an int. "
                f"{self.number} is invalid."
            )

    def __repr__(self):
        return f"timewindow{self.number}"


class Method(Enum):
    """
    Describes how was the evidence generated. these values are IDMEFv2
    https://www.ietf.org/id/draft-lehmann-idmefv2-03.html#section-5.3-4.20.1
    """

    BIOMETRIC = "Biometric"
    SIGNATURE = "Signature"
    MONITOR = "Monitor"
    POLICY = "Policy"
    STATISTICAL = "Statistical"
    AI = "AI"
    HEAT = "Heat"
    MOVEMENT = "Movement"
    BLACKHOLE = "Blackhole"
    HEURISTIC = "Heuristic"
    INTEGRITY = "Integrity"
    HONEYPOT = "Honeypot"
    TARPIT = "Tarpit"
    RECON = "Recon"
    CORRELATION = "Correlation"
    THRESHOLD = "Threshold"


@dataclass
class Evidence:
    evidence_type: EvidenceType
    description: str
    attacker: Attacker
    threat_level: ThreatLevel
    # profile of the srcip detected this evidence
    profile: ProfileID
    timewindow: TimeWindow
    # the uids of the flows causing this evidence
    uid: List[str]
    timestamp: str = field(
        metadata={"validate": lambda x: validate_timestamp(x)}
    )
    victim: Optional[Victim] = field(default=False)
    proto: Optional[Proto] = field(default=False)
    dst_port: int = field(default=None)
    src_port: int = field(default=None)
    method: Method = field(default=Method.HEURISTIC)
    # every evidence should have an ID according to the IDMEF format
    id: str = field(default_factory=lambda: str(uuid4()))
    # the confidence of this evidence on a scale from 0 to 1.
    # How sure you are that this evidence is what you say it is?
    confidence: float = field(
        default=0.0, metadata={"validate": lambda x: 0 <= x <= 1}
    )
    # uuid4 of a related evidence, for example CC client and server
    # evidence are related.
    rel_id: List[str] = field(
        default=None,
        metadata={
            "validate": lambda x: (
                all(utils.is_valid_uuid4(uuid_) for uuid_ in x) if x else True
            )
        },
    )

    def __post_init__(self):
        if not isinstance(self.uid, list) or not all(
            isinstance(uid, str) for uid in self.uid
        ):
            raise ValueError(f"uid must be a list of strings .. {self}")
        else:
            # remove duplicate uids
            self.uid = list(set(self.uid))

    def __str__(self):
        return (
            f"Evidence(\n"
            f"  Evidence Type: {self.evidence_type},\n"
            f"  Description: {self.description},\n"
            f"  Attacker: {pformat(self.attacker)},\n"
            f"  Threat Level: {self.threat_level},\n"
            f"  Profile: {pformat(self.profile)},\n"
            f"  Timewindow: {self.timewindow},\n"
            f"  UID: {self.uid},\n"
            f"  Timestamp: {self.timestamp},\n"
            f"  Victim: {pformat(self.victim)},\n"
            f"  Protocol: {self.proto},\n"
            f"  Destination Port: {self.dst_port},\n"
            f"  Source Port: {self.src_port},\n"
            f"  ID: {self.id},\n"
            f"  Confidence: {self.confidence},\n"
            f"  Related ID: {self.rel_id}\n"
            f")"
        )


def dict_to_evidence(evidence: dict) -> Evidence:
    """
    Convert a dictionary to an Evidence object.
    :param evidence: Dictionary with evidence details.
    returns an instance of the Evidence class.
    """
    evidence_attributes = {
        "evidence_type": EvidenceType[evidence["evidence_type"]],
        "description": evidence["description"],
        "attacker": Attacker(**evidence["attacker"]),
        "threat_level": ThreatLevel[evidence["threat_level"].upper()],
        "victim": (
            Victim(**evidence["victim"])
            if "victim" in evidence and evidence["victim"]
            else None
        ),
        "profile": (
            ProfileID(evidence["profile"]["ip"])
            if "profile" in evidence
            else None
        ),
        "timewindow": TimeWindow(evidence["timewindow"]["number"]),
        "uid": evidence["uid"],
        "timestamp": evidence["timestamp"],
        "proto": (
            Proto[evidence["proto"].upper()]
            if "proto" in evidence and evidence["proto"]
            else None
        ),
        "dst_port": evidence["dst_port"] if "dst_port" in evidence else None,
        "src_port": evidence["src_port"] if "src_port" in evidence else None,
        "id": evidence["id"],
        "rel_id": evidence["rel_id"],
        "confidence": evidence["confidence"],
        "method": Method[evidence["method"].upper()],
    }

    return Evidence(**evidence_attributes)
