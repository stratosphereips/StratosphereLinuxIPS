"""
Contains evidence dataclass that is used amon all slips
"""
from slips_files.common.slips_utils import utils
import ipaddress
from dataclasses import dataclass, field
from enum import Enum, auto
from uuid import uuid4
from datetime import datetime
from typing import List

def validate_timestamp(ts) -> str:
    """
    the ts of allevidence should be in
     the alerts time format, if not, raise an exception
     """
    if utils.define_time_format(ts) == utils.alerts_format:
        return ts
    else:
        raise ValueError(f"Invalid timestamp format: {ts}. "
                         f"Expected format: '%Y/%m/%d %H:%M:%S.%f%z'.")


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
    SMTP_LOGIN_BRUTE_FORCE = auto()
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
    THREAT_INTELLIGENCE_BLACKLISTED_IP = auto()
    THREAT_INTELLIGENCE_BLACKLISTED_DOMAIN = auto()
    MALICIOUS_DOWNLOADED_FILE = auto()
    MALICIOUS_URL = auto()

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


class Anomaly(Enum):
    """
    https://idea.cesnet.cz/en/classifications
    """
    TRAFFIC = "Anomaly.Traffic"
    FILE = "Anomaly.File"
    CONNECTION = "Anomaly.Connection"
    BEHAVIOUR = "Anomaly.Behaviour"


class Recon(Enum):
    RECON = "Recon"
    SCANNING = "Recon.Scanning"


class Attempt(Enum):
    LOGIN = "Attempt.Login"


class Tag(Enum):
    """
    this is the IDEA category of the source and dst ip used in the evidence
    if the Attacker.Direction is srcip this describes the source ip,
    if the Attacker.Direction is dstip this describes the dst ip.
    supported source and dst types are in the SourceTargetTag
    section https://idea.cesnet.cz/en/classifications
    this is optional in an evidence because it shouldn't
    be used with dports and sports Attacker.Direction
    """
    SUSPICIOUS_USER_AGENT = 'SuspiciousUserAgent'
    INCOMPATIBLE_USER_AGENT = 'IncompatibleUserAgent'
    EXECUTABLE_MIME_TYPE = 'ExecutableMIMEType'
    MULTIPLE_USER_AGENT = 'MultipleUserAgent'
    SENDING_UNENCRYPTED_DATA = 'SendingUnencryptedData'
    MALWARE = 'Malware'
    RECON = 'Recon'
    MITM = 'MITM'
    ORIGIN_MALWARE = 'OriginMalware'
    CC = 'CC'
    BOTNET = 'Botnet'
    BLACKLISTED_ASN = 'BlacklistedASN'
    BLACKLISTED_IP = 'BlacklistedIP'
    BLACKLISTED_DOMAIN = 'BlacklistedDomain'


class Proto(Enum):
    TCP = 'tcp'
    UDP = 'udp'
    ICMP = 'icmp'




@dataclass
class Victim:
    direction: Direction
    victim_type: IoCType
    value: str  # like the actual ip/domain/url check if value is reserved


@dataclass
class IDEACategory:
    """
    The evidence category according to IDEA categories
    https://idea.cesnet.cz/en/classifications
    """
    anomaly: Anomaly
    information = "Information"
    malware = "Malware"
    alert = auto()


@dataclass
class ProfileID:
    ip: str = field(metadata={
        'validate': lambda x: ipaddress.ip_address(x)
        }
    )

    def __repr__(self):
        return f"profile_{self.ip}"


@dataclass
class Attacker:
    direction: Direction
    attacker_type: IoCType
    value: str  # like the actual ip/domain/url check if value is reserved
    profile: ProfileID = field(defaut='')

    def __post_init__(self):
        # each attacker should have a profile if it's an IP
        if self.attacker_type == IoCType.IP:
            self.profile = ProfileID(ip=self.value)


@dataclass
class TimeWindow:
    number: int

    def __repr__(self):
        return f"timewindow{self.number}"


@dataclass
class Evidence:
    evidence_type: EvidenceType
    description: str
    attacker: Attacker
    # @@@@@@@@@@@@@@@@@@@@ todo make sure evidence.threat_level is always a
    #  tl  obj
    threat_level: ThreatLevel
    category: IDEACategory
    victim: Victim # this is not defined in all evidence, it should be #TODO
    # profile of the srcip detected this evidence
    profile: ProfileID
    # @@@@@@@@@@@@@@@ TODO always pass it in utils.alerts_format format
    timewindow: TimeWindow
    # the uids of the flows causing this evidence
    # @@@@@@@@@@@@ todo make sure this is always a list
    uid: List[str]
    timestamp: str = field(
        metadata={
            'validate': lambda x: validate_timestamp(x)
            }
        )
    proto: Proto = field(default=False)
    port: int = field(default=False)
    source_target_tag: Tag = field(default=False)
    # every evidence should have an ID according to the IDEA format
    id: str = field(default_factory=lambda: str(uuid4()))
    # the number of packets/flows/nxdomains that formed this scan/sweep/DGA.
    conn_count: int = field(
        default=1,
        metadata={
            'validate': lambda x: isinstance(x, int)
            }
        )
    # the confidence of this evidence on a scale from 0 to 1.
    # How sure you are that this evidence is what you say it is?
    confidence: float = field(
          default=0.0,
          metadata={
              'validate': lambda x: 0 <= x <= 1
            }
        )

    def __post_init__(self):
        # remove duplicate uids
        self.uid = list(set(self.uid))