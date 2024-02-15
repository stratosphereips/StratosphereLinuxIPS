"""
Contains evidence dataclass that is used in slips
"""
import ipaddress
from dataclasses import dataclass, field, asdict, is_dataclass
from enum import Enum, auto
from uuid import uuid4
from typing import List, Optional

from slips_files.common.slips_utils import utils


def validate_ip(ip):
    ipaddress.ip_address(ip)

def validate_timestamp(ts) -> str:
    """
    the ts of all evidence should be in
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

    def __post_init__(self):
        if self.victim_type == IoCType.IP:
            validate_ip(self.value)


class IDEACategory(Enum):
    """
    The evidence category according to IDEA categories
    https://idea.cesnet.cz/en/classifications
    """
    ANOMALY_TRAFFIC = "Anomaly.Traffic"
    ANOMALY_FILE = "Anomaly.File"
    ANOMALY_CONNECTION = "Anomaly.Connection"
    ANOMALY_BEHAVIOUR = "Anomaly.Behaviour"
    INFO = "Information"
    MALWARE = "Malware"
    RECON_SCANNING = "Recon.Scanning"
    ATTEMPT_LOGIN = "Attempt.Login"
    RECON = "Recon"
    INTRUSION_BOTNET = "Intrusion.Botnet"



@dataclass
class ProfileID:
    ip: str

    def __setattr__(self, name, value):
        if name == 'ip':
            assert ipaddress.ip_address(value)
        self.__dict__[name] = value

    def __repr__(self):
        return f"profile_{self.ip}"


@dataclass
class Attacker:
    direction: Direction
    attacker_type: IoCType
    value: str  # like the actual ip/domain/url check if value is reserved
    profile: ProfileID = ''

    def __post_init__(self):
        if self.attacker_type == IoCType.IP:
            validate_ip(self.value)
        # each attacker should have a profile if it's an IP
        if self.attacker_type == IoCType.IP:
            self.profile = ProfileID(ip=self.value)


@dataclass
class TimeWindow:
    number: int

    def __post_init__(self):
        if not isinstance(self.number, int):
            raise ValueError(f"timewindow number must be an int. "
                             f"{self.number} is invalid!")

    def __repr__(self):
        return f"timewindow{self.number}"


@dataclass
class Evidence:
    evidence_type: EvidenceType
    description: str
    attacker: Attacker
    threat_level: ThreatLevel
    category: IDEACategory
    # profile of the srcip detected this evidence
    profile: ProfileID
    timewindow: TimeWindow
    # the uids of the flows causing this evidence
    uid: List[str]
    timestamp: str = field(
        metadata={
            'validate': lambda x: validate_timestamp(x)
            }
        )
    victim: Optional[Victim] = field(default=False)
    proto: Optional[Proto] = field(default=False)
    port: int = field(default=None)
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
        if (
                not isinstance(self.uid, list)
                or
                not all(isinstance(uid, str) for uid in self.uid)
        ):
            raise ValueError(f"uid must be a list of strings .. {self}")
        else:
            # remove duplicate uids
            self.uid = list(set(self.uid))



def evidence_to_dict(obj):
    """
    Converts an Evidence object to a dictionary (aka json serializable)
    :param obj: object of any type.
    """
    if is_dataclass(obj):
        # run this function on each value of the given dataclass
        return {k: evidence_to_dict(v) for k, v in asdict(obj).items()}

    if isinstance(obj, Enum):
        return obj.name

    if isinstance(obj, list):
        return [evidence_to_dict(item) for item in obj]

    if isinstance(obj, dict):
        return {k: evidence_to_dict(v) for k, v in obj.items()}

    return obj

def dict_to_evidence(evidence: dict):
    """
    Convert a dictionary to an Evidence object.
    :param evidence (dict): Dictionary with evidence details.
    returns an instance of the Evidence class.
    """
    evidence_attributes = {
        'evidence_type': EvidenceType[evidence["evidence_type"]],
        'description': evidence['description'],
        'attacker': Attacker(**evidence['attacker']),
        'threat_level': ThreatLevel[evidence['threat_level']],
        'category': IDEACategory[evidence['category']],
        'victim': Victim(**evidence['victim']) if 'victim' in evidence
        and evidence['victim'] else None,
        'profile': ProfileID(evidence['profile']['ip'])
                    if 'profile' in evidence else None,
        'timewindow': TimeWindow(evidence['timewindow']['number']),
        'uid': evidence['uid'],
        'timestamp': evidence['timestamp'],
        'proto': Proto[evidence['proto'].upper()] if 'proto' in evidence and
                                             evidence['proto'] else None,
        'port': evidence['port'],
        'source_target_tag': Tag[evidence['source_target_tag']] if \
            'source_target_tag' in evidence and evidence['source_target_tag']
                    else None,
        'id': evidence['id'],
        'conn_count': evidence['conn_count'],
        'confidence': evidence['confidence']
    }

    return Evidence(**evidence_attributes)