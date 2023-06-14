from dataclasses import dataclass
from slips_files.common.slips_utils import utils
from datetime import datetime, timedelta
import json

"""
#     suricata available event_type values:
#     -flow
#     -tls
#     -http
#     -dns
#     -alert
#     -fileinfo
#     -stats (only one line - it is conclusion of entire capture)
"""


@dataclass
class SuricataFlow:
    # A suricata line of flow type usually has 2 components.
    # 1. flow information
    # 2. tcp information
    uid: str

    saddr: str
    sport: str

    daddr: str
    dport: str

    proto: str
    appproto: str

    starttime: str
    endtime: str

    spkts: int
    dpkts: int

    sbytes: int
    dbytes: int
    """
    There are different states in which a flow can be.
    Suricata distinguishes three flow-states for TCP and two for UDP. For TCP,
    these are: New, Established and Closed,for UDP only new and established.
    For each of these states Suricata can employ different timeouts.
    """
    state: str

    # required to be able to add_flow
    smac: str = ''
    dmac: str = ''
    dir_: str = '->'
    type_: str = 'conn'

    def __post_init__(self):
        self.dur = (
               utils.convert_to_datetime(self.endtime)
               - utils.convert_to_datetime(self.starttime)
            ).total_seconds() or 0
        self.pkts = self.dpkts + self.spkts
        self.bytes = self.dbytes + self.sbytes

@dataclass
class SuricataHTTP:
    starttime: str
    uid: str

    saddr: str
    sport: str

    daddr: str
    dport: str

    proto: str
    appproto: str

    method: str
    host: str
    uri: str

    user_agent: str
    status_code: str

    version: str

    request_body_len: int
    response_body_len: int

    status_msg: str = ''
    resp_mime_types: str = ''
    resp_fuids: str = ''
    type_:str = 'http'

@dataclass
class SuricataDNS:
    starttime: str
    uid: str

    saddr: str
    sport: str

    daddr: str
    dport: str

    proto: str
    appproto: str

    query: str
    TTLs: str
    qtype_name: str
    answers: list

    # these alues are not present in eve.json
    qclass_name: str = ''
    rcode_name: str = ''
    type_: str = 'dns'


@dataclass
class SuricataTLS:
    starttime: str
    uid: str

    saddr: str
    sport: str

    daddr: str
    dport: str

    proto: str
    appproto: str

    sslversion: str
    subject: str

    issuer: str
    server_name: str

    notbefore: str
    notafter: str

    type_: str = 'ssl'


@dataclass
class SuricataFile:
    starttime: str
    uid: str

    saddr: str
    sport: str

    daddr: str
    dport: str

    proto: str
    appproto: str

    size: int
    type_: str = 'files'
    # required to match zeek files.log
    md5: str = ''
    sha1: str = ''
    source: str =''
    analyzers: str =''
    tx_hosts: str = ''
    rx_hosts: str = ''

@dataclass
class SuricataSSH:
    starttime: str
    uid: str

    saddr: str
    sport: str

    daddr: str
    dport: str

    proto: str
    appproto: str

    client: str
    version: str
    server: str

    # these fields aren't available in suricata, they're available in zeek only
    auth_success: str = ''
    auth_attempts: str = ''
    cipher_alg: str = ''
    mac_alg: str = ''
    kex_alg: str = ''
    compression_alg: str = ''
    host_key_alg: str = ''
    host_key: str = ''

    type_: str = 'ssh'

