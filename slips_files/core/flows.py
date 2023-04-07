"""
Data classes for all types of flows
"""
from dataclasses import dataclass
from typing import List
from datetime import datetime, timedelta
@dataclass
class Conn:
    uid: str

    saddr: str
    daddr: str

    dur: float
    starttime: str

    proto: str
    appproto: str

    sport: str
    dport: str

    spkts: int
    dpkts: int

    sbytes: int
    dbytes: int

    smac: str
    dmac: str

    state: str
    history: str

    type_: str = 'conn'
    dir_: str = '->'

    def __post_init__(self) -> None:
        endtime = str(self.starttime) + str(timedelta(seconds=self.dur))
        self.endtime: str = endtime
        self.pkts: int =  self.spkts + self.dpkts
        self.bytes: int =  self.sbytes + self.dbytes
        self.state_hist: str = self.history or self.state

@dataclass
class DNS:
    starttime: str
    uid: str
    saddr: str
    daddr: str


    query: str

    qclass_name: str
    qtype_name: str
    rcode_name: str

    answers: str
    TTLs: str

    type_: str = 'dns'

    def __post_init__(self) -> None:
        # If the answer is only 1, Zeek gives a string
        # so convert to a list
        self.answers = [self.answers] if type(self.answers) == str else self.answers

@dataclass
class HTTP:
    starttime: str
    uid: str
    saddr: str
    daddr: str

    method: str
    host: str
    uri: str
    version: int
    user_agent: str
    request_body_len: int
    response_body_len: int
    status_code: str
    status_msg: str
    resp_mime_types: str
    resp_fuids: str

    type_: str = 'http'

    def __post_init__(self) -> None:
        pass

@dataclass
class SSL:
    starttime: str
    uid: str
    saddr: str
    daddr: str

    version: str
    sport: str
    dport: str

    cipher: str
    resumed: str

    established: str
    cert_chain_fuids: str
    client_cert_chain_fuids: str

    subject: str

    issuer: str
    validation_status: str
    curve: str
    server_name: str

    ja3: str
    ja3s: str
    is_DoH: str

    type_: str = 'ssl'

@dataclass
class SSH:
    starttime: float
    uid: str
    saddr: str
    daddr: str

    version: int
    auth_success: bool
    auth_attempts: int

    client: str
    server: str
    cipher_alg: str
    mac_alg: str

    compression_alg: str
    kex_alg: str

    host_key_alg: str
    host_key: str

    type_: str = "ssh"

@dataclass
class DHCP:
    starttime: float
    uids: List[str]
    saddr: str
    daddr: str

    client_addr: str
    server_addr: str
    host_name: str

    mac: str  # this is the client mac
    requested_addr: str

    type_: str = "dhcp"

    def __post_init__(self) -> None:
        # Some zeek flow don't have saddr or daddr,
        # seen in dhcp.log and notice.log use the mac
        # address instead
        if not self.saddr and not self.daddr:
            self.saddr = self.mac
@dataclass
class FTP:
    starttime: float
    uid: str
    saddr: str
    daddr: str

    used_port: int
    type_: str = "ftp"

@dataclass
class SMTP:
    starttime: float
    uid: str
    saddr: str
    daddr: str

    last_reply: str
    type_: str = "smtp"

@dataclass
class Tunnel:
    starttime: str
    uid: str
    saddr: str
    daddr: str

    sport: str
    dport: str

    tunnel_type: str
    action: str

    type_: str = 'tunnel'









