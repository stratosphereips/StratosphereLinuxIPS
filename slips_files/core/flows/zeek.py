"""
Data classes for all types of zeek flows
"""
from dataclasses import dataclass
from typing import List
from datetime import datetime, timedelta
from slips_files.common.slips_utils import utils
import json

@dataclass
class Conn:
    starttime: str
    uid: str
    saddr: str
    daddr: str

    dur: float

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
        self.pkts: int = self.spkts + self.dpkts
        self.bytes: int = self.sbytes + self.dbytes
        self.state_hist: str = self.history or self.state
        # community IDs are for conn.log flows only
        self.aid = utils.get_aid(self)

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

    smac: str  # this is the client mac
    requested_addr: str

    type_: str = "dhcp"

    def __post_init__(self) -> None:
        # Some zeek flow don't have saddr or daddr,
        # seen in dhcp.log and notice.log use the mac
        # address instead
        if not self.saddr and not self.daddr:
            self.saddr = self.smac

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

    sport: int
    dport: int

    tunnel_type: str
    action: str

    type_: str = 'tunnel'

@dataclass
class Notice:
    starttime: str
    uid: str
    saddr: str
    daddr: str

    sport: int
    dport: int

    note: str
    msg: str

    scanned_port: str
    scanning_ip: str

    #TODO srsly what is this?
    dst: str

    type_: str = 'notice'
    def __post_init__(self) -> None:
        # portscan notices don't have id.orig_h or id.resp_h fields, instead they have src and dst
        if not self.saddr:
            self.saddr = self.scanning_ip

        if not self.daddr:
            # set daddr to src for now because the notice
            # that contains portscan doesn't have
            # a dst field and slips needs it to work
            self.daddr = self.dst or self.saddr

        if not self.dport:
            # set the dport to the p field if it's there
            self.dport = self.scanned_port

        if not self.scanned_port:
            # set the dport to the p field if it's there
            self.dport = self.dport
@dataclass
class Files:
    starttime: str
    uid: str
    saddr: str
    daddr: str

    size: int # downloaded file size
    md5: str

    source: str
    analyzers: str
    sha1: str

    tx_hosts: List[str]
    rx_hosts: List[str]

    type_: str = 'files'
    def __post_init__(self) -> None:
        if type(self.tx_hosts) != list:
            self.tx_hosts = [self.tx_hosts]
        if saddr := self.tx_hosts[0]:
            self.saddr = saddr

        if type(self.rx_hosts) != list:
            self.rx_hosts = [self.rx_hosts]

        if daddr := self.rx_hosts[0]:
            self.daddr = daddr


@dataclass
class ARP:
    starttime: str
    uid: str
    saddr: str
    daddr: str

    smac: str
    dmac: str

    src_hw: str
    dst_hw: str

    operation: str
    # the following fields are necessary for the add_flow() function
    # the main goal is to treal ARP flows as conn.log flows and show
    # them in the timeline #TODO find a better way
    dur: str = '0'
    proto: str = 'ARP'
    state: str = ''
    pkts: int = 0
    sport: str = ''
    dport: str = ''
    bytes: str = ''
    sbytes: str = ''
    dbytes: str = ''
    spkts: str = ''
    dpkts: str = ''
    appproto: str = ''

    type_: str = 'arp'
@dataclass
class Software:
    starttime: str
    uid: str
    saddr: str
    daddr: str

    software: str

    unparsed_version: str
    version_major: str
    version_minor: str
    type_: str = 'software'

    def __post_init__(self) -> None:
        # store info about everything except http:broswer
        # we're already reading browser UA from http.log
        self.http_browser = self.software == 'HTTP::BROWSER'

@dataclass
class Weird:
    starttime: str
    uid: str
    saddr: str
    daddr: str

    name: str
    addl: str

    type_: str = 'weird'














