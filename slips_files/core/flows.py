"""
Data classes for all types of flows
"""
from dataclasses import dataclass
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