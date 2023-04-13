from dataclasses import dataclass

@dataclass
class NfdumpConn:
    starttime: str
    endtime: str

    dur: str
    proto: str

    saddr: str
    sport: str

    dir_: str

    daddr: str
    dport: str

    state: str
    spkts: str
    dpkts: str

    sbytes: int
    dbytes: int
    # required to be able to add_flow
    smac = False
    dmac = False
    appproto = False
    uid = False
    type_: str = 'nfdump'


    def __post_init__(self):
        self.pkts = self.spkts + self.dpkts
        self.bytes = self.sbytes + self.dbytes