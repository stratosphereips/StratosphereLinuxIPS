from dataclasses import dataclass

@dataclass
class ArgusConn:
    starttime: str
    endtime: str
    dur: str
    proto: str
    appproto: str
    saddr: str
    sport: str
    dir_: str
    daddr: str
    dport: str
    state: str
    pkts: str
    spkts: str
    dpkts: str
    bytes: int
    sbytes: int
    dbytes: int
    # required to be able to add_flow
    smac: str = ''
    dmac: str = ''
    type_: str = 'argus'