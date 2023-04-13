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
    pkts: int
    spkts: int
    dpkts: int
    bytes: int
    sbytes: int
    dbytes: int
    # required to be able to add_flow
    smac: str = ''
    dmac: str = ''
    uid = False
    type_: str = 'argus'