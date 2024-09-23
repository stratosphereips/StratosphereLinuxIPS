from dataclasses import dataclass, field

from slips_files.common.slips_utils import utils


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
    uid: str = field(default_factory=utils.generate_uid)
    smac: str = ""
    dmac: str = ""
    type_: str = "argus"
