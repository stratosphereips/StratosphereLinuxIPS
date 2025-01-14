# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from dataclasses import dataclass, field
from slips_files.common.slips_utils import utils


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
    uid: str = field(default_factory=utils.generate_uid)
    # required to be able to call self.db.add_flow() in profiler
    smac = False
    dmac = False
    appproto = False
    type_: str = "nfdump"

    def __post_init__(self):
        self.pkts = self.spkts + self.dpkts
        self.bytes = self.sbytes + self.dbytes
