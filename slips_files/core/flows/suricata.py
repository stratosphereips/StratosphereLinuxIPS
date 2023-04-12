from dataclasses import dataclass
from typing import List
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
    flow_id: str

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
    # smac: str = False
    # dmac: str = False
    # appproto: str = False
    dir_: str = '->'
    type_: str = 'suricata'

    def __post_init__(self):
        self.dur = (self.endtime - self.starttime).total_seconds() or 0
        self.pkts = self.dpkts + self.spkts
        self.bytes = self.dbytes + self.sbytes


