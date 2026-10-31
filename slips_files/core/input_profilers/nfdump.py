# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from typing import Tuple

from slips_files.common.abstracts.iinput_type import IInputType
from slips_files.common.slips_utils import utils
from slips_files.core.flows.nfdump import NfdumpConn


class Nfdump(IInputType):
    separator = ","

    def __init__(self, db):
        self.db = db

    def process_line(self, new_line) -> Tuple[bool, str]:
        """
        Process the line and extract columns for nfdump
        """
        line = new_line["data"]
        nline = line.strip().split(self.separator)

        def get_value_at(indx, default_=False):
            try:
                val = nline[indx].strip()
                return val or default_
            except (IndexError, KeyError):
                return default_

        starttime = utils.convert_ts_format(get_value_at(0), "unixtimestamp")
        endtime = utils.convert_ts_format(get_value_at(1), "unixtimestamp")
        protocol = str(get_value_at(7)).lower()
        protocol = {"1": "icmp", "6": "tcp", "17": "udp", "58": "icmp6"}.get(
            protocol, protocol
        )
        self.flow: NfdumpConn = NfdumpConn(
            starttime=starttime,
            endtime=endtime,
            dur=get_value_at(2),
            proto=protocol,
            saddr=get_value_at(3),
            sport=get_value_at(5),
            dir_=get_value_at(22),
            daddr=get_value_at(4),
            dport=get_value_at(6),
            state=get_value_at(8),
            spkts=int(get_value_at(11, 0)),
            dpkts=int(get_value_at(13, 0)),
            sbytes=int(get_value_at(12, 0)),
            dbytes=int(get_value_at(14, 0)),
        )
        return self.flow, ""
