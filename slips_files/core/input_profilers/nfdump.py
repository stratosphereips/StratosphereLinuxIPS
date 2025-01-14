# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from slips_files.common.abstracts.input_type import IInputType
from slips_files.common.slips_utils import utils
from slips_files.core.flows.nfdump import NfdumpConn


class Nfdump(IInputType):
    separator = ","

    def __init__(self):
        pass

    def process_line(self, new_line):
        """
        Process the line and extract columns for nfdump
        """
        self.separator = ","
        line = new_line["data"]
        nline = line.strip().split(self.separator)

        def get_value_at(indx, default_=False):
            try:
                val = nline[indx]
                return val or default_
            except (IndexError, KeyError):
                return default_

        starttime = utils.convert_format(get_value_at(0), "unixtimestamp")
        endtime = utils.convert_format(get_value_at(1), "unixtimestamp")
        self.flow: NfdumpConn = NfdumpConn(
            starttime,
            endtime,
            get_value_at(2),
            get_value_at(7),
            get_value_at(3),
            get_value_at(5),
            get_value_at(22),
            get_value_at(4),
            get_value_at(6),
            get_value_at(8),
            get_value_at(11),
            get_value_at(13),
            get_value_at(12),
            get_value_at(14),
        )
        return self.flow
