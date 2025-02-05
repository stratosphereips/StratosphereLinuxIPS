# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import sys
import traceback

from slips_files.common.abstracts.input_type import IInputType
from slips_files.common.slips_utils import utils
from slips_files.core.flows.argus import ArgusConn


class Argus(IInputType):
    def __init__(self):
        self.from_stdin = self.reading_flows_from_stdin()

    def reading_flows_from_stdin(self) -> bool:
        """returns true if we're reading argus flows from stdin"""
        return "-f" in sys.argv and "argus" in sys.argv

    def process_line(self, new_line: dict):
        """
        Process the line and extract columns for argus
        """

        self.separator = "," if new_line["data"].count(",") > 5 else "\t"

        # make sure we have a map of each field and its' index
        if not hasattr(self, "column_idx"):
            self.define_columns(new_line)
            return

        line = new_line["data"]
        nline = line.strip().split(self.separator)

        def get_value_of(field_name, default_=False):
            """field_name is used to get the index of
            the field from the column_idx dict"""
            try:
                val = nline[self.column_idx[field_name]]
                return val or default_
            except (IndexError, KeyError):
                return default_

        self.flow: ArgusConn = ArgusConn(
            utils.convert_to_datetime(get_value_of("starttime")),
            get_value_of("endtime"),
            get_value_of("dur"),
            get_value_of("proto"),
            get_value_of("appproto"),
            get_value_of("saddr"),
            get_value_of("sport"),
            get_value_of("dir"),
            get_value_of("daddr"),
            get_value_of("dport"),
            get_value_of("state"),
            int(get_value_of("pkts")),
            int(get_value_of("spkts")),
            int(get_value_of("dpkts")),
            int(get_value_of("bytes")),
            int(get_value_of("sbytes")),
            int(get_value_of("dbytes")),
        )

        return self.flow

    def get_predefined_argus_column_indices(self):
        """default column indices in case of reading argus from stdin"""
        return {
            "starttime": 0,
            "dur": 1,
            "proto": 2,
            "saddr": 3,
            "sport": 4,
            "dir": 5,
            "daddr": 6,
            "dport": 7,
            "state": 8,
            "pkts": 11,
            "bytes": 12,
            "sbytes": 13,
            "spkts": 14,
        }

    def define_columns(self, new_line: dict) -> dict:
        """
        Define the columns for Argus  from the line received
        sets teh self.column_idx var
        :param new_line: should be the header line of the argus file
        """
        if self.from_stdin:
            # reading argus flows from stdin, we have a pre-defined indices map for this
            self.column_idx = self.get_predefined_argus_column_indices()
            return self.column_idx

        # These are the indices for later fast processing
        line = new_line["data"]
        self.column_idx = {}
        # these are the fields as slips understands them
        # {original_argus_field_name: slips_field_name}
        supported_fields = {
            "time": "starttime",
            "endtime": "endtime",
            "appproto": "appproto",
            "dur": "dur",
            "proto": "proto",
            "srca": "saddr",
            "sport": "sport",
            "dir": "dir",
            "dsta": "daddr",
            "dport": "dport",
            "state": "state",
            "totpkts": "pkts",
            "totbytes": "bytes",
            "srcbytes": "sbytes",
            "dstbytes": "dbytes",
            "srcpkts": "spkts",
            "dstpkts": "dpkts",
        }
        try:
            nline = line.strip().split(self.separator)
            # parse the given nline, and try to map the fields we find to the fields slips
            # undertsands from the dict above.
            for field in nline:
                for original_field, slips_field in supported_fields.items():
                    if original_field in field.lower():
                        # found 1 original field that slips supports. store its' slips
                        # equivalent name and index in the column_index
                        self.column_idx[slips_field] = nline.index(field)
                        break
            return self.column_idx
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f"\tProblem in define_columns() line {exception_line}", 0, 1
            )
            self.print(traceback.format_exc(), 0, 1)
            sys.exit(1)
