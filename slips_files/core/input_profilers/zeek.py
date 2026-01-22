# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from re import split
from typing import Dict, Tuple
from dataclasses import fields, MISSING

from slips_files.common.abstracts.iinput_type import IInputType
from slips_files.common.slips_utils import utils
from slips_files.core.flows.zeek import (
    Conn,
    DNS,
    HTTP,
    SSL,
    SSH,
    DHCP,
    SMTP,
    Tunnel,
    Notice,
    Files,
    ARP,
    Weird,
    Software,
    FTP,
)

from slips_files.core.input_profilers.zeek_to_slips_maps import (
    conn_fields_to_slips_fields_map,
    dns_fields_to_slips_fields_map,
    http_fields_to_slips_fields_map,
    ssl_fields_to_slips_fields_map,
    ssh_fields_to_slips_fields_map,
    dhcp_fields_to_slips_fields_map,
    ftp_fields_to_slips_fields_map,
    smtp_fields_to_slips_fields_map,
    tunnel_fields_to_slips_fields_map,
    notice_fields_to_slips_fields_map,
    files_fields_to_slips_fields_map,
    arp_fields_to_slips_fields_map,
    software_fields_to_slips_fields_map,
    weird_fields_to_slips_fields_map,
)

LOG_MAP = {
    "conn.log": conn_fields_to_slips_fields_map,
    "dns.log": dns_fields_to_slips_fields_map,
    "http.log": http_fields_to_slips_fields_map,
    "ssl.log": ssl_fields_to_slips_fields_map,
    "ssh.log": ssh_fields_to_slips_fields_map,
    "dhcp.log": dhcp_fields_to_slips_fields_map,
    "ftp.log": ftp_fields_to_slips_fields_map,
    "smtp.log": smtp_fields_to_slips_fields_map,
    "tunnel.log": tunnel_fields_to_slips_fields_map,
    "notice.log": notice_fields_to_slips_fields_map,
    "files.log": files_fields_to_slips_fields_map,
    "arp.log": arp_fields_to_slips_fields_map,
    "software.log": software_fields_to_slips_fields_map,
    "weird.log": weird_fields_to_slips_fields_map,
}

# define a mapping of log types to their corresponding classes
LINE_TYPE_TO_SLIPS_CLASS = {
    "conn.log": Conn,
    "dns.log": DNS,
    "http.log": HTTP,
    "ssl.log": SSL,
    "ssh.log": SSH,
    "dhcp.log": DHCP,
    "ftp.log": FTP,
    "arp.log": ARP,
    "smtp.log": SMTP,
    "tunnel.log": Tunnel,
    "notice.log": Notice,
    "files.log": Files,
    "weird.log": Weird,
    "software.log": Software,
}


class Zeek:
    """class that contains functions needed by the zeek-tabs and zeekjson
    classes"""

    def remove_subsuffix(self, file_name: str) -> str:
        """
        turns any x.log.y to x.log only
        """
        if ".log" in file_name:
            return file_name.split(".log")[0] + ".log"
        return file_name

    def get_file_type(self, new_line: dict) -> str:
        """
        returns x.log. always. no matter whats the name given to slips
        """
        file_type = new_line["type"]
        # all zeek lines received from stdin should be of type conn
        if (
            file_type in ("stdin", "external_module")
            and new_line.get("line_type", False) == "zeek"
        ):
            return "conn.log"

        # if the zeek dir given to slips has 'conn' in it's name,
        # slips thinks it's reading a conn file
        # because we use the file path as the file 'type'
        # to fix this, only use the file name as file 'type'
        return self.remove_subsuffix(file_type.split("/")[-1])

    def get_line_processor(self, new_line: dict) -> Dict[str, str]:
        """ """
        file_type: str = self.get_file_type(new_line)
        return LOG_MAP[file_type]

    def fill_empty_class_fields(self, flow_values: dict, slips_class):
        """
        - Fill missing dataclass fields with their default value
        (or empty string if no default exists).
        - Always force `type_` from the slips class, never from Zeek input.

        Returns a ready-to-use flow_values dict that has all the fields of
        the given slips_class

        :param flow_values: a dict with the values of the given zeek log line
        :param slips_class: the class that corresponds to the given zeek log
        line
        """
        for f in fields(slips_class):
            name = f.name
            # `type_` is enforced later
            if name == "type_":
                continue

            if name in flow_values:
                continue

            if f.default is not MISSING:
                flow_values[name] = f.default
            elif f.default_factory is not MISSING:  # type: ignore
                flow_values[name] = f.default_factory()  # type: ignore
            else:
                flow_values[name] = ""

        # always use the type_ field of the slips class, this is not gonna
        # be given to slips by zeek
        flow_values["type_"] = getattr(slips_class, "type_")

        return flow_values


class ZeekJSON(IInputType, Zeek):
    """
    An instance of this class is created once on each run, not created per
    flow.
    """

    def __init__(self, db):
        super().__init__()
        self.db = db
        self.line_processor_cache = {}
        # to avoid object churn. creating a new dict per flow is CPU
        # intensive, and triggers the GC more. this is for optimizations.
        self.reusable_flow_values_dict = {}

    def process_line(self, new_line: dict) -> Tuple[bool, str]:
        line = new_line["data"]
        interface = new_line["interface"]

        if not isinstance(line, dict):
            return False, "The given zeek line is not a dict"

        file_type = self.get_file_type(new_line)

        zeek_fields_to_slips_fields_map = LOG_MAP.get(file_type)
        if not zeek_fields_to_slips_fields_map:
            return False, "Can't find zeek_fields_to_slips_fields_map"

        if ts := line.get("ts", False):
            starttime = utils.convert_to_datetime(ts)
        else:
            starttime = ""

        # reusing the dict to avoid new obj (dict) creation per flow.
        self.reusable_flow_values_dict.clear()
        self.reusable_flow_values_dict.update(
            {"starttime": starttime, "interface": interface}
        )

        for zeek_field, slips_field in zeek_fields_to_slips_fields_map.items():
            if not slips_field:
                continue
            val = line.get(zeek_field, "")
            if val == "-":
                val = ""
            self.reusable_flow_values_dict[slips_field] = val

        if file_type in LINE_TYPE_TO_SLIPS_CLASS:
            slips_class = LINE_TYPE_TO_SLIPS_CLASS[file_type]
            if file_type == "conn.log":
                self.reusable_flow_values_dict["dur"] = float(
                    self.reusable_flow_values_dict.get("dur", 0) or 0
                )
                for field in (
                    "sbytes",
                    "dbytes",
                    "spkts",
                    "dpkts",
                    "sport",
                    "dport",
                ):
                    self.reusable_flow_values_dict[field] = int(
                        self.reusable_flow_values_dict.get(field, 0) or 0
                    )
            self.reusable_flow_values_dict = self.fill_empty_class_fields(
                self.reusable_flow_values_dict, slips_class
            )

            flow = slips_class(**self.reusable_flow_values_dict)

            return flow, ""

        err = f"Invalid file_type: {file_type}, line: {line}"
        print(err)
        return False, err


class ZeekTabs(IInputType, Zeek):
    separator = "\t"
    line_processor_cache = {}

    def __init__(self, db):
        super().__init__()
        self.db = db

    @staticmethod
    def split(line: str) -> list:
        """
        the data is either \t separated or space separated
        zeek files that are space separated are either separated by 2 or 3
        spaces so we can't use python's split()
        using regex split, split line when you encounter more
        than 2 spaces in a row
        """
        line = line.rstrip("\n")
        return line.split("\t") if "\t" in line else split(r"\s{2,}", line)

    def get_slips_fields_idx_map(
        self, fields_line: dict, zeek_to_slips_field_map: dict
    ) -> Dict[int, str]:
        """
        returns a dict that has slips fields as values and the index of
        each field as keys
        e.g {0: 'starttime', 1: 'uid', 2: 'saddr' etc...
        :param fields_line: a line that starts with #fields as read from
        the given zeek.log file
        :param zeek_to_slips_field_map: a dict that maps zeek fields to slips
        the returned dict may contain None if a zeek field in the given
        line doesnt have a slips equivalent (not used in slips)
        """
        fields_line = fields_line["data"].replace("#fields", "")
        # [1:] to remove the empty "" that was between the #fields and ts
        zeek_fields_list = self.split(fields_line)[1:]

        slips_fields_idx_map = {}
        for idx, zeek_field in enumerate(zeek_fields_list):
            # map field to slips name if possible
            slips_field = zeek_to_slips_field_map.get(zeek_field)
            slips_fields_idx_map[idx] = slips_field
        return slips_fields_idx_map

    def update_line_processor_cache(self, fields_line: dict) -> None:
        """
        We need to get the index of each field in the given fields_line
        this function retrieves the dict that has those indices,
        and caches them for later use.

        caching is done to avoid doing this step for each given log line.
        we only do it once for each #field line read

        :param fields_line: dict with "data": a line that starts with
        #fields as read from the given zeek.log file
        and "type": the type of the zeek log file
        """
        zeek_to_slips_field_map: Dict[str, str] = self.get_line_processor(
            fields_line
        )

        indices_of_each_slips_field: Dict[int, str]
        indices_of_each_slips_field = self.get_slips_fields_idx_map(
            fields_line, zeek_to_slips_field_map
        )

        file_type: str = self.get_file_type(fields_line)

        indices = {file_type: indices_of_each_slips_field}
        self.line_processor_cache.update(indices)
        # for currently started profiler workers to know about the new file
        # indices
        self.db.publish(
            self.db.channels.NEW_ZEEK_FIELDS_LINE, json.dumps(indices)
        )
        # if slips starts more profilers later, they can access the
        # processors from the db directly
        self.db.store_lines_processors(file_type, indices_of_each_slips_field)

    def get_value_at(self, line: list, index: int, default_=""):
        try:
            index = int(index)
            val = line[index]
            return default_ if val == "-" else val
        except IndexError:
            return default_

    def process_line(self, new_line: dict) -> Tuple[bool, str]:
        """
        Process the tab line from zeek.
        :param new_line: a dict with "type" and "data" keys
        returns True if a flow was sucessfully processed,
        and false with an err str if it's a fields line or an error occurred
        """
        line: str = new_line["data"]

        if line.startswith("#fields"):
            # depending on the given fields, we need to map the zeek fields
            # to some slips obj (SSL, Con, SSH, etc...)
            # cache the mapping for later use
            self.update_line_processor_cache(new_line)
            return False, "Field line processed"

        file_type: str = self.get_file_type(new_line)
        # this dict is the name of each slips field and the index of it
        # in the given zeek line
        line_processor: Dict[int, str]
        line_processor = self.line_processor_cache.get(file_type)

        if not line_processor:
            return False, "unknown line_processor"

        line: list = self.split(line)

        if ts := line[0]:
            starttime = utils.convert_to_datetime(ts)
        else:
            starttime = ""

        flow_values = {"starttime": starttime}

        # this line_processor dict is like {0: 'starttime', 1: 'uid',
        # 2: 'saddr' etc...
        for idx, field in line_processor.items():
            # a field may be None if its present in zeek but not used in
            # slips.
            if not field:
                continue

            flow_values[field] = self.get_value_at(line, idx, "")

        log_type: str = self.get_file_type(new_line)
        if log_type in LINE_TYPE_TO_SLIPS_CLASS:
            # convert types for known fields if needed
            if log_type == "conn.log":
                flow_values["dur"] = float(flow_values.get("dur", 0) or 0)

                conn_fields_to_convert_to_int = (
                    "sbytes",
                    "dbytes",
                    "spkts",
                    "dpkts",
                    "sport",
                    "dport",
                )
                for field in conn_fields_to_convert_to_int:
                    flow_values[field] = int(flow_values.get(field, 0) or 0)

            # Conn, SSH, Notice, etc.
            slips_class = LINE_TYPE_TO_SLIPS_CLASS[log_type]

            flow_values = self.fill_empty_class_fields(
                flow_values, slips_class
            )

            # create the corresponding object using the mapped class
            flow = slips_class(**flow_values)
            return flow, ""

        print(f"[Profiler] Invalid file_type: {log_type}, line: {line}")
        return False, f"Invalid file_type: {log_type}, line: {line}"
