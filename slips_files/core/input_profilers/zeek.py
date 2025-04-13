# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from datetime import datetime
from re import split
from typing import Dict
from slips_files.common.abstracts.input_type import IInputType
from slips_files.common.slips_utils import utils
from slips_files.core.flows.zeek import (
    Conn,
    DNS,
    HTTP,
    SSL,
    SSH,
    DHCP,
    FTP,
    SMTP,
    Tunnel,
    Notice,
    Files,
    ARP,
    Software,
    Weird,
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
    "smtp.log": SMTP,
    "tunnel.log": Tunnel,
    "notice.log": Notice,
    "files.log": Files,
    "weird.log": Weird,
}


class ZeekJSON(IInputType):
    def __init__(self):
        pass

    def process_line(self, new_line: dict):
        """
        Process one zeek line(new_line) and extract columns
        (parse them into column_values dict) to send to the database
        """
        line = new_line["data"]
        file_type = new_line["type"]
        # all zeek lines recieved from stdin should be of type conn
        if (
            file_type in ("stdin", "external_module")
            and new_line.get("line_type", False) == "zeek"
        ):
            file_type = "conn"
        else:
            # if the zeek dir given to slips has 'conn' in it's name,
            # slips thinks it's reading a conn file
            # because we use the file path as the file 'type'
            # to fix this, only use the file name as file 'type'
            file_type = file_type.split("/")[-1]

        if ts := line.get("ts", False):
            starttime: datetime = utils.convert_to_datetime(ts)
        else:
            starttime = ""

        if "conn" in file_type:
            self.flow: Conn = Conn(
                starttime,
                line.get("uid", False),
                line.get("id.orig_h", ""),
                line.get("id.resp_h", ""),
                line.get("duration", 0),
                line.get("proto", ""),
                line.get("service", ""),
                line.get("id.orig_p", ""),
                line.get("id.resp_p", ""),
                line.get("orig_pkts", 0),
                line.get("resp_pkts", 0),
                line.get("orig_bytes", 0),
                line.get("resp_bytes", 0),
                line.get("orig_l2_addr", ""),
                line.get("resp_l2_addr", ""),
                line.get("conn_state", ""),
                line.get("history", ""),
            )
            # orig_bytes: The number of payload bytes the src sent.
            # orig_ip_bytes: the length of the header + the payload

        elif "dns" in file_type:
            self.flow: DNS = DNS(
                starttime=starttime,
                uid=line.get("uid", False),
                saddr=line.get("id.orig_h", ""),
                daddr=line.get("id.resp_h", ""),
                dport=line.get("id.resp_p", ""),
                sport=line.get("id.orig_p", ""),
                proto=line.get("proto", ""),
                query=line.get("query", ""),
                qclass_name=line.get("qclass_name", ""),
                qtype_name=line.get("qtype_name", ""),
                rcode_name=line.get("rcode_name", ""),
                answers=line.get("answers", ""),
                TTLs=line.get("TTLs", ""),
            )

        elif "http" in file_type:
            self.flow: HTTP = HTTP(
                starttime,
                line.get("uid", False),
                line.get("id.orig_h", ""),
                line.get("id.resp_h", ""),
                line.get("method", ""),
                line.get("host", ""),
                line.get("uri", ""),
                line.get("version", 0),
                line.get("user_agent", ""),
                line.get("request_body_len", 0),
                line.get("response_body_len", 0),
                line.get("status_code", ""),
                line.get("status_msg", ""),
                line.get("resp_mime_types", ""),
                line.get("resp_fuids", ""),
            )

        elif "ssl" in file_type:
            self.flow: SSL = SSL(
                starttime,
                line.get("uid", False),
                line.get("id.orig_h", ""),
                line.get("id.resp_h", ""),
                line.get("version", ""),
                line.get("id.orig_p", ","),
                line.get("id.resp_p", ","),
                line.get("cipher", ""),
                line.get("resumed", ""),
                line.get("established", ""),
                line.get("cert_chain_fuids", ""),
                line.get("client_cert_chain_fuids", ""),
                line.get("subject", ""),
                line.get("issuer", ""),
                line.get("validation_status", ""),
                line.get("curve", ""),
                line.get("server_name", ""),
                line.get("ja3", ""),
                line.get("ja3s", ""),
                line.get("is_DoH", "false"),
            )
        elif "ssh" in file_type:
            self.flow: SSH = SSH(
                starttime,
                line.get("uid", False),
                line.get("id.orig_h", ""),
                line.get("id.resp_h", ""),
                line.get("version", ""),
                line.get("auth_success", ""),
                line.get("auth_attempts", ""),
                line.get("client", ""),
                line.get("server", ""),
                line.get("cipher_alg", ""),
                line.get("mac_alg", ""),
                line.get("compression_alg", ""),
                line.get("kex_alg", ""),
                line.get("host_key_alg", ""),
                line.get("host_key", ""),
            )
        elif "dhcp" in file_type:
            self.flow: DHCP = DHCP(
                starttime,
                line.get("uids", []),
                line.get("client_addr", ""),  # saddr
                line.get("server_addr", ""),  # daddr
                line.get("client_addr", ""),
                line.get("server_addr", ""),
                line.get("host_name", ""),
                line.get("mac", ""),  # this is the client mac
                line.get("requested_addr", ""),
            )
        elif "ftp" in file_type:
            self.flow: FTP = FTP(
                starttime,
                line.get("uid", []),
                line.get("id.orig_h", ""),
                line.get("id.resp_h", ""),
                line.get("data_channel.resp_p", False),
            )
        elif "smtp" in file_type:
            self.flow: SMTP = SMTP(
                starttime,
                line.get("uid", ""),
                line.get("id.orig_h", ""),
                line.get("id.resp_h", ""),
                line.get("last_reply", ""),
            )
        elif "tunnel" in file_type:
            self.flow: Tunnel = Tunnel(
                starttime,
                line.get("uid", ""),
                line.get("id.orig_h", ""),
                line.get("id.resp_h", ""),
                line.get("id.orig_p", ""),
                line.get("id.resp_p", ""),
                line.get("tunnel_type", ""),
                line.get("action", ""),
            )

        elif "notice" in file_type:
            self.flow: Notice = Notice(
                starttime=starttime,
                uid=line.get("uid", ""),
                saddr=line.get("id.orig_h", ""),
                daddr=line.get("id.resp_h", ""),
                sport=line.get("id.orig_p", ""),
                dport=line.get("id.resp_p", ""),
                note=line.get("note", ""),
                msg=line.get("msg", ""),
                scanned_port=line.get("p", ""),
                scanning_ip=line.get("src", ""),
                dst=line.get("dst", ""),
            )

        elif "files.log" in file_type:
            self.flow: Files = Files(
                starttime,
                line.get("conn_uids", [""])[0],
                line.get("id.orig_h", ""),
                line.get("id.resp_h", ""),
                line.get("seen_bytes", ""),  # downloaded file size
                line.get("md5", ""),
                line.get("source", ""),
                line.get("analyzers", ""),
                line.get("sha1", ""),
                line.get(
                    "tx_hosts", ""
                ),  # this srcip is tx_hosts in the zeek files.log, aka sender of the
                # file, aka server
                line.get("rx_hosts", ""),  # this is the host that received
                # the file
            )
        elif "arp" in file_type:
            self.flow: ARP = ARP(
                starttime,
                line.get("uid", ""),
                line.get("orig_h", ""),
                line.get("resp_h", ""),
                line.get("src_mac", ""),
                line.get("dst_mac", ""),
                line.get("orig_hw", ""),
                line.get("resp_hw", ""),
                line.get("operation", ""),
            )

        elif "software" in file_type:
            self.flow: Software = Software(
                starttime,
                line.get("uid", ""),
                line.get("host", ""),
                line.get("resp_h", ""),
                line.get("software_type", ""),
                line.get("unparsed_version", ""),
                line.get("version.major", ""),
                line.get("version.minor", ""),
            )

        elif "weird" in file_type:
            self.flow: Weird = Weird(
                starttime,
                line.get("uid", ""),
                line.get("host", ""),
                line.get("resp_h", ""),
                line.get("name", ""),
                line.get("addl", ""),
            )

        else:
            return False
        return self.flow


class ZeekTabs(IInputType):
    separator = "\t"
    line_processor_cache = {}

    def __init__(self):
        pass

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

    @staticmethod
    def remove_subsuffix(file_name: str) -> str:
        """
        turns any x.log.y to x.log only
        """
        if ".log" in file_name:
            return file_name.split(".log")[0] + ".log"
        return file_name

    def get_file_type(self, new_line: dict) -> str:
        """
        returnx x.log. always. no atter whats the name given to slips
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
        self.line_processor_cache.update(
            {file_type: indices_of_each_slips_field}
        )

    def get_value_at(self, line: list, index: int, default_=""):
        try:
            val = line[index]
            return default_ if val == "-" else val
        except IndexError:
            return default_

    def process_line(self, new_line: dict):
        """
        Process the tab line from zeek.
        :param new_line: a dict with "type" and "data" keys
        """
        line: str = new_line["data"]

        if line.startswith("#fields"):
            # depending on the given fields, we need to map the zeek fields
            # to some slips obj (SSL, Con, SSH, etc...)
            # cache the mapping for later use
            self.update_line_processor_cache(new_line)
            return

        file_type: str = self.get_file_type(new_line)
        # this dict is the name of each slips field and the index of it
        # in the given zeek line
        line_processor: Dict[int, str]
        line_processor = self.line_processor_cache.get(file_type)

        if not line_processor:
            self.print(
                f"Slips is unable to handle the given zeek log line! "
                f"{new_line}",
                0,
                1,
            )
            return

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
            # todo the type_ isnot set correctly
            self.flow = slips_class(**flow_values)
            return self.flow

        if log_type == "arp.log":
            self.flow: ARP = ARP(
                starttime,
                self.get_value_at(line, 1, False),
                self.get_value_at(line, 4),
                self.get_value_at(line, 5),
                self.get_value_at(line, 2),
                self.get_value_at(line, 3),
                self.get_value_at(line, 6),
                self.get_value_at(line, 7),
                self.get_value_at(line, 1),
            )
            return self.flow

        return False
