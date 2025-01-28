# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json

from slips_files.common.abstracts.input_type import IInputType
from slips_files.common.slips_utils import utils
from slips_files.core.flows.suricata import (
    SuricataFlow,
    SuricataHTTP,
    SuricataDNS,
    SuricataTLS,
    SuricataFile,
    SuricataSSH,
)


class Suricata(IInputType):
    def __init__(self):
        pass

    def get_answers(self, line: dict) -> list:
        """
        reads the suricata dns answer and extracts the cname and IPs in the dns answerr=
        """
        line = line.get("dns", False)
        if not line:
            return []

        answers: dict = line.get("grouped", False)
        if not answers:
            return []

        cnames: list = answers.get("CNAME", [])
        ips: list = answers.get("A", [])

        return cnames + ips

    def process_line(self, line) -> None:
        """Read suricata json input and store it in column_values"""

        # convert to dict if it's not a dict already
        if isinstance(line, str):
            line = json.loads(line)
        else:
            # line is a dict with data and type as keys
            line = json.loads(line.get("data", False))

        if not line:
            return
        # these fields are common in all suricata lines regardless of the event type
        event_type = line["event_type"]
        flow_id = line["flow_id"]
        saddr = line["src_ip"]
        sport = line["src_port"]
        daddr = line["dest_ip"]
        dport = line["dest_port"]
        proto = line["proto"]
        appproto = line.get("app_proto", False)

        try:
            timestamp = utils.convert_to_datetime(line["timestamp"])
        except ValueError:
            # Reason for catching ValueError:
            # "ValueError: time data '1900-01-00T00:00:08.511802+0000'
            # does not match format '%Y-%m-%dT%H:%M:%S.%f%z'"
            # It means some flow do not have valid timestamp. It seems
            # to me if suricata does not know the timestamp, it put
            # there this not valid time.
            timestamp = False

        def get_value_at(field, subfield, default_=False):
            try:
                val = line[field][subfield]
                return val or default_
            except (IndexError, KeyError):
                return default_

        if event_type == "flow":
            starttime = utils.convert_format(
                get_value_at("flow", "start"), "unixtimestamp"
            )
            endtime = utils.convert_format(
                get_value_at("flow", "end"), "unixtimestamp"
            )
            self.flow: SuricataFlow = SuricataFlow(
                flow_id,
                saddr,
                sport,
                daddr,
                dport,
                proto,
                appproto,
                starttime,
                endtime,
                int(get_value_at("flow", "pkts_toserver", 0)),
                int(get_value_at("flow", "pkts_toclient", 0)),
                int(get_value_at("flow", "bytes_toserver", 0)),
                int(get_value_at("flow", "bytes_toclient", 0)),
                get_value_at("flow", "state", ""),
            )

        elif event_type == "http":
            self.flow: SuricataHTTP = SuricataHTTP(
                timestamp,
                flow_id,
                saddr,
                sport,
                daddr,
                dport,
                proto,
                appproto,
                get_value_at("http", "http_method", ""),
                get_value_at("http", "hostname", ""),
                get_value_at("http", "url", ""),
                get_value_at("http", "http_user_agent", ""),
                get_value_at("http", "status", ""),
                get_value_at("http", "protocol", ""),
                int(get_value_at("http", "request_body_len", 0)),
                int(get_value_at("http", "length", 0)),
            )

        elif event_type == "dns":
            answers: list = self.get_answers(line)
            self.flow: SuricataDNS = SuricataDNS(
                starttime=timestamp,
                uid=flow_id,
                saddr=saddr,
                sport=sport,
                daddr=daddr,
                dport=dport,
                proto=proto,
                appproto=appproto,
                query=get_value_at("dns", "rrname", ""),
                TTLs=get_value_at("dns", "ttl", ""),
                qtype_name=get_value_at("qtype_name", "rrtype", ""),
                answers=answers,
            )

        elif event_type == "tls":
            self.flow: SuricataTLS = SuricataTLS(
                timestamp,
                flow_id,
                saddr,
                sport,
                daddr,
                dport,
                proto,
                appproto,
                get_value_at("tls", "version", ""),
                get_value_at("tls", "subject", ""),
                get_value_at("tls", "issuerdn", ""),
                get_value_at("tls", "sni", ""),
                get_value_at("tls", "notbefore", ""),
                get_value_at("tls", "notafter", ""),
                get_value_at("tls", "sni", ""),
            )

        elif event_type == "fileinfo":
            self.flow: SuricataFile = SuricataFile(
                timestamp,
                flow_id,
                saddr,
                sport,
                daddr,
                dport,
                proto,
                appproto,
                get_value_at("fileinfo", "size", ""),
            )
        elif event_type == "ssh":
            self.flow: SuricataSSH = SuricataSSH(
                timestamp,
                flow_id,
                saddr,
                sport,
                daddr,
                dport,
                proto,
                appproto,
                get_value_at("ssh", "client", {}).get("software_version", ""),
                get_value_at("ssh", "client", {}).get("proto_version", ""),
                get_value_at("ssh", "server", {}).get("software_version", ""),
            )
        else:
            return False
        return self.flow
