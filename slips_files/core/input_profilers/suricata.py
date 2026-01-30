# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from typing import Tuple

from slips_files.common.abstracts.iinput_type import IInputType
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
    def __init__(self, db):
        self.db = db

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

    def process_line(self, line) -> Tuple[bool, str]:
        """Read suricata json input and store it in column_values"""

        # convert to dict if it's not a dict already
        if isinstance(line, str):
            line = json.loads(line)
        else:
            # line is a dict with data and type as keys
            line = json.loads(line.get("data", False))

        if not line:
            return False, "Can't parse suricata dictionary"

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
            starttime = utils.convert_ts_format(
                get_value_at("flow", "start"), "unixtimestamp"
            )
            endtime = utils.convert_ts_format(
                get_value_at("flow", "end"), "unixtimestamp"
            )

            self.flow = SuricataFlow(
                uid=flow_id,
                saddr=saddr,
                sport=sport,
                daddr=daddr,
                dport=dport,
                proto=proto,
                appproto=appproto,
                starttime=starttime,
                endtime=endtime,
                spkts=int(get_value_at("flow", "pkts_toserver", 0)),
                dpkts=int(get_value_at("flow", "pkts_toclient", 0)),
                sbytes=int(get_value_at("flow", "bytes_toserver", 0)),
                dbytes=int(get_value_at("flow", "bytes_toclient", 0)),
                state=get_value_at("flow", "state", ""),
            )

        elif event_type == "http":
            self.flow = SuricataHTTP(
                starttime=timestamp,
                uid=flow_id,
                saddr=saddr,
                sport=sport,
                daddr=daddr,
                dport=dport,
                proto=proto,
                appproto=appproto,
                method=get_value_at("http", "http_method", ""),
                host=get_value_at("http", "hostname", ""),
                uri=get_value_at("http", "url", ""),
                user_agent=get_value_at("http", "http_user_agent", ""),
                status_code=get_value_at("http", "status", ""),
                version=get_value_at("http", "protocol", ""),
                request_body_len=int(
                    get_value_at("http", "request_body_len", 0)
                ),
                response_body_len=int(get_value_at("http", "length", 0)),
            )

        elif event_type == "dns":
            answers = self.get_answers(line)
            self.flow = SuricataDNS(
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
                qtype_name=get_value_at("dns", "rrtype", ""),
                answers=answers,
            )

        elif event_type == "tls":
            self.flow = SuricataTLS(
                starttime=timestamp,
                uid=flow_id,
                saddr=saddr,
                sport=sport,
                daddr=daddr,
                dport=dport,
                proto=proto,
                appproto=appproto,
                sslversion=get_value_at("tls", "version", ""),
                subject=get_value_at("tls", "subject", ""),
                issuer=get_value_at("tls", "issuerdn", ""),
                server_name=get_value_at("tls", "sni", ""),
                notbefore=get_value_at("tls", "notbefore", ""),
                notafter=get_value_at("tls", "notafter", ""),
            )

        elif event_type == "fileinfo":
            self.flow = SuricataFile(
                starttime=timestamp,
                uid=flow_id,
                saddr=saddr,
                sport=sport,
                daddr=daddr,
                dport=dport,
                proto=proto,
                appproto=appproto,
                size=int(get_value_at("fileinfo", "size", 0)),
            )

        elif event_type == "ssh":
            self.flow = SuricataSSH(
                starttime=timestamp,
                uid=flow_id,
                saddr=saddr,
                sport=sport,
                daddr=daddr,
                dport=dport,
                proto=proto,
                appproto=appproto,
                client=get_value_at("ssh", "client", {}).get(
                    "software_version", ""
                ),
                version=get_value_at("ssh", "client", {}).get(
                    "proto_version", ""
                ),
                server=get_value_at("ssh", "server", {}).get(
                    "software_version", ""
                ),
            )

        else:
            return False, "Unable to recognize event type."

        return self.flow, ""
