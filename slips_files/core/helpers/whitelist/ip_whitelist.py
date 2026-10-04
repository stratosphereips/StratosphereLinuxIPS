# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from typing import List, Dict

from slips_files.common.abstracts.iwhitelist_analyzer import IWhitelistAnalyzer
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
    Direction,
)


class IPAnalyzer(IWhitelistAnalyzer):
    @property
    def name(self):
        return "IP_whitelist_analyzer"

    def init(self):
        self.read_configuration()
        # for debugging
        self.bf_hits = 0
        self.bf_misses = 0

    def read_configuration(self):
        conf = ConfigParser()
        self.enable_local_whitelist: bool = conf.enable_local_whitelist()

    @staticmethod
    def extract_dns_answers(flow) -> List[str]:
        """
        extracts all the ips we can find from the given flow
        """
        return flow.answers if flow.type_ == "dns" else []

    def is_whitelisted(
        self,
        ip: str,
        direction: Direction,
        what_to_ignore: str,
        port: int | str | None = None,
    ) -> bool:
        """
        checks the given IP in the whitelisted IPs read from whitelist.conf
        :param ip: ip to check if whitelisted
        :param direction: is the given ip a srcip or a dstip
        :param what_to_ignore: can be 'flows' or 'alerts'
        :param port: Port on the same side as the IP, if available.
        """
        if not self.enable_local_whitelist:
            return False

        if not utils.is_valid_ip(ip):
            return False

        candidates = [ip]
        if port is not None and str(port).isdecimal():
            port_number = int(port)
            if 0 <= port_number <= 65535:
                address = f"[{ip}]" if ":" in ip else ip
                candidates.append(f"{address}:{port_number}")
                candidates.append(f"*:{port_number}")

        for candidate in candidates:
            if candidate not in self.manager.bloom_filters.ips:
                self.bf_hits += 1
                continue

            ip_info: str | None = self.db.is_whitelisted(candidate, "IPs")
            if not ip_info:
                self.bf_misses += 1
                continue

            self.bf_hits += 1
            rule: Dict[str, str] = json.loads(ip_info)
            if not self.match.direction(direction, rule["from"]):
                continue
            if self.match.what_to_ignore(
                what_to_ignore, rule["what_to_ignore"]
            ):
                return True

        return False
