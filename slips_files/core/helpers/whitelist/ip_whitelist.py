# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import ipaddress
from typing import List, Dict

from slips_files.common.abstracts.whitelist_analyzer import IWhitelistAnalyzer
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.core.structures.evidence import (
    Direction,
)


class IPAnalyzer(IWhitelistAnalyzer):
    @property
    def name(self):
        return "IP_whitelist_analyzer"

    def init(self):
        self.read_configuration()

    def read_configuration(self):
        conf = ConfigParser()
        self.enable_local_whitelist: bool = conf.enable_local_whitelist()

    @staticmethod
    def extract_dns_answers(flow) -> List[str]:
        """
        extracts all the ips we can find from the given flow
        """
        return flow.answers if flow.type_ == "dns" else []

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def is_whitelisted(
        self, ip: str, direction: Direction, what_to_ignore: str
    ) -> bool:
        """
        checks the given IP in the whitelisted IPs read from whitelist.conf
        :param ip: ip to check if whitelisted
        :param direction: is the given ip a srcip or a dstip
        :param what_to_ignore: can be 'flows' or 'alerts'
        """
        if not self.enable_local_whitelist:
            return False

        if not self.is_valid_ip(ip):
            return False

        whitelisted_ips: Dict[str, dict] = self.db.get_whitelist("IPs")

        if ip not in whitelisted_ips:
            return False

        # Check if we should ignore src or dst alerts from this ip
        # from_ can be: src, dst, both
        # what_to_ignore can be: alerts or flows or both
        whitelist_direction: str = whitelisted_ips[ip]["from"]
        if not self.match.direction(direction, whitelist_direction):
            return False

        ignore: str = whitelisted_ips[ip]["what_to_ignore"]
        if not self.match.what_to_ignore(what_to_ignore, ignore):
            return False
        return True
