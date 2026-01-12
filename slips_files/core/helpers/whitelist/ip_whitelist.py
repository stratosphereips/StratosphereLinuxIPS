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

        if not utils.is_valid_ip(ip):
            return False

        if ip not in self.manager.bloom_filters.ips:
            # defnitely not whitelisted
            self.bf_hits += 1
            return False

        ip_info: str | None = self.db.is_whitelisted(ip, "IPs")
        # reaching here means ip is in the bloom filter
        if not ip_info:
            # bloom filter FP
            self.bf_misses += 1
            return False

        self.bf_hits += 1
        ip_info: Dict[str, str] = json.loads(ip_info)
        # Check if we should ignore src or dst alerts from this ip
        # from_ can be: src, dst, both
        # what_to_ignore can be: alerts or flows or both
        whitelist_direction: str = ip_info["from"]
        if not self.match.direction(direction, whitelist_direction):
            return False

        ignore: str = ip_info["what_to_ignore"]
        if not self.match.what_to_ignore(what_to_ignore, ignore):
            return False

        return True
