# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from typing import Dict

import validators

from slips_files.common.abstracts.whitelist_analyzer import IWhitelistAnalyzer
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.core.structures.evidence import (
    Direction,
)
from slips_files.core.helpers.whitelist.ip_whitelist import IPAnalyzer


class MACAnalyzer(IWhitelistAnalyzer):
    @property
    def name(self):
        return "mac_whitelist_analyzer"

    def init(self):
        self.ip_analyzer = IPAnalyzer(self.db)
        self.read_configuration()

    def read_configuration(self):
        conf = ConfigParser()
        self.enable_local_whitelist: bool = conf.enable_local_whitelist()

    @staticmethod
    def is_valid_mac(mac: str) -> bool:
        if not isinstance(mac, str):
            return False

        return validators.mac_address(mac)

    def profile_has_whitelisted_mac(
        self, profile_ip, direction: Direction, what_to_ignore: str
    ) -> bool:
        """
        Checks for alerts whitelist
        :param profile_ip: the ip we wanna check the mac of
        :param direction: is it a src ip or a dst ip
        :param what_to_ignore: can be flows or alerts
        """
        if not self.ip_analyzer.is_valid_ip(profile_ip):
            return False

        mac: str = self.db.get_mac_addr_from_profile(f"profile_{profile_ip}")
        if not mac:
            return False

        return self.is_whitelisted(mac, direction, what_to_ignore)

    def is_whitelisted(
        self, mac: str, direction: Direction, what_to_ignore: str
    ):
        """
        checks if the given mac is whitelisted
        :param mac: mac to check if whitelisted
        :param direction: is the given mac a src or a dst mac
        :param what_to_ignore: can be flows or alerts
        """
        if not self.enable_local_whitelist:
            return False

        if not self.is_valid_mac(mac):
            return False

        whitelisted_macs: Dict[str, dict] = self.db.get_whitelist("macs")
        if mac not in whitelisted_macs:
            return False

        whitelist_direction: str = whitelisted_macs[mac]["from"]
        if not self.match.direction(direction, whitelist_direction):
            return False

        whitelist_what_to_ignore: str = whitelisted_macs[mac]["what_to_ignore"]
        if not self.match.what_to_ignore(
            what_to_ignore, whitelist_what_to_ignore
        ):
            return False

        return True
