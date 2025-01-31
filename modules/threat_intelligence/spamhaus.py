# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from typing import (
    Dict,
    Tuple,
    Union,
)

from dns.exception import DNSException
import dns.resolver
from dns.resolver import NXDOMAIN


class Spamhaus:
    name = "Spamhaus"
    description = "Spamhaus lookups of IPs"
    authors = ["Alya Gomaa"]

    def __init__(self, db):
        self.db = db
        self._resolver = self._setup_resolver()

    @staticmethod
    def _setup_resolver():
        """Initialize and configure the DNS resolver."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0
        resolver.cache = dns.resolver.LRUCache()
        return resolver

    def query(self, ip) -> Union[bool, Dict[str, str]]:
        """Queries the Spamhaus DNSBL to check if the IP is listed."""
        spamhaus_dns_hostname: str = self._get_dns_hostname(ip)
        spamhaus_result = self._perform_dns_query(spamhaus_dns_hostname)

        if not spamhaus_result:
            return False

        return self._parse_result(spamhaus_result)

    @staticmethod
    def _get_dns_hostname(ip) -> str:
        """Formats the IP address for the Spamhaus DNS query."""
        return ".".join(ip.split(".")[::-1]) + ".zen.spamhaus.org"

    def _perform_dns_query(self, hostname):
        """Performs the DNS query to the Spamhaus service."""
        try:
            return self._resolver.resolve(hostname, "A")
        except (DNSException, NXDOMAIN):
            return None

    def _parse_result(self, spamhaus_result):
        """Parses the DNS query result and maps it to the dataset info."""
        lists_names: Dict[str, str] = self._get_list_names()
        list_descriptions: Dict[str, str] = self._get_list_descriptions()

        lists_that_have_this_ip = [data.to_text() for data in spamhaus_result]

        source_dataset: str
        description: str
        source_dataset, description = self._get_dataset_info(
            lists_that_have_this_ip, lists_names, list_descriptions
        )

        if not source_dataset:
            return False

        return {
            "source": f"{source_dataset} spamhaus",
            "description": description,
            "threat_level": "medium",
            "tags": "spam",
        }

    @staticmethod
    def _get_list_names():
        """Returns the mapping of IPs to their dataset names."""
        return {
            "127.0.0.2": "SBL Data",
            "127.0.0.3": "SBL CSS Data",
            "127.0.0.4": "XBL CBL Data",
            "127.0.0.9": "SBL DROP/EDROP Data",
            "127.0.0.10": "PBL ISP Maintained",
            "127.0.0.11": "PBL Spamhaus Maintained",
            0: False,
        }

    @staticmethod
    def _get_list_descriptions():
        """Returns the mapping of IPs to their descriptions."""
        return {
            "127.0.0.2": (
                "IP under the control of spammers or abusers in unsolicited "
                "bulk email or other Internet-based abuse."
            ),
            "127.0.0.3": (
                "IP involved in sending low-reputation email or a "
                "compromised host."
            ),
            "127.0.0.4": (
                "IP address of exploited systems, such as open proxies or "
                "malware-infected hosts."
            ),
            "127.0.0.9": (
                "IP is part of a netblock leased or hijacked by spam or "
                "cyber-crime operations."
            ),
            "127.0.0.10": (
                "IP should not be delivering unauthenticated SMTP email "
                "to any Internet mail server."
            ),
            "127.0.0.11": (
                "IP is part of dynamic or residential space and should not "
                "be delivering unauthenticated SMTP email."
            ),
        }

    @staticmethod
    def _get_dataset_info(
        ip_list, lists_names, list_descriptions
    ) -> Tuple[str, str]:
        """Extracts the source dataset and description based on the IP list."""
        source_dataset = ""
        description = ""
        for ip in ip_list:
            name = lists_names.get(ip, False)
            if not name:
                continue
            source_dataset += f"{name}, "
            description = list_descriptions.get(ip, "")

        return source_dataset, description
