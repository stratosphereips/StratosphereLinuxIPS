# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from typing import List, Dict, Any
import tldextract

from slips_files.common.abstracts.iwhitelist_analyzer import IWhitelistAnalyzer
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
    Direction,
)
from slips_files.core.helpers.whitelist.ip_whitelist import IPAnalyzer


class DomainAnalyzer(IWhitelistAnalyzer):
    @property
    def name(self):
        return "domain_whitelist_analyzer"

    def init(self):
        self.ip_analyzer = IPAnalyzer(self.db)
        self.read_configuration()
        # for debugging
        self.bf_hits = 0
        self.bf_misses = 0

    def read_configuration(self):
        conf = ConfigParser()
        self.enable_online_whitelist: bool = conf.enable_online_whitelist()
        self.enable_local_whitelist: bool = conf.enable_local_whitelist()

    def get_domains_of_ip(self, ip: str) -> List[str]:
        """
        returns the domains of this IP, e.g. the DNS resolution, the SNI, etc.
        """
        domains = []
        if ip_data := self.db.get_ip_info(ip, "SNI"):
            ip_data: List[Dict[str, Any]]
            if sni_info := ip_data[0]:
                domains.append(sni_info.get("server_name", ""))

        try:
            resolution = self.db.get_dns_resolution(ip).get("domains", [])
            domains.extend(iter(resolution))
        except (KeyError, TypeError):
            pass

        return domains

    def get_src_domains_of_flow(self, flow) -> List[str]:
        return self.get_domains_of_ip(flow.saddr)

    def get_dst_domains_of_flow(self, flow) -> List[str]:
        """
        returns the domains of flow depending on the flow type
        for example, HTTP flow have their domains in the host field
        SSL flows have the host in the SNI field
        etc.
        """
        domains: List[str] = self.get_domains_of_ip(flow.daddr)
        if flow.type_ == "ssl":
            domains.append(flow.server_name)
            domains.append(flow.subject.replace("CN=", ""))
        elif flow.type_ == "http":
            domains.append(flow.host)
        elif flow.type_ == "dns":
            domains.append(flow.query)
        return domains

    def is_whitelisted(
        self, domain: str, direction: Direction, should_ignore: str
    ) -> bool:
        """
        Checks the whitelisted domains and tranco whitelisted domains for
        the given domain
        :param domain: domain to check if whitelisted
        :param direction: is the given domain src or dst domain?
        :param should_ignore: which whitelist to check? can be flows or alerts
        """
        # the reason why this function doesnt support the Attacker or
        # Victim as a parameter directly is that we may call it on other
        # values. not just attacker and victim domains.
        if not isinstance(domain, str):
            return False

        parent_domain: str = utils.extract_hostname(domain)
        if not parent_domain:
            return False

        # is the parent domain in any of slips whitelists?? like tranco or
        # whitelist.conf?
        # if so we need to get extra info about that domain based on the
        # whitelist.
        # e.g  by default slips whitelists all evidence and alerts from and to
        # tranco domains.
        # but domains taken from whitelist.conf have their own direction
        # and type
        if self.is_domain_in_tranco_list(parent_domain):
            if not self.enable_online_whitelist:
                # domain is in the tranco whitelist, but the it's whitelist
                # not enabled
                return False
            whitelist_should_ignore = "alerts"
            dir_from_whitelist = "dst"
        else:
            if not self.enable_local_whitelist:
                # domain is in the local whitelist, but the local whitelist
                # not enabled
                return False

            if parent_domain not in self.manager.bloom_filters.domains:
                # definitely not whitelisted
                self.bf_hits += 1
                return False

            domain_info: str | None = self.db.is_whitelisted(
                parent_domain, "domains"
            )
            if not domain_info:
                # bloom filter FP
                self.bf_misses += 1
                return False

            self.bf_hits += 1
            domain_info: Dict[str, str] = json.loads(domain_info)
            # did the user say slips should ignore flows or alerts in the
            # config file?
            whitelist_should_ignore = domain_info["what_to_ignore"]
            # did the user say slips should ignore flows/alerts  TO or from
            # that domain in the config file?
            dir_from_whitelist: str = domain_info["from"]

        # match the direction and whitelist_Type of the given domain to the
        # ones we have from the whitelist.
        if not self.match.what_to_ignore(
            should_ignore, whitelist_should_ignore
        ):
            return False

        if not self.match.direction(direction, dir_from_whitelist):
            return False

        return True

    def is_domain_in_tranco_list(self, domain):
        """
        The Tranco list contains the top 10k known benign domains
        https://tranco-list.eu/list/X5QNN/1000000
        """
        return self.db.is_whitelisted_tranco_domain(domain)

    @staticmethod
    def get_tld(url: str):
        """returns the top level domain from the given url"""
        return tldextract.extract(url).suffix
