from typing import List, Dict
import tldextract

from slips_files.common.abstracts.whitelist_analyzer import IWhitelistAnalyzer
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

    def get_domains_of_ip(self, ip: str) -> List[str]:
        """
        returns the domains of this IP, e.g. the DNS resolution, the SNI, etc.
        """
        domains = []
        if ip_data := self.db.get_ip_info(ip):
            if sni_info := ip_data.get("SNI", [{}])[0]:
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

        if not isinstance(domain, str):
            return False

        parent_domain: str = utils.extract_hostname(domain)
        if not parent_domain:
            return False

        if self.is_domain_in_tranco_list(parent_domain):
            return True

        whitelisted_domains: Dict[str, Dict[str, str]]
        whitelisted_domains = self.db.get_whitelist("domains")

        # is domain in whitelisted domains?
        if parent_domain not in whitelisted_domains:
            # if the parent domain not in whitelisted domains, then the
            # child definetely isn't
            return False

        # Ignore flows or alerts?
        whitelist_should_ignore = whitelisted_domains[parent_domain][
            "what_to_ignore"
        ]
        if not self.match.what_to_ignore(
            should_ignore, whitelist_should_ignore
        ):
            return False

        # Ignore src or dst
        dir_from_whitelist: str = whitelisted_domains[parent_domain]["from"]
        if not self.match.direction(direction, dir_from_whitelist):
            return False

        return True

    def is_domain_in_tranco_list(self, domain):
        """
        The Tranco list contains the top 10k known benign domains
        https://tranco-list.eu/list/X5QNN/1000000
        """
        # todo the db shouldn't be checking this, we should check it here
        return self.db.is_whitelisted_tranco_domain(domain)

    @staticmethod
    def get_tld(url: str):
        """returns the top level domain from the given url"""
        return tldextract.extract(url).suffix
