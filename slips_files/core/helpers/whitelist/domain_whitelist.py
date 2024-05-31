from typing import List, Dict
import tldextract

from slips_files.common.abstracts.whitelist_analyzer import IWhitelistAnalyzer
from slips_files.common.slips_utils import utils
from slips_files.core.evidence_structure.evidence import (
    Direction,
)
from slips_files.core.helpers.whitelist.ip_whitelist import IPAnalyzer


class DomainAnalyzer(IWhitelistAnalyzer):
    @property
    def name(self):
        return "domain_whitelist_analyzer"

    def init(self):
        self.ip_analyzer = IPAnalyzer(self.db)

    def get_dst_domains_of_flow(self, flow) -> List[str]:
        """
        return sthe domains of flow depending on the flow type
        for example, HTTP flow have their domains in the host field
        SSL flows have the host in the SNI field
        etc.
        """
        domains = []
        if flow.type_ == "ssl":
            domains.append(flow.server_name)
        elif flow.type_ == "http":
            domains.append(flow.host)
        elif flow.type_ == "ssl":
            domains.append(flow.subject.replace("CN=", ""))
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
        :param should_ignore: can be flows or alerts
        """
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
        """returns the top level domain from the gven url"""
        return tldextract.extract(url).suffix
