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

    def is_whitelisted_domain_in_flow(
        self,
        whitelisted_domain,
        direction: Direction,
        domains_of_flow,
        ignore_type,
    ):
        """
        Given the domain of a flow, and a whitelisted domain,
        this function checks any of the flow domains
        is a subdomain or the same domain as the whitelisted domain

        :param whitelisted_domain: the domain we want to check if it exists in the domains_of_flow
        :param ignore_type: alerts or flows or both
        :param direction: Direction obj
        :param domains_of_flow: src domains of the src IP of the flow,
                                or dst domains of the dst IP of the flow
        """
        whitelisted_domains = self.db.get_whitelist("domains")
        if not whitelisted_domains:
            return False

        # do we wanna whitelist flows coming from or going to this domain or both?
        from_ = whitelisted_domains[whitelisted_domain]["from"]
        from_ = Direction.SRC if "src" in from_ else Direction.DST
        # Now check the domains of the src IP
        if (
            direction == from_
            or "both" in whitelisted_domains[whitelisted_domain]["from"]
        ):
            what_to_ignore = whitelisted_domains[whitelisted_domain][
                "what_to_ignore"
            ]

            for domain_to_check in domains_of_flow:
                main_domain = domain_to_check[-len(whitelisted_domain) :]
                if whitelisted_domain in main_domain:
                    # We can ignore flows or alerts, what is it?
                    if (
                        ignore_type in what_to_ignore
                        or "both" in what_to_ignore
                    ):
                        return True
        return False

    def is_whitelisted_domain(
        self, domain_to_check, saddr, daddr, ignore_type
    ):
        """
        Used only when checking whitelisted flows
        (aka domains associated with the src or dstip of a flow)
        :param domain_to_check: the domain we want to know if whitelisted or not
        :param saddr: saddr of the flow we're checking
        :param daddr: daddr of the flow we're checking
        :param ignore_type: what did the user whitelist? alerts or flows or both
        """

        whitelisted_domains = self.db.get_whitelist("domains")
        if not whitelisted_domains:
            return False

        # get the domains of this flow
        dst_domains_of_flow: List[str] = self.ip_analyzer.get_domains_of_ip(
            daddr
        )
        src_domains_of_flow: List[str] = self.ip_analyzer.get_domains_of_ip(
            saddr
        )

        # self.print(f'Domains to check from flow: {domains_to_check},
        # {domains_to_check_dst} {domains_to_check_src}')
        # Go through each whitelisted domain and check if what arrived is there
        for whitelisted_domain in list(whitelisted_domains.keys()):
            what_to_ignore = whitelisted_domains[whitelisted_domain][
                "what_to_ignore"
            ]
            # Here we iterate over all the domains to check if we can find
            # subdomains. If slack.com was whitelisted, then test.slack.com
            # should be ignored too. But not 'slack.com.test'
            main_domain = domain_to_check[-len(whitelisted_domain) :]
            if whitelisted_domain in main_domain:
                # We can ignore flows or alerts, what is it?
                if ignore_type in what_to_ignore or "both" in what_to_ignore:
                    # self.print(f'Whitelisting the domain
                    # {domain_to_check} due to whitelist of {domain_to_check}')
                    return True

            if self.is_whitelisted_domain_in_flow(
                whitelisted_domain,
                Direction.SRC,
                src_domains_of_flow,
                ignore_type,
            ):
                # self.print(f"Whitelisting the domain
                # {domain_to_check} because is related"
                #            f" to domain {domain_to_check}
                #            of dst IP {daddr}")
                return True

            if self.is_whitelisted_domain_in_flow(
                whitelisted_domain,
                Direction.DST,
                dst_domains_of_flow,
                ignore_type,
            ):
                # self.print(f"Whitelisting the domain
                # {domain_to_check} because is"
                #            f"related to domain {domain_to_check}
                #            of src IP {saddr}")
                return True
        return False

    def get_domains_of_flow(self, flow) -> List[str]:
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

    def is_domain_whitelisted(self, domain: str, direction: Direction):
        # todo differentiate between this and is_whitelisted_Domain()

        parent_domain: str = utils.extract_hostname(domain)
        if not parent_domain:
            return

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
        what_to_ignore = whitelisted_domains[parent_domain]["what_to_ignore"]
        if not self.manager.should_ignore_alerts(what_to_ignore):
            return False

        # Ignore src or dst
        dir_from_whitelist: str = whitelisted_domains[parent_domain]["from"]
        if not self.manager.ioc_dir_match_whitelist_dir(
            direction, dir_from_whitelist
        ):
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
