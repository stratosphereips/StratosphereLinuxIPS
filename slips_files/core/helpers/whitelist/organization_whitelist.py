import ipaddress
import json
from typing import List, Dict

from slips_files.common.abstracts.whitelist_analyzer import IWhitelistAnalyzer
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
    IoCType,
    Direction,
)
from slips_files.core.helpers.whitelist.domain_whitelist import DomainAnalyzer
from slips_files.core.helpers.whitelist.ip_whitelist import IPAnalyzer


class OrgAnalyzer(IWhitelistAnalyzer):
    """
    is_part_of_a_whitelisted_org()
    is the one you should mainly use
    from the outside.
     unless you're not checking if a flow/alert is whitelisted,
    (e.g. like in is_well_known_org)
    """

    @property
    def name(self):
        return "organization_whitelist_analyzer"

    def init(self):
        self.ip_analyzer = IPAnalyzer(self.db)
        self.domain_analyzer = DomainAnalyzer(self.db)
        self.org_info_path = "slips_files/organizations_info/"

    def is_domain_in_org(self, domain: str, org: str):
        """
        Checks if the given domains belongs to the given org using
        the hardcoded org domains in organizations_info/org_domains
        """
        try:
            org_domains = json.loads(self.db.get_org_info(org, "domains"))
            flow_tld = self.domain_analyzer.get_tld(domain)

            for org_domain in org_domains:
                org_domain_tld = self.domain_analyzer.get_tld(org_domain)

                if flow_tld != org_domain_tld:
                    continue

                # match subdomains too
                # if org has org.com, and the flow_domain is xyz.org.com
                # whitelist it
                if org_domain in domain:
                    return True

                # if org has xyz.org.com, and the flow_domain is org.com
                # whitelist it
                if domain in org_domain:
                    return True

        except (KeyError, TypeError):
            # comes here if the whitelisted org doesn't have domains in
            # slips/organizations_info (not a famous org)
            # and ip doesn't have asn info.
            # so we don't know how to link this ip to the whitelisted org!
            return False

    def is_ip_in_org(self, ip: str, org):
        """
        Check if the given ip belongs to the given org
        """
        try:
            org_subnets: dict = self.db.get_org_ips(org)

            first_octet: str = utils.get_first_octet(ip)
            if not first_octet:
                return
            ip_obj = ipaddress.ip_address(ip)
            # organization IPs are sorted by first octet for faster search
            for range_ in org_subnets.get(first_octet, []):
                if ip_obj in ipaddress.ip_network(range_):
                    return True
        except (KeyError, TypeError):
            # comes here if the whitelisted org doesn't have
            # info in slips/organizations_info (not a famous org)
            # and ip doesn't have asn info.
            pass
        return False

    def is_ip_asn_in_org_asn(self, ip: str, org):
        """
        returns true if the ASN of the given IP is listed in
         the ASNs of the given org
        """
        ip_data = self.db.get_ip_info(ip)
        if not ip_data:
            return

        try:
            ip_asn = ip_data["asn"]["number"]
        except KeyError:
            return

        if not (ip_asn and ip_asn != "Unknown"):
            return False

        # because all ASN stored in slips organization_info/ are uppercase
        ip_asn: str = ip_asn.upper()

        org_asn: List[str] = json.loads(self.db.get_org_info(org, "asn"))
        return org.upper() in ip_asn or ip_asn in org_asn

    def is_whitelisted(self, flow) -> bool:
        """checks if the given flow is whitelisted"""
        flow_dns_answers: List[str] = self.ip_analyzer.extract_dns_answers(
            flow
        )

        for domain in self.domain_analyzer.get_dst_domains_of_flow(flow):
            if self.is_part_of_a_whitelisted_org(
                domain, IoCType.DOMAIN, Direction.DST, "flows"
            ):
                return True

        for domain in self.domain_analyzer.get_src_domains_of_flow(flow):
            if self.is_part_of_a_whitelisted_org(
                domain, IoCType.DOMAIN, Direction.SRC, "flows"
            ):
                return True

        if self.is_part_of_a_whitelisted_org(
            flow.saddr, IoCType.IP, Direction.SRC, "flows"
        ):
            return True

        for ip in [flow.daddr] + flow_dns_answers:
            if self.is_part_of_a_whitelisted_org(
                ip, IoCType.IP, Direction.DST, "flows"
            ):
                return True

    def is_ip_part_of_a_whitelisted_org(self, ip: str, org: str) -> bool:
        """
        returns true if the given ip is a part of the given org
        by checking the ASN of the ip and by checking if the IP is
        part of the hardcoded IPs as part of this org in
        slips_files/organizations_info
        """
        if self.is_ip_asn_in_org_asn(ip, org):
            return True

        # search in the list of organization IPs
        return self.is_ip_in_org(ip, org)

    def is_part_of_a_whitelisted_org(
        self,
        ioc: str,
        ioc_type: IoCType,
        direction: Direction,
        what_to_ignore: str,
    ) -> bool:
        """
        Handles the checking of whitelisted evidence or alerts
        :param ioc: can be an ip or a domain
        :param ioc_type: type of the given ioc
        :param direction: direction of the given ioc, src or dst?
        :param what_to_ignore: can be flows or alerts or both
        """

        if ioc_type == "IP" and self.ip_analyzer.is_private_ip(ioc):
            return False

        whitelisted_orgs: Dict[str, dict] = self.db.get_whitelist(
            "organizations"
        )
        if not whitelisted_orgs:
            return False

        for org in whitelisted_orgs:
            dir_from_whitelist = whitelisted_orgs[org]["from"]
            if not self.match.direction(direction, dir_from_whitelist):
                continue

            whitelist_what_to_ignore = whitelisted_orgs[org]["what_to_ignore"]
            if not self.match.what_to_ignore(
                what_to_ignore, whitelist_what_to_ignore
            ):
                continue

            cases = {
                IoCType.DOMAIN.name: self.is_domain_in_org,
                IoCType.IP.name: self.is_ip_part_of_a_whitelisted_org,
            }
            if cases[ioc_type](ioc, org):
                return True

        return False
