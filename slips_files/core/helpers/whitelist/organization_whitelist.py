import ipaddress
import json
import os
from typing import List, Dict

from slips_files.common.abstracts.whitelist_analyzer import IWhitelistAnalyzer
from slips_files.common.slips_utils import utils
from slips_files.core.evidence_structure.evidence import (
    Attacker,
    IoCType,
)
from slips_files.core.helpers.whitelist.ip_whitelist import IPAnalyzer


class OrgAnalyzer(IWhitelistAnalyzer):
    @property
    def name(self):
        return "organization_whitelist_analyzer"

    def init(self):
        self.ip_analyzer = IPAnalyzer(self.db)
        self.org_info_path = "slips_files/organizations_info/"

    def is_domain_in_org(self, domain: str, org: str):
        """
        Checks if the given domains belongs to the given org
        """
        try:
            org_domains = json.loads(self.db.get_org_info(org, "domains"))
            flow_tld = self.get_tld(domain)

            for org_domain in org_domains:
                org_domain_tld = self.get_tld(org_domain)

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
            pass

    def is_ip_in_org(self, ip: str, org):
        """
        Check if the given ip belongs to the given org
        """
        try:
            org_subnets: dict = self.db.get_org_IPs(org)

            first_octet: str = utils.get_first_octet(ip)
            if not first_octet:
                return
            ip_obj = ipaddress.ip_address(ip)
            # organization IPs are sorted by first octet for faster search
            for range in org_subnets.get(first_octet, []):
                if ip_obj in ipaddress.ip_network(range):
                    return True
        except (KeyError, TypeError):
            # comes here if the whitelisted org doesn't have
            # info in slips/organizations_info (not a famous org)
            # and ip doesn't have asn info.
            pass
        return False

    def is_ip_asn_in_org_asn(self, ip: str, org):
        """
        returns true if the ASN of the given IP is listed in the ASNs of
        the given org ASNs
        """
        ip_data = self.db.get_ip_info(ip)
        if not ip_data:
            return

        try:
            ip_asn = ip_data["asn"]["number"]
        except KeyError:
            return
        # because all ASN stored in slips organization_info/ are uppercase
        ip_asn: str = ip_asn.upper()

        org_asn: List[str] = json.loads(self.db.get_org_info(org, "asn"))
        return org.upper() in ip_asn or ip_asn in org_asn

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

    def is_part_of_a_whitelisted_org(self, ioc):
        """
        Handles the checking of whitelisted evidence/alerts only
        doesn't check if we should ignore flows
        :param ioc: can be an Attacker or a Victim object
        """
        ioc_type: str = (
            ioc.attacker_type if isinstance(ioc, Attacker) else ioc.victim_type
        )

        if self.ip_analyzer.is_private_ip(ioc_type, ioc):
            return False

        whitelisted_orgs: Dict[str, dict] = self.db.get_whitelist(
            "organizations"
        )
        if not whitelisted_orgs:
            return False

        for org in whitelisted_orgs:
            dir_from_whitelist = whitelisted_orgs[org]["from"]
            if not self.manager.ioc_dir_match_whitelist_dir(
                ioc.direction, dir_from_whitelist
            ):
                continue

            cases = {
                IoCType.DOMAIN.name: self.is_domain_in_org,
                IoCType.IP.name: self.is_ip_part_of_a_whitelisted_org,
            }
            if cases[ioc_type](ioc.value, org):
                return True
        return False

    def is_asn_in_org(self, ip, org):
        ip_data = self.db.get_ip_info(ip)
        try:
            ip_asn = ip_data["asn"]["asnorg"]
            org_asn = json.loads(self.db.get_org_info(org, "asn"))
            if (
                ip_asn
                and ip_asn != "Unknown"
                and (org.lower() in ip_asn.lower() or ip_asn in org_asn)
            ):
                # this ip belongs to a whitelisted org, ignore flow
                # self.print(f"The ASN {ip_asn} of IP {ip} "
                #            f"is in the values of org {org}. Whitelisted.")
                return True
        except (KeyError, TypeError):
            # No asn data for src ip
            pass

    def load_org_asn(self, org) -> list:
        """
        Reads the specified org's asn from slips_files/organizations_info
         and stores the info in the database
        org: 'google', 'facebook', 'twitter', etc...
        returns a list containing the org's asn
        """
        try:
            # Each file is named after the organization's name followed by _asn
            org_asn = []
            asn_info_file = os.path.join(self.org_info_path, f"{org}_asn")
            with open(asn_info_file, "r") as f:
                while line := f.readline():
                    # each line will be something like this: 34.64.0.0/10
                    line = line.replace("\n", "").strip()
                    # Read all as upper
                    org_asn.append(line.upper())

        except (FileNotFoundError, IOError):
            # theres no slips_files/organizations_info/{org}_asn for this org
            # see if the org has asn cached in our db
            asn_cache: dict = self.db.get_asn_cache()
            org_asn = []
            # asn_cache is a dict sorted by first octet
            for octet, range_info in asn_cache.items():
                # range_info is a serialized dict of ranges
                range_info = json.loads(range_info)
                for range, asn_info in range_info.items():
                    # we have the asn of this given org cached
                    if org in asn_info["org"].lower():
                        org_asn.append(org)

        self.db.set_org_info(org, json.dumps(org_asn), "asn")
        return org_asn

    def load_org_domains(self, org):
        """
        Reads the specified org's domains from slips_files/organizations_info
        and stores the info in the database
        org: 'google', 'facebook', 'twitter', etc...
        returns a list containing the org's domains
        """
        try:
            domains = []
            # Each file is named after the organization's name followed by _domains
            domain_info_file = os.path.join(
                self.org_info_path, f"{org}_domains"
            )
            with open(domain_info_file, "r") as f:
                while line := f.readline():
                    # each line will be something like this: 34.64.0.0/10
                    line = line.replace("\n", "").strip()
                    domains.append(line.lower())
                    # Store the IPs of this org
        except (FileNotFoundError, IOError):
            return False

        self.db.set_org_info(org, json.dumps(domains), "domains")
        return domains

    def load_org_ips(self, org):
        """
        Reads the specified org's info from slips_files/organizations_info
        and stores the info in the database
        if there's no file for this org, it get the IP ranges from asnlookup.com
        org: 'google', 'facebook', 'twitter', etc...
        returns a list of this organization's subnets
        """
        if org not in utils.supported_orgs:
            return

        org_info_file = os.path.join(self.org_info_path, org)
        try:
            # Each file is named after the organization's name
            # Each line of the file contains an ip range, for example: 34.64.0.0/10
            org_subnets = {}
            with open(org_info_file, "r") as f:
                while line := f.readline():
                    # each line will be something like this: 34.64.0.0/10
                    line = line.replace("\n", "").strip()
                    try:
                        # make sure this line is a valid network
                        ipaddress.ip_network(line)
                    except ValueError:
                        # not a valid line, ignore it
                        continue

                    first_octet = utils.get_first_octet(line)
                    if not first_octet:
                        continue

                    try:
                        org_subnets[first_octet].append(line)
                    except KeyError:
                        org_subnets[first_octet] = [line]

        except (FileNotFoundError, IOError):
            # there's no slips_files/organizations_info/{org} for this org
            return

        # Store the IPs of this org
        self.db.set_org_info(org, json.dumps(org_subnets), "IPs")
        return org_subnets
