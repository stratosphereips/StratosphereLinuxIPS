# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import ipaddress
import os
from pathlib import Path
from typing import TextIO, List, Dict, Optional
import validators

from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import EvidenceType


def web_whitelist_path(local_path: str) -> Path:
    """Locate web-managed rules beside the configured local whitelist.

    Parameters:
        local_path: Configured local whitelist filename.

    Returns:
        Path of the separate web-managed rule file.
    """
    path = Path(local_path)
    return path.with_name(path.name + ".web.conf")


class WhitelistParser:
    """Parses the whitelist in config/whitelist.conf"""

    def __init__(self, db, manager):
        self.db = db
        # to have access to the print function
        self.manager = manager
        self.read_configuration()
        self.whitelisted_ips = {}
        self.whitelisted_domains = {}
        self.whitelisted_orgs = {}
        self.whitelisted_mac = {}
        self.org_info_path = "slips_files/organizations_info/"

    def get_dict_for_storing_data(self, data_type: str):
        """
        returns the appropriate dict for storing the given data type
        """
        storage = {
            "ip": self.whitelisted_ips,
            "domain": self.whitelisted_domains,
            "org": self.whitelisted_orgs,
            "mac": self.whitelisted_mac,
        }
        return storage[data_type]

    def read_configuration(self):
        conf = ConfigParser()
        self.local_whitelist_path = conf.local_whitelist_path()

    def open_whitelist_for_reading(self) -> TextIO:
        try:
            return open(self.local_whitelist_path)
        except FileNotFoundError:
            self.manager.print(
                f"Can't find {self.local_whitelist_path}. "
                f"Local whitelist disabled."
            )

    def remove_entry_from_cache_db(
        self, entry_to_remove: Dict[str, str]
    ) -> bool:
        """
        :param entry_to_remove: the line that was commented using # in the db,
        meaning it should be removed from the database
        it should be the output of self.parse_line()
        its a dict with the following keys {
               type": ..
            "data": ..
            "from": ..
            "what_to_ignore" : ..}
        """
        entry_type = entry_to_remove["type"]
        cache: Dict[str, dict] = self.get_dict_for_storing_data(entry_type)
        if entry_to_remove["data"] not in cache:
            return False

        # we do have it stored in the cache, we should remove it
        cached_entry: Dict[str, str] = cache[entry_to_remove["data"]]
        if (
            cached_entry["from"] == entry_to_remove["from"]
            and cached_entry["what_to_ignore"]
            == entry_to_remove["what_to_ignore"]
        ):
            cache.pop(entry_to_remove["data"])
        return True

    def update_whitelisted_domains(self, domain: str, info: Dict[str, str]):
        if not utils.is_valid_domain(domain):
            return

        self.whitelisted_domains[domain] = info
        # to be able to whitelist subdomains faster
        # the goal is to have an entry for each
        # subdomain and its parent domain
        hostname = utils.extract_hostname(domain)
        self.whitelisted_domains[hostname] = info

    def update_whitelisted_orgs(self, org: str, info: Dict[str, str]):
        if org not in utils.supported_orgs:
            return

        try:
            # org already whitelisted, update info
            self.whitelisted_orgs[org]["from"] = info["from"]
            self.whitelisted_orgs[org]["what_to_ignore"] = info[
                "what_to_ignore"
            ]
        except KeyError:
            # first time seeing this org
            self.whitelisted_orgs[org] = info

    def update_whitelisted_mac_addresses(self, mac: str, info: Dict[str, str]):
        if not validators.mac_address(mac):
            return
        self.whitelisted_mac[mac] = info

    def update_whitelisted_ips(self, ip: str, info: Dict[str, str]) -> None:
        """Store an IP rule, optionally scoped to a port.

        :param ip: IPv4, IPv6, IPv4:port, [IPv6]:port, or *:port.
        :param info: Direction and ignore type for the rule.
        """
        if validators.ipv6(ip) or validators.ipv4(ip):
            key = (
                f"{ip}|{info['evidence_type']}"
                if info.get("evidence_type")
                else ip
            )
            self.whitelisted_ips[key] = info
            return

        if ip.startswith("["):
            address, separator, port = ip[1:].partition("]:")
            valid_address = separator and validators.ipv6(address)
        else:
            address, separator, port = ip.rpartition(":")
            valid_address = separator and (
                address == "*" or validators.ipv4(address)
            )

        if not valid_address or not port.isdecimal():
            return
        if not 0 <= int(port) <= 65535 or str(int(port)) != port:
            return
        key = (
            f"{ip}|{info['evidence_type']}"
            if info.get("evidence_type")
            else ip
        )
        self.whitelisted_ips[key] = info

    def parse_line(self, line: str) -> Dict[str, str]:
        """Parse one local rule with an optional evidence type.

        Parameters:
            line: Comma-separated whitelist line.

        Returns:
            Parsed rule fields or an empty dict for an incomplete line.
        """
        # line should be:
        # "type","domain/ip/organization/mac","from","what_to_ignore"
        line: List = line.replace("\n", "").replace(" ", "").split(",")
        try:
            return {
                "type": (line[0]).lower(),
                "data": line[1],
                "from": line[2],
                "what_to_ignore": line[3],
                "evidence_type": line[4].upper() if len(line) > 4 else "",
            }
        except IndexError:
            # line is missing a column, ignore it.
            # TODO raise an exception and handle it in whitelist.py
            return {}

    def call_handler(self, parsed_line: Dict[str, str]):
        """
        calls the appropriate handler based on the type of data in the
        given line
        :param parsed_line: output dict of self.parse_line
        should have the following keys {
            type": ..
            "data": ..
            "from": ..
            "what_to_ignore" : ..}
        """
        handlers = {
            "ip": self.update_whitelisted_ips,
            "domain": self.update_whitelisted_domains,
            "organization": self.update_whitelisted_orgs,
            "mac": self.update_whitelisted_mac_addresses,
        }

        entry_type = parsed_line["type"]
        if entry_type not in handlers:
            self.manager.print(
                f"{parsed_line['data']} is not a valid" f" {entry_type}.", 1, 0
            )
            return

        entry_details = {
            "from": parsed_line["from"],
            "what_to_ignore": parsed_line["what_to_ignore"],
        }
        evidence_type = parsed_line.get("evidence_type", "")
        if evidence_type:
            if (
                entry_type != "ip"
                or evidence_type not in EvidenceType.__members__
                or entry_details["what_to_ignore"] != "alerts"
            ):
                self.manager.print(
                    "Invalid evidence-scoped whitelist rule.", 1, 0
                )
                return
            entry_details["evidence_type"] = evidence_type
        handlers[entry_type](parsed_line["data"], entry_details)

    def load_org_asn(self, org) -> Optional[List[str]]:
        """
        Reads the specified org's asn from slips_files/organizations_info
         and stores the info in the database
        org: 'google', 'facebook', 'twitter', etc...
        returns a list containing the org's asn
        """
        asn_info_file = os.path.join(self.org_info_path, f"{org}_asn")
        try:
            org_asn_file = open(asn_info_file)
        except (FileNotFoundError, IOError):
            return

        org_asn = []
        while line := org_asn_file.readline():
            line = line.replace("\n", "").strip()
            org_asn.append(line.upper())
        org_asn_file.close()
        self.db.set_org_info(org, org_asn, "asn")
        return org_asn

    def load_org_domains(self, org):
        """
        Reads the specified org's domains from
        slips_files/organizations_info
        and stores the info in the database
        org: 'google', 'facebook', 'twitter', etc...
        returns a list containing the org's domains
        """
        domain_info_file = os.path.join(self.org_info_path, f"{org}_domains")
        try:
            domain_info = open(domain_info_file)
        except (FileNotFoundError, IOError):
            return False

        domains = []
        while line := domain_info.readline():
            # each line will be something like this: 34.64.0.0/10
            line = line.replace("\n", "").strip()
            domains.append(line.lower())
        domain_info.close()

        self.db.set_org_info(org, domains, "domains")
        return domains

    def is_valid_network(self, network: str) -> bool:
        try:
            ipaddress.ip_network(network)
            return True
        except ValueError:
            return False

    def load_org_ips(self, org) -> Optional[Dict[str, List[str]]]:
        """
        Reads the specified org's info from slips_files/organizations_info
        and stores the info in the database
        :param org: has to be a supported org.
         'google', 'facebook', 'twitter', etc...
        returns a dict of this organization's subnets
        """
        if org not in utils.supported_orgs:
            return

        org_info_file = os.path.join(self.org_info_path, f"{org}_ip_ranges")
        try:
            org_info = open(org_info_file)
        except (FileNotFoundError, IOError):
            # there's no slips_files/organizations_info/{org}_ip_ranges
            # for this org
            return

        org_subnets = {}
        # Each line of the file contains an ip range,
        # for example: 34.64.0.0/10
        while line := org_info.readline():
            line = line.replace("\n", "").strip()

            if not self.is_valid_network(line):
                continue

            first_octet = utils.get_first_octet(line)
            if not first_octet:
                continue

            try:
                org_subnets[first_octet].append(line)
            except KeyError:
                org_subnets[first_octet] = [line]

        org_info.close()

        self.db.set_org_cidrs(org, org_subnets)
        return org_subnets

    def parse(self) -> bool:
        """Parse the configured whitelist, then persistent web-managed rules.

        Returns:
            Whether at least one whitelist file was available.
        """
        sources = [self.open_whitelist_for_reading()]
        try:
            sources.append(
                web_whitelist_path(self.local_whitelist_path).open(
                    encoding="utf-8"
                )
            )
        except FileNotFoundError:
            pass

        found = False
        for whitelist in sources:
            if not whitelist:
                continue
            found = True
            with whitelist:
                for line_number, line in enumerate(whitelist, start=1):
                    if line.startswith(('"IoCType"', ";")):
                        continue
                    if line.startswith("#"):
                        self.remove_entry_from_cache_db(
                            self.parse_line(line.replace("#", ""))
                        )
                        continue
                    try:
                        parsed_line: Dict[str, str] = self.parse_line(line)
                        if not parsed_line:
                            continue
                    except Exception:
                        self.manager.print(
                            f"Line {line_number} in whitelist.conf is invalid."
                            f" Skipping."
                        )
                        continue
                    self.call_handler(parsed_line)
        return found
