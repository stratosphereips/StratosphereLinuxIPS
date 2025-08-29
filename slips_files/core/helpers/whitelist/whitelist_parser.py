# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import ipaddress
import json
import os
from typing import TextIO, List, Dict, Optional
import validators

from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils


class WhitelistParser:
    """Parses the whitelist in config/whitelist.conf"""

    def __init__(self, db, manager):
        self.db = db
        # to have access to the print function
        self.manager = manager
        self.read_configuration()
        self.init_whitelists()
        self.org_info_path = "slips_files/organizations_info/"

    def init_whitelists(self):
        """
        initializes the dicts we'll be using for storing the parsed
        whitelists.
        uses existing dicts from the db if found.
        """
        self.whitelisted_ips = {}
        self.whitelisted_domains = {}
        self.whitelisted_orgs = {}
        self.whitelisted_mac = {}
        if self.db.has_cached_whitelist():
            # since this parser can run when the user modifies whitelist.conf
            # and not just when the user starts slips
            # we need to check if the dicts are already there in the cache db
            self.whitelisted_ips = self.db.get_whitelist("IPs")
            self.whitelisted_domains = self.db.get_whitelist("domains")
            self.whitelisted_orgs = self.db.get_whitelist("organizations")
            self.whitelisted_mac = self.db.get_whitelist("mac")

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

    def set_number_of_columns(self, line: str) -> None:
        self.NUMBER_OF_WHITELIST_COLUMNS: int = len(line.split(","))

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

    def update_whitelisted_ips(self, ip: str, info: Dict[str, str]):
        if not (validators.ipv6(ip) or validators.ipv4):
            return
        self.whitelisted_ips[ip] = info

    def parse_line(self, line: str) -> Dict[str, str]:
        # line should be:
        # "type","domain/ip/organization/mac","from","what_to_ignore"
        line: List = line.replace("\n", "").replace(" ", "").split(",")
        try:
            return {
                "type": (line[0]).lower(),
                "data": line[1],
                "from": line[2],
                "what_to_ignore": line[3],
            }
        except IndexError:
            # line is missing a column, ignore it.
            # TODO raise an exception and handle it in whitelist.py
            return {}

    def call_handler(self, parsed_line: Dict[str, str]):
        """
        calls the appropriate handler based on the type of data in the
        parsed line
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
        self.db.set_org_info(org, json.dumps(org_asn), "asn")
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

        self.db.set_org_info(org, json.dumps(domains), "domains")
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

        # Each file is named after the organization's name
        org_info_file = os.path.join(self.org_info_path, org)
        try:
            org_info = open(org_info_file)
        except (FileNotFoundError, IOError):
            # there's no slips_files/organizations_info/{org} for this org
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
        self.db.set_org_info(org, json.dumps(org_subnets), "IPs")
        return org_subnets

    def parse(self) -> bool:
        """parses the whitelist specified in the slips.yaml"""
        line_number = 0

        whitelist = self.open_whitelist_for_reading()
        if not whitelist:
            return False

        while line := whitelist.readline():
            line_number += 1
            if line.startswith('"IoCType"'):
                self.set_number_of_columns(line)
                continue

            if line.startswith(";"):
                # user comment
                continue

            # check if the user commented an org, ip or domain that
            # was whitelisted before, we need to remove it from the db
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
                    f" Skipping. "
                )
                continue

            self.call_handler(parsed_line)
        whitelist.close()
        return True
