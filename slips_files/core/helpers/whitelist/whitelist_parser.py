# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import ipaddress
import fcntl
import os
import shutil
import tempfile
from pathlib import Path
from typing import TextIO, List, Dict, Optional
import validators

from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import EvidenceType


def split_ip_destination_port(value: str) -> tuple[str, str]:
    """Read a source-IP-to-destination-port rule without changing older values.

    Parameters:
        value: IP whitelist value, optionally written as source->*:port.

    Returns:
        Source IP and destination port, or the original value and an empty port.
        Invalid connection rules raise ValueError.
    """
    if "->" not in value:
        return value, ""
    source, separator, port = value.partition("->*:")
    if not separator or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("Use source-IP->*:port with a port from 1 to 65535")
    if str(int(port)) != port:
        raise ValueError(
            "Destination port must be a whole number without leading zeros"
        )
    if source.startswith("[") and source.endswith("]"):
        source = source[1:-1]
    if "%" in source:
        raise ValueError("Source IP must not include an interface zone")
    return str(ipaddress.ip_address(source)), port


def format_ip_destination_port(source_ip: str, dst_port: int | str) -> str:
    """Build a canonical rule for one source IP and one destination port.

    Parameters:
        source_ip: Individual source IPv4 or IPv6 address.
        dst_port: Destination port, from 1 to 65535.

    Returns:
        Source->*:port value; invalid addresses or ports raise ValueError.
    """
    address = ipaddress.ip_address(source_ip)
    port = str(dst_port)
    if (
        not port.isdecimal()
        or not 1 <= int(port) <= 65535
        or "%" in str(address)
    ):
        raise ValueError(
            "Use an individual source IP and a destination port from 1 to 65535"
        )
    source = f"[{address}]" if address.version == 6 else str(address)
    return f"{source}->*:{int(port)}"


def web_whitelist_path(local_path: str) -> Path:
    """Locate web-managed rules beside the configured local whitelist.

    Parameters:
        local_path: Configured local whitelist filename.

    Returns:
        Path of the separate web-managed rule file.
    """
    path = Path(local_path)
    return path.with_name(path.name + ".web.conf")


def whitelist_backup_path(local_path: str) -> Path:
    """Return the private recovery copy beside a configured whitelist.

    Parameters:
        local_path: Configured whitelist filename.

    Returns:
        Path of its recovery copy.
    """
    path = Path(local_path)
    return path.with_name(path.name + ".bak")


def backup_local_whitelist(path: Path) -> None:
    """Atomically preserve the complete configured whitelist.

    Parameters:
        path: Existing configured whitelist file.
    """
    backup = whitelist_backup_path(str(path))
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
    try:
        shutil.copy2(path, temporary)
        os.replace(temporary, backup)
    finally:
        temporary.unlink(missing_ok=True)


def web_managed_lines(path: Path) -> set[str]:
    """Read non-comment web rules from a whitelist without parsing its IoCs.

    Parameters:
        path: Whitelist or recovery copy to inspect.

    Returns:
        Set of web-managed rule lines.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    start = "; Begin rules added from the Slips web interface"
    end = "; End rules added from the Slips web interface"
    if start not in lines or end not in lines:
        return set()
    first = lines.index(start) + 1
    last = lines.index(end, first)
    return {
        line.strip()
        for line in lines[first:last]
        if line.strip() and not line.lstrip().startswith((";", "#"))
    }


def ensure_local_whitelist(local_path: str) -> Path:
    """Restore a missing whitelist or fail before running without its rules.

    Parameters:
        local_path: Path configured for the local whitelist.

    Returns:
        Existing or restored whitelist path.
    """
    path = Path(local_path)
    backup = whitelist_backup_path(local_path)
    lock_path = path.with_name(path.name + ".lock")
    with lock_path.open("a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not path.exists():
            if not backup.is_file():
                raise FileNotFoundError(
                    f"Configured local whitelist {path} is missing and "
                    f"there is no recovery copy at {backup}. "
                    "Slips will not start without its whitelist."
                )
            with tempfile.NamedTemporaryFile(
                dir=path.parent, delete=False
            ) as handle:
                temporary = Path(handle.name)
            try:
                shutil.copy2(backup, temporary)
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
        if not path.is_file():
            raise ValueError(
                f"Configured local whitelist {path} is not a file"
            )
        if backup.is_file() and (
            web_managed_lines(backup) - web_managed_lines(path)
        ):
            raise ValueError(
                f"Configured local whitelist {path} has lost web-managed "
                f"rules preserved in {backup}. Restore those rules before "
                "starting Slips; the backup has not been overwritten."
            )
        backup_local_whitelist(path)
    return path


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
        self.whitelisted_uris = {}
        self.org_info_path = "slips_files/organizations_info/"

    def get_dict_for_storing_data(self, data_type: str):
        """
        returns the appropriate dict for storing the given data type
        """
        storage = {
            "ip": self.whitelisted_ips,
            "domain": self.whitelisted_domains,
            "org": self.whitelisted_orgs,
            "organization": self.whitelisted_orgs,
            "mac": self.whitelisted_mac,
            "uri": self.whitelisted_uris,
        }
        return storage[data_type]

    def read_configuration(self):
        conf = ConfigParser()
        self.local_whitelist_path = conf.local_whitelist_path()

    def open_whitelist_for_reading(self) -> Optional[TextIO]:
        """Open the configured local whitelist, recovering it if necessary.

        Returns:
            The open whitelist.
        """
        path = ensure_local_whitelist(self.local_whitelist_path)
        return path.open(encoding="utf-8")

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
        try:
            cache: Dict[str, dict] = self.get_dict_for_storing_data(
                entry_to_remove.get("type", "")
            )
        except KeyError:
            return False
        key = entry_to_remove["data"]
        if entry_to_remove.get("type") == "ip":
            try:
                source, port = split_ip_destination_port(key)
            except ValueError:
                return False
            if port:
                key = format_ip_destination_port(source, port)
            if entry_to_remove.get("evidence_type"):
                key += f"|{entry_to_remove['evidence_type']}"
        if key not in cache:
            return False

        # we do have it stored in the cache, we should remove it
        cached_entry: Dict[str, str] = cache[key]
        if (
            cached_entry["from"] == entry_to_remove["from"]
            and cached_entry["what_to_ignore"]
            == entry_to_remove["what_to_ignore"]
        ):
            cache.pop(key)
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

    def update_whitelisted_uris(self, uri: str, info: Dict[str, str]) -> None:
        """Store a literal request URI for flow suppression.

        Parameters:
            uri: Request URI as Zeek records it.
            info: Rule direction and suppression mode.
        """
        if (
            uri.startswith("/")
            and len(uri) <= 256
            and not any(char in uri for char in ("\r", "\n", ","))
            and info.get("what_to_ignore") in {"flows", "both"}
        ):
            self.whitelisted_uris[uri] = info

    def update_whitelisted_ips(self, ip: str, info: Dict[str, str]) -> None:
        """Store an IP rule, optionally scoped to a port.

        :param ip: IP, same-side IP:port, *:port, or source-IP->*:destination-port.
        :param info: Direction and ignore type for the rule.
        """
        try:
            source, dst_port = split_ip_destination_port(ip)
        except ValueError:
            return
        if dst_port:
            if (
                info.get("from") != "src"
                or info.get("what_to_ignore") != "alerts"
            ):
                self.manager.printer.print(
                    "Source-to-destination-port rules require src,alerts.",
                    1,
                    0,
                )
                return
            value = format_ip_destination_port(source, dst_port)
            key = (
                f"{value}|{info['evidence_type']}"
                if info.get("evidence_type")
                else value
            )
            self.whitelisted_ips[key] = {**info, "dst_port": dst_port}
            return
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
        line: List = [part.strip() for part in line.rstrip("\n").split(",")]
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
            "uri": self.update_whitelisted_uris,
        }

        entry_type = parsed_line["type"]
        if parsed_line["what_to_ignore"] == "blocking":
            try:
                address = str(ipaddress.ip_address(parsed_line["data"]))
            except ValueError:
                address = ""
            if (
                entry_type != "ip"
                or not address
                or parsed_line["from"] != "both"
                or parsed_line.get("evidence_type")
            ):
                self.manager.printer.print(
                    "Blocking whitelist rules require an IP address, "
                    "both directions and no evidence type.",
                    1,
                    0,
                )
                return
        if entry_type not in handlers:
            self.manager.printer.print(
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
                self.manager.printer.print(
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
                    line = line.strip()
                    if line.startswith(('"IoCType"', ";")):
                        continue
                    if line.startswith("#"):
                        self.remove_entry_from_cache_db(
                            self.parse_line(line[1:])
                        )
                        continue
                    try:
                        parsed_line: Dict[str, str] = self.parse_line(line)
                        if not parsed_line:
                            continue
                    except Exception:
                        self.manager.printer.print(
                            f"Line {line_number} in whitelist.conf is invalid."
                            f" Skipping."
                        )
                        continue
                    self.call_handler(parsed_line)
        return found
