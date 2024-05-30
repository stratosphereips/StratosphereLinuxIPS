from typing import Optional, Dict, List
import tldextract
import json
import ipaddress
import validators
import os


from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.observer import IObservable
from slips_files.core.helpers.whitelist.ip_whitelist import IPAnalyzer
from slips_files.core.output import Output
from slips_files.core.evidence_structure.evidence import (
    Evidence,
    Direction,
    IoCType,
    Attacker,
)


class Whitelist(IObservable):
    def __init__(self, logger: Output, db):
        IObservable.__init__(self)
        self.logger = logger
        self.add_observer(self.logger)
        self.name = "whitelist"
        self.read_configuration()
        self.org_info_path = "slips_files/organizations_info/"
        self.ignored_flow_types = "arp"
        self.db = db
        self.ip_analyzer = IPAnalyzer(self.db, whitelist_manager=self)

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        # the only observer we have for now in the output.
        # used for logging the msgs too cli and slips log files
        self.notify_observers(
            {
                "from": self.name,
                "txt": text,
                "verbose": verbose,
                "debug": debug,
            }
        )

    def read_configuration(self):
        conf = ConfigParser()
        self.whitelist_path = conf.whitelist_path()

    def is_whitelisted_asn(self, ip, org):
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

    def is_ignored_flow_type(self, flow_type) -> bool:
        """
        Function reduce the number of checks we make if we don't need to check this type of flow
        """
        if flow_type in self.ignored_flow_types:
            return True

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
        dst_domains_of_flow: List[str] = self.get_domains_of_ip(daddr)
        src_domains_of_flow: List[str] = self.get_domains_of_ip(saddr)

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

    def extract_dns_answers(self, flow) -> List[str]:
        """
        extracts all the ips we can find from the given flow
        """
        ips = []
        if flow.type_ == "dns":
            ips = ips + flow.answers
        return ips

    def is_whitelisted_flow(self, flow) -> bool:
        """
        Checks if the src IP, dst IP, domain, dns answer, or  organization
         of this flow is whitelisted.
        """
        saddr = flow.saddr
        daddr = flow.daddr
        flow_type = flow.type_
        # get the domains of the IPs this flow
        domains_to_check: List[str] = (
            self.get_domains_of_ip(daddr)
            + self.get_domains_of_ip(saddr)
            + self.get_domains_of_flow(flow)
        )

        # domains_to_check_dst: List[str] = self.get_domains_of_ip(daddr)
        # domains_to_check_src: List[str] = self.get_domains_of_ip(saddr)
        #
        # check if we have whitelisted domains
        # domains_to_check = self.get_domains_of_flow(flow)
        for domain in domains_to_check:
            if self.is_whitelisted_domain(domain, saddr, daddr, "flows"):
                return True

        if self.db.get_whitelist("IPs"):
            if self.is_ip_whitelisted(saddr, Direction.SRC, "flows"):
                return True

            if self.is_ip_whitelisted(daddr, Direction.DST, "flows"):
                return True

            for answer in self.extract_dns_answers(flow):
                # the direction doesn't matter here
                for direction in [Direction.SRC, Direction.DST]:
                    if self.is_ip_whitelisted(answer, direction, "flows"):
                        return True

        if whitelisted_macs := self.db.get_whitelist("mac"):
            # try to get the mac address of the current flow
            src_mac = flow.smac if hasattr(flow, "smac") else False

            if not src_mac:
                if src_mac := self.db.get_mac_addr_from_profile(
                    f"profile_{saddr}"
                ):
                    src_mac = src_mac[0]

            if src_mac and src_mac in list(whitelisted_macs.keys()):
                # the src mac of this flow is whitelisted, but which direction?
                from_ = whitelisted_macs[src_mac]["from"]
                what_to_ignore = whitelisted_macs[src_mac]["what_to_ignore"]

                if (
                    "src" in from_ or "both" in from_
                ) and self.should_ignore_flows(what_to_ignore):
                    # self.print(f"The source MAC of this flow
                    # {src_mac} is whitelisted")
                    return True

            dst_mac = flow.dmac if hasattr(flow, "smac") else False
            if dst_mac and dst_mac in list(whitelisted_macs.keys()):
                # the dst mac of this flow is whitelisted, but which direction?
                from_ = whitelisted_macs[dst_mac]["from"]
                what_to_ignore = whitelisted_macs[dst_mac]["what_to_ignore"]

                if (
                    "dst" in from_ or "both" in from_
                ) and self.should_ignore_flows(what_to_ignore):
                    # self.print(f"The dst MAC of this flow {dst_mac}
                    # is whitelisted")
                    return True

        if self.is_ignored_flow_type(flow_type):
            return False

        if whitelisted_orgs := self.db.get_whitelist("organizations"):
            # self.print('Check if the organization is whitelisted')
            # Check if IP belongs to a whitelisted organization range
            # Check if the ASN of this IP is any of these organizations

            for org in whitelisted_orgs:
                from_ = whitelisted_orgs[org]["from"]  # src or dst or both
                what_to_ignore = whitelisted_orgs[org][
                    "what_to_ignore"
                ]  # flows, alerts or both
                # self.print(f'Checking {org}, from:{from_} type {what_to_ignore}')

                if self.should_ignore_flows(what_to_ignore):
                    # We want to block flows from this org. get the domains
                    # of this flow based on the direction.
                    # if "both" in from_:
                    #     domains_to_check = (
                    #         domains_to_check_src + domains_to_check_dst
                    #     )
                    # elif "src" in from_:
                    #     domains_to_check = domains_to_check_src
                    # elif "dst" in from_:
                    #     domains_to_check = domains_to_check_dst

                    if "src" in from_ or "both" in from_:
                        # Method 1 Check if src IP belongs to a whitelisted
                        # organization range
                        try:
                            if self.is_ip_in_org(saddr, org):
                                # self.print(f"The src IP {saddr} is in the
                                # ranges of org {org}. Whitelisted.")
                                return True
                        except ValueError:
                            # Some flows don't have IPs, but mac address or
                            # just - in some cases
                            return False

                        # Method 2 Check if the ASN of this src IP is any of
                        # these organizations
                        if self.is_whitelisted_asn(saddr, org):
                            # this ip belongs to a whitelisted org, ignore
                            # flow
                            # self.print(f"The src IP {saddr} belong to {org}.
                            # Whitelisted because of ASN.")
                            return True

                    if "dst" in from_ or "both" in from_:
                        # Method 1 Check if dst IP belongs to a whitelisted
                        # organization range
                        try:
                            if self.is_ip_in_org(flow.daddr, org):
                                # self.print(f"The dst IP
                                # {column_values['daddr']} "
                                #            f"is in the network range of org
                                #            {org}. Whitelisted.")
                                return True
                        except ValueError:
                            # Some flows don't have IPs, but mac address or
                            # just - in some cases
                            return False

                        # Method 2 Check if the ASN of this dst IP is any of
                        # these organizations
                        if self.is_whitelisted_asn(daddr, org):
                            # this ip belongs to a whitelisted org, ignore flow
                            return True

                    # either we're blocking src, dst, or both check the
                    # domain of this flow
                    # Method 3 Check if the domains of this flow belong
                    # to this org
                    # domains to check are usually 1 or 2 domains
                    for flow_domain in domains_to_check:
                        if self.is_domain_in_org(flow_domain, org):
                            return True

        return False

    @staticmethod
    def get_tld(url: str):
        """returns the top level domain from the gven url"""
        return tldextract.extract(url).suffix

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

    def read_whitelist(self):
        """Reads the content of whitelist.conf and stores information about
        each ip/org/domain in the database"""

        # since this function can be run when the user modifies whitelist.conf
        # we need to check if the dicts are already there
        whitelisted_ips = self.db.get_whitelist("IPs")
        whitelisted_domains = self.db.get_whitelist("domains")
        whitelisted_orgs = self.db.get_whitelist("organizations")
        whitelisted_mac = self.db.get_whitelist("mac")
        # Process lines after comments
        line_number = 0
        try:
            with open(self.whitelist_path) as whitelist:
                # line = whitelist.readline()
                while line := whitelist.readline():
                    line_number += 1
                    if line.startswith('"IoCType"'):
                        continue

                    # check if the user commented an org, ip or domain that
                    # was whitelisted
                    if line.startswith("#"):
                        if whitelisted_ips:
                            for ip in list(whitelisted_ips):
                                # make sure the user commented the line we
                                # have in cache exactly
                                if (
                                    ip in line
                                    and whitelisted_ips[ip]["from"] in line
                                    and whitelisted_ips[ip]["what_to_ignore"]
                                    in line
                                ):
                                    # remove that entry from whitelisted_ips
                                    whitelisted_ips.pop(ip)
                                    break

                        if whitelisted_domains:
                            for domain in list(whitelisted_domains):
                                if (
                                    domain in line
                                    and whitelisted_domains[domain]["from"]
                                    in line
                                    and whitelisted_domains[domain][
                                        "what_to_ignore"
                                    ]
                                    in line
                                ):
                                    # remove that entry from whitelisted_domains
                                    whitelisted_domains.pop(domain)
                                    break

                        if whitelisted_orgs:
                            for org in list(whitelisted_orgs):
                                if (
                                    org in line
                                    and whitelisted_orgs[org]["from"] in line
                                    and whitelisted_orgs[org]["what_to_ignore"]
                                    in line
                                ):
                                    # remove that entry from whitelisted_domains
                                    whitelisted_orgs.pop(org)
                                    break

                        # todo if the user closes slips, changes the whitelist, and reopens slips ,
                        #  slips will still have the old whitelist in the cache!
                        continue
                    # line should be: ["type","domain/ip/organization",
                    # "from","what_to_ignore"]
                    line = line.replace("\n", "").replace(" ", "").split(",")
                    try:
                        type_, data, from_, what_to_ignore = (
                            (line[0]).lower(),
                            line[1],
                            line[2],
                            line[3],
                        )
                    except IndexError:
                        # line is missing a column, ignore it.
                        self.print(
                            f"Line {line_number} in whitelist.conf "
                            f"is missing a column. Skipping."
                        )
                        continue

                    # Validate the type before processing
                    try:
                        whitelist_line_info = {
                            "from": from_,
                            "what_to_ignore": what_to_ignore,
                        }
                        if "ip" in type_ and (
                            validators.ip_address.ipv6(data)
                            or validators.ip_address.ipv4(data)
                        ):
                            whitelisted_ips[data] = whitelist_line_info
                        elif "domain" in type_ and validators.domain(data):
                            whitelisted_domains[data] = whitelist_line_info
                            # to be able to whitelist subdomains faster
                            # the goal is to have an entry for each
                            # subdomain and its parent domain
                            hostname = self.extract_hostname(data)
                            whitelisted_domains[hostname] = whitelist_line_info
                        elif "mac" in type_ and validators.mac_address(data):
                            whitelisted_mac[data] = whitelist_line_info
                        elif "org" in type_:
                            if data not in utils.supported_orgs:
                                self.print(
                                    f"Whitelisted org {data} is not"
                                    f" supported in slips"
                                )
                                continue
                            # organizations dicts look something like this:
                            #  {'google': {'from':'dst',
                            #               'what_to_ignore': 'alerts'
                            #               'IPs': {'34.64.0.0/10': subnet}}
                            try:
                                # org already whitelisted, update info
                                whitelisted_orgs[data]["from"] = from_
                                whitelisted_orgs[data][
                                    "what_to_ignore"
                                ] = what_to_ignore
                            except KeyError:
                                # first time seeing this org
                                whitelisted_orgs[data] = whitelist_line_info

                        else:
                            self.print(f"{data} is not a valid {type_}.", 1, 0)
                    except Exception:
                        self.print(
                            f"Line {line_number} in whitelist.conf is invalid."
                            f" Skipping. "
                        )
        except FileNotFoundError:
            self.print(
                f"Can't find {self.whitelist_path}, using slips default "
                f"whitelist.conf instead"
            )
            if self.whitelist_path != "config/whitelist.conf":
                self.whitelist_path = "config/whitelist.conf"
                self.read_whitelist()

        # store everything in the cache db because we'll be needing this
        # info in the evidenceProcess
        self.db.set_whitelist("IPs", whitelisted_ips)
        self.db.set_whitelist("domains", whitelisted_domains)
        self.db.set_whitelist("organizations", whitelisted_orgs)
        self.db.set_whitelist("macs", whitelisted_mac)

        return (
            whitelisted_ips,
            whitelisted_domains,
            whitelisted_orgs,
            whitelisted_mac,
        )

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

    def profile_has_whitelisted_mac(
        self, profile_ip, whitelisted_macs, direction: Direction
    ) -> bool:
        """
        Checks for alerts whitelist
        """
        mac = self.db.get_mac_addr_from_profile(f"profile_{profile_ip}")

        if not mac:
            # we have no mac for this profile
            return False

        mac = mac[0]
        if mac in list(whitelisted_macs.keys()):
            # src or dst and
            from_ = whitelisted_macs[mac]["from"]
            what_to_ignore = whitelisted_macs[mac]["what_to_ignore"]
            # do we want to whitelist alerts?
            if "alerts" in what_to_ignore or "both" in what_to_ignore:
                if direction == Direction.DST and (
                    "src" in from_ or "both" in from_
                ):
                    return True
                if direction == Direction.DST and (
                    "dst" in from_ or "both" in from_
                ):
                    return True

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

    def should_ignore_from(self, direction) -> bool:
        """
        Returns true if the user wants to whitelist alerts/flows from
         a source e.g(ip, org, mac, etc)
        """
        return "src" in direction or "both" in direction

    def should_ignore_to(self, direction) -> bool:
        """
        Returns true if the user wants to whitelist alerts/flows to
        this source(ip, org, mac, etc)
        """
        return "dst" in direction or "both" in direction

    def should_ignore_alerts(self, what_to_ignore) -> bool:
        """
        returns true we if the user wants to ignore alerts
        """
        return "alerts" in what_to_ignore or "both" in what_to_ignore

    def should_ignore_flows(self, what_to_ignore) -> bool:
        """
        returns true we if the user wants to ignore alerts
        """
        return "flows" in what_to_ignore or "both" in what_to_ignore

    def get_all_whitelist(self) -> Optional[Dict[str, dict]]:
        """
        returns the whitelisted ips, domains, org from the db
        returns a dict with the following keys
        'mac', 'organizations', 'IPs', 'domains'
        this function tries to get the whitelist from the db 10 times
        """
        whitelist: Dict[str, dict] = self.db.get_all_whitelist()
        max_tries = 10
        # if this module is loaded before profilerProcess or before we're
        # done processing the whitelist in general
        # the database won't return the whitelist
        # so we need to try several times until the db returns the
        # populated whitelist
        # empty dicts evaluate to False
        while not bool(whitelist) and max_tries != 0:
            # try max 10 times to get the whitelist, if it's still empty
            # hen it's not empty by mistake
            max_tries -= 1
            whitelist = self.db.get_all_whitelist()

        if max_tries == 0:
            # we tried 10 times to get the whitelist, it's probably empty.
            return

        return whitelist

    def is_whitelisted_evidence(self, evidence: Evidence) -> bool:
        """
        Checks if an evidence is whitelisted
        """
        if self.is_whitelisted_attacker(evidence):
            return True

        if self.is_whitelisted_victim(evidence):
            return True

    def is_whitelisted_victim(self, evidence: Evidence) -> bool:
        if not hasattr(evidence, "victim"):
            return False

        victim = evidence.victim
        if not victim:
            return False

        if self.is_ip_whitelisted(victim.value, victim.direction, "alerts"):
            return True

        if (
            victim.victim_type == IoCType.DOMAIN.name
            and self._is_domain_whitelisted(victim.value, victim.direction)
        ):
            return True

        if self.is_part_of_a_whitelisted_org(victim):
            return True

    def is_whitelisted_attacker(self, evidence: Evidence):
        if not hasattr(evidence, "attacker"):
            return False

        attacker: Attacker = evidence.attacker
        if not attacker:
            return False

        whitelisted_orgs: Dict[str, dict] = self.db.get_whitelist(
            "organizations"
        )
        if not whitelisted_orgs:
            return False

        if (
            attacker.attacker_type == IoCType.DOMAIN.name
            and self._is_domain_whitelisted(attacker.value, attacker.direction)
        ):
            # ############ TODO check that the wat_to_ignore matches
            return True

        elif attacker.attacker_type == IoCType.IP.name:
            # Check that the IP in the content of the alert is whitelisted
            if self.is_ip_whitelisted(
                attacker.value, attacker.direction, "alerts"
            ):
                return True

        if self.is_part_of_a_whitelisted_org(attacker):
            ############ TODO check that the wat_to_ignore matches
            return True

        return False

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

    def load_org_IPs(self, org):
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
                        line = f.readline()
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

    def what_to_ignore_match_whitelist(
        self, checking: str, whitelist_to_ignore: str
    ):
        """
        returns True if we're checking a flow, and the whitelist has
        'flows' or 'both' as the type to ignore
        OR
        if we're checking an alert and the whitelist has 'alerts' or 'both' as the
        type to ignore
        :param checking: can be flows or alerts
        :param whitelist_to_ignore: can be flows or alerts
        """
        return checking == whitelist_to_ignore or whitelist_to_ignore == "both"

    def is_valid_mac(self, mac: str) -> bool:
        return validators.mac_address(mac)

    # def is_mac_whitelisted(self, mac: str):
    #     if not self.is_valid_mac(mac):
    #         return False
    #
    #     whitelisted_macs: Dict[str, dict] = self.db.get_whitelist("macs")
    #
    #     if mac in whitelisted_macs:
    #         # Check if we should ignore src or dst alerts from this ip
    #         # from_ can be: src, dst, both
    #         # what_to_ignore can be: alerts or flows or both
    #         whitelist_direction: str = whitelisted_ips[ip]["from"]
    #         what_to_ignore = whitelisted_ips[ip]["what_to_ignore"]
    #         ignore_alerts = self.should_ignore_alerts(what_to_ignore)
    #
    #         if self.ignore_alert(
    #             direction, ignore_alerts, whitelist_direction
    #         ):
    #             # self.print(f'Whitelisting src IP {srcip} for evidence'
    #             #            f' about {ip}, due to a connection related to {data} '
    #             #            f'in {description}')
    #             return True
    #
    #         # Now we know this ipv4 or ipv6 isn't whitelisted
    #         # is the mac address of this ip whitelisted?
    #         if whitelisted_macs and self.profile_has_whitelisted_mac(
    #             ip, whitelisted_macs, direction
    #         ):
    #             return True
    #     return False

    def ignore_alert(
        self, direction, ignore_alerts, whitelist_direction
    ) -> bool:
        """
        determines whether or not we should ignore the given alert based
         on the ip's direction and the whitelist direction
        """
        if (
            self.ignore_alerts_from_ip(
                direction, ignore_alerts, whitelist_direction
            )
            or self.ignore_alerts_to_ip(
                direction, ignore_alerts, whitelist_direction
            )
            or self.ignore_alerts_from_both_directions(
                ignore_alerts, whitelist_direction
            )
        ):
            return True

    def ignore_alerts_from_both_directions(
        self, ignore_alerts: bool, whitelist_direction: str
    ) -> bool:
        return ignore_alerts and "both" in whitelist_direction

    def extract_hostname(self, url: str) -> str:
        """
        extracts the parent domain from the given domain/url
        """
        parsed_url = tldextract.extract(url)
        return f"{parsed_url.domain}.{parsed_url.suffix}"

    def _is_domain_whitelisted(self, domain: str, direction: Direction):
        # todo differentiate between this and is_whitelisted_Domain()
        # extracts the parent domain
        parent_domain: str = self.extract_hostname(domain)
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
        if not self.should_ignore_alerts(what_to_ignore):
            return False

        # Ignore src or dst
        dir_from_whitelist: str = whitelisted_domains[parent_domain]["from"]
        if not self.ioc_dir_match_whitelist_dir(direction, dir_from_whitelist):
            return False

        return True

    def is_domain_in_tranco_list(self, domain):
        """
        The Tranco list contains the top 10k known benign domains
        https://tranco-list.eu/list/X5QNN/1000000
        """
        # todo the db shouldn't be checking this, we should check it here
        return self.db.is_whitelisted_tranco_domain(domain)

    def ioc_dir_match_whitelist_dir(
        self,
        ioc_direction: Direction,
        dir_from_whitelist: str,
    ) -> bool:
        """
        Checks if the ioc direction given (ioc_direction) matches the
        direction
        that we
        should whitelist taken from whitelist.conf (dir_from_whitelist)

        for example
        if dir_to_check is srs and the dir_from whitelist is both,
        this function returns true

        :param ioc_direction: Direction obj, this is the dir of the ioc
        that we wanna check
        :param dir_from_whitelist: the direction read from whitelist.conf.
        can be "src", "dst" or "both":
        """
        if dir_from_whitelist == "both":
            return True

        whitelist_src = (
            "src" in dir_from_whitelist and ioc_direction == Direction.SRC
        )
        whitelist_dst = (
            "dst" in dir_from_whitelist and ioc_direction == Direction.DST
        )

        return whitelist_src or whitelist_dst

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

        if self.is_private_ip(ioc_type, ioc):
            return False

        whitelisted_orgs: Dict[str, dict] = self.db.get_whitelist(
            "organizations"
        )
        if not whitelisted_orgs:
            return False

        for org in whitelisted_orgs:
            dir_from_whitelist = whitelisted_orgs[org]["from"]
            if not self.ioc_dir_match_whitelist_dir(
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
