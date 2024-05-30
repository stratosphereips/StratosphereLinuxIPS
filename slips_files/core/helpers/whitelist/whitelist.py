from typing import Optional, Dict, List
import validators


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

    def is_ignored_flow_type(self, flow_type) -> bool:
        """
        Function reduce the number of checks we make if we don't need to check this type of flow
        """
        if flow_type in self.ignored_flow_types:
            return True

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
                        if self.is_asn_in_org(saddr, org):
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
                        if self.is_asn_in_org(daddr, org):
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
