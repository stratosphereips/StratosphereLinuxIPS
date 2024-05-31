from typing import Optional, Dict, List


from slips_files.common.abstracts.observer import IObservable
from slips_files.core.helpers.whitelist.domain_whitelist import DomainAnalyzer
from slips_files.core.helpers.whitelist.ip_whitelist import IPAnalyzer
from slips_files.core.helpers.whitelist.mac_whitelist import MACAnalyzer
from slips_files.core.helpers.whitelist.organization_whitelist import (
    OrgAnalyzer,
)
from slips_files.core.helpers.whitelist.whitelist_parser import WhitelistParser
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
        self.ignored_flow_types = "arp"
        self.db = db
        self.parser = WhitelistParser(self.db)
        self.ip_analyzer = IPAnalyzer(self.db, whitelist_manager=self)
        self.domain_analyzer = DomainAnalyzer(self.db, whitelist_manager=self)
        self.mac_analyzer = MACAnalyzer(self.db, whitelist_manager=self)
        self.org_analyzer = OrgAnalyzer(self.db, whitelist_manager=self)

    def update(self):
        """
        parses the whitelist specified in the slips.conf and stores the
        parsed results in the db
        """
        self.parser.parse()
        self.db.set_whitelist("IPs", self.parser.whitelisted_ips)
        self.db.set_whitelist("domains", self.parser.whitelisted_domains)
        self.db.set_whitelist("organizations", self.parser.whitelisted_orgs)
        self.db.set_whitelist("macs", self.parser.whitelisted_mac)

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

    def is_ignored_flow_type(self, flow_type) -> bool:
        """
        Function reduce the number of checks we make if we don't need to check this type of flow
        """
        if flow_type in self.ignored_flow_types:
            return True

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
            self.ip_analyzer.get_domains_of_ip(daddr)
            + self.ip_analyzer.get_domains_of_ip(saddr)
            + self.domain_analyzer.get_domains_of_flow(flow)
        )

        # domains_to_check_dst: List[str] = self.get_domains_of_ip(daddr)
        # domains_to_check_src: List[str] = self.get_domains_of_ip(saddr)
        #
        # check if we have whitelisted domains
        # domains_to_check = self.get_domains_of_flow(flow)
        for domain in domains_to_check:
            if self.domain_analyzer.is_whitelisted_domain(
                domain, saddr, daddr, "flows"
            ):
                return True

        if self.db.get_whitelist("IPs"):
            if self.ip_analyzer.is_ip_whitelisted(
                saddr, Direction.SRC, "flows"
            ):
                return True

            if self.ip_analyzer.is_ip_whitelisted(
                daddr, Direction.DST, "flows"
            ):
                return True

            for answer in self.ip_analyzer.extract_dns_answers(flow):
                # the direction doesn't matter here
                for direction in [Direction.SRC, Direction.DST]:
                    if self.ip_analyzer.is_ip_whitelisted(
                        answer, direction, "flows"
                    ):
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
                            if self.org_analyzer.is_ip_in_org(saddr, org):
                                # self.print(f"The src IP {saddr} is in the
                                # ranges of org {org}. Whitelisted.")
                                return True
                        except ValueError:
                            # Some flows don't have IPs, but mac address or
                            # just - in some cases
                            return False

                        # Method 2 Check if the ASN of this src IP is any of
                        # these organizations
                        if self.org_analyzer.is_asn_in_org(saddr, org):
                            # this ip belongs to a whitelisted org, ignore
                            # flow
                            # self.print(f"The src IP {saddr} belong to {org}.
                            # Whitelisted because of ASN.")
                            return True

                    if "dst" in from_ or "both" in from_:
                        # Method 1 Check if dst IP belongs to a whitelisted
                        # organization range
                        try:
                            if self.org_analyzer.is_ip_in_org(flow.daddr, org):
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
                        if self.org_analyzer.is_asn_in_org(daddr, org):
                            # this ip belongs to a whitelisted org, ignore flow
                            return True

                    # either we're blocking src, dst, or both check the
                    # domain of this flow
                    # Method 3 Check if the domains of this flow belong
                    # to this org
                    # domains to check are usually 1 or 2 domains
                    for flow_domain in domains_to_check:
                        if self.org_analyzer.is_domain_in_org(
                            flow_domain, org
                        ):
                            return True

        return False

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

        if self.ip_analyzer.is_ip_whitelisted(
            victim.value, victim.direction, "alerts"
        ):
            return True

        if self.domain_analyzer.is_domain_whitelisted(
            victim.value, victim.direction
        ):
            return True

        if self.org_analyzer.is_part_of_a_whitelisted_org(victim):
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
            and self.domain_analyzer.is_domain_whitelisted(
                attacker.value, attacker.direction
            )
        ):
            # ############ TODO check that the wat_to_ignore matches
            return True

        elif attacker.attacker_type == IoCType.IP.name:
            # Check that the IP in the content of the alert is whitelisted
            if self.ip_analyzer.is_ip_whitelisted(
                attacker.value, attacker.direction, "alerts"
            ):
                return True

        if self.org_analyzer.is_part_of_a_whitelisted_org(attacker):
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
            self.ip_analyzer.ignore_alerts_from_ip(
                direction, ignore_alerts, whitelist_direction
            )
            or self.ip_analyzer.ignore_alerts_to_ip(
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
