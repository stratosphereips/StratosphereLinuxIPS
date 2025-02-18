# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from typing import Optional, Dict, List, Union

from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.printer import Printer
from slips_files.core.helpers.whitelist.domain_whitelist import DomainAnalyzer
from slips_files.core.helpers.whitelist.ip_whitelist import IPAnalyzer
from slips_files.core.helpers.whitelist.mac_whitelist import MACAnalyzer
from slips_files.core.helpers.whitelist.matcher import WhitelistMatcher
from slips_files.core.helpers.whitelist.organization_whitelist import (
    OrgAnalyzer,
)
from slips_files.core.helpers.whitelist.whitelist_parser import WhitelistParser
from slips_files.core.output import Output
from slips_files.core.structures.evidence import (
    Evidence,
    Direction,
    Attacker,
    Victim,
)


class Whitelist:
    name = "Whitelist"

    def __init__(self, logger: Output, db):
        self.printer = Printer(logger, self.name)
        self.name = "whitelist"
        self.db = db
        self.match = WhitelistMatcher()
        self.parser = WhitelistParser(self.db, self)
        self.ip_analyzer = IPAnalyzer(self.db, whitelist_manager=self)
        self.domain_analyzer = DomainAnalyzer(self.db, whitelist_manager=self)
        self.mac_analyzer = MACAnalyzer(self.db, whitelist_manager=self)
        self.org_analyzer = OrgAnalyzer(self.db, whitelist_manager=self)
        self.read_configuration()

    def read_configuration(self):
        conf = ConfigParser()
        self.enable_local_whitelist: bool = conf.enable_local_whitelist()

    def update(self):
        """
        parses the local whitelist specified in the slips.yaml
        and stores the parsed results in the db
        """
        self.parser.parse()
        self.db.set_whitelist("IPs", self.parser.whitelisted_ips)
        self.db.set_whitelist("domains", self.parser.whitelisted_domains)
        self.db.set_whitelist("organizations", self.parser.whitelisted_orgs)
        self.db.set_whitelist("macs", self.parser.whitelisted_mac)

    def _check_if_whitelisted_domains_of_flow(self, flow) -> bool:
        dst_domains_to_check: List[str] = (
            self.domain_analyzer.get_dst_domains_of_flow(flow)
        )

        src_domains_to_check: List[str] = (
            self.domain_analyzer.get_src_domains_of_flow(flow)
        )

        for domain in dst_domains_to_check:
            if self.domain_analyzer.is_whitelisted(
                domain, Direction.DST, "flows"
            ):
                return True

        for domain in src_domains_to_check:
            if self.domain_analyzer.is_whitelisted(
                domain, Direction.SRC, "flows"
            ):
                return True
        return False

    def _flow_contains_whitelisted_ip(self, flow):
        """
        Returns True if any of the flow ips are whitelisted.
        checks the saddr, the daddr, and the dns answer
        """
        if self.ip_analyzer.is_whitelisted(flow.saddr, Direction.SRC, "flows"):
            return True

        if self.ip_analyzer.is_whitelisted(flow.daddr, Direction.DST, "flows"):
            return True

        for answer in self.ip_analyzer.extract_dns_answers(flow):
            if self.ip_analyzer.is_whitelisted(answer, Direction.DST, "flows"):
                return True
        return False

    def _flow_contains_whitelisted_mac(self, flow) -> bool:
        """
        Returns True if any of the flow MAC addresses are whitelisted.
        checks the MAC of the saddr, and the daddr
        """
        if self.mac_analyzer.profile_has_whitelisted_mac(
            flow.saddr, Direction.SRC, "flows"
        ):
            return True

        if self.mac_analyzer.profile_has_whitelisted_mac(
            flow.daddr, Direction.DST, "flows"
        ):
            return True

        # try to get the mac address of the current flow
        src_mac: str = flow.smac if hasattr(flow, "smac") else False
        if self.mac_analyzer.is_whitelisted(src_mac, Direction.SRC, "flows"):
            return True

        dst_mac = flow.dmac if hasattr(flow, "dmac") else False
        if self.mac_analyzer.is_whitelisted(dst_mac, Direction.DST, "flows"):
            return True
        return False

    def is_whitelisted_flow(self, flow) -> bool:
        """
        Checks if the src IP, dst IP, domain, dns answer, or organization
         of this flow is whitelisted.
        """
        if self._check_if_whitelisted_domains_of_flow(flow):
            return True

        if self._flow_contains_whitelisted_ip(flow):
            return True

        if self._flow_contains_whitelisted_mac(flow):
            return True

        if self.match.is_ignored_flow_type(flow.type_):
            return False

        return self.org_analyzer.is_whitelisted(flow)

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
        if self._is_whitelisted_entity(evidence, "attacker"):
            return True

        if self._is_whitelisted_entity(evidence, "victim"):
            return True
        return False

    def _is_whitelisted_entity(
        self, evidence: Evidence, entity_type: str
    ) -> bool:
        """
        checks the attacker or victim entities of the given evidence for
        whitelisted ips/domains/SNIs etc.
        :param entity_type: either 'victim' or 'attacker'
        """
        entity: Union[Attacker, Victim]
        entity = getattr(evidence, entity_type, None)
        if not entity:
            return False

        what_to_ignore = "alerts"

        if self.ip_analyzer.is_whitelisted(
            entity.value, entity.direction, what_to_ignore
        ):
            return True

        if self.domain_analyzer.is_whitelisted(
            entity.value, entity.direction, what_to_ignore
        ):
            return True

        # check the rest of the domains that belong to this domain/IP
        resolutions = entity.DNS_resolution if entity.DNS_resolution else []
        cnames = entity.CNAME if entity.CNAME else []
        for domain in [entity.SNI] + resolutions + cnames:
            if self.domain_analyzer.is_whitelisted(
                domain, Direction.DST, what_to_ignore
            ):
                return True

        if self.mac_analyzer.profile_has_whitelisted_mac(
            entity.value, entity.direction, what_to_ignore
        ):
            return True

        org_check_method = self.org_analyzer.is_part_of_a_whitelisted_org
        if org_check_method(
            entity.value,
            entity.ioc_type,
            entity.direction,
            what_to_ignore,
        ):
            return True

        return False
