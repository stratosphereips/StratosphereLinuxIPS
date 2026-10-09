# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import time
import ipaddress
from collections import OrderedDict
from typing import (
    Any,
    Dict,
    List,
    Union,
    Set,
)

from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.input_type import InputType
from slips_files.common.printer import Printer
from slips_files.core.helpers.bloom_filters_manager import BFManager
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
    IoCType,
)


class Whitelist:
    name = "whitelist"

    def __init__(self, logger: Output, db, bloom_filter_manager: BFManager):
        self.printer = Printer(logger, self.name)
        self.name = "whitelist"
        self.db = db
        self.bloom_filters: BFManager = bloom_filter_manager
        self.match = WhitelistMatcher()
        self.parser = WhitelistParser(self.db, self)
        self.ip_analyzer = IPAnalyzer(self.db, whitelist_manager=self)
        self.domain_analyzer = DomainAnalyzer(self.db, whitelist_manager=self)
        self.mac_analyzer = MACAnalyzer(self.db, whitelist_manager=self)
        self.org_analyzer = OrgAnalyzer(self.db, whitelist_manager=self)
        self.read_configuration()
        self._filter_slips_own_traffic = (
            self.db.get_input_type() == InputType.INTERFACE
        )
        self._own_source_cache: OrderedDict[str, tuple[bool, float]] = (
            OrderedDict()
        )

    def read_configuration(self):
        conf = ConfigParser()
        self.enable_local_whitelist: bool = conf.enable_local_whitelist()

    def update(self):
        """
        parses the local whitelist specified in the slips.yaml
        and stores the parsed results in the db and in bloom filters
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

    def _flow_contains_whitelisted_ip(self, flow) -> bool:
        """
        Returns True if any of the flow ips are whitelisted.
        checks the saddr, the daddr, and the dns answer
        """
        if self.ip_analyzer.is_whitelisted(
            flow.saddr, Direction.SRC, "flows", getattr(flow, "sport", None)
        ):
            return True

        if self.ip_analyzer.is_whitelisted(
            flow.daddr, Direction.DST, "flows", getattr(flow, "dport", None)
        ):
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
        if self._is_slips_own_flow(flow):
            return True

        if self._check_if_whitelisted_domains_of_flow(flow):
            return True

        if self._flow_contains_whitelisted_ip(flow):
            return True

        if self._flow_contains_whitelisted_mac(flow):
            return True

        if self.match.is_ignored_flow_type(flow.type_):
            return False

        return self.org_analyzer.is_whitelisted(flow)

    def _is_slips_own_flow(self, flow: Any) -> bool:
        """Exclude a live flow only when its exact tuple came from Slips.

        Parameters:
            flow: Parsed connection or protocol flow.

        Returns:
            True only for a module-owned socket in this live run.
        """
        if not self._filter_slips_own_traffic:
            return False
        proto = str(getattr(flow, "proto", "")).lower()
        src_port = getattr(flow, "sport", None)
        dst_port = getattr(flow, "dport", None)
        if proto not in ("tcp", "udp") or src_port is None or dst_port is None:
            return False
        try:
            src_ip = str(ipaddress.ip_address(str(flow.saddr)))
            dst_ip = str(ipaddress.ip_address(str(flow.daddr)))
        except ValueError:
            return False
        if proto == "tcp" and str(dst_port) == "43":
            if (
                self.db.is_slips_own_service_port(
                    self.db.main_pid, proto, dst_port, src_ip
                )
                is True
            ):
                return True
        now = time.monotonic()
        cached = self._own_source_cache.get(src_ip)
        if cached is None or cached[1] <= now:
            own_source = (
                self.db.is_slips_own_source_ip(self.db.main_pid, src_ip)
                is True
            )
            self._own_source_cache[src_ip] = (
                own_source,
                now + (60 if own_source else 2),
            )
            if len(self._own_source_cache) > 1024:
                self._own_source_cache.popitem(last=False)
        else:
            own_source = cached[0]
            self._own_source_cache.move_to_end(src_ip)
        if not own_source:
            return False
        return (
            self.db.is_slips_own_connection(
                self.db.main_pid,
                proto,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
            )
            is True
        )

    def is_whitelisted_evidence(self, evidence: Evidence) -> bool:
        """
        Checks if an evidence is whitelisted
        """
        if self._is_whitelisted_entity(evidence, "attacker"):
            return True

        if self._is_whitelisted_entity(evidence, "victim"):
            return True
        return False

    def extract_ips_from_entity(
        self, entity: Union[Attacker, Victim]
    ) -> Set[str]:
        """extracts all the ips it can from the given attacker/victim"""
        # check the IPs that belong to this domain
        entity_ip = (
            [entity.value]
            if entity.ioc_type in (IoCType.IP, IoCType.IP.name)
            else []
        )
        resolutions: List[str] = (
            entity.DNS_resolution if entity.DNS_resolution else []
        )
        unique_ips = set(entity_ip + resolutions)
        return unique_ips

    def extract_domains_from_entity(
        self, entity: Union[Attacker, Victim]
    ) -> Set[str]:
        """extracts all the domains it can from the given attacker/victim"""
        # check the rest of the domains that belong to this domain/IP
        queries = entity.queries if entity.queries else []
        # entities of type ips and domains both can have cnames
        cnames = entity.CNAME if entity.CNAME else []
        sni = [entity.SNI] if entity.SNI else []
        entity_domain = (
            [entity.value]
            if entity.ioc_type in (IoCType.DOMAIN, IoCType.DOMAIN.name)
            else []
        )
        unique_domains = set(sni + queries + cnames + entity_domain)
        return unique_domains

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
        port = (
            evidence.src_port
            if entity.direction in (Direction.SRC, Direction.SRC.name)
            else evidence.dst_port
        )

        for ip in self.extract_ips_from_entity(entity):
            if self.ip_analyzer.is_whitelisted(
                ip,
                entity.direction,
                what_to_ignore,
                (
                    port
                    if entity.ioc_type in (IoCType.IP, IoCType.IP.name)
                    and ip == entity.value
                    else None
                ),
                evidence.evidence_type.name,
            ):
                return True

        for domain in self.extract_domains_from_entity(entity):
            if self.domain_analyzer.is_whitelisted(
                domain, Direction.DST, what_to_ignore
            ):
                return True

        if self.mac_analyzer.profile_has_whitelisted_mac(
            entity.value, entity.direction, what_to_ignore
        ):
            return True

        if self.org_analyzer.is_whitelisted_entity(entity):
            return True

        return False

    def get_bloom_filters_stats(self) -> Dict[str, float]:
        """
        returns the bloom filters stats
        """
        total_hits = 0
        total_misses = 0

        for helper in (
            self.ip_analyzer,
            self.domain_analyzer,
            self.mac_analyzer,
            self.org_analyzer,
        ):
            total_hits += helper.bf_hits
            total_misses += helper.bf_misses

        # Bloom filters cannot produce false negatives:D
        return (
            f"Number of times bloom filter was acuurate (TN + TP):"
            f" {total_hits}, FPs: {total_misses}"
        )
