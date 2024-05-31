import ipaddress
from typing import List, Dict, Union

from slips_files.common.abstracts.whitelist_analyzer import IWhitelistAnalyzer
from slips_files.common.slips_utils import utils
from slips_files.core.evidence_structure.evidence import (
    Direction,
    Attacker,
    Victim,
    IoCType,
)


class IPAnalyzer(IWhitelistAnalyzer):
    @property
    def name(self):
        return "IP_whitelist_analyzer"

    def init(self): ...

    @staticmethod
    def extract_dns_answers(flow) -> List[str]:
        """
        extracts all the ips we can find from the given flow
        """
        return flow.answers if flow.type_ == "dns" else []

    @staticmethod
    def is_valid_ip(ip: str):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def get_domains_of_ip(self, ip: str) -> List[str]:
        """
        returns the domains of this IP, e.g. the DNS resolution, the SNI, etc.
        """
        domains = []
        if ip_data := self.db.get_ip_info(ip):
            if sni_info := ip_data.get("SNI", [{}])[0]:
                domains.append(sni_info.get("server_name", ""))

        try:
            resolution = self.db.get_dns_resolution(ip).get("domains", [])
            domains.extend(iter(resolution))
        except (KeyError, TypeError):
            pass

        return domains

    def is_ip_whitelisted(
        self, ip: str, direction: Direction, what_to_ignore: str
    ) -> bool:
        """
        checks the given IP in the whitelisted IPs read from whitelist.conf
        :param ip: ip to check if whitelisted
        :param direction: is the given ip a srcip or a dstip
        :param what_to_ignore: can be 'flows' or 'alerts'
        """
        if not self.is_valid_ip(ip):
            return False

        whitelisted_ips: Dict[str, dict] = self.db.get_whitelist("IPs")

        if ip not in whitelisted_ips:
            return False

        # Check if we should ignore src or dst alerts from this ip
        # from_ can be: src, dst, both
        # what_to_ignore can be: alerts or flows or both
        whitelist_direction: str = whitelisted_ips[ip]["from"]
        if not self.manager.ioc_dir_match_whitelist_dir(
            direction, whitelist_direction
        ):
            return False

        ignore: str = whitelisted_ips[ip]["what_to_ignore"]
        if not self.manager.what_to_ignore_match_whitelist(
            what_to_ignore, ignore
        ):
            return False
        return True

    def ignore_alerts_from_ip(
        self,
        direction: Direction,
        ignore_alerts: bool,
        whitelist_direction: str,
    ) -> bool:
        if not ignore_alerts:
            return False

        if direction == Direction.SRC and self.manager.should_ignore_from(
            whitelist_direction
        ):
            return True

    def ignore_alerts_to_ip(
        self,
        direction: Direction,
        ignore_alerts: bool,
        whitelist_direction: str,
    ) -> bool:
        if not ignore_alerts:
            return False

        if direction == Direction.DST and self.manager.should_ignore_to(
            whitelist_direction
        ):
            return True

    @staticmethod
    def is_private_ip(ioc_type, ioc: Union[Attacker, Victim]):
        """checks if the given ioc is an ip and is private"""
        if ioc_type != IoCType.IP.name:
            return False

        ip_obj = ipaddress.ip_address(ioc.value)
        if utils.is_private_ip(ip_obj):
            return True
