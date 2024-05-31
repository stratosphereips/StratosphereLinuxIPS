import validators

from slips_files.common.abstracts.whitelist_analyzer import IWhitelistAnalyzer
from slips_files.core.evidence_structure.evidence import (
    Direction,
)


class MACAnalyzer(IWhitelistAnalyzer):
    @property
    def name(self):
        return "mac_whitelist_analyzer"

    def init(self): ...

    @staticmethod
    def is_valid_mac(mac: str) -> bool:
        return validators.mac_address(mac)

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

    # def is_mac_whitelisted(self, mac: str):
    #     if not self.is_valid_mac(mac):
    #         return False
    #     # todo it should be known whether this is a src or dst mac!
    #     whitelisted_macs: Dict[str, dict] = self.db.get_whitelist("macs")
    #
    #     if mac in whitelisted_macs:
    #         # Check if we should ignore src or dst alerts from this ip
    #         # from_ can be: src, dst, both
    #         # what_to_ignore can be: alerts or flows or both
    #         whitelist_direction: str = whitelisted_macs[mac]["from"]
    #         what_to_ignore = whitelisted_macs[mac]["what_to_ignore"]
    #         if self.manager.ignore_alert(
    #             what_to_ignore
    #         ):
    #             # self.print(f'Whitelisting src IP {srcip} for evidence'
    #             #            f' about {ip}, due to a connection related to {data} '
    #             #            f'in {description}')
    #             return True
    #
    #         # todo match directions
    #         is (self.manager.ioc_dir_match_whitelist_dir( .. ,
    #             whitelist_direction))
    #         # todo this should be here
    #         if self.profile_has_whitelisted_mac(
    #             ip, whitelisted_macs, direction
    #         ):
    #             return True
    #     return False
