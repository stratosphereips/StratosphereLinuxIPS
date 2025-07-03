from typing import List

from slips_files.common.slips_utils import utils
from slips_files.core.database.database_manager import DBManager


class ARPEvidenceFilter:
    """
    A class to filter ARP evidence coming from a peer slips.
    Slips uses arp poisoning, arp spoofing, and arp scans to discover
    attackers and isolate them from the network, we don't want this
    instance of Slips to block other Slips instances, so we discard
    evidence about other slips attacking.
    """

    def __init__(self, conf, slips_args, db: DBManager):
        self.db = db
        self.conf = conf
        self.args = slips_args
        # p2p needs to be enabled for slips to be able to recognize slips peers
        self.p2p_enabled = False
        if self.conf.use_local_p2p():
            self.p2p_enabled = True
        self.our_ips: List[str] = utils.get_own_ips(ret="List")

    def should_discard_evidence(self, ip: str) -> bool:
        return self.is_slips_peer(ip) or self.is_self_defense(ip)

    def is_self_defense(self, ip: str):
        """
        slips uses arp poison to defend itself and th enetwork,
        check arp_poison.py for more details.
        goal of this function is to discard evidence about slips doing arp
        attacks when it's just attacking attackers
        """
        loaded_modules = self.db.get_pids().keys()
        return (
            ip in self.our_ips
            and self.args.blocking
            and "ARP Poisoner" in loaded_modules
        )

    def is_slips_peer(self, ip: str) -> bool:
        """
        Check if the given IP address is a trusted Slips peer.
        Trust here is defined from the p2p network (trust model).
        Only works if the local p2p is enabled.

        :param ip: The IP address to check.
        """
        if not self.p2p_enabled or not utils.is_private_ip(ip):
            return False

        trust = self.db.get_peer_trust(ip)
        if not trust:
            return False

        return trust >= 0.3
