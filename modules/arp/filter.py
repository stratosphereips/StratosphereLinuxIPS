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

    def __init__(self, conf, db: DBManager):
        self.db = db
        # p2p needs to be enabled for slips to be able to recognize slips peers
        self.p2p_enabled = False
        if conf.use_local_p2p():
            self.p2p_enabled = True

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
        if trust >= 0.3:
            return True
        return False
