from typing import List, Optional, Union

from redis.client import Redis

from ..messaging.model import PeerInfo
from ..model.aliases import PeerId, Target, OrganisationId
from ..model.configuration import TrustModelConfiguration
from ..model.peer_trust_data import PeerTrustData, TrustMatrix
from ..model.threat_intelligence import SlipsThreatIntelligence
from ..persistence.trust import TrustDatabase


# because this will be implemented
# noinspection DuplicatedCode
class SlipsTrustDatabase(TrustDatabase):
    """Trust database implementation that uses Slips redis as a storage."""

    # TODO: [S] implement this

    def __init__(self, configuration: TrustModelConfiguration, r: Redis):
        super().__init__(configuration)
        self.__r = r

    def store_connected_peers_list(self, current_peers: List[PeerInfo]):
        """Stores list of peers that are directly connected to the Slips."""

        raise NotImplemented()

    def get_connected_peers(self) -> List[PeerInfo]:
        """Returns list of peers that are directly connected to the Slips."""
        raise NotImplemented()

    def get_peers_with_organisations(self, organisations: List[OrganisationId]) -> List[PeerInfo]:
        """Returns list of peers that have one of given organisations."""
        raise NotImplemented()

    def get_peers_with_geq_recommendation_trust(self, minimal_recommendation_trust: float) -> List[PeerInfo]:
        """Returns peers that have >= recommendation_trust then the minimal."""
        raise NotImplemented()

    def store_peer_trust_data(self, trust_data: PeerTrustData):
        """Stores trust data for given peer - overwrites any data if existed."""
        raise NotImplemented()

    def store_peer_trust_matrix(self, trust_matrix: TrustMatrix):
        """Stores trust matrix."""
        for peer in trust_matrix.values():
            self.store_peer_trust_data(peer)

    def get_peer_trust_data(self, peer: Union[PeerId, PeerInfo]) -> Optional[PeerTrustData]:
        """Returns trust data for given peer ID, if no data are found, returns None."""
        raise NotImplemented()

    def get_peers_trust_data(self, peer_ids: List[Union[PeerId, PeerInfo]]) -> TrustMatrix:
        """Return trust data for each peer from peer_ids."""
        return {peer_id: self.get_peer_trust_data(peer_id) for peer_id in peer_ids}

    def cache_network_opinion(self, ti: SlipsThreatIntelligence):
        """Caches aggregated opinion on given target."""
        raise NotImplemented()

    def get_cached_network_opinion(self, target: Target) -> Optional[SlipsThreatIntelligence]:
        """Returns cached network opinion. Checks cache time and returns None if data expired."""
        raise NotImplemented()
