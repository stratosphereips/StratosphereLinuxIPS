from typing import List, Optional, Union, Dict, Tuple

from ..messaging.model import PeerInfo
from ..model.aliases import PeerId, Target, OrganisationId
from ..model.configuration import TrustModelConfiguration
from ..model.peer_trust_data import PeerTrustData, TrustMatrix
from ..model.threat_intelligence import SlipsThreatIntelligence
from ..persistence.trust import TrustDatabase
from ..utils.time import Time, now


class InMemoryTrustDatabase(TrustDatabase):
    """Trust database implementation that stores data in memory.

    This should not be in production, it is for tests mainly.
    """

    def __init__(self, configuration: TrustModelConfiguration):
        super().__init__(configuration)
        self.__connected_peers: List[PeerInfo] = []
        self.__trust_matrix: TrustMatrix = {}
        self.__network_opinions: Dict[Target, Tuple[Time, SlipsThreatIntelligence]] = {}

    def store_connected_peers_list(self, current_peers: List[PeerInfo]):
        """Stores list of peers that are directly connected to the Slips."""
        self.__connected_peers = current_peers

    def get_connected_peers(self) -> List[PeerInfo]:
        """Returns list of peers that are directly connected to the Slips."""
        return list(self.__connected_peers)

    def get_peers_with_organisations(self, organisations: List[OrganisationId]) -> List[PeerInfo]:
        """Returns list of peers that have one of given organisations."""
        required = set(organisations)
        return [p.info for p in self.__trust_matrix.values() if len(required.intersection(p.organisations)) > 0]

    def get_peers_with_geq_recommendation_trust(self, minimal_recommendation_trust: float) -> List[PeerInfo]:
        """Returns peers that have >= recommendation_trust then the minimal."""
        return [p.info for p in self.__trust_matrix.values() if p.recommendation_trust >= minimal_recommendation_trust]

    def store_peer_trust_data(self, trust_data: PeerTrustData):
        """Stores trust data for given peer - overwrites any data if existed."""
        self.__trust_matrix[trust_data.peer_id] = trust_data

    def get_peer_trust_data(self, peer: Union[PeerId, PeerInfo]) -> Optional[PeerTrustData]:
        """Returns trust data for given peer ID, if no data are found, returns None."""
        peer_id = peer
        if isinstance(peer, PeerInfo):
            peer_id = peer.id
        return self.__trust_matrix.get(peer_id, None)

    def get_peers_info(self, peer_ids: List[PeerId]) -> List[PeerInfo]:
        return [tr.info for p in peer_ids if (tr := self.__trust_matrix.get(p))]

    def get_peers_with_geq_service_trust(self, minimal_service_trust: float) -> List[PeerInfo]:
        return [p.info for p in self.__trust_matrix.values() if p.service_trust >= minimal_service_trust]

    def cache_network_opinion(self, ti: SlipsThreatIntelligence):
        """Caches aggregated opinion on given target."""
        self.__network_opinions[ti.target] = now(), ti

    def get_cached_network_opinion(self, target: Target) -> Optional[SlipsThreatIntelligence]:
        """Returns cached network opinion. Checks cache time and returns None if data expired."""
        rec = self.__network_opinions.get(target)
        if rec is None:
            return None
        created_seconds, ti = rec
        # we need to check if the cache is still valid
        if now() - created_seconds < self.__configuration.network_opinion_cache_valid_seconds:
            return ti
        else:
            return None
