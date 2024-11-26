from typing import List

from ..messaging.network_bridge import NetworkBridge
from ..model.peer import PeerInfo
from ..persistence.trust_db import SlipsTrustDatabase
from ..protocols.initial_trusl import InitialTrustProtocol
from ..protocols.recommendation import RecommendationProtocol


class PeerListUpdateProtocol:
    """Protocol handling situations when peer list was updated."""

    def __init__(self,
                 trust_db: SlipsTrustDatabase,
                 bridge: NetworkBridge,
                 recommendation_protocol: RecommendationProtocol,
                 trust_protocol: InitialTrustProtocol
                 ):
        self.__trust_db = trust_db
        self.__bridge = bridge
        self.__recommendation_protocol = recommendation_protocol
        self.__trust_protocol = trust_protocol

    def handle_peer_list_updated(self, peers: List[PeerInfo]):
        """Processes updated peer list."""
        # first store them in the database
        self.__trust_db.store_connected_peers_list(peers)
        # and now find their trust metrics to send it to the network module
        trust_data = self.__trust_db.get_peers_trust_data([p.id for p in peers])
        known_peers = {peer_id for peer_id, trust in trust_data.items() if trust is not None}
        # if we don't have data for all peers that means that there are some new peers
        # we need to establish initial trust for them
        if len(known_peers) != len(peers):
            new_trusts = []
            for peer in [p for p in peers if p.id not in known_peers]:
                # this stores trust in database as well, do not get recommendations because at this point
                # we don't have correct peer list in database
                peer_trust = self.__trust_protocol.determine_and_store_initial_trust(peer, get_recommendations=False)
                new_trusts.append(peer_trust)
                # get recommendations for this peer
                self.__recommendation_protocol.get_recommendation_for(peer, connected_peers=list(known_peers))
            # send only updated trusts to the network layer
            self.__bridge.send_peers_reliability({p.peer_id: p.service_trust for p in new_trusts})
        # now set update peer list in database
        self.__trust_db.store_connected_peers_list(peers)
