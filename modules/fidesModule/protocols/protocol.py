from typing import Dict, Tuple

from ..evaluation.service.interaction import Satisfaction, Weight
from ..evaluation.service.process import process_service_interaction
from ..messaging.network_bridge import NetworkBridge
from ..model.aliases import PeerId
from ..model.configuration import TrustModelConfiguration
from ..model.peer_trust_data import PeerTrustData, TrustMatrix
from modules.fidesModule.persistence.trust import TrustDatabase


class Protocol:

    def __init__(self,
                 configuration: TrustModelConfiguration,
                 trust_db: TrustDatabase,
                 bridge: NetworkBridge):
        self._configuration = configuration
        self._trust_db = trust_db
        self._bridge = bridge

    def _evaluate_interaction(self,
                              peer: PeerTrustData,
                              satisfaction: Satisfaction,
                              weight: Weight
                              ) -> PeerTrustData:
        """Callback to evaluate and save new trust data for given peer."""
        return self._evaluate_interactions({peer.peer_id: (peer, satisfaction, weight)})[peer.peer_id]

    def _evaluate_interactions(self,
                               data: Dict[PeerId, Tuple[PeerTrustData, Satisfaction, Weight]]) -> TrustMatrix:
        """Callback to evaluate and save new trust data for given peer matrix."""
        trust_matrix: TrustMatrix = {}
        # first process all interactions
        for _, (peer_trust, satisfaction, weight) in data.items():
            updated_trust = process_service_interaction(self._configuration, peer_trust, satisfaction, weight)
            trust_matrix[updated_trust.peer_id] = updated_trust
        # then store matrix
        self._trust_db.store_peer_trust_matrix(trust_matrix)
        # and dispatch this update to the network layer
        self._bridge.send_peers_reliability({p.peer_id: p.service_trust for p in trust_matrix.values()})
        return trust_matrix
