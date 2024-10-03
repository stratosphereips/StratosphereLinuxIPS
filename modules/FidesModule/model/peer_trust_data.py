from dataclasses import dataclass
from typing import Dict, List

from ..model.aliases import PeerId, OrganisationId
from ..model.peer import PeerInfo
from ..model.recommendation_history import RecommendationHistory
from ..model.service_history import ServiceHistory


@dataclass
class PeerTrustData:
    """Trust data related to given peer j - in model's notation "peer_id" is actually "j"."""

    info: PeerInfo
    """Information about the peer."""

    has_fixed_trust: bool
    """Determines if the trust is dynamic or fixed."""

    service_trust: float
    """Service Trust Metric.
    
    Semantic meaning is basically "trust" - how much does current peer trust peer "j" about quality of service.
    In model's notation st_ij.
    
    0 <= service_trust <= 1
    """

    reputation: float
    """Reputation Metric.
    
    The reputation metric measures a stranger’s trustworthiness based on recommendations.
    In model's notation r_ij.
    
    0 <= reputation <= 1
    """

    recommendation_trust: float
    """Recommendation Trust Metric.
    
    How much does the peer trust that any recommendation received from this peer is correct.
    In model's notation rt_ij.
    
    0 <= recommendation_trust <= 1
    """

    competence_belief: float
    """How much is peer satisfied with historical service interactions.

    In general, this is expected mean behavior of the peer.
    In model's notation cb_ij.

    0 <= competence_belief <= 1
    """

    integrity_belief: float
    """How much is peer consistent in its behavior.

    In general, this is standard deviation from the mean behavior.
    In model's notation ib_ij.

    0 <= integrity_belief <= 1
    """

    initial_reputation_provided_by_count: int
    """How many peers provided recommendation during initial calculation of reputation.
    
    In model's notation η_ij.
    """

    service_history: ServiceHistory
    """History of interactions, in model's notation SH_ij."""

    recommendation_history: RecommendationHistory
    """History of recommendation, in model's notation RH_ij."""

    @property
    def peer_id(self) -> PeerId:
        """ID of the peer these data are for."""
        return self.info.id

    @property
    def organisations(self) -> List[OrganisationId]:
        """Organisations that signed this peer."""
        return self.info.organisations

    @property
    def service_history_size(self):
        """Size of the history, in model's notation sh_ij."""
        return len(self.service_history)

    @property
    def recommendation_history_size(self):
        """Size of the recommendation history, in model's notation rh_ij."""
        return len(self.recommendation_history)


TrustMatrix = Dict[PeerId, PeerTrustData]
"""Matrix that have PeerId as a key and then value is data about trust we have."""


def trust_data_prototype(peer: PeerInfo, has_fixed_trust: bool = False) -> PeerTrustData:
    """Creates clear trust object with 0 values and given peer info."""
    return PeerTrustData(
        info=peer,
        has_fixed_trust=has_fixed_trust,
        service_trust=0,
        reputation=0,
        recommendation_trust=0,
        competence_belief=0,
        integrity_belief=0,
        initial_reputation_provided_by_count=0,
        service_history=[],
        recommendation_history=[]
    )
