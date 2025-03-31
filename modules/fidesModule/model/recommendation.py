from dataclasses import dataclass


@dataclass
class Recommendation:
    """Represents k peer's response to recommendation query about peer j."""

    competence_belief: float
    """How much is peer satisfied with historical service interactions.
    
    In general, this is expected mean behavior of the peer.
    In model's notation cb_kj.
    
    0 <= competence_belief <= 1
    """

    integrity_belief: float
    """How much is peer consistent in its behavior.
    
    In general, this is standard deviation from the mean behavior.
    In model's notation ib_kj.
    
    0 <= integrity_belief <= 1
    """

    service_history_size: int
    """Size of service interaction history.
    
    In model's notation sh_kj.
    """

    recommendation: float
    """Recommendation about reputation.
    
    In model's notation r_kj.
    
    0 <= recommendation <= 1
    """

    initial_reputation_provided_by_count: int
    """How many peers which provided recommendation during the initial calculation of r_kj.
    
    In model's notation η_kj.
    """
