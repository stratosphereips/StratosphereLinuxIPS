from dataclasses import dataclass

from ..model.aliases import Target
from ..model.threat_intelligence import ThreatIntelligence


@dataclass
class Alert(ThreatIntelligence):
    """Alert that was broadcast on the network."""

    target: Target
    """Target that """

    score: float
    """Score of the alert. See ThreatIntelligence.score."""

    confidence: float
    """Confidence of the alert. See ThreatIntelligence.confidence."""
