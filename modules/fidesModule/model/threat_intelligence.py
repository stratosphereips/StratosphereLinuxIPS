from dataclasses import dataclass
from typing import Optional

from ..model.aliases import Target, ConfidentialityLevel, Score, Confidence


@dataclass
class ThreatIntelligence:
    """Representation of peer's opinion on a subject (IP address or domain)."""

    score: Score
    """How much is subject malicious or benign.
    
    -1 <= score <= 1
    """

    confidence: Confidence
    """How much does peer trust, that score is correct.
    
    0 <= confidence <= 1
    """


@dataclass
class SlipsThreatIntelligence(ThreatIntelligence):
    target: Target
    """Target of the intelligence."""

    confidentiality: Optional[ConfidentialityLevel] = None
    """Confidentiality level if known."""

    def to_dict(self):
        result = {
            "target": self.target,
            "score": self.score,
            "confidence": self.confidence,
        }
        if self.confidentiality is not None:
            result["confidentiality"] = self.confidentiality
        return result

    # Create an instance from a dictionary
    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            target=data["target"],
            confidentiality=float(data["confidentiality"]) if data.get("confidentiality") else None,
            score=float(data["score"]) if data.get("score") else None,
            confidence=float(data["confidence"]) if data.get("confidence") else None
        )
