from dataclasses import dataclass
from typing import List

from ..utils.time import Time


@dataclass
class RecommendationHistoryRecord:
    """Represents an evaluation of a single recommendation interaction between peer i and peer j."""

    satisfaction: float
    """Peer's satisfaction with the recommendation. In model's notation rs_ij.

    0 <= satisfaction <= 1
    """

    weight: float
    """Weight of the recommendation. In model's notation rw_ij.

    0 <= weight <= 1
    """

    timestamp: Time
    """Date time when this recommendation happened."""


    def to_dict(self):
        """Convert the instance to a dictionary."""
        return {
            'satisfaction': self.satisfaction,
            'weight': self.weight,
            'timestamp': self.timestamp  # Keep as float
        }

    @classmethod
    def from_dict(cls, dict_obj):
        """Create an instance of RecommendationHistoryRecord from a dictionary."""
        return cls(
            satisfaction=dict_obj['satisfaction'],
            weight=dict_obj['weight'],
            timestamp=dict_obj['timestamp']  # Keep as float
        )


RecommendationHistory = List[RecommendationHistoryRecord]
"""Ordered list with history of recommendation interactions. 

First element in the list is the oldest one. 
"""
