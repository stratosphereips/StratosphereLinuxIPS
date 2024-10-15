from dataclasses import dataclass
from typing import List

from ..utils.time import Time


@dataclass
class ServiceHistoryRecord:
    """Represents an evaluation of a single service interaction between peer i and peer j."""

    satisfaction: float
    """Peer's satisfaction with the service. In model's notation s_ij.
    
    0 <= satisfaction <= 1
    """

    weight: float
    """Weight of the service interaction. In model's notation w_ij.
    
    0 <= weight <= 1
    """

    timestamp: Time
    """Date time when this interaction happened."""

    def to_dict(self):
        """Convert the instance to a dictionary."""
        return {
            'satisfaction': self.satisfaction,
            'weight': self.weight,
            'timestamp': self.timestamp
        }

    @classmethod
    def from_dict(cls, dict_obj):
        """Create an instance of ServiceHistoryRecord from a dictionary."""
        return cls(
            satisfaction=dict_obj['satisfaction'],
            weight=dict_obj['weight'],
            timestamp=dict_obj['timestamp']  # Convert ISO format back to datetime
        )


ServiceHistory = List[ServiceHistoryRecord]
"""Ordered list with history of service interactions. 

First element in the list is the oldest one. 
"""
