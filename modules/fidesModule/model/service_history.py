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


ServiceHistory = List[ServiceHistoryRecord]
"""Ordered list with history of service interactions. 

First element in the list is the oldest one. 
"""
