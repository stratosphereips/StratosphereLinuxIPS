from dataclasses import dataclass
from typing import List, Optional

from ..model.aliases import PeerId, OrganisationId, IP


@dataclass
class PeerInfo:
    """Identification data of a single peer in the network."""

    id: PeerId
    """Unique identification of a peer in the network."""

    organisations: List[OrganisationId]
    """List of organization that signed public key of this peer.
    According to the protocol, these are organizations that trust the peer.
    """

    ip: Optional[IP] = None
    """Ip address of the peer, if we know it.
    There are cases when we don't know the IP of the peer - when running behind NAT 
    or when the peers used TURN server to connect to each other.
    """

    def to_dict(self):
        """Convert to dictionary for serialization."""
        return {
            'id': self.id,
            'organisations': [org for org in self.organisations],
            'ip': self.ip,
        }

    @classmethod
    def from_dict(cls, data):
        """Create an instance from a dictionary."""
        return cls(**data)
