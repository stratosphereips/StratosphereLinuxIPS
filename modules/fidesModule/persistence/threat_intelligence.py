from typing import Optional

from ..model.aliases import Target
from ..model.threat_intelligence import SlipsThreatIntelligence


class ThreatIntelligenceDatabase:
    """Database that stores threat intelligence data."""

    def get_for(self, target: Target) -> Optional[SlipsThreatIntelligence]:
        """Returns threat intelligence for given target or None if there are no data."""
        raise NotImplemented()
