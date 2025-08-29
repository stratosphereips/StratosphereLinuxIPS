from typing import Optional

from modules.fidesModule.model.aliases import Target
from modules.fidesModule.model.threat_intelligence import SlipsThreatIntelligence


class ThreatIntelligenceDatabase:
    """Database that stores threat intelligence data."""

    def get_for(self, target: Target) -> Optional[SlipsThreatIntelligence]:
        """Returns threat intelligence for given target or None if there are no data."""
        raise NotImplemented()
