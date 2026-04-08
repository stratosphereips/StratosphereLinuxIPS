from typing import Optional

from modules.fides.model.aliases import Target
from modules.fides.model.threat_intelligence import (
    SlipsThreatIntelligence,
)


class ThreatIntelligenceDatabase:
    """Database that stores threat intelligence data."""

    def get_for(self, target: Target) -> Optional[SlipsThreatIntelligence]:
        """Returns threat intelligence for given target or None if there are no data."""
        raise NotImplementedError()
