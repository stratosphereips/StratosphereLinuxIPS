from typing import Optional, Dict

from ..model.aliases import Target
from ..model.threat_intelligence import SlipsThreatIntelligence
from ..persistence.threat_intelligence import ThreatIntelligenceDatabase


class InMemoryThreatIntelligenceDatabase(ThreatIntelligenceDatabase):
    """Implementation of ThreatIntelligenceDatabase that stores data in memory.

    This should not be used in production.
    """

    def __init__(self):
        self.__db: Dict[Target, SlipsThreatIntelligence] = {}

    def get_for(self, target: Target) -> Optional[SlipsThreatIntelligence]:
        """Returns threat intelligence for given target or None if there are no data."""
        return self.__db.get(target, None)

    def save(self, ti: SlipsThreatIntelligence):
        """Saves given ti to the database."""
        self.__db[ti.target] = ti
