from typing import Optional

from redis.client import Redis

from ..model.aliases import Target
from ..model.configuration import TrustModelConfiguration
from ..model.threat_intelligence import SlipsThreatIntelligence
from ..persistence.threat_intelligence import ThreatIntelligenceDatabase


class SlipsThreatIntelligenceDatabase(ThreatIntelligenceDatabase):
    """Implementation of ThreatIntelligenceDatabase that uses Slips native storage for the TI."""

    def __init__(self, configuration: TrustModelConfiguration, r: Redis):
        self.__configuration = configuration
        self.__r = r

    def get_for(self, target: Target) -> Optional[SlipsThreatIntelligence]:
        """Returns threat intelligence for given target or None if there are no data."""
        # TODO: [S] implement this
        raise NotImplemented()
