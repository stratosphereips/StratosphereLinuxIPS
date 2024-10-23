from typing import Optional

from redis.client import Redis

from ..model.aliases import Target
from ..model.configuration import TrustModelConfiguration
from ..model.threat_intelligence import SlipsThreatIntelligence
from ..persistence.threat_intelligence import ThreatIntelligenceDatabase

from slips_files.core.database.database_manager import DBManager
import json

class SlipsThreatIntelligenceDatabase(ThreatIntelligenceDatabase):
    """Implementation of ThreatIntelligenceDatabase that uses Slips native storage for the TI."""

    def __init__(self, configuration: TrustModelConfiguration, db: DBManager, sqldb):
        self.__configuration = configuration
        self.db = db

    def get_for(self, target: Target) -> Optional[SlipsThreatIntelligence]:
        """Returns threat intelligence for given target or None if there are no data."""
        out = self.db.get_fides_ti(target) # returns str containing dumped dict of STI or None
        if out:
            out = SlipsThreatIntelligence(**json.loads(out))
        else:
            pass #TODO implement SQLite fall back
        return out

    def save(self, ti: SlipsThreatIntelligence):
        self.db.save_fides_ti(ti.target, json.dumps(ti.to_dict()))

