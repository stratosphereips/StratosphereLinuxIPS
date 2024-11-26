from typing import Optional


from ..model.aliases import Target
from ..model.configuration import TrustModelConfiguration
from ..model.threat_intelligence import SlipsThreatIntelligence
from modules.fidesModule.persistence.threat_intelligence import ThreatIntelligenceDatabase

from slips_files.core.database.database_manager import DBManager
import json
from .sqlite_db import SQLiteDB


class SlipsThreatIntelligenceDatabase(ThreatIntelligenceDatabase):
    """Implementation of ThreatIntelligenceDatabase that uses Slips native
    storage for the TI."""

    def __init__(
        self,
        configuration: TrustModelConfiguration,
        db: DBManager,
        sqldb: SQLiteDB,
    ):
        self.__configuration = configuration
        self.db = db
        self.sqldb = sqldb

    def get_for(self, target: Target) -> Optional[SlipsThreatIntelligence]:
        """Returns threat intelligence for given target or None if
        there are no data."""
        out = self.db.get_fides_ti(target)  # returns str containing dumped
        # dict of STI or None
        if out:
            out = SlipsThreatIntelligence(**json.loads(out))
        else:
            out = self.sqldb.get_slips_threat_intelligence_by_target(target)
        return out

    def save(self, ti: SlipsThreatIntelligence):
        self.sqldb.store_slips_threat_intelligence(ti)
        self.db.save_fides_ti(ti.target, json.dumps(ti.to_dict()))
