from typing import List, Optional, Union

from ..messaging.model import PeerInfo
from ..model.aliases import PeerId, Target, OrganisationId
from ..model.configuration import TrustModelConfiguration
from ..model.peer_trust_data import PeerTrustData, TrustMatrix
from ..model.threat_intelligence import SlipsThreatIntelligence
from modules.fidesModule.persistence.trust import TrustDatabase
from .sqlite_db import SQLiteDB

from slips_files.core.database.database_manager import DBManager
import json
from ..utils.time import now


# because this will be implemented
# noinspection DuplicatedCode
class SlipsTrustDatabase(TrustDatabase):
    """Trust database implementation that uses Slips redis and own SQLite as
    a storage."""

    def __init__(
        self,
        configuration: TrustModelConfiguration,
        db: DBManager,
        sqldb: SQLiteDB,
    ):
        super().__init__(configuration)
        self.db = db
        self.sqldb = sqldb
        self.__configuration = configuration
        self.conf = configuration

    def store_connected_peers_list(self, current_peers: List[PeerInfo]):
        """Stores list of peers that are directly connected to the Slips."""

        json_peers = [json.dumps(peer.to_dict()) for peer in current_peers]
        self.sqldb.store_connected_peers_list(current_peers)
        self.db.store_connected_peers(json_peers)

    def get_connected_peers(self) -> List[PeerInfo]:
        """Returns list of peers that are directly connected to the Slips."""
        json_peers = self.db.get_connected_peers()  # on no data returns []
        if not json_peers:
            current_peers = self.sqldb.get_connected_peers()
        else:
            current_peers = [
                PeerInfo(**json.loads(peer_json)) for peer_json in json_peers
            ]
        return current_peers

    def get_peers_with_organisations(
        self, organisations: List[OrganisationId]
    ) -> List[PeerInfo]:
        """Returns list of peers that have one of given organisations."""
        out = []
        raw = self.get_connected_peers()

        # self.sqldb.get_peers_by_organisations(organisations)
        for peer in raw:
            for organisation in organisations:
                if organisation in peer.organisations:
                    out.append(peer)
        return out

    def get_peers_with_geq_recommendation_trust(
        self, minimal_recommendation_trust: float
    ) -> List[PeerInfo]:
        """
        Returns peers that have >= recommendation_trust then the minimal.
        """
        connected_peers = self.get_connected_peers()  # returns data or []
        out = []

        # if no peers present in Redis, try SQLite DB
        if connected_peers:
            for peer in connected_peers:
                td = self.get_peer_trust_data(peer.id)

                if (
                    td is not None
                    and td.recommendation_trust >= minimal_recommendation_trust
                ):
                    out.append(peer)
        else:
            out = self.sqldb.get_peers_by_minimal_recommendation_trust(
                minimal_recommendation_trust
            )

        return out

    def store_peer_trust_data(self, trust_data: PeerTrustData):
        """
        Stores trust data for given peer - overwrites any data if existed.
        """
        self.sqldb.store_peer_trust_data(trust_data)
        id_ = trust_data.info.id
        td_json = json.dumps(trust_data.to_dict())
        self.db.store_peer_trust_data(id_, td_json)

    def store_peer_trust_matrix(self, trust_matrix: TrustMatrix):
        """Stores trust matrix."""
        for peer in trust_matrix.values():
            self.store_peer_trust_data(peer)

    def get_peer_trust_data(
        self, peer: Union[PeerId, PeerInfo]
    ) -> Optional[PeerTrustData]:
        """Returns trust data for given peer ID, if no data are found,
        returns None."""
        out = None
        peer_id = ""

        if isinstance(peer, PeerId):
            peer_id = peer
        elif isinstance(peer, PeerInfo):
            peer_id = peer.id
        else:
            return out

        td_json = self.db.get_peer_trust_data(peer_id)
        if td_json:  # Redis has available data
            out = PeerTrustData(**json.loads(td_json))
        else:  # if redis is empty, try SQLite
            out = self.sqldb.get_peer_trust_data(peer_id)
        return out

    def get_peers_trust_data(
        self, peer_ids: List[Union[PeerId, PeerInfo]]
    ) -> TrustMatrix:
        """Return trust data for each peer from peer_ids."""
        out = {}
        peer_id = None

        for peer in peer_ids:
            # get PeerID to properly create TrustMatrix
            if isinstance(peer, PeerId):
                peer_id = peer
            elif isinstance(peer, PeerInfo):
                peer_id = peer.id

            # TrustMatrix = Dict[PeerId, PeerTrustData]; here - peer_id: PeerId
            out[peer_id] = self.get_peer_trust_data(peer_id)
        return out

    def cache_network_opinion(self, ti: SlipsThreatIntelligence):
        """Caches aggregated opinion on given target."""
        # cache is not backed up into SQLite, can be recalculated, not critical
        self.db.cache_network_opinion(ti.target, ti.to_dict(), now())

    def get_cached_network_opinion(
        self, target: Target
    ) -> Optional[SlipsThreatIntelligence]:
        """Returns cached network opinion. Checks cache time and returns None
        if data expired."""
        # cache is not backed up into SQLite, can be recalculated,
        # not critical
        rec = self.db.get_cached_network_opinion(
            target,
            self.__configuration.network_opinion_cache_valid_seconds,
            now(),
        )
        if rec is None:
            return None
        else:
            return SlipsThreatIntelligence.from_dict(rec)
