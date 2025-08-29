from typing import List, Callable, Optional

from ..evaluation.service.interaction import Weight, SatisfactionLevels
from ..evaluation.ti_evaluation import TIEvaluation
from ..messaging.model import PeerIntelligenceResponse
from ..messaging.network_bridge import NetworkBridge
from ..model.aliases import Target
from ..model.configuration import TrustModelConfiguration
from ..model.peer import PeerInfo
from ..model.peer_trust_data import PeerTrustData
from ..model.threat_intelligence import ThreatIntelligence, SlipsThreatIntelligence
from ..persistence.threat_intelligence_db import SlipsThreatIntelligenceDatabase
from ..persistence.trust_db import SlipsTrustDatabase
from ..protocols.initial_trusl import InitialTrustProtocol
from ..protocols.opinion import OpinionAggregator
from ..protocols.protocol import Protocol
from ..utils.logger import Logger

logger = Logger(__name__)


class ThreatIntelligenceProtocol(Protocol):
    """Class handling threat intelligence requests and responses."""

    def __init__(self,
                 trust_db: SlipsTrustDatabase,
                 ti_db: SlipsThreatIntelligenceDatabase,
                 bridge: NetworkBridge,
                 configuration: TrustModelConfiguration,
                 aggregator: OpinionAggregator,
                 trust_protocol: InitialTrustProtocol,
                 ti_evaluation_strategy: TIEvaluation,
                 network_opinion_callback: Callable[[SlipsThreatIntelligence], None]
                 ):
        super().__init__(configuration, trust_db, bridge)
        self.__ti_db = ti_db
        self.__aggregator = aggregator
        self.__trust_protocol = trust_protocol
        self.__ti_evaluation_strategy = ti_evaluation_strategy
        self.__network_opinion_callback = network_opinion_callback

    def request_data(self, target: Target):
        """Requests network opinion on given target."""
        cached = self._trust_db.get_cached_network_opinion(target)
        if cached:
            logger.debug(f'TI for target {target} found in cache.')
            return self.__network_opinion_callback(cached)
        else:
            logger.debug(f'Requesting data for target {target} from network.')
            self._bridge.send_intelligence_request(target)

    def handle_intelligence_request(self, request_id: str, sender: PeerInfo, target: Target):
        """Handles intelligence request."""
        peer_trust = self._trust_db.get_peer_trust_data(sender.id)
        if not peer_trust:
            logger.debug(f'We don\'t have any trust data for peer {sender.id}!')
            peer_trust = self.__trust_protocol.determine_and_store_initial_trust(sender)

        ti = self.__filter_ti(self.__ti_db.get_for(target), peer_trust)
        if ti is None:
            # we send just zeros if we don't have any data about the target
            ti = ThreatIntelligence(score=0, confidence=0)

        # and respond with data we have
        self._bridge.send_intelligence_response(request_id, target, ti)
        self._evaluate_interaction(peer_trust,
                                   SatisfactionLevels.Ok,
                                   Weight.INTELLIGENCE_REQUEST)

    def handle_intelligence_response(self, responses: List[PeerIntelligenceResponse]):
        """Handles intelligence responses."""
        trust_matrix = self._trust_db.get_peers_trust_data([r.sender.id for r in responses])
        assert len(trust_matrix) == len(responses), 'We need to have trust data for all peers that sent the response.'
        target = {r.target for r in responses}
        assert len(target) == 1, 'Responses should be for a single target.'
        target = target.pop()

        # now everything is checked, so we aggregate it and get the threat intelligence
        r = {r.sender.id: r for r in responses}
        ti = self.__aggregator.evaluate_intelligence_response(target, r, trust_matrix)
        # cache data for further retrieval
        self._trust_db.cache_network_opinion(ti)
        #test = self._trust_db.get_cached_network_opinion(target)

        interaction_matrix = self.__ti_evaluation_strategy.evaluate(
            aggregated_ti=ti,
            responses=r,
            trust_matrix=trust_matrix,
            local_ti=self.__ti_db.get_for(target)
        )
        self._evaluate_interactions(interaction_matrix)

        return self.__network_opinion_callback(ti)

    def __filter_ti(self,
                    ti: Optional[SlipsThreatIntelligence],
                    peer_trust: PeerTrustData) -> Optional[SlipsThreatIntelligence]:
        if ti is None:
            return None

        peers_allowed_levels = [p.confidentiality_level
                                for p in self._configuration.trusted_organisations if
                                p.id in peer_trust.organisations]

        peers_allowed_levels.append(peer_trust.service_trust)
        # select maximum allowed level
        allowed_level = max(peers_allowed_levels)

        # set correct confidentiality
        ti.confidentiality = ti.confidentiality if ti.confidentiality else self._configuration.data_default_level
        # check if data confidentiality is lower than allowed level for the peer
        return ti if ti.confidentiality <= allowed_level else None
