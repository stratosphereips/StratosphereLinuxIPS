import math
from typing import List, Optional

from ..evaluation.recommendation.process import process_new_recommendations
from ..evaluation.service.interaction import Weight, SatisfactionLevels
from ..messaging.model import PeerRecommendationResponse
from ..messaging.network_bridge import NetworkBridge
from ..model.aliases import PeerId
from ..model.configuration import TrustModelConfiguration
from ..model.peer import PeerInfo
from ..model.recommendation import Recommendation
from ..persistence.trust_db import SlipsTrustDatabase
from ..protocols.protocol import Protocol
from ..utils.logger import Logger

logger = Logger(__name__)


class RecommendationProtocol(Protocol):
    """Protocol that is responsible for getting and updating recommendation data."""

    def __init__(self, configuration: TrustModelConfiguration, trust_db: SlipsTrustDatabase, bridge: NetworkBridge):
        super().__init__(configuration, trust_db, bridge)
        self.__rec_conf = configuration.recommendations
        self.__trust_db = trust_db
        self.__bridge = bridge

    def get_recommendation_for(self, peer: PeerInfo, connected_peers: Optional[List[PeerId]] = None):
        """Dispatches recommendation request from the network.

        connected_peers - new peer list if the one from database is not accurate
        """
        if not self.__rec_conf.enabled:
            logger.debug(f"Recommendation protocol is disabled. NOT getting recommendations for Peer {peer.id}.")
            return

        connected_peers = connected_peers if connected_peers is not None else self.__trust_db.get_connected_peers()
        recipients = self.__get_recommendation_request_recipients(peer, connected_peers)
        if recipients:
            self.__bridge.send_recommendation_request(recipients=recipients, peer=peer.id)
        else:
            logger.debug(f"No peers are trusted enough to ask them for recommendation!")

    def handle_recommendation_request(self, request_id: str, sender: PeerInfo, subject: PeerId):
        """Handle request for recommendation on given subject."""
        sender_trust = self.__trust_db.get_peer_trust_data(sender)
        # TODO: [+] implement data filtering based on the sender
        trust = self.__trust_db.get_peer_trust_data(subject)
        # if we know sender, and we have some trust for the target
        if sender_trust and trust:
            recommendation = Recommendation(
                competence_belief=trust.competence_belief,
                integrity_belief=trust.integrity_belief,
                service_history_size=trust.service_history_size,
                recommendation=trust.reputation,
                initial_reputation_provided_by_count=trust.initial_reputation_provided_by_count
            )
        else:
            recommendation = Recommendation(
                competence_belief=0,
                integrity_belief=0,
                service_history_size=0,
                recommendation=0,
                initial_reputation_provided_by_count=0
            )
        self.__bridge.send_recommendation_response(request_id, sender.id, subject, recommendation)
        # it is possible that we saw sender for the first time
        # TODO: [+] initialise peer if we saw it for the first time
        if sender_trust:
            self._evaluate_interaction(sender_trust, SatisfactionLevels.Ok, Weight.INTELLIGENCE_REQUEST)

    def handle_recommendation_response(self, responses: List[PeerRecommendationResponse]):
        """Handles response from peers with recommendations. Updates all necessary values in db."""
        if len(responses) == 0:
            return
        # TODO: [+] handle cases with multiple subjects
        assert all(responses[0].subject == r.subject for r in responses), \
            "Responses are not for the same subject!"

        subject = self.__trust_db.get_peer_trust_data(responses[0].subject)
        if subject is None:
            logger.warn(f'Received recommendation for subject {responses[0].subject} that does not exist!')
            return

        recommendations = {r.sender.id: r.recommendation for r in responses}
        trust_matrix = self.__trust_db.get_peers_trust_data(list(recommendations.keys()))

        # check that the data are consistent
        assert len(trust_matrix) == len(responses) == len(recommendations), \
            f'Data are not consistent: TM: {len(trust_matrix)}, RES: {len(responses)}, REC: {len(recommendations)}!'

        # update all recommendations
        updated_matrix = process_new_recommendations(
            configuration=self._configuration,
            subject=subject,
            matrix=trust_matrix,
            recommendations=recommendations
        )
        # now store updated matrix
        self.__trust_db.store_peer_trust_matrix(updated_matrix)
        # and dispatch event
        self.__bridge.send_peers_reliability({p.peer_id: p.service_trust for p in updated_matrix.values()})

        # TODO: [+] optionally employ same thing as when receiving TI
        interaction_matrix = {p.peer_id: (p, SatisfactionLevels.Ok, Weight.RECOMMENDATION_RESPONSE)
                              for p in trust_matrix.values()}
        self._evaluate_interactions(interaction_matrix)

    @staticmethod
    def __is_zero_recommendation(recommendation: Recommendation) -> bool:
        return recommendation.competence_belief == 0 and \
               recommendation.integrity_belief == 0 and \
               recommendation.service_history_size == 0 and \
               recommendation.recommendation == 0 and \
               recommendation.initial_reputation_provided_by_count == 0

    def __get_recommendation_request_recipients(self,
                                                subject: PeerInfo,
                                                connected_peers: List[PeerInfo]) -> List[PeerId]:
        recommenders: List[PeerInfo] = []
        require_trusted_peer_count = self.__rec_conf.required_trusted_peers_count
        trusted_peer_threshold = self.__rec_conf.trusted_peer_threshold

        if self.__rec_conf.only_connected:
            recommenders = connected_peers

        if self.__rec_conf.only_preconfigured:
            preconfigured_peers = set(p.id for p in self._configuration.trusted_peers)
            preconfigured_organisations = set(p.id for p in self._configuration.trusted_organisations)

            if len(recommenders) > 0:
                # if there are already some recommenders it means that only_connected filter is enabled
                # in that case we need to filter those peers and see if they either are on preconfigured
                # list or if they have any organisation
                recommenders = [p for p in recommenders
                                if p.id in preconfigured_peers
                                or preconfigured_organisations.intersection(p.organisations)]
            else:
                # if there are no recommenders, only_preconfigured is disabled, so we select all preconfigured
                # peers and all peers from database that have the organisation
                recommenders = self.__trust_db.get_peers_info(list(preconfigured_peers)) \
                               + self.__trust_db.get_peers_with_organisations(list(preconfigured_organisations))
            # if we have only_preconfigured, we do not need to care about minimal trust because we're safe enough
            require_trusted_peer_count = -math.inf
        elif not self.__rec_conf.only_connected:
            # in this case there's no restriction, and we can freely select any peers
            # select peers that hev at least trusted_peer_threshold recommendation trust
            recommenders = self.__trust_db.get_peers_with_geq_recommendation_trust(trusted_peer_threshold)
            # if there's not enough peers like that, select some more with this service trust
            if len(recommenders) <= self.__rec_conf.peers_max_count:
                # TODO: [+] maybe add higher trusted_peer_threshold for this one
                recommenders += self.__trust_db.get_peers_with_geq_service_trust(trusted_peer_threshold)

        # now we need to get all trust data and sort them by recommendation trust
        candidates = list(self.__trust_db.get_peers_trust_data(recommenders).values())
        candidates = [c for c in candidates if c.peer_id != subject.id]
        # check if we can proceed
        if len(candidates) == 0 or len(candidates) < require_trusted_peer_count:
            logger.debug(
                f"Not enough trusted peers! Candidates: {len(candidates)}, requirement: {require_trusted_peer_count}.")
            return []

        # now sort them
        candidates.sort(key=lambda c: c.service_trust, reverse=True)
        # and take only top __rec_conf.peers_max_count peers to ask for recommendations
        return [p.peer_id for p in candidates][:self.__rec_conf.peers_max_count]
