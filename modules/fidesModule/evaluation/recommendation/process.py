import dataclasses
from typing import Dict

from ...evaluation.discount_factor import compute_discount_factor
from ...evaluation.recommendation.new_history import create_recommendation_history_for_peer
from ...evaluation.recommendation.peer_update import update_recommendation_data_for_peer
from ...model.aliases import PeerId
from ...model.configuration import TrustModelConfiguration
from ...model.peer_trust_data import TrustMatrix, PeerTrustData
from ...model.recommendation import Recommendation


def process_new_recommendations(
        configuration: TrustModelConfiguration,
        subject: PeerTrustData,
        matrix: TrustMatrix,
        recommendations: Dict[PeerId, Recommendation]
) -> TrustMatrix:
    """
    Evaluates received recommendation, computing recommendations and recommendation
    trust for each peer in :param recommendations.

    This function should be called when new recommendations are available.

    Returns dictionary with peers which were updated.

    :param configuration: configuration of the current trust model
    :param subject: subject of recommendations, this peer was asking other peers for recommendation about
    this subject, in model's notation this is "j"
    :param matrix: trust matrix with peers that provided recommendations, in model's notation this is "k"s,
    part of the T_i set
    :param recommendations: responses received from the network when
    asking for recommendations, peer ids here are in model's notation "k"s
    :return: new matrix that contains only peers that were updated - it should contain
    """
    # verify that peers with responses are in trust matrix
    for peer in recommendations.keys():
        assert matrix[peer] is not None, f"Peer {peer} is not present in peer matrix."

    er_ij = __estimate_recommendation(matrix, recommendations)
    ecb_ij, eib_ij = __estimate_competence_integrity_belief(matrix, recommendations)

    history_sizes = [r.service_history_size for r in recommendations.values()]
    history_mean = int(sum(history_sizes) / len(history_sizes))

    integrity_discount = compute_discount_factor()
    history_factor = history_mean / configuration.service_history_max_size
    # ecb_ij -0.5 * eib_ij (where -0.5 is integrity discount)
    own_experience = history_factor * (ecb_ij + integrity_discount * eib_ij)
    reputation_experience = (1 - history_factor) * er_ij

    # r_ij
    reputation = own_experience + reputation_experience
    # now update final trust for the subject with new reputation
    # we also trust the subject same with service as well as with recommendations
    # we also set service_trust if it is not set, because for the first interaction it is equal to reputation
    updated_subject_trust = dataclasses \
        .replace(subject,
                 service_trust=max(subject.service_trust, reputation),
                 reputation=reputation,
                 recommendation_trust=reputation,
                 initial_reputation_provided_by_count=len(recommendations)
                 )
    peers_updated_matrix = {updated_subject_trust.peer_id: updated_subject_trust}

    # now we need to reflect performed reputation query and update how much we trust other peers
    for peer_id, recommendation in recommendations.items():
        peer = matrix[peer_id]
        # build new history
        new_history = create_recommendation_history_for_peer(
            configuration=configuration, peer=peer, recommendation=recommendation,
            history_factor=history_factor, er_ij=er_ij, ecb_ij=ecb_ij, eib_ij=eib_ij
        )
        # and update peer and its recommendation data
        updated_peer = update_recommendation_data_for_peer(configuration=configuration,
                                                           peer=peer,
                                                           new_history=new_history)
        peers_updated_matrix[updated_peer.peer_id] = updated_peer

    return peers_updated_matrix


def __estimate_recommendation(
        matrix: TrustMatrix,
        recommendations: Dict[PeerId, Recommendation]
) -> float:
    """
    Computes estimation about recommendation.

    In model's notation er_ij.

    :param matrix: trust matrix with peers that provided recommendations
    :param recommendations: responses from the peers
    :return: estimation about recommendation er_ij
    """
    normalisation = sum([
        matrix[peer].recommendation_trust * response.initial_reputation_provided_by_count
        for peer, response
        in recommendations.items()]
    )

    recommendations = sum(
        [matrix[peer].recommendation_trust * response.initial_reputation_provided_by_count * response.recommendation
         for peer, response
         in recommendations.items()])

    return recommendations / normalisation if normalisation > 0 else 0


def __estimate_competence_integrity_belief(
        matrix: TrustMatrix,
        recommendations: Dict[PeerId, Recommendation]
) -> [float, float]:
    """
    Estimates about competence and integrity beliefs.

    In model's notation ecb_ij and eib_ij.

    :param matrix: trust matrix with peers that provided recommendations
    :param recommendations: responses from the peers
    :return: tuple with [competence, integrity] beliefs -> [ecb_ij, eib_ij]
    """
    normalisation = 0
    competence = 0
    integrity = 0

    # as we would need to iterate three times, it's just better to make for cycle
    for peer, response in recommendations.items():
        trust_history_size = matrix[peer].recommendation_trust * response.service_history_size
        # rt_ik * sh_kj
        normalisation += trust_history_size
        # rt_ik * sh_kj * cb_kj
        competence += trust_history_size * response.competence_belief
        # rt_ik * sh_kj * ib_kj
        integrity += trust_history_size * response.integrity_belief

    competence_belief = competence / normalisation if normalisation > 0 else 0
    integrity_belief = integrity / normalisation if normalisation > 0 else 0

    return [competence_belief, integrity_belief]
