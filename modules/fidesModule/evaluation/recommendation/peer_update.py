import dataclasses
from math import sqrt
from typing import List

from ...evaluation.discount_factor import compute_discount_factor
from ...model.configuration import TrustModelConfiguration
from ...model.peer_trust_data import PeerTrustData
from ...model.recommendation_history import RecommendationHistory


# noinspection DuplicatedCode
# TODO: [+] try to abstract this
def update_recommendation_data_for_peer(
        configuration: TrustModelConfiguration,
        peer: PeerTrustData,
        new_history: RecommendationHistory
) -> PeerTrustData:
    """
    Computes and updates all recommendation data for given peer with new_history.

    Does not modify given trust values directly, returns new object - however, this
    method does not create new collections as they're not being modified, they're simply copied.

    :param configuration: current trust model configuration
    :param peer: peer to be updated, its recommendation_history is older than new_history
    :param new_history: history to be used as base for recommendation computation
    :return: new object peer trust data with updated recommendation_trust and recommendation_history
    """
    fading_factor = __compute_fading_factor(configuration, new_history)
    competence_belief = __compute_competence_belief(new_history, fading_factor)
    integrity_belief = __compute_integrity_belief(new_history, fading_factor, competence_belief)
    integrity_discount = compute_discount_factor()

    history_factor = len(new_history) / configuration.recommendations.history_max_size

    # (rh_ik / rh_max) * (rcb_ik -0.5 * rib_ik) -> where -0.5 is discount factor
    reputation_trust_own_experience = history_factor * (competence_belief + integrity_discount * integrity_belief)
    # (1 - (rh_ik / rh_max)) * r_ik
    reputation_experience = (1 - history_factor) * peer.reputation
    # and now add both parts together
    recommendation_trust = reputation_trust_own_experience + reputation_experience

    updated_trust = dataclasses.replace(peer,
                                        recommendation_trust=recommendation_trust,
                                        recommendation_history=new_history
                                        )

    return updated_trust


def __compute_fading_factor(configuration: TrustModelConfiguration,
                            recommendation_history: RecommendationHistory) -> List[float]:
    """
    Computes fading factor for each record in recommendation history.

    In model's notation rf^z_ik where "z" is index in recommendation history.

    :param configuration: trust models configuration
    :param recommendation_history: history for which should be fading factor generated
    :return: ordered list of fading factors, index of fading factor matches record in RecommendationHistory
    """
    # TODO: [?] this might be time based in the future
    # f^k_ij = k / sh_ij
    # where 1 <= k <= sh_ij
    # Linear forgetting
    # history_size = len(recommendation_history)
    # return [i / history_size for i, _ in enumerate(recommendation_history, start=1)]

    # Do not forget anything
    return [1] * len(recommendation_history)


def __compute_competence_belief(recommendation_history: RecommendationHistory, fading_factor: List[float]) -> float:
    """
    Computes competence belief - rcb_ik.

    :param recommendation_history: history for peer k
    :param fading_factor: fading factors for given history
    :return: reputation competence belief for given data
    """
    assert len(recommendation_history) == len(fading_factor), \
        "Recommendation history must have same length as fading factors."

    normalisation = sum(
        [recommendation.weight * fading for recommendation, fading in zip(recommendation_history, fading_factor)])

    belief = sum([service.satisfaction * service.weight * fading
                  for service, fading
                  in zip(recommendation_history, fading_factor)])

    return belief / normalisation if normalisation > 0 else 0


def __compute_integrity_belief(recommendation_history: RecommendationHistory,
                               fading_factor: List[float],
                               recommendation_competence_belief: float) -> float:
    """
    Computes integrity belief - rib_ik.

    :param recommendation_competence_belief: rcb_ik competence belief for given service history and fading factor
    :param recommendation_history: history for peer k
    :param fading_factor: fading factors for given history
    :return: integrity belief for given data
    """
    assert len(recommendation_history) == len(fading_factor), \
        "Recommendation history must have same length as fading factors."

    history_size = len(recommendation_history)
    weight_mean = sum(service.weight for service in recommendation_history) / history_size
    fading_mean = sum(fading_factor) / history_size

    sat = sum((recommendation.satisfaction * weight_mean * fading_mean - recommendation_competence_belief) ** 2
              for recommendation
              in recommendation_history)

    return sqrt(sat / history_size)
