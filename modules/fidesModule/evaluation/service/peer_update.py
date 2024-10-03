import dataclasses
from math import sqrt
from typing import List

from ...evaluation.discount_factor import compute_discount_factor
from ...model.configuration import TrustModelConfiguration
from ...model.peer_trust_data import PeerTrustData
from ...model.service_history import ServiceHistory
from ...utils import bound


# noinspection DuplicatedCode
# TODO: [+] try to abstract this

def update_service_data_for_peer(
        configuration: TrustModelConfiguration,
        peer: PeerTrustData,
        new_history: ServiceHistory
) -> PeerTrustData:
    """
    Computes and updates PeerTrustData.service_trust - st_ij - for peer j - based on the given data.

    Does not modify given trust values directly, returns new object - however, this
    method does not create new collections as they're not being modified, they're simply copied.

    :param configuration: configuration of the current trust model
    :param peer: trust data for peer j with old history, to be updated
    :param new_history: history with updated records
    :return: new peer trust data object with fresh service_trust, competence_belief, integrity_belief
     and service_history
    """

    fading_factor = __compute_fading_factor(configuration, new_history)
    competence_belief = __compute_competence_belief(new_history, fading_factor)
    integrity_belief = __compute_integrity_belief(new_history, fading_factor, competence_belief)
    integrity_discount = compute_discount_factor()

    history_factor = len(new_history) / configuration.service_history_max_size

    # (sh_ij / sh_max) * (cb_ij -0.5 * ib_ij) -> where -0.5 is discount factor
    service_trust_own_experience = history_factor * (competence_belief + integrity_discount * integrity_belief)
    # (1 - (sh_ij / sh_max)) * r_ij
    service_trust_reputation = (1 - history_factor) * peer.reputation
    # and now add both parts together
    service_trust = service_trust_own_experience + service_trust_reputation
    # TODO: [?] verify why do we need that
    # (case when the data do not follow normal distribution and ib is higher then mean)
    service_trust = bound(service_trust, 0, 1)

    updated_trust = dataclasses.replace(peer,
                                        service_trust=service_trust,
                                        competence_belief=competence_belief,
                                        integrity_belief=integrity_belief,
                                        service_history=new_history
                                        )

    return updated_trust


def __compute_fading_factor(configuration: TrustModelConfiguration, service_history: ServiceHistory) -> List[float]:
    """
    Computes fading factor for each record in service history.

    In model's notation f^k_ij where "k" is index in service history.

    :param configuration: trust models configuration
    :param service_history: history for which should be fading factor generated
    :return: ordered list of fading factors, index of fading factor matches record in ServiceHistory
    """
    # TODO: [?] this might be time based in the future
    # f^k_ij = k / sh_ij
    # where 1 <= k <= sh_ij

    # Linear forgetting
    # history_size = len(service_history)
    # return [i / history_size for i, _ in enumerate(service_history, start=1)]

    # Do not forget anything
    return [1] * len(service_history)


def __compute_competence_belief(service_history: ServiceHistory, fading_factor: List[float]) -> float:
    """
    Computes competence belief - cb_ij.

    :param service_history: history for peer j
    :param fading_factor: fading factors for given history
    :return: competence belief for given data
    """
    assert len(service_history) == len(fading_factor), "Service history must have same length as fading factors."

    normalisation = sum([service.weight * fading for service, fading in zip(service_history, fading_factor)])
    belief = sum([service.satisfaction * service.weight * fading
                  for service, fading
                  in zip(service_history, fading_factor)])

    return belief / normalisation


def __compute_integrity_belief(service_history: ServiceHistory,
                               fading_factor: List[float],
                               competence_belief: float) -> float:
    """
    Computes integrity belief - ib_ij.

    :param competence_belief: competence belief for given service history and fading factor
    :param service_history: history for peer j
    :param fading_factor: fading factors for given history
    :return: integrity belief for given data
    """
    assert len(service_history) == len(fading_factor), "Service history must have same length as fading factors."

    history_size = len(service_history)
    weight_mean = sum([service.weight for service in service_history]) / history_size
    fading_mean = sum(fading_factor) / history_size

    sat = sum([(service.satisfaction * weight_mean * fading_mean - competence_belief) ** 2
               for service
               in service_history])

    ib = sqrt(sat / history_size)
    return ib
