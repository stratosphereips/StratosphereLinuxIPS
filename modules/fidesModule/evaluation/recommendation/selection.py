from math import sqrt
from typing import Dict, List

from ...model.aliases import PeerId


def select_trustworthy_peers_for_recommendations(
        data: Dict[PeerId, float],
        max_peers: int
) -> List[PeerId]:
    """
    Selects peers that can be asked for recommendation.
    :param data: PeerId: Peer.recommendation_trust
    :param max_peers: maximum of peers to select
    :return: list of peers that should be asked for recommendation
    """
    mean = sum(data.values()) / len(data.values())
    var = sqrt(sum((rt - mean) ** 2 for rt in data.values()))
    lowest_rt = mean - var
    # select only peers that have recommendation_trust higher than mean - variance
    candidates = sorted([
        {'id': peer_id, 'rt': rt} for peer_id, rt in data.items() if rt >= lowest_rt
    ], key=lambda x: x['rt'], reverse=True)
    # and now cut them at max
    return [p['id'] for p in candidates[: max_peers]]
