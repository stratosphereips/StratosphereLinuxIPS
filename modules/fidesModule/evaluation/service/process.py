import dataclasses

from ...evaluation.service.interaction import Satisfaction, Weight
from ...evaluation.service.peer_update import update_service_data_for_peer
from ...model.configuration import TrustModelConfiguration
from ...model.peer_trust_data import PeerTrustData
from ...model.service_history import ServiceHistoryRecord
from ...utils.logger import Logger
from ...utils.time import now

logger = Logger(__name__)


def process_service_interaction(
        configuration: TrustModelConfiguration,
        peer: PeerTrustData,
        satisfaction: Satisfaction,
        weight: Weight
) -> PeerTrustData:
    """Processes given interaction and updates trust data."""
    new_history = peer.service_history + [ServiceHistoryRecord(
        satisfaction=satisfaction,
        weight=weight.value,
        timestamp=now()
    )]
    # now restrict new history to max length
    if len(new_history) > configuration.service_history_max_size:
        last = len(new_history)
        new_history = new_history[last - configuration.service_history_max_size: last]

    # we don't update service trust for fixed trust peers
    if peer.has_fixed_trust:
        logger.debug(f"Peer {peer.peer_id} has fixed trust.")
        return dataclasses.replace(peer, service_history=new_history)
    else:
        return update_service_data_for_peer(
            configuration=configuration,
            peer=peer,
            new_history=new_history
        )
