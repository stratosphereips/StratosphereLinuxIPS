from http.client import responses
from typing import Dict, List, Callable, Optional, Union, Any

from absl.logging import debug

from slips_files.common.printer import Printer
from ..messaging.dacite import from_dict

from ..messaging.model import NetworkMessage, PeerInfo, \
    PeerIntelligenceResponse, PeerRecommendationResponse
from ..model.alert import Alert
from ..model.aliases import PeerId, Target
from ..model.recommendation import Recommendation
from ..model.threat_intelligence import ThreatIntelligence
from ..utils.logger import Logger

logger = Logger(__name__)



class MessageHandler:
    """
    Class responsible for parsing messages and handling requests coming from the queue.

    The entrypoint is on_message.
    """



    #def print(self, *args, **kwargs):
    #    return self.printer.print(*args, **kwargs)

    version = 1

    def __init__(self,
                 on_peer_list_update: Callable[[List[PeerInfo]], None],
                 on_recommendation_request: Callable[[str, PeerInfo, PeerId], None],
                 on_recommendation_response: Callable[[List[PeerRecommendationResponse]], None],
                 on_alert: Callable[[PeerInfo, Alert], None],
                 on_intelligence_request: Callable[[str, PeerInfo, Target], None],
                 on_intelligence_response: Callable[[List[PeerIntelligenceResponse]], None],
                 on_unknown: Optional[Callable[[NetworkMessage], None]] = None,
                 on_error: Optional[Callable[[Union[str, NetworkMessage], Exception], None]] = None
                 ):
        #self.logger = None
        self.__on_peer_list_update_callback = on_peer_list_update
        self.__on_recommendation_request_callback = on_recommendation_request
        self.__on_recommendation_response_callback = on_recommendation_response
        self.__on_alert_callback = on_alert
        self.__on_intelligence_request_callback = on_intelligence_request
        self.__on_intelligence_response_callback = on_intelligence_response
        self.__on_unknown_callback = on_unknown
        self.__on_error = on_error
        #self.printer = Printer(self.logger, self.name)

    def on_message(self, message: NetworkMessage):
        """
        Entry point for generic messages coming from the queue.
        This method parses the message and then executes correct procedure from event.
        :param message: message from the queue
        :return: value from the underlining function from the constructor
        """
        if message.version != self.version:
            logger.warn(f'Unknown message version! This handler supports {self.version}.', message)
            return self.__on_unknown_message(message)

        execution_map = {
            'nl2tl_peers_list': self.__on_nl2tl_peer_list,
            'nl2tl_recommendation_request': self.__on_nl2tl_recommendation_request,
            'nl2tl_recommendation_response': self.__on_nl2tl_recommendation_response,
            'nl2tl_alert': self.__on_nl2tl_alert,
            'nl2tl_intelligence_request': self.__on_nl2tl_intelligence_request,
            'nl2tl_intelligence_response': self.__on_nl2tl_intelligence_response
        }
        func = execution_map.get(message.type, lambda data: self.__on_unknown_message(message))
        # we want to handle everything
        # noinspection PyBroadException
        try:
            # we know that the functions can handle that, and if not, there's always error handling
            # noinspection PyArgumentList
            return func(message.data)
        except Exception as ex:
            logger.error(f"Error when executing handler for message: {message.type}.", ex)
            if self.__on_error:
                return self.__on_error(message, ex)

    def on_error(self, original_data: str, exception: Optional[Exception] = None):
        """
        Should be executed when it was not possible to parse the message.
        :param original_data: string received from the queue
        :param exception: exception that occurred during handling
        :return:
        """
        logger.error(f'Unknown data received: {original_data}.')
        if self.__on_error:
            self.__on_error(original_data, exception if exception else Exception('Unknown data type!'))

    def __on_unknown_message(self, message: NetworkMessage):
        logger.warn(f'Unknown message handler executed!')
        logger.debug(f'Message:', message)

        if self.__on_unknown_callback is not None:
            self.__on_unknown_callback(message)

    def __on_nl2tl_peer_list(self, data: Dict):
        logger.debug('nl2tl_peer_list message')

        peers = [from_dict(data_class=PeerInfo, data=peer) for peer in data['peers']]
        return self.__on_peer_list_update(peers)

    def __on_peer_list_update(self, peers: List[PeerInfo]):
        return self.__on_peer_list_update_callback(peers)

    def __on_nl2tl_recommendation_request(self, data: Dict):
        logger.debug('nl2tl_recommendation_request message')

        request_id = data['request_id']
        sender = from_dict(data_class=PeerInfo, data=data['sender'])
        subject = data['payload']
        return self.__on_recommendation_request(request_id, sender, subject)

    def __on_recommendation_request(self, request_id: str, sender: PeerInfo, subject: PeerId):
        return self.__on_recommendation_request_callback(request_id, sender, subject)

    def __on_nl2tl_recommendation_response(self, data: List[Dict]):
        logger.debug('nl2tl_recommendation_response message')

        responses = [PeerRecommendationResponse(
            sender=from_dict(data_class=PeerInfo, data=single['sender']),
            subject=single['payload']['subject'],
            recommendation=from_dict(data_class=Recommendation, data=single['payload']['recommendation'])
        ) for single in data]
        return self.__on_recommendation_response(responses)

    def __on_recommendation_response(self, recommendations: List[PeerRecommendationResponse]):
        return self.__on_recommendation_response_callback(recommendations)

    def __on_nl2tl_alert(self, data: Dict):
        logger.debug('nl2tl_alert message')

        sender = from_dict(data_class=PeerInfo, data=data['sender'])
        alert = from_dict(data_class=Alert, data=data['payload'])
        return self.__on_alert(sender, alert)

    def __on_alert(self, sender: PeerInfo, alert: Alert):
        return self.__on_alert_callback(sender, alert)

    def __on_nl2tl_intelligence_request(self, data: Dict):
        logger.debug('nl2tl_intelligence_request message')

        request_id = data['request_id']
        sender = from_dict(data_class=PeerInfo, data=data['sender'])
        target = data['payload']
        return self.__on_intelligence_request(request_id, sender, target)

    def __on_intelligence_request(self, request_id: str, sender: PeerInfo, target: Target):
        return self.__on_intelligence_request_callback(request_id, sender, target)

    def __on_nl2tl_intelligence_response(self, data: Dict):
        logger.debug('nl2tl_intelligence_response message')

        responses = []

        try:
            responses = [PeerIntelligenceResponse(
                sender=from_dict(data_class=PeerInfo, data=single['sender']),
                intelligence=from_dict(data_class=ThreatIntelligence, data=single['payload']['intelligence']),
                target=single['payload']['target']
            ) for single in data]
        except Exception as e:
            print("Error in Fides message_handler.py __on_nl2tl_intelligence_response(): ", e.__str__())
            #self.print("Error in Fides message_handler.py __on_nl2tl_intelligence_response(): ")
        return self.__on_intelligence_response(responses)

    def __on_intelligence_response(self, responses: List[PeerIntelligenceResponse]):
        return self.__on_intelligence_response_callback(responses)
