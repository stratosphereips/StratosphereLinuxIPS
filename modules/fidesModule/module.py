import json
import sys
from dataclasses import asdict
from multiprocessing import Process

from fides.messaging.message_handler import MessageHandler
from fides.messaging.network_bridge import NetworkBridge
from fides.model.configuration import load_configuration
from fides.model.threat_intelligence import SlipsThreatIntelligence
from fides.protocols.alert import AlertProtocol
from fides.protocols.initial_trusl import InitialTrustProtocol
from fides.protocols.opinion import OpinionAggregator
from fides.protocols.peer_list import PeerListUpdateProtocol
from fides.protocols.recommendation import RecommendationProtocol
from fides.protocols.threat_intelligence import ThreatIntelligenceProtocol
from fides.utils.logger import LoggerPrintCallbacks, Logger
from fidesModule.messaging.queue import RedisQueue, RedisSimplexQueue
from fidesModule.originals.abstracts import Module
from fidesModule.originals.database import __database__
from fidesModule.persistance.threat_intelligence import SlipsThreatIntelligenceDatabase
from fidesModule.persistance.trust import SlipsTrustDatabase

logger = Logger("SlipsFidesModule")


class SlipsFidesModule(Module, Process):
    # Name: short name of the module. Do not use spaces
    name = 'GlobalP2P'
    description = 'Global p2p Threat Intelligence Sharing Module'
    authors = ['Lukas Forst', 'Martin Repa']

    def __init__(self, output_queue, slips_conf):
        Process.__init__(self)
        self.__output = output_queue
        # TODO: [S+] add path to trust model configuration yaml to the slips conf
        self.__slips_config = slips_conf

        # connect to slips database
        __database__.start(slips_conf)

        # now setup logging
        LoggerPrintCallbacks.clear()
        LoggerPrintCallbacks.append(self.__format_and_print)

        # load trust model configuration
        self.__trust_model_config = load_configuration(self.__slips_config.trust_model_path)

        # prepare variables for global protocols
        self.__bridge: NetworkBridge
        self.__intelligence: ThreatIntelligenceProtocol
        self.__alerts: AlertProtocol
        self.__slips_fides: RedisQueue

    def __setup_trust_model(self):
        r = __database__.r

        # TODO: [S] launch network layer binary if necessary

        # create database wrappers for Slips using Redis
        trust_db = SlipsTrustDatabase(self.__trust_model_config, r)
        ti_db = SlipsThreatIntelligenceDatabase(self.__trust_model_config, r)

        # create queues
        # TODO: [S] check if we need to use duplex or simplex queue for communication with network module
        network_fides_queue = RedisSimplexQueue(r, send_channel='fides2network', received_channel='network2fides')
        slips_fides_queue = RedisSimplexQueue(r, send_channel='fides2slips', received_channel='slips2fides')

        bridge = NetworkBridge(network_fides_queue)

        recommendations = RecommendationProtocol(self.__trust_model_config, trust_db, bridge)
        trust = InitialTrustProtocol(trust_db, self.__trust_model_config, recommendations)
        peer_list = PeerListUpdateProtocol(trust_db, bridge, recommendations, trust)
        opinion = OpinionAggregator(self.__trust_model_config, ti_db, self.__trust_model_config.ti_aggregation_strategy)

        intelligence = ThreatIntelligenceProtocol(trust_db, ti_db, bridge, self.__trust_model_config, opinion, trust,
                                                  self.__slips_config.interaction_evaluation_strategy,
                                                  self.__network_opinion_callback)
        alert = AlertProtocol(trust_db, bridge, trust, self.__trust_model_config, opinion,
                              self.__network_opinion_callback)

        # TODO: [S+] add on_unknown and on_error handlers if necessary
        message_handler = MessageHandler(
            on_peer_list_update=peer_list.handle_peer_list_updated,
            on_recommendation_request=recommendations.handle_recommendation_request,
            on_recommendation_response=recommendations.handle_recommendation_response,
            on_alert=alert.handle_alert,
            on_intelligence_request=intelligence.handle_intelligence_request,
            on_intelligence_response=intelligence.handle_intelligence_response,
            on_unknown=None,
            on_error=None
        )

        # bind local vars
        self.__bridge = bridge
        self.__intelligence = intelligence
        self.__alerts = alert
        self.__slips_fides = slips_fides_queue

        # and finally execute listener
        self.__bridge.listen(message_handler, block=False)

    def __network_opinion_callback(self, ti: SlipsThreatIntelligence):
        """This is executed every time when trust model was able to create an aggregated network opinion."""
        logger.info(f'Callback: Target: {ti.target}, Score: {ti.score}, Confidence: {ti.confidence}.')
        # TODO: [S+] document that we're sending this type
        self.__slips_fides.send(json.dumps(asdict(ti)))

    def __format_and_print(self, level: str, msg: str):
        # TODO: [S+] determine correct level for trust model log levels
        self.__output.put(f"33|{self.name}|{level} {msg}")

    def run(self):
        # as a first thing we need to set up all dependencies and bind listeners
        self.__setup_trust_model()

        # main loop for handling data coming from Slips
        while True:
            try:
                message = self.__slips_fides.get_message(timeout_seconds=0.1)
                # if there's no string data message we can continue in waiting
                if not message \
                        or not message['data'] \
                        or type(message['data']) != str:
                    continue
                # handle case when the Slips decide to stop the process
                if message['data'] == 'stop_process':
                    # Confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True
                data = json.loads(message['data'])

                # TODO: [S+] document that we need this structure
                # data types
                if data['type'] == 'alert':
                    self.__alerts.dispatch_alert(target=data['target'],
                                                 confidence=data['confidence'],
                                                 score=data['score'])
                elif data['type'] == 'intelligence_request':
                    self.__intelligence.request_data(target=data['target'])
                else:
                    logger.warn(f"Unhandled message! {message['data']}", message)

            except KeyboardInterrupt:
                # On KeyboardInterrupt, slips.py sends a stop_process msg to all modules, so continue to receive it
                continue
            except Exception as ex:
                exception_line = sys.exc_info()[2].tb_lineno
                logger.error(f'Problem on the run() line {exception_line}, {ex}.')
                return True
