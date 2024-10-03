# Must imports
from slips_files.common.imports import *

from slips_files.common.parsers.config_parser import ConfigParser # solves slips_config

import os

# original module imports
import json
import sys
from dataclasses import asdict
from multiprocessing import Process


from ..fidesModule.messaging.message_handler import MessageHandler
from ..fidesModule.messaging.network_bridge import NetworkBridge
from ..fidesModule.model.configuration import load_configuration
from ..fidesModule.model.threat_intelligence import SlipsThreatIntelligence
from ..fidesModule.protocols.alert import AlertProtocol
from ..fidesModule.protocols.initial_trusl import InitialTrustProtocol
from ..fidesModule.protocols.opinion import OpinionAggregator
from ..fidesModule.protocols.peer_list import PeerListUpdateProtocol
from ..fidesModule.protocols.recommendation import RecommendationProtocol
from ..fidesModule.protocols.threat_intelligence import ThreatIntelligenceProtocol
from ..fidesModule.utils.logger import LoggerPrintCallbacks, Logger
from ..fidesModule.messaging.queueF import RedisQueue, RedisSimplexQueue
from ..fidesModule.originals.abstracts import Module
from ..fidesModule.originals.database import __database__
from ..fidesModule.persistance.threat_intelligence import SlipsThreatIntelligenceDatabase
from ..fidesModule.persistance.trust import SlipsTrustDatabase

logger = Logger("SlipsFidesModule")

class fidesModule(IModule):
    # Name: short name of the module. Do not use spaces
    name = "Fides"
    description = "Trust computation module for P2P interactions."
    authors = ['David Otta']

    def init(self):
        # Process.__init__(self) done by IModule
        self.__output = self.logger
        
        slips_conf = os.path.join('modules', 'fidesModule', 'config', 'fides.conf.yml')

        # self.__slips_config = slips_conf # TODONE give it path to config file and move the config file to module
        self.read_configuration() # hope it works

        # connect to slips database
        #__database__.start(slips_conf) # __database__ replaced by self.db from IModule, no need ot start it

        # IModule has its own logger, no set-up
        LoggerPrintCallbacks.clear()
        LoggerPrintCallbacks.append(self.__format_and_print)

        # load trust model configuration
        #self.__trust_model_config = load_configuration(self.__slips_config.trust_model_path) # TODO fix this to make it work under new management
        self.__trust_model_config = load_configuration(slips_conf)


        # prepare variables for global protocols
        self.__bridge: NetworkBridge
        self.__intelligence: ThreatIntelligenceProtocol
        self.__alerts: AlertProtocol
        self.__slips_fides: RedisQueue

    def read_configuration(self) -> bool:
        """reurns true if all necessary configs are present and read"""
        conf = ConfigParser()
        self.__slips_config = conf.export_to()

    def __setup_trust_model(self):
        r = self.db.rdb
        #print("-1-", end="")

        # create database wrappers for Slips using Redis
        trust_db = SlipsTrustDatabase(self.__trust_model_config, r)
        #print("-2-", end="")
        ti_db = SlipsThreatIntelligenceDatabase(self.__trust_model_config, r)
        #print("-3-", end="")

        # create queues
        # TODO: [S] check if we need to use duplex or simplex queue for communication with network module
        network_fides_queue = RedisSimplexQueue(r, send_channel='fides2network', received_channel='network2fides')
        #print("-3.5-", end="")
        # 1 # slips_fides_queue = RedisSimplexQueue(r, send_channel='fides2slips', received_channel='slips2fides')
        #print("-4-", end="")

        bridge = NetworkBridge(network_fides_queue)
        #print("-5-", end="")

        recommendations = RecommendationProtocol(self.__trust_model_config, trust_db, bridge)
        trust = InitialTrustProtocol(trust_db, self.__trust_model_config, recommendations)
        peer_list = PeerListUpdateProtocol(trust_db, bridge, recommendations, trust)
        opinion = OpinionAggregator(self.__trust_model_config, ti_db, self.__trust_model_config.ti_aggregation_strategy)
        #print("-6-", end="")

        intelligence = ThreatIntelligenceProtocol(trust_db, ti_db, bridge, self.__trust_model_config, opinion, trust,
                                                  self.__slips_config.interaction_evaluation_strategy,
                                                  self.__network_opinion_callback)
        alert = AlertProtocol(trust_db, bridge, trust, self.__trust_model_config, opinion,
                              self.__network_opinion_callback)
        #print("-7-", end="")

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
        #print("-8-", end="")

        # bind local vars
        self.__bridge = bridge
        self.__intelligence = intelligence
        self.__alerts = alert
        # 1 # self.__slips_fides = slips_fides_queue
        self.__channel_slips_fides = self.db.subscribe("fides_d")
        # and finally execute listener
        self.__bridge.listen(message_handler, block=False)
        #print("-9-", end="")

        self.channels = {
            "fides_d": self.__channel_slips_fides,
        }

    def __network_opinion_callback(self, ti: SlipsThreatIntelligence):
        """This is executed every time when trust model was able to create an aggregated network opinion."""
        logger.info(f'Callback: Target: {ti.target}, Score: {ti.score}, Confidence: {ti.confidence}.')
        # TODO: [S+] document that we're sending this type
        self.__slips_fides.send(json.dumps(asdict(ti)))

    def __format_and_print(self, level: str, msg: str):
        # TODO: [S+] determine correct level for trust model log levels
        self.__output.put(f"33|{self.name}|{level} {msg}")

    def pre_main(self):
        """
        Initializations that run only once before the main() function runs in a loop
        """
        #print("~", end="")
        # utils.drop_root_privs()
        self.__setup_trust_model()
        #print("~", end="")


    def main(self):
        print("+", end="")
        try:
            if msg := self.get_msg("tw_modified"):
                # if there's no string data message we can continue in waiting
                if not msg['data']:# or type(msg['data']) != str:
                    return
                data = json.loads(msg['data'])

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
            return # REPLACE old continue
        except Exception as ex:
            exception_line = sys.exc_info()[2].tb_lineno
            logger.error(f'Problem on the run() line {exception_line}, {ex}.')
            return True