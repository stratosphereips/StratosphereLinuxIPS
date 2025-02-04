import os
import json
from dataclasses import asdict
from pathlib import Path

from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.module import IModule
from slips_files.common.parsers.config_parser import (
    ConfigParser,
)
from slips_files.core.structures.alerts import (
    dict_to_alert,
    Alert,
)
from .messaging.model import NetworkMessage
from ..fidesModule.messaging.message_handler import MessageHandler
from ..fidesModule.messaging.network_bridge import NetworkBridge
from ..fidesModule.model.configuration import load_configuration
from ..fidesModule.model.threat_intelligence import SlipsThreatIntelligence, ThreatIntelligence
from ..fidesModule.protocols.alert import AlertProtocol
from ..fidesModule.protocols.initial_trusl import InitialTrustProtocol
from ..fidesModule.protocols.opinion import OpinionAggregator
from ..fidesModule.protocols.peer_list import PeerListUpdateProtocol
from ..fidesModule.protocols.recommendation import RecommendationProtocol
from ..fidesModule.protocols.threat_intelligence import (
    ThreatIntelligenceProtocol,
)
from ..fidesModule.utils.logger import LoggerPrintCallbacks
from ..fidesModule.messaging.redis_simplex_queue import RedisSimplexQueue, RedisDuplexQueue
from ..fidesModule.persistence.threat_intelligence_db import (
    SlipsThreatIntelligenceDatabase,
)
from ..fidesModule.persistence.trust_db import SlipsTrustDatabase
from ..fidesModule.persistence.sqlite_db import SQLiteDB

from ..fidesModule.model.alert import Alert as FidesAlert


class FidesModule(IModule):
    """
    This module ony runs when slips is running on an interface
    """

    name = "Fides"
    description = "Trust computation module for P2P interactions."
    authors = ["David Otta", "Lukáš Forst"]

    def init(self):
        self.__output = self.logger

        # IModule has its own logger, no set-up
        LoggerPrintCallbacks.clear()
        LoggerPrintCallbacks.append(self.print)

        # load trust model configuration
        current_dir = Path(__file__).resolve().parent
        config_path = current_dir / "config" / "fides.conf.yml"
        self.__trust_model_config = load_configuration(config_path.__str__())

        # prepare variables for global protocols
        self.__bridge: NetworkBridge
        self.__intelligence: ThreatIntelligenceProtocol
        self.__alerts: AlertProtocol
        self.f2n = self.db.subscribe("fides2network")
        self.n2f = self.db.subscribe("network2fides")
        self.s2f = self.db.subscribe("slips2fides")
        self.ch_alert = self.db.subscribe("new_alert")
        self.f2s = self.db.subscribe("fides2slips")
        self.ch_ip = self.db.subscribe("new_ip")
        self.channels = {
            "network2fides": self.n2f,
            "fides2network": self.f2n,
            "slips2fides": self.s2f,
            "fides2slips": self.f2s,
            "new_alert": self.ch_alert,
            "new_ip": self.ch_ip,
        }

        # this sqlite is shared between all runs, like a cache,
        # so it shouldnt be stored in the current output dir, it should be
        # in the main slips dir
        self.sqlite = SQLiteDB(
            self.logger,
            os.path.join(os.getcwd(), self.__trust_model_config.database),
        )

    def read_configuration(self):
        """reurns true if all necessary configs are present and read"""
        conf = ConfigParser()
        self.__slips_config = conf.export_to()

    def __setup_trust_model(self):
        # create database wrappers for Slips using Redis
        # trust_db = InMemoryTrustDatabase(self.__trust_model_config)
        # ti_db =  InMemoryThreatIntelligenceDatabase()
        trust_db = SlipsTrustDatabase(
            self.__trust_model_config, self.db, self.sqlite
        )
        ti_db = SlipsThreatIntelligenceDatabase(
            self.__trust_model_config, self.db, self.sqlite
        )

        # create queues
        # TODONE: [S] check if we need to use duplex or simplex queue for
        # communication with network module
        self.network_fides_queue = RedisSimplexQueue(
            self.db,
            send_channel="fides2network",
            received_channel="network2fides",
            channels=self.channels,
        )

        # #iris uses only one channel for communication
        # self.network_fides_queue = RedisDuplexQueue(
        #     self.db,
        #     channel="fides2network",
        #     channels=self.channels,
        # )

        bridge = NetworkBridge(self.network_fides_queue)

        recommendations = RecommendationProtocol(
            self.__trust_model_config, trust_db, bridge
        )
        trust = InitialTrustProtocol(
            trust_db, self.__trust_model_config, recommendations
        )
        peer_list = PeerListUpdateProtocol(
            trust_db, bridge, recommendations, trust
        )
        opinion = OpinionAggregator(
            self.__trust_model_config,
            ti_db,
            self.__trust_model_config.ti_aggregation_strategy,
        )

        intelligence = ThreatIntelligenceProtocol(
            trust_db,
            ti_db,
            bridge,
            self.__trust_model_config,
            opinion,
            trust,
            self.__trust_model_config.interaction_evaluation_strategy,
            self.__network_opinion_callback,
        )
        alert = AlertProtocol(
            trust_db,
            bridge,
            trust,
            self.__trust_model_config,
            opinion,
            self.__network_opinion_callback,
        )

        # [S+] add on_unknown and on_error handlers if necessary
        message_handler = MessageHandler(
            on_peer_list_update=peer_list.handle_peer_list_updated,
            on_recommendation_request=recommendations.handle_recommendation_request,
            on_recommendation_response=recommendations.handle_recommendation_response,
            on_alert=alert.handle_alert,
            on_intelligence_request=intelligence.handle_intelligence_request,
            on_intelligence_response=intelligence.handle_intelligence_response,
            on_unknown=None,
            on_error=None,
        )

        # bind local vars
        self.__bridge = bridge
        self.__intelligence = intelligence
        self.__alerts = alert

        # and finally execute listener
        self.__bridge.listen(message_handler, block=False)

    def __network_opinion_callback(self, ti: SlipsThreatIntelligence):
        """This is executed every time when trust model was able to create an
        aggregated network opinion."""
        self.db.publish("fides2slips", json.dumps(ti.to_dict()))

    def shutdown_gracefully(self):
        self.sqlite.close()
        self.network_fides_queue.stop_all_queue_threads()

    def pre_main(self):
        """
        Initializations that run only once before the main() function
         runs in a loop
        """
        self.__setup_trust_model()
        utils.drop_root_privs()

    def main(self):
        if msg := self.get_msg("new_alert"):
            # if there's no string data message we can continue waiting
            if not msg["data"]:
                return
            alert: dict = json.loads(msg["data"])
            alert: Alert = dict_to_alert(alert)
            self.__alerts.dispatch_alert(
                target=alert.profile.ip,
                confidence=0.5,
                score=0.8,
            )
            # envelope = NetworkMessage(
            #     type="tl2nl_alert",
            #     version=self.__bridge.version,
            #     data={
            #         "payload": FidesAlert(
            #             target=alert.profile.ip,
            #             score=0.8,
            #             confidence=0.5,
            #         )
            #     },
            # )
            # self.db.publish("fides2network", json.dumps(asdict(envelope)))

        if msg := self.get_msg("new_ip"):
            # if there's no string data message we can continue waiting
            if not msg["data"]:
                return

            ip = msg["data"]

            if utils.detect_ioc_type(ip) != "ip":
                return

            if utils.is_ignored_ip(ip):
                return
            self.__intelligence.request_data(ip)

        # TODO: the code below exists for testing purposes for
        #  tests/integration_tests/test_fides.py
        if msg := self.get_msg("fides2network"):
            pass
