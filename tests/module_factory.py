# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import shutil
from unittest.mock import (
    patch,
    Mock,
    MagicMock,
    mock_open,
)
import os
from multiprocessing import Queue

from managers.host_ip_manager import HostIPManager
from managers.metadata_manager import MetadataManager
from managers.profilers_manager import ProfilersManager
from modules.flowalerts.conn import Conn
from modules.threat_intelligence.circl_lu import Circllu
from modules.threat_intelligence.spamhaus import Spamhaus
from slips_files.core.database.database_manager import DBManager
from slips_files.core.database.redis_db.constants import (
    Constants,
    Channels,
)
from slips_files.core.evidence_handler import EvidenceHandler
from modules.rnn_cc_detection.rnn_cc_detection import CCDetection
from slips_files.core.helpers.notify import Notify
from modules.flowalerts.dns import DNS
from modules.flowalerts.downloaded_file import DownloadedFile
from slips_files.core.helpers.symbols_handler import SymbolHandler
from slips_files.core.database.redis_db.profile_handler import ProfileHandler
from modules.flowalerts.notice import Notice
from modules.flowalerts.smtp import SMTP
from modules.flowalerts.software import Software
from modules.flowalerts.ssh import SSH
from modules.flowalerts.ssl import SSL
from modules.flowalerts.tunnel import Tunnel
from modules.p2ptrust.trust.trustdb import TrustDB
from modules.p2ptrust.utils.go_director import GoDirector
from slips.main import Main
from modules.update_manager.update_manager import UpdateManager
from modules.leak_detector.leak_detector import LeakDetector
from slips_files.core.profiler import Profiler
from slips_files.core.output import Output
from modules.threat_intelligence.threat_intelligence import ThreatIntel
from modules.threat_intelligence.urlhaus import URLhaus
from modules.flowalerts.flowalerts import FlowAlerts
from modules.flowalerts.set_evidence import SetEvidenceHelper
from slips_files.core.input import Input
from modules.blocking.blocking import Blocking
from modules.http_analyzer.http_analyzer import HTTPAnalyzer
from modules.ip_info.ip_info import IPInfo
from slips_files.common.slips_utils import utils
from slips_files.core.helpers.whitelist.whitelist import Whitelist
from modules.virustotal.virustotal import VT
from managers.process_manager import ProcessManager
from managers.redis_manager import RedisManager
from modules.ip_info.asn_info import ASN
from slips_files.core.helpers.flow_handler import FlowHandler
from modules.network_discovery.horizontal_portscan import HorizontalPortscan
from modules.network_discovery.network_discovery import NetworkDiscovery
from modules.network_discovery.vertical_portscan import VerticalPortscan
from modules.p2ptrust.trust.base_model import BaseModel
from slips_files.core.database.redis_db.alert_handler import AlertHandler
from modules.arp.arp import ARP
from slips.daemon import Daemon
from slips_files.core.database.redis_db.ioc_handler import IoCHandler
from slips_files.core.helpers.checker import Checker
from modules.timeline.timeline import Timeline
from modules.cesnet.cesnet import CESNET
from modules.riskiq.riskiq import RiskIQ
from slips_files.common.markov_chains import Matrix
from slips_files.core.structures.evidence import (
    Attacker,
    Direction,
    Evidence,
    IoCType,
    ProfileID,
    Proto,
    TimeWindow,
    Victim,
)
from modules.fidesModule.fidesModule import FidesModule
from slips_files.core.text_formatters.evidence import EvidenceFormatter


def read_configuration():
    return


def check_zeek_or_bro():
    """
    Check if we have zeek or bro
    """
    if shutil.which("zeek"):
        return "zeek"
    if shutil.which("bro"):
        return "bro"
    return False


MODULE_DB_MANAGER = "slips_files.common.abstracts.module.DBManager"
# CORE_DB_MANAGER = "slips_files.common.abstracts.core.DBManager"
DB_MANAGER = "slips_files.core.database.database_manager.DBManager"


class ModuleFactory:
    def __init__(self):
        self.profiler_queue = Queue()
        self.input_queue = Queue()
        self.logger = Mock()

    def get_default_db(self):
        """default is o port 6379, this is the one we're using in conftest"""
        return self.create_db_manager_obj(6379)

    def create_db_manager_obj(
        self,
        port,
        output_dir="output/",
        flush_db=False,
        start_redis_server=True,
    ):
        """
        flush_db is False by default  because we use this function to check
        the db after integration tests to make sure everything's going fine
        """
        # to prevent config/redis.conf from being overwritten
        with patch(
            "slips_files.core.database.redis_db.database."
            "RedisDB._set_redis_options",
            return_value=Mock(),
        ):
            db = DBManager(
                self.logger,
                output_dir,
                port,
                flush_db=flush_db,
                start_sqlite=False,
                start_redis_server=start_redis_server,
            )
        db.print = Mock()
        # for easier access to redis db
        db.r = db.rdb.r
        assert db.get_used_redis_port() == port
        return db

    def create_main_obj(self):
        """returns an instance of Main() class in slips.py"""
        main = Main(testing=True)
        main.input_information = ""
        main.input_type = "pcap"
        main.line_type = False
        return main

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_http_analyzer_obj(self, mock_db):
        http_analyzer = HTTPAnalyzer(
            self.logger,
            "dummy_output_dir",
            6379,
            Mock(),
        )

        # override the self.print function to avoid broken pipes
        http_analyzer.print = Mock()
        return http_analyzer

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_fidesModule_obj(self, mock_db):
        fm = FidesModule(
            self.logger,
            "dummy_output_dir",
            6379,
            Mock(),
        )

        # override the self.print function
        fm.print = Mock()
        return fm

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_virustotal_obj(self, mock_db):
        virustotal = VT(
            self.logger,
            "dummy_output_dir",
            6379,
            Mock(),
        )
        virustotal.print = Mock()
        virustotal.__read_configuration = Mock()
        return virustotal

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_arp_obj(self, mock_db):
        with patch(
            "modules.arp.arp.ARP.wait_for_arp_scans", return_value=Mock()
        ):
            arp = ARP(
                self.logger,
                "dummy_output_dir",
                6379,
                Mock(),
            )
        arp.print = Mock()
        return arp

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_blocking_obj(self, mock_db):
        blocking = Blocking(
            self.logger,
            "dummy_output_dir",
            6379,
            Mock(),
        )
        # override the print function to avoid broken pipes
        blocking.print = Mock()
        return blocking

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_flowalerts_obj(self, mock_db):
        flowalerts = FlowAlerts(
            self.logger,
            "dummy_output_dir",
            6379,
            Mock(),
        )

        # override the self.print function to avoid broken pipes
        flowalerts.print = Mock()
        return flowalerts

    @patch(DB_MANAGER, name="mock_db")
    def create_dns_analyzer_obj(self, mock_db):
        flowalerts = self.create_flowalerts_obj()
        return DNS(flowalerts.db, flowalerts=flowalerts)

    @patch(DB_MANAGER, name="mock_db")
    def create_notice_analyzer_obj(self, mock_db):
        flowalerts = self.create_flowalerts_obj()
        return Notice(flowalerts.db, flowalerts=flowalerts)

    @patch(DB_MANAGER, name="mock_db")
    def create_smtp_analyzer_obj(self, mock_db):
        flowalerts = self.create_flowalerts_obj()
        return SMTP(flowalerts.db, flowalerts=flowalerts)

    @patch(DB_MANAGER, name="mock_db")
    def create_ssl_analyzer_obj(self, mock_db):
        flowalerts = self.create_flowalerts_obj()
        return SSL(flowalerts.db, flowalerts=flowalerts)

    @patch(DB_MANAGER, name="mock_db")
    def create_ssh_analyzer_obj(self, mock_db):
        flowalerts = self.create_flowalerts_obj()
        return SSH(flowalerts.db, flowalerts=flowalerts)

    @patch(DB_MANAGER, name="mock_db")
    def create_downloaded_file_analyzer_obj(self, mock_db):
        flowalerts = self.create_flowalerts_obj()
        return DownloadedFile(flowalerts.db, flowalerts=flowalerts)

    @patch(DB_MANAGER, name="mock_db")
    def create_tunnel_analyzer_obj(self, mock_db):
        flowalerts = self.create_flowalerts_obj()
        return Tunnel(flowalerts.db, flowalerts=flowalerts)

    @patch(DB_MANAGER, name="mock_db")
    def create_conn_analyzer_obj(self, mock_db):
        flowalerts = self.create_flowalerts_obj()
        return Conn(flowalerts.db, flowalerts=flowalerts)

    @patch(DB_MANAGER, name="mock_db")
    def create_software_analyzer_obj(self, mock_db):
        flowalerts = self.create_flowalerts_obj()
        return Software(flowalerts.db, flowalerts=flowalerts)

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_input_obj(
        self, input_information, input_type, mock_db, line_type=False
    ):
        zeek_tmp_dir = os.path.join(os.getcwd(), "zeek_dir_for_testing")
        input = Input(
            Output(),
            "dummy_output_dir",
            6379,
            is_input_done=Mock(),
            profiler_queue=self.profiler_queue,
            input_type=input_type,
            input_information=input_information,
            cli_packet_filter=None,
            zeek_or_bro=check_zeek_or_bro(),
            zeek_dir=zeek_tmp_dir,
            line_type=line_type,
            is_profiler_done_event=Mock(),
            termination_event=Mock(),
        )
        input.db = mock_db
        input.mark_self_as_done_processing = Mock()
        input.bro_timeout = 1
        # override the print function to avoid broken pipes
        input.print = Mock()
        input.stop_queues = Mock()
        input.testing = True

        return input

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_ip_info_obj(self, mock_db):
        ip_info = IPInfo(
            self.logger,
            "dummy_output_dir",
            6379,
            Mock(),
        )
        # override the self.print function to avoid broken pipes
        ip_info.print = Mock()
        return ip_info

    @patch(DB_MANAGER, name="mock_db")
    def create_asn_obj(self, mock_db):
        return ASN(mock_db)

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_leak_detector_obj(self, mock_db):
        # this file will be used for storing the module output
        # and deleted when the tests are done
        test_pcap = "dataset/test7-malicious.pcap"
        yara_rules_path = "tests/yara_rules_for_testing/rules/"
        compiled_yara_rules_path = "tests/yara_rules_for_testing/compiled/"
        leak_detector = LeakDetector(
            self.logger,
            "dummy_output_dir",
            6379,
            Mock(),
        )
        leak_detector.print = Mock()
        # this is the path containing 1 yara rule for testing,
        # it matches every pcap
        leak_detector.yara_rules_path = yara_rules_path
        leak_detector.compiled_yara_rules_path = compiled_yara_rules_path
        leak_detector.pcap = test_pcap
        return leak_detector

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_profiler_obj(self, mock_db):
        profiler = Profiler(
            self.logger,
            "output/",
            6379,
            Mock(),
            is_profiler_done=Mock(),
            profiler_queue=self.input_queue,
            is_profiler_done_event=Mock(),
        )
        # override the self.print function to avoid broken pipes
        profiler.print = Mock()
        profiler.local_whitelist_path = "tests/test_whitelist.conf"
        profiler.db = mock_db
        return profiler

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_redis_manager_obj(self, mock_db):
        main = self.create_main_obj()
        main.db = mock_db
        main.args = Mock()
        return RedisManager(main)

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_profilers_manager_obj(self, mock_db):
        main = self.create_main_obj()
        main.db = mock_db
        main.args = Mock()
        return ProfilersManager(main)

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_host_ip_manager_obj(self, mock_db):
        main = self.create_main_obj()
        main.db = mock_db
        main.print = Mock()
        return HostIPManager(main)

    def create_utils_obj(self):
        return utils

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_threatintel_obj(self, mock_db):
        threatintel = ThreatIntel(
            self.logger,
            "dummy_output_dir",
            6379,
            Mock(),
        )

        # override the self.print function to avoid broken pipes
        threatintel.print = Mock()
        return threatintel

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_spamhaus_obj(self, mock_db):
        return Spamhaus(mock_db)

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_update_manager_obj(self, mock_db):
        update_manager = UpdateManager(
            self.logger,
            "dummy_output_dir",
            6379,
            Mock(),
        )
        # override the self.print function to avoid broken pipes
        update_manager.print = Mock()
        return update_manager

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_whitelist_obj(self, mock_db):
        whitelist = Whitelist(self.logger, mock_db)
        # override the self.print function to avoid broken pipes
        whitelist.print = Mock()
        whitelist.whitelist_path = "tests/test_whitelist.conf"
        return whitelist

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_flow_handler_obj(self, flow, mock_db):
        symbol = SymbolHandler(self.logger, mock_db)
        flow_handler = FlowHandler(mock_db, symbol, flow)
        flow_handler.profileid = "profile_id"
        flow_handler.twid = "timewindow_id"
        return flow_handler

    @patch(DB_MANAGER, name="mock_db")
    def create_horizontal_portscan_obj(self, mock_db):
        horizontal_ps = HorizontalPortscan(mock_db)
        return horizontal_ps

    @patch(DB_MANAGER, name="mock_db")
    def create_vertical_portscan_obj(self, mock_db):
        vertical_ps = VerticalPortscan(mock_db)
        return vertical_ps

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_urlhaus_obj(self, mock_db):
        """Create an instance of URLhaus."""
        urlhaus = URLhaus(mock_db)
        return urlhaus

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_circllu_obj(self, mock_db):
        """Create an instance of Circllu."""
        return Circllu(mock_db, Queue())

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_set_evidence_helper(self, mock_db):
        """Create an instance of SetEvidenceHelper."""
        set_evidence_helper = SetEvidenceHelper(mock_db)
        return set_evidence_helper

    def create_output_obj(self):
        return Output()

    def create_attacker_obj(
        self,
        value="192.168.1.1",
        direction=Direction.SRC,
        ioc_type=IoCType.IP,
    ):
        return Attacker(direction=direction, ioc_type=ioc_type, value=value)

    def create_victim_obj(
        self,
        value="192.168.1.2",
        direction=Direction.DST,
        ioc_type=IoCType.IP,
    ):
        return Victim(direction=direction, ioc_type=ioc_type, value=value)

    def create_profileid_obj(self, ip="192.168.1.3"):
        return ProfileID(ip=ip)

    def create_timewindow_obj(self, number=1):
        return TimeWindow(number=number)

    def create_proto_obj(self):
        return Proto

    def create_evidence_obj(
        self,
        evidence_type,
        description,
        attacker,
        threat_level,
        victim,
        profile,
        timewindow,
        uid,
        timestamp,
        proto,
        dst_port,
        id,
        confidence,
    ):
        return Evidence(
            evidence_type=evidence_type,
            description=description,
            attacker=attacker,
            threat_level=threat_level,
            victim=victim,
            profile=profile,
            timewindow=timewindow,
            uid=uid,
            timestamp=timestamp,
            proto=proto,
            dst_port=dst_port,
            id=id,
            confidence=confidence,
        )

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_network_discovery_obj(self, mock_db):
        network_discovery = NetworkDiscovery(
            self.logger,
            "dummy_output_dir",
            6379,
            Mock(),
        )
        return network_discovery

    def create_markov_chain_obj(self):
        return Matrix()

    def create_checker_obj(self):
        mock_main = Mock()
        mock_main.args = MagicMock()
        mock_main.args.output = "test_output"
        mock_main.args.verbose = "0"
        mock_main.args.debug = "0"
        mock_main.redis_man = Mock()
        mock_main.terminate_slips = Mock()
        mock_main.print_version = Mock()
        mock_main.get_input_file_type = Mock()
        mock_main.handle_flows_from_stdin = Mock()
        mock_main.pid = 12345

        checker = Checker(mock_main)
        return checker

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_go_director_obj(self, mock_db):
        with patch("modules.p2ptrust.utils.utils.send_evaluation_to_go"):
            go_director = GoDirector(
                logger=self.logger,
                trustdb=Mock(spec=TrustDB),
                db=mock_db,
                storage_name="test_storage",
                override_p2p=False,
                gopy_channel="test_gopy",
                pygo_channel="test_pygo",
                p2p_reports_logfile="test_reports.log",
            )
            go_director.print = Mock()
        return go_director

    @patch(DB_MANAGER, name="mock_db")
    def create_daemon_object(self, mock_db):
        with (
            patch("slips.daemon.Daemon.read_pidfile", return_type=None),
            patch("slips.daemon.Daemon.read_configuration"),
            patch("builtins.open", mock_open(read_data=None)),
        ):
            daemon = Daemon(MagicMock())
        daemon.stderr = "errors.log"
        daemon.stdout = "slips.log"
        daemon.stdin = "/dev/null"
        daemon.logsfile = "slips.log"
        daemon.pidfile_dir = "/tmp"
        daemon.pidfile = os.path.join(daemon.pidfile_dir, "slips_daemon.lock")
        daemon.daemon_start_lock = "slips_daemon_start"
        daemon.daemon_stop_lock = "slips_daemon_stop"
        return daemon

    @patch("sqlite3.connect", name="sqlite_mock")
    def create_trust_db_obj(self, sqlite_mock):
        trust_db = TrustDB(self.logger, Mock(), drop_tables_on_startup=False)
        trust_db.conn = Mock()
        trust_db.print = Mock()
        return trust_db

    def create_base_model_obj(self):
        logger = Mock(spec=Output)
        trustdb = Mock()
        return BaseModel(logger, trustdb)

    def create_notify_obj(self):
        notify = Notify()
        return notify

    def create_ioc_handler_obj(self):
        handler = IoCHandler()
        handler.r = Mock()
        handler.rcache = Mock()
        handler.constants = Constants()
        handler.channels = Channels()
        return handler

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_cesnet_obj(self, mock_db):
        output_dir = "dummy_output_dir"
        redis_port = 6379
        termination_event = MagicMock()

        cesnet = CESNET(self.logger, output_dir, redis_port, termination_event)
        cesnet.db = mock_db
        cesnet.wclient = MagicMock()
        cesnet.node_info = [
            {"Name": "TestNode", "Type": ["IPS"], "SW": ["Slips"]}
        ]

        cesnet.print = MagicMock()
        return cesnet

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_evidence_handler_obj(self, mock_db):
        logger = Mock()
        output_dir = "/tmp"
        redis_port = 6379
        termination_event = Mock()
        handler = EvidenceHandler(
            logger, output_dir, redis_port, termination_event
        )
        handler.db = mock_db
        return handler

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_evidence_formatter_obj(self, mock_db):
        return EvidenceFormatter(mock_db)

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_symbol_handler_obj(self, mock_db):
        mock_logger = Mock()
        mock_db.get_t2_for_profile_tw.return_value = (1000.0, 2000.0)
        return SymbolHandler(mock_logger, mock_db)

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_riskiq_obj(self, mock_db):
        termination_event = MagicMock()
        riskiq = RiskIQ(
            self.logger,
            "dummy_output_dir",
            6379,
            termination_event,
        )
        riskiq.db = mock_db
        return riskiq

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_timeline_object(self, mock_db):
        logger = Mock()
        output_dir = "/tmp"
        redis_port = 6379
        termination_event = Mock()
        tl = Timeline(logger, output_dir, redis_port, termination_event)
        tl.db = mock_db
        return tl

    def create_alert_handler_obj(self):
        alert_handler = AlertHandler()
        alert_handler.constants = Constants()
        return alert_handler

    def create_profile_handler_obj(self):
        handler = ProfileHandler()
        handler.constants = Constants()
        handler.r = Mock()
        handler.rcache = Mock()
        handler.separator = "_"
        handler.width = 3600
        handler.print = Mock()
        return handler

    def create_process_manager_obj(self):
        main_mock = Mock()
        main_mock.conf.get_disabled_modules.return_value = []
        #main_mock.conf.get_bootstrapping_setting.return_value = (False, [])
        main_mock.conf.is_bootstrapping_node.return_value = False
        main_mock.conf.get_bootstrapping_modules.return_value = ["fidesModule", "irisModule"]
        main_mock.input_type = "pcap"
        main_mock.mode = "normal"
        main_mock.stdout = ""
        main_mock.args = Mock(growing=False, input_module=False, testing=False)
        return ProcessManager(main_mock)

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_metadata_manager_obj(self, mock_db):
        main = self.create_main_obj()
        metadata_manager = MetadataManager(main)

        mock_attributes = {
            "db": mock_db,
            "print": MagicMock(),
            "args": MagicMock(
                output="/tmp/output",
                config="config/slips.yaml",
                filepath=MagicMock(),
            ),
            "conf": MagicMock(
                enable_metadata=MagicMock(return_value=True),
                whitelist_path=MagicMock(
                    return_value="/path/to/whitelist.conf"
                ),
                get_disabled_modules=MagicMock(return_value=[]),
                evidence_detection_threshold=MagicMock(return_value=0.5),
            ),
            "version": "1.0",
            "input_information": "test_input",
            "input_type": MagicMock(),
            "zeek_dir": MagicMock(),
        }

        for attr, value in mock_attributes.items():
            setattr(metadata_manager.main, attr, value)

        return metadata_manager

    @patch(MODULE_DB_MANAGER, name="mock_db")
    def create_rnn_detection_object(self, mock_db):
        logger = Mock()
        output_dir = "/tmp"
        redis_port = 6379
        termination_event = Mock()

        with patch.object(CCDetection, "__init__", return_value=None):
            cc_detection = CCDetection(
                logger, output_dir, redis_port, termination_event
            )
            cc_detection.db = mock_db
            cc_detection.exporter = Mock()
            return cc_detection
