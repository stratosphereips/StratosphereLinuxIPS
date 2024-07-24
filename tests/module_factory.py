import shutil
from unittest.mock import patch, Mock
import os

from modules.flowalerts.conn import Conn
from modules.flowalerts.dns import DNS
from modules.flowalerts.downloaded_file import DownloadedFile
from modules.flowalerts.notice import Notice
from modules.flowalerts.smtp import SMTP
from modules.flowalerts.software import Software
from modules.flowalerts.ssh import SSH
from modules.flowalerts.ssl import SSL
from modules.flowalerts.tunnel import Tunnel
from modules.p2ptrust.utils.go_director import GoDirector
from slips.main import Main
from modules.update_manager.update_manager import UpdateManager
from modules.leak_detector.leak_detector import LeakDetector
from slips_files.core.database.database_manager import DBManager
from slips_files.core.profiler import Profiler
from slips_files.core.output import Output
from modules.threat_intelligence.threat_intelligence import ThreatIntel
from modules.threat_intelligence.urlhaus import URLhaus
from modules.flowalerts.flowalerts import FlowAlerts
from modules.flowalerts.set_evidence import SetEvidnceHelper
from slips_files.core.input import Input
from modules.blocking.blocking import Blocking
from modules.http_analyzer.http_analyzer import HTTPAnalyzer
from modules.ip_info.ip_info import IPInfo
from slips_files.common.slips_utils import utils
from slips_files.core.helpers.whitelist.whitelist import Whitelist
from tests.common_test_utils import do_nothing
from modules.virustotal.virustotal import VT
from managers.process_manager import ProcessManager
from managers.redis_manager import RedisManager
from modules.ip_info.asn_info import ASN
from multiprocessing import Queue, Event, Semaphore
from slips_files.core.helpers.flow_handler import FlowHandler
from slips_files.core.helpers.symbols_handler import SymbolHandler
from modules.network_discovery.horizontal_portscan import HorizontalPortscan
from modules.network_discovery.network_discovery import NetworkDiscovery
from modules.network_discovery.vertical_portscan import VerticalPortscan
from modules.arp.arp import ARP


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


class ModuleFactory:
    def __init__(self):
        # same db as in conftest
        self.profiler_queue = Queue()
        self.input_queue = Queue()
        self.dummy_termination_event = Event()
        self.logger = Mock()  # Output()

    def get_default_db(self):
        """default is o port 6379, this is the one we're using in conftest"""
        return self.create_db_manager_obj(6379)

    def create_db_manager_obj(
        self, port, output_dir="output/", flush_db=False
    ):
        # to prevent config/redis.conf from being overwritten
        with patch(
            "slips_files.core.database.redis_db.database.RedisDB._set_redis_options",
            return_value=Mock(),
        ):
            db = DBManager(self.logger, output_dir, port, flush_db=flush_db)
        db.r = db.rdb.r
        db.print = do_nothing
        assert db.get_used_redis_port() == port
        return db

    def create_main_obj(self, input_information):
        """returns an instance of Main() class in slips.py"""
        main = Main(testing=True)
        main.input_information = input_information
        main.input_type = "pcap"
        main.line_type = False
        return main

    def create_http_analyzer_obj(self, mock_db):
        with patch.object(DBManager, "create_sqlite_db", return_value=Mock()):
            http_analyzer = HTTPAnalyzer(
                self.logger,
                "dummy_output_dir",
                6379,
                self.dummy_termination_event,
            )
            http_analyzer.db.rdb = mock_db

        # override the self.print function to avoid broken pipes
        http_analyzer.print = do_nothing
        return http_analyzer

    def create_virustotal_obj(self, mock_db):
        with patch.object(DBManager, "create_sqlite_db", return_value=Mock()):
            virustotal = VT(
                self.logger,
                "dummy_output_dir",
                6379,
                self.dummy_termination_event,
            )
            virustotal.db.rdb = mock_db

        # override the self.print function to avoid broken pipes
        virustotal.print = do_nothing
        virustotal.__read_configuration = read_configuration
        virustotal.key_file = (
            "/media/alya/W/SLIPPS/modules/virustotal/api_key_secret"
        )
        return virustotal

    def create_arp_obj(self, mock_db):
        with patch.object(DBManager, "create_sqlite_db", return_value=Mock()):
            arp = ARP(
                self.logger,
                "dummy_output_dir",
                6379,
                self.dummy_termination_event,
            )
            arp.db.rdb = mock_db
        # override the self.print function to avoid broken pipes
        arp.print = do_nothing
        return arp

    def create_blocking_obj(self, mock_db):
        with patch.object(DBManager, "create_sqlite_db", return_value=Mock()):
            blocking = Blocking(
                self.logger,
                "dummy_output_dir",
                6379,
                self.dummy_termination_event,
            )
            blocking.db.rdb = mock_db

        # override the print function to avoid broken pipes
        blocking.print = do_nothing
        return blocking

    def create_flowalerts_obj(self, mock_db):
        with patch.object(DBManager, "create_sqlite_db", return_value=Mock()):
            flowalerts = FlowAlerts(
                self.logger,
                "dummy_output_dir",
                6379,
                self.dummy_termination_event,
            )
            flowalerts.db.rdb = mock_db

        # override the self.print function to avoid broken pipes
        flowalerts.print = do_nothing
        return flowalerts

    def create_dns_analyzer_obj(self, mock_db):
        flowalerts = self.create_flowalerts_obj(mock_db)
        return DNS(flowalerts.db, flowalerts=flowalerts)

    def create_notice_analyzer_obj(self, mock_db):
        flowalerts = self.create_flowalerts_obj(mock_db)
        return Notice(flowalerts.db, flowalerts=flowalerts)

    def create_smtp_analyzer_obj(self, mock_db):
        flowalerts = self.create_flowalerts_obj(mock_db)
        return SMTP(flowalerts.db, flowalerts=flowalerts)

    def create_ssl_analyzer_obj(self, mock_db):
        flowalerts = self.create_flowalerts_obj(mock_db)
        return SSL(flowalerts.db, flowalerts=flowalerts)

    def create_ssh_analyzer_obj(self, mock_db):
        flowalerts = self.create_flowalerts_obj(mock_db)
        return SSH(flowalerts.db, flowalerts=flowalerts)

    def create_downloaded_file_analyzer_obj(self, mock_db):
        flowalerts = self.create_flowalerts_obj(mock_db)
        return DownloadedFile(flowalerts.db, flowalerts=flowalerts)

    def create_tunnel_analyzer_obj(self, mock_db):
        flowalerts = self.create_flowalerts_obj(mock_db)
        return Tunnel(flowalerts.db, flowalerts=flowalerts)

    def create_conn_analyzer_obj(self, mock_db):
        flowalerts = self.create_flowalerts_obj(mock_db)
        return Conn(flowalerts.db, flowalerts=flowalerts)

    def create_software_analyzer_obj(self, mock_db):
        flowalerts = self.create_flowalerts_obj(mock_db)
        return Software(flowalerts.db, flowalerts=flowalerts)

    def create_input_obj(
        self, input_information, input_type, mock_db, line_type=False
    ):
        zeek_tmp_dir = os.path.join(os.getcwd(), "zeek_dir_for_testing")
        dummy_semaphore = Semaphore(0)
        with patch.object(DBManager, "create_sqlite_db", return_value=Mock()):
            input = Input(
                Output(),
                "dummy_output_dir",
                6379,
                self.dummy_termination_event,
                is_input_done=dummy_semaphore,
                profiler_queue=self.profiler_queue,
                input_type=input_type,
                input_information=input_information,
                cli_packet_filter=None,
                zeek_or_bro=check_zeek_or_bro(),
                zeek_dir=zeek_tmp_dir,
                line_type=line_type,
                is_profiler_done_event=self.dummy_termination_event,
            )
        input.db.rdb = mock_db
        input.is_done_processing = do_nothing
        input.bro_timeout = 1
        # override the print function to avoid broken pipes
        input.print = do_nothing
        input.stop_queues = do_nothing
        input.testing = True

        return input

    def create_ip_info_obj(self, mock_db):
        with patch.object(DBManager, "create_sqlite_db", return_value=Mock()):
            ip_info = IPInfo(
                self.logger,
                "dummy_output_dir",
                6379,
                self.dummy_termination_event,
            )
            ip_info.db.rdb = mock_db
        # override the self.print function to avoid broken pipes
        ip_info.print = do_nothing
        return ip_info

    def create_asn_obj(self, mock_db):
        return ASN(mock_db)

    def create_leak_detector_obj(self, mock_db):
        # this file will be used for storing the module output
        # and deleted when the tests are done
        test_pcap = "dataset/test7-malicious.pcap"
        yara_rules_path = "tests/yara_rules_for_testing/rules/"
        compiled_yara_rules_path = "tests/yara_rules_for_testing/compiled/"
        with patch.object(DBManager, "create_sqlite_db", return_value=Mock()):
            leak_detector = LeakDetector(
                self.logger,
                "dummy_output_dir",
                6379,
                self.dummy_termination_event,
            )
            leak_detector.db.rdb = mock_db
        # override the self.print function to avoid broken pipes
        leak_detector.print = do_nothing
        # this is the path containing 1 yara rule for testing, it matches every pcap
        leak_detector.yara_rules_path = yara_rules_path
        leak_detector.compiled_yara_rules_path = compiled_yara_rules_path
        leak_detector.pcap = test_pcap
        return leak_detector

    def create_profiler_obj(self, mock_db):
        dummy_semaphore = Semaphore(0)
        profiler = Profiler(
            self.logger,
            "output/",
            6379,
            self.dummy_termination_event,
            is_profiler_done=dummy_semaphore,
            profiler_queue=self.input_queue,
            is_profiler_done_event=self.dummy_termination_event,
        )

        # override the self.print function to avoid broken pipes
        profiler.print = do_nothing
        profiler.whitelist_path = "tests/test_whitelist.conf"
        profiler.db = mock_db
        return profiler

    def create_redis_manager_obj(self, main):
        return RedisManager(main)

    def create_process_manager_obj(self):
        return ProcessManager(self.create_main_obj(""))

    def create_utils_obj(self):
        return utils

    def create_threatintel_obj(self, mock_db):
        with patch.object(DBManager, "create_sqlite_db", return_value=Mock()):
            threatintel = ThreatIntel(
                self.logger,
                "dummy_output_dir",
                6379,
                self.dummy_termination_event,
            )
            threatintel.db = mock_db

        # override the self.print function to avoid broken pipes
        threatintel.print = do_nothing
        return threatintel

    def create_update_manager_obj(self, mock_db):
        with patch.object(DBManager, "create_sqlite_db", return_value=Mock()):
            update_manager = UpdateManager(
                self.logger,
                "dummy_output_dir",
                6379,
                self.dummy_termination_event,
            )

            update_manager.db.rdb = mock_db

        # override the self.print function to avoid broken pipes
        update_manager.print = do_nothing
        return update_manager

    def create_whitelist_obj(self, mock_db):
        with patch.object(DBManager, "create_sqlite_db", return_value=Mock()):
            whitelist = Whitelist(self.logger, mock_db)
            whitelist.db.rdb = mock_db

        # override the self.print function to avoid broken pipes
        whitelist.print = do_nothing
        whitelist.whitelist_path = "tests/test_whitelist.conf"
        return whitelist

    def create_flow_handler_obj(self, flow, mock_db):
        with patch.object(DBManager, "create_sqlite_db", return_value=Mock()):
            symbol = SymbolHandler(self.logger, mock_db)
            flow_handler = FlowHandler(mock_db, symbol, flow)
            return flow_handler

    def create_horizontal_portscan_obj(self, mock_db):
        with patch.object(DBManager, "create_sqlite_db", return_value=Mock()):
            horizontal_ps = HorizontalPortscan(mock_db)
            return horizontal_ps

    def create_vertical_portscan_obj(self, mock_db):
        with patch.object(DBManager, "create_sqlite_db", return_value=Mock()):
            vertical_ps = VerticalPortscan(mock_db)
            return vertical_ps

    def create_urlhaus_obj(self, mock_db):
        """Create an instance of URLhaus."""
        urlhaus = URLhaus(mock_db)
        return urlhaus

    def create_set_evidence_helper(self, mock_db):
        """Create an instance of SetEvidenceHelper."""
        set_evidence_helper = SetEvidnceHelper(mock_db)
        return set_evidence_helper

    def create_network_discovery_obj(self, mock_db):
        with patch('modules.network_discovery.network_discovery.NetworkDiscovery.__init__', return_value=None):
            network_discovery = NetworkDiscovery(mock_db)
            network_discovery.db = mock_db 
        return network_discovery

    def create_go_director_obj(self, mock_db):
        with patch('modules.p2ptrust.utils.utils.send_evaluation_to_go'):
            go_director = GoDirector(
                logger=self.logger,
                trustdb=Mock(spec=TrustDB),
                db=mock_db,
                storage_name="test_storage",
                override_p2p=False,
                gopy_channel="test_gopy",
                pygo_channel="test_pygo",
                p2p_reports_logfile="test_reports.log"
            )
            go_director.print = Mock()  
        return go_director
