import multiprocessing

from slips import Main
from modules.update_manager.update_manager import UpdateManager
from modules.leak_detector.leak_detector import LeakDetector
from slips_files.core.database.database_manager import DBManager
from slips_files.core.profilerProcess import ProfilerProcess
from modules.threat_intelligence.threat_intelligence import ThreatIntel
from modules.flowalerts.flowalerts import FlowAlerts
from slips_files.core.inputProcess import InputProcess
from modules.blocking.blocking import Blocking
from modules.http_analyzer.http_analyzer import HTTPAnalyzer
from modules.ip_info.ip_info import IPInfo
from slips_files.common.slips_utils import utils
from slips_files.core.helpers.whitelist import Whitelist
from tests.common_test_utils import do_nothing
from modules.virustotal.virustotal import VT
from process_manager import ProcessManager
from redis_manager import RedisManager
from modules.ip_info.asn_info import ASN
from multiprocessing import Queue, Event
from modules.arp.arp import ARP
import shutil
from unittest.mock import patch, Mock, MagicMock
import os



def read_configuration():
    return

def check_zeek_or_bro():
    """
    Check if we have zeek or bro
    """
    if shutil.which('zeek'):
        return 'zeek'
    if shutil.which('bro'):
        return 'bro'
    return False

class ModuleFactory:
    def __init__(self):
        # same db as in conftest
        self.output_queue = Queue()
        self.profiler_queue = Queue()
        self.input_queue = Queue()
        self.dummy_termination_event = Event()


    def get_default_db(self):
        """default is o port 6379, this is the one we're using in conftest"""
        return self.create_db_manager_obj(6379)

    def create_db_manager_obj(self, port, output_dir='output/', flush_db=False):
        db = DBManager(output_dir, self.output_queue, port, flush_db=flush_db)
        db.r = db.rdb.r
        db.print = do_nothing
        assert db.get_used_redis_port() == port
        return db


    def create_main_obj(self, input_information):
        """returns an instance of Main() class in slips.py"""
        main = Main(testing=True)
        main.input_information = input_information
        main.input_type = 'pcap'
        main.line_type = False
        return main


    def create_http_analyzer_obj(self, mock_rdb):
        with patch.object(DBManager, 'create_sqlite_db', return_value=Mock()):
            http_analyzer = HTTPAnalyzer(self.output_queue, 'dummy_output_dir', 6379, self.dummy_termination_event)
            http_analyzer.db.rdb = mock_rdb

        # override the self.print function to avoid broken pipes
        http_analyzer.print = do_nothing
        return http_analyzer

    def create_virustotal_obj(self, mock_rdb):
        with patch.object(DBManager, 'create_sqlite_db', return_value=Mock()):
            virustotal = VT(self.output_queue, 'dummy_output_dir', 6379, self.dummy_termination_event)
            virustotal.db.rdb = mock_rdb

        # override the self.print function to avoid broken pipes
        virustotal.print = do_nothing
        virustotal.__read_configuration = read_configuration
        virustotal.key_file = (
            '/media/alya/W/SLIPPS/modules/virustotal/api_key_secret'
        )
        return virustotal

    def create_arp_obj(self, mock_rdb):
        with patch.object(DBManager, 'create_sqlite_db', return_value=Mock()):
            arp = ARP(self.output_queue, 'dummy_output_dir', 6379, self.dummy_termination_event)
            arp.db.rdb = mock_rdb
        # override the self.print function to avoid broken pipes
        arp.print = do_nothing
        return arp

    def create_blocking_obj(self, mock_rdb):
        with patch.object(DBManager, 'create_sqlite_db', return_value=Mock()):
            blocking = Blocking(self.output_queue, 'dummy_output_dir', 6379, self.dummy_termination_event)
            blocking.db.rdb = mock_rdb

        # override the print function to avoid broken pipes
        blocking.print = do_nothing
        return blocking

    def create_flowalerts_obj(self, mock_rdb):
        with patch.object(DBManager, 'create_sqlite_db', return_value=Mock()):
            flowalerts = FlowAlerts(self.output_queue, 'dummy_output_dir', 6379, self.dummy_termination_event)
            flowalerts.db.rdb = mock_rdb

        # override the self.print function to avoid broken pipes
        flowalerts.print = do_nothing
        return flowalerts

    def create_inputProcess_obj(
            self, input_information, input_type, mock_rdb
            ):

        zeek_tmp_dir = os.path.join(os.getcwd(), 'zeek_dir_for_testing' )
        with patch.object(DBManager, 'create_sqlite_db', return_value=Mock()):
            inputProcess = InputProcess(
                self.output_queue,
                'dummy_output_dir', 6379,
                # 'output/',
                self.dummy_termination_event,
                profiler_queue=self.profiler_queue,
                input_type=input_type,
                input_information=input_information,
                cli_packet_filter= None,
                zeek_or_bro=check_zeek_or_bro(),
                zeek_dir=zeek_tmp_dir,
                line_type=False,
            )
            inputProcess.db.rdb = mock_rdb

        inputProcess.bro_timeout = 1
        # override the print function to avoid broken pipes
        inputProcess.print = do_nothing
        inputProcess.stop_queues = do_nothing
        inputProcess.testing = True

        return inputProcess


    def create_ip_info_obj(self, mock_rdb):
        with patch.object(DBManager, 'create_sqlite_db', return_value=Mock()):
            ip_info = IPInfo(self.output_queue, 'dummy_output_dir', 6379, self.dummy_termination_event)
            ip_info.db.rdb = mock_rdb
        # override the self.print function to avoid broken pipes
        ip_info.print = do_nothing
        return ip_info

    def create_asn_obj(self, db):
        return ASN(db)

    def create_leak_detector_obj(self, mock_rdb):
        # this file will be used for storing the module output
        # and deleted when the tests are done
        test_pcap = 'dataset/test7-malicious.pcap'
        yara_rules_path = 'tests/yara_rules_for_testing/rules/'
        compiled_yara_rules_path = 'tests/yara_rules_for_testing/compiled/'
        with patch.object(DBManager, 'create_sqlite_db', return_value=Mock()):
            leak_detector = LeakDetector(self.output_queue, 'dummy_output_dir', 6379, self.dummy_termination_event)
            leak_detector.db.rdb = mock_rdb
        # override the self.print function to avoid broken pipes
        leak_detector.print = do_nothing
        # this is the path containing 1 yara rule for testing, it matches every pcap
        leak_detector.yara_rules_path = yara_rules_path
        leak_detector.compiled_yara_rules_path = compiled_yara_rules_path
        leak_detector.pcap = test_pcap
        return leak_detector


    def create_profilerProcess_obj(self):
        profilerProcess = ProfilerProcess(
            self.output_queue,
            'output/', 6377,
            self.dummy_termination_event,
            profiler_queue=self.input_queue,
        )

        # override the self.print function to avoid broken pipes
        profilerProcess.print = do_nothing
        profilerProcess.whitelist_path = 'tests/test_whitelist.conf'
        return profilerProcess

    def create_redis_manager_obj(self, main):
        return RedisManager(main)

    def create_process_manager_obj(self):
        return ProcessManager(self.create_main_obj(''))

    def create_utils_obj(self):
        return utils

    def create_threatintel_obj(self, mock_rdb):
        with patch.object(DBManager, 'create_sqlite_db', return_value=Mock()):
            threatintel = ThreatIntel(self.output_queue, 'dummy_output_dir', 6379, self.dummy_termination_event)
            threatintel.db.rdb = mock_rdb

        # override the self.print function to avoid broken pipes
        threatintel.print = do_nothing
        return threatintel

    def create_update_manager_obj(self, mock_rdb):
        with patch.object(DBManager, 'create_sqlite_db', return_value=Mock()):
            update_manager = UpdateManager(self.output_queue, 'dummy_output_dir', 6379, self.dummy_termination_event)
            update_manager.db.rdb = mock_rdb

        # override the self.print function to avoid broken pipes
        update_manager.print = do_nothing
        return update_manager

    def create_whitelist_obj(self, mock_rdb):
        with patch.object(DBManager, 'create_sqlite_db', return_value=Mock()):
            whitelist = Whitelist(self.output_queue, mock_rdb)
            whitelist.db.rdb = mock_rdb

        # override the self.print function to avoid broken pipes
        whitelist.print = do_nothing
        whitelist.whitelist_path = 'tests/test_whitelist.conf'
        return whitelist

