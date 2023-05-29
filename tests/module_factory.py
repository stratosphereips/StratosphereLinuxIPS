from modules.update_manager.update_file_manager import UpdateFileManager
import modules.leak_detector.leak_detector as leak_detector_module
from slips_files.core.profilerProcess import ProfilerProcess
import modules.threat_intelligence.threat_intelligence as ti
import modules.flowalerts.flowalerts as flowalerts_module
from slips_files.core.inputProcess import InputProcess
import modules.blocking.blocking as blocking_module
import modules.http_analyzer.http_analyzer as http
from slips_files.common.slips_utils import utils
from slips_files.core.whitelist import Whitelist
from tests.common_test_utils import do_nothing
import modules.virustotal.virustotal as vt
from process_manager import ProcessManager
from redis_manager import RedisManager
import modules.ip_info.ip_info as ip_info
import modules.ip_info.asn_info as asn
import modules.arp.arp as arp
from slips import Main
import shutil
import os


def read_configuration():
    return
def check_zeek_or_bro():
    """
    Check if we have zeek or bro
    """
    zeek_bro = None
    if shutil.which('zeek'):
        zeek_bro = 'zeek'
    elif shutil.which('bro'):
        zeek_bro = 'bro'
    else:
        return False

    return zeek_bro

class ModuleFactory:
    def __init__(self):
        # used to create a different port for inputproc tests
        self.redis_port = 6531

    def create_main_obj(self, input_information):
        """returns an instance of Main() class in slips.py"""
        main = Main(testing=True)
        main.input_information = input_information
        main.input_type = 'pcap'
        main.line_type = False
        return main


    def create_http_analyzer_obj(self, output_queue):
        http_analyzer = http.Module(output_queue)
        # override the self.print function to avoid broken pipes
        http_analyzer.print = do_nothing
        return http_analyzer

    def create_virustotal_obj(self, output_queue):
        virustotal = vt.Module(output_queue)
        # override the self.print function to avoid broken pipes
        virustotal.print = do_nothing
        virustotal.__read_configuration = read_configuration
        virustotal.key_file = (
            '/media/alya/W/SLIPPS/modules/virustotal/api_key_secret'
        )
        return virustotal

    def create_ARP_obj(self, output_queue):
        ARP = arp.Module(output_queue)
        # override the self.print function to avoid broken pipes
        ARP.print = do_nothing
        return ARP
    @classmethod
    def create_blocking_obj( output_queue):
        blocking = blocking_module.Module(output_queue)
        # override the print function to avoid broken pipes
        blocking.print = do_nothing
        return blocking

    def create_flowalerts_obj(output_queue):
        flowalerts = flowalerts_module.Module(output_queue)
        # override the self.print function to avoid broken pipes
        flowalerts.print = do_nothing
        return flowalerts
    def create_inputProcess_obj(
        self, output_queue, profiler_queue, input_information, input_type
    ):
        self.redis_port +=1

        zeek_tmp_dir = os.path.join(os.getcwd(), 'zeek_dir_for_testing' )

        inputProcess = InputProcess(
            output_queue,
            profiler_queue,
            input_type,
            input_information,
            None,
            check_zeek_or_bro(),
            zeek_tmp_dir,
            False,
        )

        inputProcess.bro_timeout = 1
        # override the print function to avoid broken pipes
        inputProcess.print = do_nothing
        inputProcess.stop_queues = do_nothing
        inputProcess.testing = True

        return inputProcess


    def create_ip_info_obj(output_queue):
        # override the self.print function to avoid broken pipes
        ip_info.print = do_nothing
        return ip_info

    def create_ASN_Info_obj(self):
        return asn.ASN()

    @staticmethod
    def create_leak_detector_obj(output_queue):
        # this file will be used for storing the module output
        # and deleted when the tests are done
        test_pcap = 'dataset/test7-malicious.pcap'
        yara_rules_path = 'tests/yara_rules_for_testing/rules/'
        compiled_yara_rules_path = 'tests/yara_rules_for_testing/compiled/'
        compiled_test_rule = f'{compiled_yara_rules_path}test_rule.yara_compiled'
        leak_detector = leak_detector_module.Module(output_queue)
        # override the self.print function to avoid broken pipes
        leak_detector.print = do_nothing
        # this is the path containing 1 yara rule for testing, it matches every pcap
        leak_detector.yara_rules_path = yara_rules_path
        leak_detector.compiled_yara_rules_path = compiled_yara_rules_path
        leak_detector.pcap = test_pcap
        return leak_detector


    @staticmethod
    def create_profilerProcess_obj(self, output_queue, input_queue):

        profilerProcess = ProfilerProcess(
            input_queue,
            output_queue,
            1, 0,
        )

        # override the self.print function to avoid broken pipes
        profilerProcess.print = do_nothing
        profilerProcess.whitelist_path = 'tests/test_whitelist.conf'
        return profilerProcess

    @staticmethod
    def create_redis_manager_obj(main):
        return RedisManager(main)

    def create_process_manager_obj(self):
        return ProcessManager(self.create_main_obj(''))

    @staticmethod
    def create_utils_obj():
        return utils

    @staticmethod
    def create_threatintel_obj(output_queue):
        threatintel = ti.Module(output_queue)
        # override the self.print function to avoid broken pipes
        threatintel.print = do_nothing
        return threatintel

    @staticmethod
    def create_update_manager_obj(output_queue):
        update_manager = UpdateFileManager(output_queue)
        # override the self.print function to avoid broken pipes
        update_manager.print = do_nothing
        return update_manager

    @staticmethod
    def create_whitelist_obj(output_queue):
        whitelist = Whitelist(output_queue)
        # override the self.print function to avoid broken pipes
        whitelist.print = do_nothing
        whitelist.whitelist_path = 'tests/test_whitelist.conf'
        return whitelist

