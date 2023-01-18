"""Unit test for modules/threat_intelligence/threat_intelligence.py"""
from ..modules.threat_intelligence.threat_intelligence import Module
from ..slips_files.common.slips_utils import utils
import configparser
import os


def do_nothing(*args):
    """Used to override the print function because using the self.print causes broken pipes"""
    pass


def create_threatintel_instance(outputQueue):
    """Create an instance of threatintel.py
    needed by every other test in this file"""
    threatintel = Module(outputQueue, 1234)
    # override the self.print function to avoid broken pipes
    threatintel.print = do_nothing
    return threatintel


def test_parse_ti_file(database, outputQueue):
    threatintel = create_threatintel_instance(outputQueue)
    local_ti_files_dir = threatintel.path_to_local_ti_files
    local_ti_file = os.path.join(local_ti_files_dir, 'own_malicious_iocs.csv')
    # this is an ip we know we have in own_maicious_iocs.csv
    assert threatintel.parse_local_ti_file(local_ti_file) == True
    assert database.search_IP_in_IoC('54.192.46.116')


def test_check_local_ti_files_for_update(outputQueue):
    threatintel = create_threatintel_instance(outputQueue)
    dir_ = threatintel.path_to_local_ti_files
    assert threatintel.check_local_ti_files_for_update(dir_) == True
