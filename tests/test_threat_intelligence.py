"""Unit test for modules/threat_intelligence/threat_intelligence.py"""
from ..modules.threat_intelligence.threat_intelligence import Module
import configparser
import os


def do_nothing(*args):
    """Used to override the print function because using the self.print causes broken pipes"""
    pass


def create_threatintel_instance(outputQueue):
    """Create an instance of threatintel.py
    needed by every other test in this file"""
    config = configparser.ConfigParser()
    threatintel = Module(outputQueue, config, 6380)
    # override the self.print function to avoid broken pipes
    threatintel.print = do_nothing
    return threatintel


def test_parse_ti_file(outputQueue):
    threatintel = create_threatintel_instance(outputQueue)
    # get local data dir
    dir_ = threatintel.path_to_local_threat_intelligence_data
    # get the first local threat intel file in local_data_files
    filename = os.listdir('modules/threat_intelligence/local_data_files')[0]
    assert threatintel.parse_local_ti_file(dir_ + filename) == True


def test_check_local_ti_files(outputQueue):
    threatintel = create_threatintel_instance(outputQueue)
    dir_ = threatintel.path_to_local_threat_intelligence_data
    assert threatintel.check_local_ti_files_for_update(dir_) == True
