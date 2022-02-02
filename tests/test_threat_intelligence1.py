""" Unit test for modules/ThreatIntelligence1/threat_intelligence1_module.py """
from ..modules.ThreatIntelligence1.threat_intelligence1_module import Module
import configparser

def do_nothing(*args):
    """ Used to override the print function because using the self.print causes broken pipes """
    pass

def create_threatintel_instance(outputQueue):
    """ Create an instance of threatintel.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    threatintel = Module(outputQueue, config)
    # override the self.print function to avoid broken pipes
    threatintel.print = do_nothing
    return threatintel

def test_load_malicious_datafile(outputQueue):
    threatintel = create_threatintel_instance(outputQueue)
    # get local data dir
    dir_ = threatintel.path_to_local_threat_intelligence_data
    # get the first local threat intel file in local_data_files
    import os
    filename = os.listdir('modules/ThreatIntelligence1/local_data_files')[0]
    assert threatintel.parse_ti_file(dir_ + filename) == True

def test_load_malicious_local_files(outputQueue):
    threatintel = create_threatintel_instance(outputQueue)
    dir_ = threatintel.path_to_local_threat_intelligence_data
    assert threatintel.check_local_ti_files(dir_) == True

