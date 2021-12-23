""" Unit test for modules/leak_detector/leak_detector.py """
import os

from ..modules.leak_detector.leak_detector import Module
import configparser


def do_nothing(*args):
    """ Used to override the print function because using the self.print causes broken pipes """
    pass

# this file will be used for storing the module output
# and deleted when the tests are done
test_pcap =  'dataset/hide-and-seek-short.pcap'
yara_rules_path = 'tests/yara_rules_for_testing/rules/'
compiled_yara_rules_path = 'tests/yara_rules_for_testing/compiled/'
compiled_test_rule = compiled_yara_rules_path + 'test_rule.yara_compiled'

def create_leak_detector_instance(outputQueue):
    """ Create an instance of leak_detector.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    leak_detector = Module(outputQueue, config)
    # override the self.print function to avoid broken pipes
    leak_detector.print = do_nothing
    # this is the path containing 1 yara rule for testing, it matches every pcap
    leak_detector.yara_rules_path = yara_rules_path
    leak_detector.compiled_yara_rules_path = compiled_yara_rules_path
    leak_detector.pcap = test_pcap
    return leak_detector

def test_compile_and_save_rules(outputQueue):
    leak_detector = create_leak_detector_instance(outputQueue)
    leak_detector.compile_and_save_rules()
    compiled_rules = os.listdir(compiled_yara_rules_path)
    assert 'test_rule.yara_compiled' in compiled_rules
    # delete teh compiled file so it doesn't affect further unit tests
    os.remove(compiled_test_rule)




