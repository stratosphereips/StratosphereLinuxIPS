""" Unit test for modules/leak_detector/leak_detector.py """
import os

from ..modules.leak_detector.leak_detector import Module
import configparser


def do_nothing(*args):
    """ Used to override the print function because using the self.print causes broken pipes """
    pass

def create_leak_detector_instance(outputQueue):
    """ Create an instance of leak_detector.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    leak_detector = Module(outputQueue, config)
    # override the self.print function to avoid broken pipes
    leak_detector.print = do_nothing
    # this is the path containing 1 yara rule for testing, it matches every pcap
    leak_detector.yara_rules_path = 'tests/yara_rules_for_testing/'
    leak_detector.compiled_yara_rules_path = 'tests/yara_rules_for_testing/'
    leak_detector.pcap = 'dataset/hide-and-seek-short.pcap'
    # this file will be deleted when the tests are done
    leak_detector.output_file = 'test_leak_detector_output.txt'
    return leak_detector

def test_compile_and_save_rules(outputQueue):
    leak_detector = create_leak_detector_instance(outputQueue)
    leak_detector.compile_and_save_rules()
    assert 'test_rule.yara_compiled' in os.listdir('tests/yara_rules_for_testing/')
    # delete teh compiled file so it doesn't affect further unit tests
    os.remove('tests/yara_rules_for_testing/test_rule.yara_compiled')


