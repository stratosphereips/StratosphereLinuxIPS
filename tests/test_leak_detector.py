"""Unit test for modules/leak_detector/leak_detector.py"""
from tests.module_factory import ModuleFactory
import os


def test_compile_and_save_rules(mock_rdb):
    leak_detector = ModuleFactory().create_leak_detector_obj(mock_rdb)
    leak_detector.compile_and_save_rules()
    compiled_rules = os.listdir(leak_detector.compiled_yara_rules_path)
    assert 'test_rule.yara_compiled' in compiled_rules
    # delete the compiled file so it doesn't affect further unit tests
    compiled_test_rule = os.path.join(
        leak_detector.compiled_yara_rules_path,
        'test_rule.yara_compiled'
        )
    os.remove(compiled_test_rule)
