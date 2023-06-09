"""
This file tests 2 different config files other than slips' default config/slips.conf
test/test.conf and tests/test2.conf
"""
from tests.common_test_utils import (
        is_evidence_present,
        create_output_dir,
        has_errors,
        check_for_text,
)
from tests.module_factory import ModuleFactory
import pytest
from ...slips import *
import shutil


alerts_file = 'alerts.log'

def create_Main_instance(input_information):
    """returns an instance of Main() class in slips.py"""
    main = Main(testing=True)
    main.input_information = input_information
    main.input_type = 'pcap'
    main.line_type = False
    return main


@pytest.mark.parametrize(
    'pcap_path, expected_profiles, output_dir, redis_port',
    [
        (
            'dataset/test7-malicious.pcap',
            290,
            'test_configuration_file/',
            6667,
        )
    ],
)
def test_conf_file(
    pcap_path, expected_profiles, output_dir, redis_port, output_queue
):
    """
    In this test we're using tests/test.conf
    """
    output_dir = create_output_dir(output_dir)
    output_dir = create_output_dir(output_dir)

    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py ' \
              f'-t ' \
              f'-f {pcap_path} ' \
              f'-o {output_dir} ' \
              f'-c tests/integration_tests/test.conf  ' \
              f'-P {redis_port} ' \
              f'> {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)

    assert has_errors(output_dir) is False

    database = ModuleFactory().create_db_manager_obj(redis_port, output_dir=output_dir)
    profiles = database.get_profiles_len()
    # expected_profiles is more than 50 because we're using direction = all
    assert profiles > expected_profiles

    log_file = os.path.join(output_dir, alerts_file)

    # testing disabled_detections param in the configuration file
    disabled_evidence = 'a connection without DNS resolution'
    assert is_evidence_present(log_file, disabled_evidence) is False

    # testing time_window_width param in the configuration file
    assert check_for_text('in the last 115740 days', output_dir) is True

    # test delete_zeek_files param
    zeek_output_dir = database.get_zeek_output_dir()[2:]
    assert zeek_output_dir not in os.listdir()

    # test store_a_copy_of_zeek_files
    assert 'zeek_files' in os.listdir(output_dir)

    # test metadata_dir
    assert 'metadata' in os.listdir(output_dir)
    metadata_path = os.path.join(output_dir, 'metadata')
    for file in ('test.conf', 'whitelist.conf', 'info.txt'):
        assert file in os.listdir(metadata_path)

    # test label=malicious
    assert int(database.get_label_count('malicious')) > 370

    # test disable
    for module in ['template' , 'ensembling', 'Flow ML Detection']:
        assert module in database.get_disabled_modules()

    shutil.rmtree(output_dir)


@pytest.mark.parametrize(
    'pcap_path, expected_profiles, output_dir, redis_port',
    [
        (
            'dataset/test8-malicious.pcap',
            1,
            'pcap_test_conf2/',
            6668,
        )
    ],
)
def test_conf_file2(
    pcap_path, expected_profiles, output_dir, redis_port, output_queue
):
    """
    In this test we're using tests/test2.conf
    """

    output_dir = create_output_dir(output_dir)
    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py ' \
              f'-t ' \
              f'-f {pcap_path} ' \
              f'-o {output_dir} ' \
              f'-c tests/integration_tests/test2.conf ' \
              f'-P {redis_port} ' \
              f'> {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)

    assert has_errors(output_dir) is False

    database = ModuleFactory().create_db_manager_obj(redis_port, output_dir=output_dir)

    # test 1 homenet ip
    # the only profile we should have is the one in home_network parameter
    profiles = database.get_profiles_len()
    assert profiles == expected_profiles

    shutil.rmtree(output_dir)



