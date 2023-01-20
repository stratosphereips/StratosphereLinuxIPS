"""
This file tests 2 different config files other than slips' default config/slips.conf
test/test.conf and tests/test2.conf
"""
import os
import pytest
from ...slips import *
from pathlib import Path
import shutil

alerts_file = 'alerts.log'


def connect_to_redis(redis_port):
    from slips_files.core.database.database import __database__

    __database__.connect_to_redis_server(redis_port)
    return __database__


def is_evidence_present(log_file, expected_evidence):
    """Function to read the log file line by line and returns when it finds the expected evidence"""
    with open(log_file, 'r') as f:
        line = f.readline()
        while line:
            if expected_evidence in line:
                return True
            line = f.readline()
        # evidence not found in any line
        return False

def create_output_dir(dirname):
    """
    creates this output dir inside output/integration_tests/
    returns a full path to the created output dir
    """

    path = Path(os.path.join('output/integration_tests/', dirname))
    # clear output dir before running the test
    if os.path.exists(path):
        shutil.rmtree(path)

    path.mkdir(parents=True, exist_ok=True)

    return path

def has_errors(output_dir):
    """function to parse slips_output file and check for errors"""
    error_files = ('slips_output.txt', 'errors.log')
    error_files = [os.path.join(output_dir, file) for file in error_files]

    # we can't redirect stderr to a file and check it because we catch all exceptions in slips
    for file in error_files:
        with open(file, 'r') as f:
            for line in f:
                if '<class' in line or 'error' in line:
                    # connection errors shouldn't fail the integration tests
                    if 'Connection error' in line or 'while downloading' in line:
                        continue
                    return True

    return False


def create_Main_instance(input_information):
    """returns an instance of Main() class in slips.py"""
    main = Main(testing=True)
    main.input_information = input_information
    main.input_type = 'pcap'
    main.line_type = False
    return main

def check_for_text(txt, output_dir):
    """function to parse slips_output file and check for a given string"""
    slips_output = os.path.join(output_dir, 'slips_output.txt')
    with open(slips_output, 'r') as f:
        for line in f:
            if txt in line:
                return True
    return False

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
    pcap_path, expected_profiles, output_dir, redis_port
):
    """
    In this test we're using tests/test.conf
    """
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

    assert has_errors(output_dir) == False

    database = connect_to_redis(redis_port)
    profiles = int(database.getProfilesLen())
    # expected_profiles is more than 50 because we're using direction = all
    assert profiles > expected_profiles

    log_file = os.path.join(output_dir, alerts_file)

    # testing disabled_detections param in the configuration file
    disabled_evidence = 'a connection without DNS resolution'
    assert is_evidence_present(log_file, disabled_evidence) == False

    # testing time_window_width param in the configuration file
    assert check_for_text('in the last 115740 days', output_dir) == True

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
    assert int(database.get_label_count('malicious')) > 700

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
    pcap_path, expected_profiles, output_dir, redis_port
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

    assert has_errors(output_dir) == False

    database = connect_to_redis(redis_port)

    # test 1 homenet ip
    # the only profile we should have is the one in home_network parameter
    profiles = int(database.getProfilesLen())
    assert profiles == expected_profiles

    shutil.rmtree(output_dir)
    slips = create_Main_instance(pcap_path)
    slips.prepare_zeek_output_dir()

