"""
This file tests all kinds of input in our dataset/
It checks a random evidence and the total number of profiles in every file
"""
import os
import pytest
import shutil
# from test_slips import create_Main_instance
from ..slips import *

alerts_file = 'alerts.log'


def connect_to_redis(redis_port):
    from slips_files.core.database import __database__

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


def has_errors(output_dir):
    """function to parse slips_output file and check for errors"""
    error_files = [os.path.join(output_dir, 'slips_output.txt'),
                          os.path.join(output_dir, 'errors.log')]
    # we can't redirect stderr to a file and check it because we catch all exceptions in slips
    for file in error_files:
        with open(file, 'r') as f:
            for line in f:
                if '<class' in line or 'error' in line:
                    # connection errors shouldn't fail the integration tests
                    if 'Connection error' in line:
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

@pytest.mark.parametrize(
    'pcap_path, expected_profiles, output_dir, expected_evidence, redis_port',
    [
        (
            'dataset/hide-and-seek-short.pcap',
            15,
            'pcap/',
            'horizontal port scan to port  23',
            6666,
        ),
        ('dataset/arp-only.pcap', 3, 'pcap2/', 'performing an arp scan', 6665),
    ],
)
def test_pcap(
    pcap_path, expected_profiles, output_dir, expected_evidence, redis_port
):
    try:
        os.mkdir(output_dir)
    except FileExistsError:
        pass
    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -f {pcap_path} -o {output_dir}  -P {redis_port} > {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)

    assert has_errors(output_dir) == False

    database = connect_to_redis(redis_port)
    profiles = int(database.getProfilesLen())
    assert profiles > expected_profiles

    log_file = output_dir + alerts_file
    assert is_evidence_present(log_file, expected_evidence) == True
    shutil.rmtree(output_dir)

    slips = create_Main_instance(pcap_path)
    slips.prepare_zeek_output_dir()
    # remove the generated zeek files
    # shutil.rmtree(f"zeek_files_{pcap_path.split('/')[-1]}")
    shutil.rmtree(f"{slips.zeek_folder}")

@pytest.mark.parametrize(
    'binetflow_path, expected_profiles, expected_evidence, output_dir, redis_port',
    [
        (
            'dataset/test2.binetflow',
            1,
            'Detected Long Connection.',
            'test2/',
            6664,
        ),
        (
            'dataset/test3.binetflow',
            20,
            'horizontal port scan to port  3389',
            'test3/',
            6663,
        ),
        (
            'dataset/test4.binetflow',
            2,
            'horizontal port scan to port  81',
            'test4/',
            6662,
        ),
        ('dataset/test5.binetflow', 4, 'Long Connection', 'test5/', 6655),
    ],
)
def test_binetflow(
    database,
    binetflow_path,
    expected_profiles,
    expected_evidence,
    output_dir,
    redis_port,
):
    try:
        os.mkdir(output_dir)
    except FileExistsError:
        pass

    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -o {output_dir}  -P {redis_port} -f {binetflow_path}  >  {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)

    assert has_errors(output_dir) == False

    database = connect_to_redis(redis_port)
    profiles = int(database.getProfilesLen())
    assert profiles > expected_profiles

    log_file = output_dir + alerts_file
    assert is_evidence_present(log_file, expected_evidence) == True

    shutil.rmtree(output_dir)


@pytest.mark.parametrize(
    'zeek_dir_path,expected_profiles, expected_evidence,  output_dir, redis_port',
    [
        (
            'dataset/sample_zeek_files',
            4,
            [
                'SSL certificate validation failed with (certificate is not yet valid)',
                'performing bad SMTP login to 80.75.42.226',
                'performing SMTP login bruteforce to 80.75.42.226. 3 logins in 10 seconds',
                'multiple empty HTTP connections to bing.com',
                'Detected Possible SSH bruteforce by using multiple SSH versions 9_1 then 8_1',
            ],
            'sample_zeek_files/',
            6661,
        ),
        (
            'dataset/sample_zeek_files-2',
            20,
            'horizontal port scan',
            'sample_zeek_files-2/',
            6660,
        ),
    ],
)
def test_zeek_dir(
    database,
    zeek_dir_path,
    expected_profiles,
    expected_evidence,
    output_dir,
    redis_port,
):

    try:
        os.mkdir(output_dir)
    except FileExistsError:
        pass

    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -f {zeek_dir_path}  -o {output_dir}  -P {redis_port} > {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)
    assert has_errors(output_dir) == False

    database = connect_to_redis(redis_port)
    profiles = int(database.getProfilesLen())
    assert profiles > expected_profiles

    log_file = output_dir + alerts_file
    if type(expected_evidence) == list:
        # make sure all the expected evidence are there
        for evidence in expected_evidence:
            assert is_evidence_present(log_file, evidence) == True
    else:
        assert is_evidence_present(log_file, expected_evidence) == True
    shutil.rmtree(output_dir)


@pytest.mark.parametrize(
    'conn_log_path, expected_profiles, expected_evidence,  output_dir, redis_port',
    [
        (
            'dataset/sample_zeek_files/conn.log',
            4,
            'a connection without DNS resolution to IP: 185.33.223.203',
            'conn_log/',
            6659,
        ),
        (
            'dataset/sample_zeek_files-2/conn.log',
            5,
            'a connection without DNS resolution',
            'conn_log-2/',
            6658,
        ),
    ],
)
def test_zeek_conn_log(
    database,
    conn_log_path,
    expected_profiles,
    expected_evidence,
    output_dir,
    redis_port,
):
    try:
        os.mkdir(output_dir)
    except FileExistsError:
        pass

    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -f {conn_log_path}  -o {output_dir}  -P {redis_port} > {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)
    assert has_errors(output_dir) == False

    database = connect_to_redis(redis_port)
    profiles = int(database.getProfilesLen())
    assert profiles > expected_profiles

    log_file = output_dir + alerts_file
    assert is_evidence_present(log_file, expected_evidence) == True
    shutil.rmtree(output_dir)


@pytest.mark.parametrize(
    'suricata_path,  output_dir, redis_port',
    [('dataset/suricata-flows.json', 'suricata/', 6657)],
)
def test_suricata(database, suricata_path, output_dir, redis_port):
    try:
        os.mkdir(output_dir)
    except FileExistsError:
        pass
    expected_evidence = 'Connection to unknown destination port 5901/TCP'

    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -f {suricata_path} -o {output_dir}  -P {redis_port} > {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)

    assert has_errors(output_dir) == False

    database = connect_to_redis(redis_port)
    profiles = int(database.getProfilesLen())
    assert profiles > 90

    log_file = output_dir + alerts_file
    assert is_evidence_present(log_file, expected_evidence) == True
    shutil.rmtree(output_dir)




@pytest.mark.skipif(
    'nfdump' not in shutil.which('nfdump'), reason='nfdump is not installed'
)
@pytest.mark.parametrize(
    'nfdump_path,  output_dir, redis_port',
    [('dataset/test.nfdump', 'nfdump/', 6656)],
)
def test_nfdump(database, nfdump_path, output_dir, redis_port):
    try:
        os.mkdir(output_dir)
    except FileExistsError:
        pass

    expected_evidence = 'Connection to unknown destination port 902/TCP'

    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -f {nfdump_path}  -o {output_dir}  -P {redis_port} > {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)

    database = connect_to_redis(redis_port)
    profiles = int(database.getProfilesLen())
    assert has_errors(output_dir) == False
    # make sure slips generated profiles for this file (can't
    # put the number of profiles exactly because slips
    # doesn't generate a const number of profiles per file)
    assert profiles > 0

    log_file = output_dir + alerts_file
    assert is_evidence_present(log_file, expected_evidence) == True
    shutil.rmtree(output_dir)
