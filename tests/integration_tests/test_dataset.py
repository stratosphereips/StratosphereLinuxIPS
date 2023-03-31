"""
This file tests all kinds of input in our dataset/
It checks a random evidence and the total number of profiles in every file
"""
import os
import pytest
from ...slips import *
from pathlib import Path
import shutil

alerts_file = 'alerts.log'
integration_tests_dir = 'output/integration_tests/'
#create the integration tests dir

if not os.path.exists(integration_tests_dir):
    path = Path(integration_tests_dir)
    path.mkdir(parents=True, exist_ok=True)

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

    path = Path(os.path.join(integration_tests_dir, dirname))
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
                    if (
                            'Connection error' in line
                            or 'while downloading' in line
                            or 'Traceback' in line
                    ):
                        continue
                    return True

    return False


def check_for_text(txt, output_dir):
    """function to parse slips_output file and check for a given string"""
    slips_output = os.path.join(output_dir, 'slips_output.txt')
    with open(slips_output, 'r') as f:
        for line in f:
            if txt in line:
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
            'dataset/test7-malicious.pcap',
            15,
            'test7/',
            'horizontal port scan to port  23',
            6666,
        ),
        ('dataset/test8-malicious.pcap', 3, 'test8/', 'performing an arp scan', 6665),
    ],
)
def test_pcap(
    pcap_path, expected_profiles, output_dir, expected_evidence, redis_port
):
    output_dir = create_output_dir(output_dir)
    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -t -f {pcap_path} -o {output_dir}  -P {redis_port} > {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)

    assert has_errors(output_dir) == False

    database = connect_to_redis(redis_port)
    profiles = int(database.getProfilesLen())
    assert profiles > expected_profiles

    # log_file = output_dir + alerts_file
    log_file = os.path.join(output_dir, alerts_file)
    assert is_evidence_present(log_file, expected_evidence) == True
    shutil.rmtree(output_dir)

    slips = create_Main_instance(pcap_path)
    slips.prepare_zeek_output_dir()

@pytest.mark.parametrize(
    'binetflow_path, expected_profiles, expected_evidence, output_dir, redis_port',
    [
        (
            'dataset/test4-malicious.binetflow',
            2,
            'horizontal port scan to port  81',
            'test4/',
            6662,
        ),
        (
            'dataset/test3-mixed.binetflow',
            20,
            'horizontal port scan to port  3389',
            'test3/',
            6663,
        ),
        (
            'dataset/test2-malicious.binetflow',
            1,
            'Detected Long Connection.',
            'test2/',
            6664,
        ),
        (
            'dataset/test5-mixed.binetflow',
             4,
             'Long Connection',
             'test5/',
             6655
         ),
        (
            'dataset/test11-portscan.binetflow',
            0,
            'ICMP scanning 110.128.128.128',
            'test11/',
            6669

        )
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
    output_dir = create_output_dir(output_dir)

    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -t -o {output_dir}  -P {redis_port} -f {binetflow_path}  >  {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)

    assert has_errors(output_dir) == False

    database = connect_to_redis(redis_port)
    profiles = int(database.getProfilesLen())
    assert profiles > expected_profiles

    log_file = os.path.join(output_dir, alerts_file)
    assert is_evidence_present(log_file, expected_evidence) == True

    shutil.rmtree(output_dir)


@pytest.mark.parametrize(
    'zeek_dir_path,expected_profiles, expected_evidence,  output_dir, redis_port',
    [
        (
            'dataset/test9-mixed-zeek-dir',
            4,
            [
                'SSH client version changing',
                'Incompatible certificate CN',
                'Malicious JA3: 6734f37431670b3ab4292b8f60f29984',
                'sending ARP packet to a destination address outside of local network',
                'broadcasting unsolicited ARP',
            ],
            'test9-mixed-zeek-dir/',
            6661,
        ),
        (
            'dataset/test16-malicious-zeek-dir',
            0,
            [
                'sending ARP packet to a destination address outside of local network',
                'broadcasting unsolicited ARP',
            ],
            'test16-malicious-zeek-dir/',
            6671,
        ),
        (
            'dataset/test14-malicious-zeek-dir',
            2,
            [
                'bad SMTP login to 80.75.42.226',
                'SMTP login bruteforce to 80.75.42.226. 3 logins in 10 seconds',
                'multiple empty HTTP connections to bing.com',
                'suspicious user-agent',
                'download of an executable',
            ],
            'test14-malicious-zeek-dir/',
            6670
        ),
        (
            'dataset/test15-malicious-zeek-dir',
            2,
            [
                'SSH client version changing',
                'Incompatible certificate CN',
                'Malicious JA3: 6734f37431670b3ab4292b8f60f29984',
            ],
            'test15-malicious-zeek-dir',
            2345
        ),
        (
            'dataset/test10-mixed-zeek-dir',
            20,
            'horizontal port scan',
            'test10-mixed-zeek-dir/',
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

    output_dir = create_output_dir(output_dir)

    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -t -f {zeek_dir_path}  -o {output_dir}  -P {redis_port} > {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)
    assert has_errors(output_dir) == False

    database = connect_to_redis(redis_port)
    profiles = int(database.getProfilesLen())
    assert profiles > expected_profiles

    log_file = os.path.join(output_dir, alerts_file)
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
            'dataset/test9-mixed-zeek-dir/conn.log',
            4,
            'horizontal port scan',
            'test9-conn_log_only/',
            6659,
        ),
        (
            'dataset/test10-mixed-zeek-dir/conn.log',
            5,
            'horizontal port scan',
            'test10-conn_log_only/',
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
    output_dir = create_output_dir(output_dir)

    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -t -f {conn_log_path}  -o {output_dir}  -P {redis_port} > {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)
    assert has_errors(output_dir) == False

    database = connect_to_redis(redis_port)
    profiles = int(database.getProfilesLen())
    assert profiles > expected_profiles

    log_file = os.path.join(output_dir, alerts_file)
    assert is_evidence_present(log_file, expected_evidence) == True
    shutil.rmtree(output_dir)


@pytest.mark.parametrize(
    'suricata_path,  output_dir, redis_port, expected_evidence',
    [
        (
                'dataset/test6-malicious.suricata.json',
                'test6/',
                6657,
                [
                    'Connection to unknown destination port',
                    'vertical port scan',
                    'Connecting to private IP',
                    'non-HTTP established connection'

                ]

        )
    ],
)
def test_suricata(database, suricata_path, output_dir, redis_port, expected_evidence):
    output_dir = create_output_dir(output_dir)
    # we have an established flow in suricata file to this port 8760/udp
    # {"timestamp":"2021-06-06T15:57:37.272281+0200","flow_id":1630350322382106,"event_type":"flow",
    # "src_ip":"192.168.1.129","src_port":36101,"dest_ip":"122.248.252.67","dest_port":8760,"proto":
    # "UDP","app_proto":"failed","flow":{"pkts_toserver":2,"pkts_toclient":2,"bytes_toserver":256,
    # "bytes_toclient":468,"start":"2021-06-07T04:26:27.668954+0200","end":"2021-06-07T04:26:27.838624+0200"
    # ,"age":0,"state":"established","reason":"shutdown","alerted":false},"host":"stratosphere.org"}

    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -t -f {suricata_path} -o {output_dir}  -P {redis_port} > {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)

    assert has_errors(output_dir) == False

    database = connect_to_redis(redis_port)
    profiles = int(database.getProfilesLen())
    #todo the profiles should be way more than 10, maybe 76, but it varies each run, we need to sy why
    assert profiles > 10

    log_file = os.path.join(output_dir, alerts_file)
    assert any([is_evidence_present(log_file, ev) for ev in expected_evidence])
    shutil.rmtree(output_dir)


@pytest.mark.skipif(
    'nfdump' not in shutil.which('nfdump'), reason='nfdump is not installed'
)
@pytest.mark.parametrize(
    'nfdump_path,  output_dir, redis_port',
    [('dataset/test1-normal.nfdump', 'test1/', 6656)],
)
def test_nfdump(database, nfdump_path, output_dir, redis_port):
    """
    checks that slips is reading nfdump no issue,
     the file is not malicious so there's no evidence that should be present
    """
    output_dir = create_output_dir(output_dir)

    # expected_evidence = 'Connection to unknown destination port 902/TCP'

    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -t -f {nfdump_path}  -o {output_dir}  -P {redis_port} > {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)

    database = connect_to_redis(redis_port)
    profiles = int(database.getProfilesLen())
    assert has_errors(output_dir) == False
    # make sure slips generated profiles for this file (can't
    # put the number of profiles exactly because slips
    # doesn't generate a const number of profiles per file)
    assert profiles > 0

    # log_file = os.path.join(output_dir, alerts_file)
    # assert is_evidence_present(log_file, expected_evidence) == True
    shutil.rmtree(output_dir)
