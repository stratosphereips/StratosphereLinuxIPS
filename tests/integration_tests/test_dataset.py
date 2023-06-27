"""
This file tests all kinds of input in our dataset/
It checks a random evidence and the total number of profiles in every file
"""
from tests.common_test_utils import (
        get_total_profiles,
        is_evidence_present,
        create_output_dir,
        has_errors,
)
from tests.module_factory import ModuleFactory
import pytest
from ...slips import *
import shutil

alerts_file = 'alerts.log'



def run_slips(cmd):
    """runs slips and waits for it to end"""
    slips = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        shell=True
    )
    return_code = slips.wait()
    return return_code


@pytest.mark.parametrize(
    'pcap_path, expected_profiles, output_dir, expected_evidence, redis_port',
    [
        (
            'dataset/test7-malicious.pcap',
            15,
            'test7/',
            'A device changing IPs',
            6666,
        ),
        ('dataset/test8-malicious.pcap', 3, 'test8/', 'performing an arp scan', 6665),
    ],
)
def test_pcap(
    pcap_path, expected_profiles, output_dir, expected_evidence, redis_port, output_queue
):
    output_dir = create_output_dir(output_dir)
    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -t -f {pcap_path} -o {output_dir}  -P {redis_port} > {output_file} 2>&1'
    # this function returns when slips is done
    run_slips(command)
    assert has_errors(output_dir) is False

    db = ModuleFactory().create_db_manager_obj(redis_port, output_dir=output_dir)
    profiles = db.get_profiles_len()
    assert profiles > expected_profiles

    log_file = os.path.join(output_dir, alerts_file)
    assert is_evidence_present(log_file, expected_evidence) is True
    shutil.rmtree(output_dir)

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
        # (
        #     'dataset/test11-portscan.binetflow',
        #     0,
        #     'ICMP scanning',
        #     'test11/',
        #     6669
        # )
    ],
)
def test_binetflow(
    output_queue,
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
    run_slips(command)

    assert has_errors(output_dir) is False

    database = ModuleFactory().create_db_manager_obj(redis_port, output_dir=output_dir)
    profiles = database.get_profiles_len()
    assert profiles > expected_profiles

    log_file = os.path.join(output_dir, alerts_file)
    assert is_evidence_present(log_file, expected_evidence) is True

    shutil.rmtree(output_dir)


@pytest.mark.parametrize(
    'zeek_dir_path,expected_profiles, expected_evidence,  output_dir, redis_port',
    [
        (
            'dataset/test9-mixed-zeek-dir',
            4,
            [
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
                'GRE tunnel'
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
    output_queue,
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
    run_slips(command)
    assert has_errors(output_dir) is False

    database = ModuleFactory().create_db_manager_obj(redis_port, output_dir=output_dir)
    profiles = database.get_profiles_len()
    assert profiles > expected_profiles

    log_file = os.path.join(output_dir, alerts_file)
    if type(expected_evidence) == list:
        # make sure all the expected evidence are there
        for evidence in expected_evidence:
            assert is_evidence_present(log_file, evidence) is True
    else:
        assert is_evidence_present(log_file, expected_evidence) is True
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
    output_queue,
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
    run_slips(command)
    assert has_errors(output_dir) is False

    database = ModuleFactory().create_db_manager_obj(redis_port, output_dir=output_dir)
    profiles = database.get_profiles_len()
    assert profiles > expected_profiles

    log_file = os.path.join(output_dir, alerts_file)
    assert is_evidence_present(log_file, expected_evidence) is True
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
def test_suricata(
        output_queue,
        suricata_path,
        output_dir,
        redis_port,
        expected_evidence
        ):
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
    run_slips(command)

    assert has_errors(output_dir) is False

    database = ModuleFactory().create_db_manager_obj(redis_port, output_dir=output_dir)
    profiles = database.get_profiles_len()
    #todo the profiles should be way more than 10, maybe 76, but it varies each run, we need to sy why
    assert profiles > 10

    log_file = os.path.join(output_dir, alerts_file)
    assert any(is_evidence_present(log_file, ev) for ev in expected_evidence)
    shutil.rmtree(output_dir)


@pytest.mark.skipif(
    'nfdump' not in shutil.which('nfdump'), reason='nfdump is not installed'
)
@pytest.mark.parametrize(
    'nfdump_path,  output_dir, redis_port',
    [('dataset/test1-normal.nfdump', 'test1/', 6656)],
)
def test_nfdump(
        output_queue,
        nfdump_path,
        output_dir,
        redis_port
        ):
    """
    checks that slips is reading nfdump no issue,
     the file is not malicious so there's no evidence that should be present
    """
    output_dir = create_output_dir(output_dir)

    # expected_evidence = 'Connection to unknown destination port 902/TCP'

    output_file = os.path.join(output_dir, 'slips_output.txt')
    command = f'./slips.py -t -f {nfdump_path}  -o {output_dir}  -P {redis_port} > {output_file} 2>&1'
    # this function returns when slips is done
    run_slips(command)

    database = ModuleFactory().create_db_manager_obj(redis_port, output_dir=output_dir)
    profiles = database.get_profiles_len()
    assert has_errors(output_dir) is False
    # make sure slips generated profiles for this file (can't
    # put the number of profiles exactly because slips
    # doesn't generate a const number of profiles per file)
    assert profiles > 0

    # log_file = os.path.join(output_dir, alerts_file)
    # assert is_evidence_present(log_file, expected_evidence) == True
    shutil.rmtree(output_dir)
