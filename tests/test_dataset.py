"""
This file tests all kinds of input in our datasert/
It checks a random evidence and the total number of profiles in every file
"""
import os
import pytest
alerts_log_file = 'output/alerts.json'

use_sudo = False
sudo =''
if use_sudo == True:
    sudo = 'sudo'

@pytest.mark.parametrize("pcap_path", [('dataset/hide-and-seek-short.pcap')])
def test_pcap(database, pcap_path):
    command = f'{sudo} ./slips.py -l -c slips.conf -f {pcap_path}'
    # this function returns when slips is done
    os.system(command)
    # check that we have exactly 16 profile in the db
    profiles = database.getProfiles()
    assert len(profiles) == 16
    expected_evidence = 'New horizontal port scan detected to port 23'
    with open(alerts_log_file, 'r') as f:
        assert expected_evidence in f.read()

@pytest.mark.parametrize("binetflow_path, expected_profiles, expected_evidence", [
     ('dataset/test2.binetflow',3,'New horizontal port scan detected to port 443'),
    ('dataset/test3.binetflow',20,'New horizontal port scan detected to port 3389'),
    ('dataset/test4.binetflow',2,'New horizontal port scan detected to port 81'),
    ('dataset/test5.binetflow',4,'RNN C&C channels detection')])
def test_binetflow(database, binetflow_path, expected_profiles, expected_evidence):
    command = f'{sudo} ./slips.py -l -c slips.conf -f {binetflow_path}'
    # this function returns when slips is done
    os.system(command)
    profiles = database.getProfiles()
    assert len(profiles) > expected_profiles
    with open(alerts_log_file, 'r') as f:
        assert expected_evidence in f.read()

@pytest.mark.parametrize("zeek_dir_path,expected_profiles, expected_evidence",
    [('dataset/sample_zeek_files',4,'SSL certificate validation failed with (certificate is not yet valid)'),
    ('dataset/sample_zeek_files-2',20,'Zeek: Horizontal port scan. 147.32.83.156 scanned at least 25 unique hosts on port 2323/tcp in 3m51s')])
def test_zeek_dir(database, zeek_dir_path, expected_profiles, expected_evidence):
    command = f'{sudo} ./slips.py -l -c slips.conf -f {zeek_dir_path}'
    # this function returns when slips is done
    os.system(command)
    profiles = database.getProfiles()
    assert len(profiles) > expected_profiles
    with open(alerts_log_file, 'r') as f:
        assert expected_evidence in f.read()

@pytest.mark.parametrize("conn_log_path, expected_profiles, expected_evidence",
     [('dataset/sample_zeek_files/conn.log',4,'RNN C&C channels detection'),
     ('dataset/sample_zeek_files-2/conn.log',20,'RNN C&C channels detection')])
def test_zeek_conn_log(database, conn_log_path, expected_profiles, expected_evidence):
    command = f'{sudo} ./slips.py -l -c slips.conf -f {conn_log_path}'
    # this function returns when slips is done
    os.system(command)
    profiles = database.getProfiles()
    assert len(profiles) > expected_profiles
    with open(alerts_log_file, 'r') as f:
        assert expected_evidence in f.read()

@pytest.mark.parametrize('suricata_path',[('dataset/suricata-flows.json')])
def test_suricata(database, suricata_path):
    command = f'{sudo} ./slips.py -c slips.conf -f {suricata_path}'
    # this function returns when slips is done
    os.system(command)
    profiles = database.getProfiles()
    expected_evidence = 'New vertical port scan detected to IP 192.168.1.129 from 193.46.255.92'
    assert len(profiles) > 300
    with open(alerts_log_file, 'r') as f:
        assert expected_evidence in f.read()

@pytest.mark.parametrize('nfdump_path',[('dataset/test.nfdump')])
def test_nfdump(database, nfdump_path):
    command = f'{sudo} ./slips.py -c slips.conf -f {nfdump_path}'
    # this function returns when slips is done
    os.system(command)
    profiles = database.getProfiles()
    expected_evidence = 'RNN C&C channels detection'
    # make sure slips generated profiles for this file (can't set ==1 or ==2 because slips doesn't generate a const number of profiles per file)
    assert len(profiles) > 0
    with open(alerts_log_file, 'r') as f:
        evidence = f.read()
        assert expected_evidence in evidence