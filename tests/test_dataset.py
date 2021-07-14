"""
This file tests all kinds of input in our datasert/
It checks a random evidence and the total number of profiles in every file
"""
import os
import pytest
alerts_log_file = 'output/alerts.log'

@pytest.mark.parametrize("pcap_path", [('dataset/hide-and-seek-short.pcap')])
def test_pcap(database, pcap_path):
    command = f'./slips.py -l -c slips.conf -f {pcap_path}'
    # this function returns when slips is done
    os.system(command)
    # check that we have exactly 16 profile in the db
    profiles = database.getProfiles()
    assert len(profiles) == 16
    expected_evidence = 'Detected IP 192.168.2.16  due to New horizontal port scan detected to port 23. Not Estab TCP from IP: 192.168.2.16. Tot pkts sent all IPs: 9.'
    with open(alerts_log_file, 'r') as f:
        assert expected_evidence in f.read()

@pytest.mark.parametrize("binetflow_path, expected_profiles, expected_evidence", [
    ('dataset/test2.binetflow',5,'Detected IP 10.8.0.69  due to New horizontal port scan detected to port 443. Not Estab TCP from IP: 10.8.0.69. Tot pkts sent all IPs: 12.'),
    ('dataset/test3.binetflow',27,'Detected IP 46.166.151.160  due to New horizontal port scan detected to port 3389. Not Estab TCP from IP: 46.166.151.160. Tot pkts sent all IPs: 3.'),
    ('dataset/test4.binetflow',3,'Detected IP 192.168.2.12  due to New horizontal port scan detected to port 81. Not Estab TCP from IP: 192.168.2.12. Tot pkts sent all IPs: 3.')])
def test_binetflow(database, binetflow_path, expected_profiles, expected_evidence):
    command = f'./slips.py -l -c slips.conf -f {binetflow_path}'
    # this function returns when slips is done
    os.system(command)
    profiles = database.getProfiles()
    assert len(profiles) == expected_profiles
    with open(alerts_log_file, 'r') as f:
        assert expected_evidence in f.read()

@pytest.mark.parametrize("zeek_dir_path,expected_profiles, expected_evidence",
    [('dataset/sample_zeek_files',5,'Detected domain xnore.com due to {"description": "Xnore", "source": "network.csv"}.'),
    ('dataset/sample_zeek_files-2',25,'Detected IP 147.32.83.156  due to Zeek: Horizontal port scan. 147.32.83.156 scanned at least 25 unique hosts on port 2323/tcp in 3m51s.')])
def test_zeek_dir(database, zeek_dir_path, expected_profiles, expected_evidence):
    command = f'./slips.py -l -c slips.conf -f {zeek_dir_path}'
    # this function returns when slips is done
    os.system(command)
    profiles = database.getProfiles()
    assert len(profiles) == expected_profiles
    with open(alerts_log_file, 'r') as f:
        assert expected_evidence in f.read()

@pytest.mark.parametrize("conn_log_path, expected_profiles, expected_evidence",
     [('dataset/sample_zeek_files/conn.log',5,"Detected IP 10.0.2.15  due to RNN C&C channels detection, score: 0.9618623, tuple ID:'147.32.80.7:80:tcp"),
     ('dataset/sample_zeek_files-2/conn.log',24,"Detected IP 2001:718:2:1663:dc58:6d9:ef13:51a5  due to RNN C&C channels detection, score: 0.921535, tuple ID:'2620:0:862:ed1a::2:b:443:tcp'")])
def test_zeek_conn_log(database, conn_log_path, expected_profiles, expected_evidence):
    command = f'./slips.py -l -c slips.conf -f {conn_log_path}'
    # this function returns when slips is done
    os.system(command)
    profiles = database.getProfiles()
    assert len(profiles) == expected_profiles
    with open(alerts_log_file, 'r') as f:
        assert expected_evidence in f.read()

@pytest.mark.parametrize('suricata_path',[('dataset/suricata-flows.json')])
def test_suricata(database, suricata_path):
    command = f'./slips.py -l -c slips.conf -f {suricata_path}'
    # this function returns when slips is done
    os.system(command)
    profiles = database.getProfiles()
    expected_evidence = 'Detected blacklisted IP 185.142.236.35  due to AIP_historical_blacklist_prioritized_by_newest_attackers.csv'
    assert len(profiles) == 954
    with open(alerts_log_file, 'r') as f:
        assert expected_evidence in f.read()

@pytest.mark.parametrize('nfdump_path',[('dataset/test.nfdump')])
def test_nfdump(database, nfdump_path):
    command = f'./slips.py -l -c slips.conf -f {nfdump_path}'
    # this function returns when slips is done
    os.system(command)
    profiles = database.getProfiles()
    expected_evidence = "Detected IP 147.32.80.119  due to RNN C&C channels detection, score: 0.909935, tuple ID:'147.32.82.62:902:TCP"
    assert len(profiles) == 1
    with open(alerts_log_file, 'r') as f:
        assert expected_evidence in f.read()