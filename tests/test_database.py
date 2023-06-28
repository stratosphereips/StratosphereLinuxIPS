from slips_files.common.slips_utils import utils
from slips_files.core.flows.zeek import Conn
from tests.module_factory import ModuleFactory
import redis
import os
import json
import time


# random values for testing
profileid = 'profile_192.168.1.1'
twid = 'timewindow1'
test_ip = '192.168.1.1'
flow = Conn(
    5,
    '1234',
    test_ip,
    '8.8.8.8',
    5,
    'TCP',
    'dhcp',
    80,88,
    20,20,
    20,20,
    '','',
    'Established',''
)

# this should always be the first unit test in this file
# because we don't want another unit test adding the same flow before this one

database = ModuleFactory().create_db_manager_obj(6379, flush_db=True)


def add_flow():
    database.add_flow(flow, '', profileid, twid, label='benign')


def test_getProfileIdFromIP():
    """unit test for addProfile and getProfileIdFromIP"""

    # clear the database before running this test
    os.system('./slips.py -c slips.conf -cc')

    # add a profile
    database.addProfile('profile_192.168.1.1', '00:00', '1')
    # try to retrieve it
    assert database.getProfileIdFromIP(test_ip) is not False


def test_timewindows():
    """unit tests for addNewTW ,getLastTWforProfile and getFirstTWforProfile"""
    profileid = 'profile_192.168.1.1'
    # add a profile
    database.addProfile(profileid, '00:00', '1')
    # add a tw to that profile (first tw)
    database.addNewTW(profileid, 0.0)
    # add  a new tw (last tw)
    database.addNewTW(profileid, 5.0)
    assert database.getFirstTWforProfile(profileid) == [('timewindow1', 0.0)]
    assert database.get_last_twid_of_profile(profileid) == [('timewindow2', 5.0)]


def getSlipsInternalTime():
    """return a random time for testing"""
    return 50.0


def test_add_ips():
    # add a profile
    database.addProfile(profileid, '00:00', '1')
    # add a tw to that profile
    database.addNewTW(profileid, 0.0)
    columns = {
        'dport': 80,
        'sport': 80,
        'totbytes': 80,
        'pkts': 20,
        'sbytes': 30,
        'bytes': 30,
        'spkts': 70,
        'state': 'Not Established',
        'uid': '1234',
        'proto': 'TCP',
        'saddr': '8.8.8.8',
        'daddr': test_ip,
        'starttime': '20.0',
    }
    # make sure ip is added
    assert (
        database.add_ips(profileid, twid, flow, 'Server') is True
    )
    hash_id = f'{profileid}_{twid}'
    stored_dstips = database.r.hget(hash_id, 'SrcIPs')
    assert stored_dstips == '{"192.168.1.1": 1}'


def test_add_port():
    new_flow = flow
    new_flow.state = 'Not Established'
    database.add_port(profileid, twid, flow, 'Server', 'Dst')
    hash_key = f'{profileid}_{twid}'
    added_ports = database.r.hgetall(hash_key)
    assert 'DstPortsServerTCPNot Established' in added_ports.keys()
    assert flow.daddr in added_ports['DstPortsServerTCPNot Established']


def test_setEvidence():
    attacker_direction = 'ip'
    attacker = test_ip
    evidence_type = f'SSHSuccessful-by-{attacker}'
    threat_level = 0.01
    confidence = 0.6
    description = 'SSH Successful to IP :' + '8.8.8.8' + '. From IP ' + test_ip
    timestamp = time.time()
    category = 'Infomation'
    uid = '123'
    database.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                         timestamp, category, profileid=profileid, twid=twid, uid=uid)

    added_evidence = database.r.hget(f'evidence{profileid}', twid)
    added_evidence2 = database.r.hget(f'{profileid}_{twid}', 'Evidence')
    assert added_evidence2 == added_evidence

    added_evidence = json.loads(added_evidence)
    description = 'SSH Successful to IP :8.8.8.8. From IP 192.168.1.1'
    #  note that added_evidence may have evidence from other unit tests
    evidence_uid =  next(iter(added_evidence))
    evidence_details = json.loads(added_evidence[evidence_uid])
    assert 'description' in evidence_details
    assert evidence_details['description'] == description


def test_deleteEvidence():
    description = 'SSH Successful to IP :8.8.8.8. From IP 192.168.1.1'
    database.deleteEvidence(profileid, twid, description)
    added_evidence = json.loads(database.r.hget(f'evidence{profileid}', twid))
    added_evidence2 = json.loads(
        database.r.hget(f'{profileid}_{twid}', 'Evidence')
    )
    assert 'SSHSuccessful-by-192.168.1.1' not in added_evidence
    assert 'SSHSuccessful-by-192.168.1.1' not in added_evidence2



def test_setInfoForDomains():
    """ tests setInfoForDomains, setNewDomain and getDomainData """
    domain = 'www.google.com'
    domain_data = {'threatintelligence': 'sample data'}
    database.setInfoForDomains(domain, domain_data)

    stored_data = database.getDomainData(domain)
    assert 'threatintelligence' in stored_data
    assert stored_data['threatintelligence'] == 'sample data'


def test_subscribe():
    # invalid channel
    assert database.subscribe('invalid_channel') is False
    # valid channel, shoud return a pubsub object
    assert type(database.subscribe('tw_modified')) == redis.client.PubSub


def test_profile_moddule_labels():
    """ tests set and get_profile_module_label """
    module_label = 'malicious'
    module_name = 'test'
    database.set_profile_module_label(profileid, module_name, module_label)
    labels = database.get_profile_modules_labels(profileid)
    assert 'test' in labels
    assert labels['test'] == 'malicious'


def test_add_mac_addr_to_profile():
    ipv4 = '192.168.1.5'
    profileid_ipv4 = f'profile_{ipv4}'
    MAC_info = {'MAC': '00:00:5e:00:53:af'}
    # first associate this ip with some mac
    assert database.add_mac_addr_to_profile(profileid_ipv4, MAC_info) is True
    assert ipv4 in str(database.r.hget('MAC', MAC_info['MAC']))

    # now claim that we found another profile
    # that has the same mac as this one
    # both ipv4
    profileid = 'profile_192.168.1.6'
    assert database.add_mac_addr_to_profile(profileid, MAC_info) is False
    # this ip shouldnt be added to the profile as they're both ipv4
    assert '192.168.1.6' not in database.r.hget('MAC', MAC_info['MAC'])

    # now claim that another ipv6 has this mac
    ipv6 = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    profileid_ipv6 = f'profile_{ipv6}'
    database.add_mac_addr_to_profile(profileid_ipv6, MAC_info)
    # make sure the mac is associated with his ipv6
    assert ipv6 in database.r.hget('MAC', MAC_info['MAC'])
    # make sure the ipv4 is associated with this
    # ipv6 profile
    assert ipv4 in str(database.r.hmget(profileid_ipv6, 'IPv4'))

    # make sure the ipv6 is associated with the
    # profile that has the same ipv4 as the mac
    assert ipv6 in str(database.r.hmget(profileid_ipv4, 'IPv6'))


def test_get_the_other_ip_version():
    # profileid is ipv4
    ipv6 = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    database.set_ipv6_of_profile(profileid, ipv6)
    # the other ip version is ipv6
    other_ip = json.loads(database.get_the_other_ip_version(profileid))
    assert other_ip == ipv6
