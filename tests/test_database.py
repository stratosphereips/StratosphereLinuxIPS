import redis
import os
import json
import time
import pytest

from slips_files.common.slips_utils import utils
from slips_files.core.flows.zeek import Conn
from slips_files.common.slips_utils import utils
from tests.module_factory import ModuleFactory
from slips_files.core.evidence_structure.evidence import (
    dict_to_evidence,
    Evidence,
    Direction,
    IoCType,
    EvidenceType,
    IDEACategory,
    Proto,
    Tag,
    Attacker,
    Victim,
    ThreatLevel,
    ProfileID,
    TimeWindow
    )


# random values for testing
profileid = 'profile_192.168.1.1'
twid = 'timewindow1'
test_ip = '192.168.1.1'
flow = Conn(
    '1601998398.945854',
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

db = ModuleFactory().create_db_manager_obj(6379, flush_db=True)


def add_flow():
    db.add_flow(flow, '', profileid, twid, label='benign')


def test_getProfileIdFromIP():
    """unit test for add_profile and getProfileIdFromIP"""

    # clear the database before running this test
    os.system('./slips.py -c slips.conf -cc')

    # add a profile
    db.add_profile('profile_192.168.1.1', '00:00', '1')
    # try to retrieve it
    assert db.get_profileid_from_ip(test_ip) is not False


def test_timewindows():
    """unit tests for addNewTW , getLastTWforProfile and
    getFirstTWforProfile"""
    profileid = 'profile_192.168.1.1'
    # add a profile
    db.add_profile(profileid, '00:00', '1')
    # add a tw to that profile (first tw)
    db.add_new_tw(profileid, 'timewindow1', 0.0)
    # add  a new tw (last tw)
    db.add_new_tw(profileid, 'timewindow2', 3700)
    assert db.get_first_twid_for_profile(profileid) == ('timewindow1', 0.0)
    assert db.get_last_twid_of_profile(profileid) == ('timewindow2', 3700.0)


def getSlipsInternalTime():
    """return a random time for testing"""
    return 50.0


def test_add_ips():
    # add a profile
    db.add_profile(profileid, '00:00', '1')
    # add a tw to that profile
    db.add_new_tw(profileid, 'timewindow1', 0.0)
    # make sure ip is added
    assert (
        db.add_ips(profileid, twid, flow, 'Server') is True
    )
    hash_id = f'{profileid}_{twid}'
    stored_dstips = db.r.hget(hash_id, 'SrcIPs')
    assert stored_dstips == '{"192.168.1.1": 1}'


def test_add_port():
    new_flow = flow
    new_flow.state = 'Not Established'
    db.add_port(profileid, twid, flow, 'Server', 'Dst')
    hash_key = f'{profileid}_{twid}'
    added_ports = db.r.hgetall(hash_key)
    assert 'DstPortsServerTCPNot Established' in added_ports.keys()
    assert flow.daddr in added_ports['DstPortsServerTCPNot Established']


def test_set_evidence():
    attacker: Attacker = Attacker(
            direction=Direction.SRC,
            attacker_type=IoCType.IP,
            value=test_ip
        )
    threat_level: ThreatLevel = ThreatLevel.INFO
    confidence = 0.8
    description = f'SSH Successful to IP : 8.8.8.8 . From IP {test_ip}'
    timestamp = time.time()
    uid = ['123']
    victim: Victim = Victim(
            direction=Direction.DST,
            victim_type=IoCType.IP,
            value='8.8.8.8'
        )
    evidence: Evidence = Evidence(
            evidence_type=EvidenceType.SSH_SUCCESSFUL,
            attacker=attacker,
            victim=victim,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=test_ip),
            timewindow=TimeWindow(number=1),
            uid=uid,
            timestamp=timestamp,
            category=IDEACategory.INFO,
        )

    db.set_evidence(evidence)
    added = db.r.hget(f'{profileid}_{twid}_evidence', evidence.id)
    assert added



def test_setInfoForDomains():
    """ tests setInfoForDomains, setNewDomain and getDomainData """
    domain = 'www.google.com'
    domain_data = {'threatintelligence': 'sample data'}
    db.setInfoForDomains(domain, domain_data)

    stored_data = db.getDomainData(domain)
    assert 'threatintelligence' in stored_data
    assert stored_data['threatintelligence'] == 'sample data'


def test_subscribe():
    # invalid channel
    assert db.subscribe('invalid_channel') is False
    # valid channel, shoud return a pubsub object
    assert type(db.subscribe('tw_modified')) == redis.client.PubSub


def test_profile_moddule_labels():
    """ tests set and get_profile_module_label """
    module_label = 'malicious'
    module_name = 'test'
    db.set_profile_module_label(profileid, module_name, module_label)
    labels = db.get_profile_modules_labels(profileid)
    assert 'test' in labels
    assert labels['test'] == 'malicious'


def test_add_mac_addr_to_profile():
    ipv4 = '192.168.1.5'
    profileid_ipv4 = f'profile_{ipv4}'
    mac_addr = '00:00:5e:00:53:af'
    # first associate this ip with some mac
    assert db.add_mac_addr_to_profile(profileid_ipv4, mac_addr) is True
    assert ipv4 in str(db.r.hget('MAC', mac_addr))

    # now claim that we found another profile
    # that has the same mac as this one
    # both ipv4
    profileid = 'profile_192.168.1.6'
    assert db.add_mac_addr_to_profile(profileid, mac_addr) is False
    # this ip shouldnt be added to the profile as they're both ipv4
    assert '192.168.1.6' not in db.r.hget('MAC', mac_addr)

    # now claim that another ipv6 has this mac
    ipv6 = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    profileid_ipv6 = f'profile_{ipv6}'
    db.add_mac_addr_to_profile(profileid_ipv6, mac_addr)
    # make sure the mac is associated with his ipv6
    assert ipv6 in db.r.hget('MAC', mac_addr)
    # make sure the ipv4 is associated with this
    # ipv6 profile
    assert ipv4 in str(db.r.hmget(profileid_ipv6, 'IPv4'))

    # make sure the ipv6 is associated with the
    # profile that has the same ipv4 as the mac
    assert ipv6 in str(db.r.hmget(profileid_ipv4, 'IPv6'))


def test_get_the_other_ip_version():
    # profileid is ipv4
    ipv6 = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    db.set_ipv6_of_profile(profileid, ipv6)
    # the other ip version is ipv6
    other_ip = json.loads(db.get_the_other_ip_version(profileid))
    assert other_ip == ipv6

@pytest.mark.parametrize(
    'tupleid, symbol, role, expected_direction',
    [
        # no prev_symbols will be found for this
        ('8.8.8.8-5-tcp', ('1', (False, 1601998366.785668)), 'Client', 'OutTuples'),
        ('8.8.8.8-5-tcp', ('8.888123..1', (1601998366.806331, 1601998366.958409)), 'Server', 'InTuples'),
    ],
)
def test_add_tuple(tupleid: str, symbol, expected_direction, role, flow):
    db.add_tuple(profileid, twid, tupleid, symbol, role, flow)
    assert symbol[0] in db.r.hget(f'profile_{flow.saddr}_{twid}', expected_direction)


@pytest.mark.parametrize(
    'max_threat_level, cur_threat_level, expected_max',
    [
        ('info', 'info', utils.threat_levels['info']),
        ('critical', 'info', utils.threat_levels['critical']),
        ('high', 'critical', utils.threat_levels['critical']),
    ],
)
def test_update_max_threat_level(
        max_threat_level, cur_threat_level, expected_max
    ):
    db.set_max_threat_level(profileid, max_threat_level)
    assert db.update_max_threat_level(
        profileid, cur_threat_level) == expected_max