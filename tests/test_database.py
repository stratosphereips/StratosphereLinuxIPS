# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import (
    Mock,
    call,
)

import redis
import json
import time
import pytest

from slips_files.common.slips_utils import utils
from slips_files.core.flows.zeek import Conn
from tests.module_factory import ModuleFactory
from slips_files.core.structures.evidence import (
    Evidence,
    Direction,
    IoCType,
    EvidenceType,
    Attacker,
    Victim,
    ThreatLevel,
    ProfileID,
    TimeWindow,
)


# random values for testing
profileid = "profile_192.168.1.1"
twid = "timewindow1"
test_ip = "192.168.1.1"
flow = Conn(
    "1601998398.945854",
    "1234",
    test_ip,
    "8.8.8.8",
    5,
    "TCP",
    "dhcp",
    80,
    88,
    20,
    20,
    20,
    20,
    "",
    "",
    "Established",
    "",
)


def test_getProfileIdFromIP():
    """unit test for add_profile and getProfileIdFromIP"""
    db = ModuleFactory().create_db_manager_obj(6380, flush_db=True)

    # add a profile
    db.add_profile("profile_192.168.1.1", "00:00")
    # try to retrieve it
    assert db.get_profileid_from_ip(test_ip) is not False


def test_timewindows():
    """unit tests for addNewTW , getLastTWforProfile and
    getFirstTWforProfile"""
    db = ModuleFactory().create_db_manager_obj(6381, flush_db=True)
    profileid = "profile_192.168.1.1"
    # add a profile
    db.add_profile(profileid, "00:00")
    # add a tw to that profile (first tw)
    db.add_new_tw(profileid, "timewindow1", 0.0)
    # add  a new tw (last tw)
    db.add_new_tw(profileid, "timewindow2", 3700)
    assert db.get_first_twid_for_profile(profileid) == ("timewindow1", 0.0)
    assert db.get_last_twid_of_profile(profileid) == ("timewindow2", 3700.0)


def test_add_ips():
    db = ModuleFactory().create_db_manager_obj(6382, flush_db=True)
    # add a profile
    db.add_profile(profileid, "00:00")
    # add a tw to that profile
    db.add_new_tw(profileid, "timewindow1", 0.0)
    # make sure ip is added
    assert db.add_ips(profileid, twid, flow, "Server") is True
    stored_src_ips = db.r.hget(f"{profileid}_{twid}", "SrcIPs")
    assert stored_src_ips == '{"192.168.1.1": 1}'


def test_add_port():
    db = ModuleFactory().create_db_manager_obj(6383, flush_db=True)
    new_flow = flow
    new_flow.state = "Not Established"
    db.add_port(profileid, twid, flow, "Server", "Dst")
    hash_key = f"{profileid}_{twid}"
    added_ports = db.r.hgetall(hash_key)
    assert "DstPortsServerTCPNot Established" in added_ports.keys()
    assert flow.daddr in added_ports["DstPortsServerTCPNot Established"]


def test_set_evidence():
    db = ModuleFactory().create_db_manager_obj(6384, flush_db=True)
    attacker: Attacker = Attacker(
        direction=Direction.SRC, ioc_type=IoCType.IP, value=test_ip
    )
    threat_level: ThreatLevel = ThreatLevel.INFO
    confidence = 0.8
    description = f"SSH Successful to IP : 8.8.8.8 . From IP {test_ip}"
    timestamp = time.time()
    uid = ["123"]
    victim: Victim = Victim(
        direction=Direction.DST, ioc_type=IoCType.IP, value="8.8.8.8"
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
    )

    db.set_evidence(evidence)
    added = db.r.hget(f"{profileid}_{twid}_evidence", evidence.id)
    assert added


def test_setInfoForDomains():
    """tests setInfoForDomains, setNewDomain and getDomainData"""
    db = ModuleFactory().create_db_manager_obj(6385, flush_db=True)
    domain = "www.google.com"
    domain_data = {"threatintelligence": "sample data"}
    db.set_info_for_domains(domain, domain_data)

    stored_data = db.get_domain_data(domain)
    assert "threatintelligence" in stored_data
    assert stored_data["threatintelligence"] == "sample data"


def test_subscribe():
    db = ModuleFactory().create_db_manager_obj(6386, flush_db=True)
    # invalid channel
    assert db.subscribe("invalid_channel") is False
    # valid channel, shoud return a pubsub object
    assert isinstance(db.subscribe("tw_modified"), redis.client.PubSub)


def test_profile_moddule_labels():
    """tests set and get_profile_module_label"""
    db = ModuleFactory().create_db_manager_obj(6387, flush_db=True)
    module_label = "malicious"
    module_name = "test"
    db.set_module_label_for_profile(profileid, module_name, module_label)
    labels = db.get_modules_labels_of_a_profile(profileid)
    assert "test" in labels
    assert labels["test"] == "malicious"


def test_add_mac_addr_with_new_ipv4():
    """
    adding an ipv4 to no cached ip
    """
    db = ModuleFactory().create_db_manager_obj(6388, flush_db=True)
    ipv4 = "192.168.1.5"
    profileid_ipv4 = f"profile_{ipv4}"
    mac_addr = "00:00:5e:00:53:af"

    db.rdb.is_gw_mac = Mock(return_value=False)
    db.r.hget = Mock()
    db.r.hset = Mock()
    db.r.hmget = Mock(return_value=[None])  # No entry initially

    # simulate adding a new MAC and IPv4 address
    assert db.add_mac_addr_to_profile(profileid_ipv4, mac_addr) is True

    # Ensure the IP is associated in the 'MAC' hash
    db.r.hmget.assert_called_with("MAC", mac_addr)
    db.r.hset.assert_any_call("MAC", mac_addr, json.dumps([ipv4]))


def test_add_mac_addr_with_existing_ipv4():
    """
    adding an ipv4 to a cached ipv4
    """
    db = ModuleFactory().create_db_manager_obj(6389, flush_db=True)
    ipv4 = "192.168.1.5"
    mac_addr = "00:00:5e:00:53:af"
    db.rdb.is_gw_mac = Mock(return_value=False)
    db.r.hget = Mock()
    db.r.hset = Mock()
    db.r.hmget = Mock(return_value=[json.dumps([ipv4])])

    new_profile = "profile_192.168.1.6"

    # try to add a new profile with the same MAC but another IPv4 address
    assert db.add_mac_addr_to_profile(new_profile, mac_addr) is False


def test_add_mac_addr_with_ipv6_association():
    """
    adding an ipv6 to a cached ipv4
    """
    db = ModuleFactory().create_db_manager_obj(6390, flush_db=True)
    ipv4 = "192.168.1.5"
    profile_ipv4 = "profile_192.168.1.5"
    mac_addr = "00:00:5e:00:53:af"

    # mock existing entry with ipv6
    db.rdb.is_gw_mac = Mock(return_value=False)
    db.rdb.update_mac_of_profile = Mock()
    db.r.hmget = Mock(return_value=[json.dumps([ipv4])])
    db.r.hset = Mock()
    db.r.hget = Mock()

    ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    profile_ipv6 = f"profile_{ipv6}"
    # try to associate an ipv6 with the same MAC address
    assert db.add_mac_addr_to_profile(profile_ipv6, mac_addr)

    expected_calls = [
        call(profile_ipv4, mac_addr),  # call with ipv4 profile id
        call(profile_ipv6, mac_addr),  # call with ipv6 profile id
    ]
    db.rdb.update_mac_of_profile.assert_has_calls(
        expected_calls, any_order=True
    )


def test_get_the_other_ip_version():
    db = ModuleFactory().create_db_manager_obj(6391, flush_db=True)
    # profileid is ipv4
    ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    db.set_ipv6_of_profile(profileid, ipv6)
    # the other ip version is ipv6
    other_ip = json.loads(db.get_the_other_ip_version(profileid))
    assert other_ip == ipv6


@pytest.mark.parametrize(
    "tupleid, symbol, role, expected_direction",
    [
        # no prev_symbols will be found for this
        (
            "8.8.8.8-5-tcp",
            ("1", (False, 1601998366.785668)),
            "Client",
            "OutTuples",
        ),
        (
            "8.8.8.8-5-tcp",
            ("8.888123..1", (1601998366.806331, 1601998366.958409)),
            "Server",
            "InTuples",
        ),
    ],
)
def test_add_tuple(tupleid: str, symbol, expected_direction, role, flow):
    db = ModuleFactory().create_db_manager_obj(6392, flush_db=True)
    db.add_tuple(profileid, twid, tupleid, symbol, role, flow)
    assert symbol[0] in db.r.hget(
        f"profile_{flow.saddr}_{twid}", expected_direction
    )


@pytest.mark.parametrize(
    "max_threat_level, cur_threat_level, expected_max",
    [
        ("info", "info", utils.threat_levels["info"]),
        ("critical", "info", utils.threat_levels["critical"]),
        ("high", "critical", utils.threat_levels["critical"]),
    ],
)
def test_update_max_threat_level(
    max_threat_level, cur_threat_level, expected_max
):
    db = ModuleFactory().create_db_manager_obj(6393, flush_db=True)
    db.set_max_threat_level(profileid, max_threat_level)
    assert (
        db.update_max_threat_level(profileid, cur_threat_level) == expected_max
    )
