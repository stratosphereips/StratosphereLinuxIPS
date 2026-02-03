# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import (
    Mock,
    call,
)

import redis
import json

from slips_files.core.flows.zeek import Conn
from tests.module_factory import ModuleFactory


# random values for testing
profileid = "profile_192.168.1.1"
twid = "timewindow1"
test_ip = "192.168.1.1"
flow = Conn(
    starttime="1601998398.945854",
    uid="1234",
    saddr=test_ip,
    daddr="8.8.8.8",
    dur=5,
    proto="TCP",
    appproto="dhcp",
    sport=80,
    dport=88,
    spkts=20,
    dpkts=20,
    sbytes=20,
    dbytes=20,
    state="",
    history="",
    smac="Established",
    dmac="",
    interface="eth0",
)


def test_set_info_for_domains():
    """tests set_info_for_domains, setNewDomain and get_domain_data"""
    db = ModuleFactory().create_db_manager_obj(6379, flush_db=True)
    domain = "www.google.com"
    domain_data = {"threatintelligence": "sample data"}
    db.set_info_for_domains(domain, domain_data)

    stored_data = db.get_domain_data(domain)
    assert "threatintelligence" in stored_data
    assert stored_data["threatintelligence"] == "sample data"


def test_subscribe():
    db = ModuleFactory().create_db_manager_obj(6379, flush_db=True)
    # invalid channel
    assert db.subscribe("invalid_channel") is False
    # valid channel, shoud return a pubsub object
    assert isinstance(db.subscribe("tw_modified"), redis.client.PubSub)


def test_profile_moddule_labels():
    """tests set and get_profile_module_label"""
    db = ModuleFactory().create_db_manager_obj(6379, flush_db=True)
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
    db = ModuleFactory().create_db_manager_obj(6379, flush_db=True)
    ipv4 = "192.168.1.5"
    profileid_ipv4 = f"profile_{ipv4}"
    mac_addr = "00:00:5e:00:53:af"

    db.rdb.is_gw_mac = Mock(return_value=False)
    db.rdb._should_associate_this_mac_with_this_ip = Mock(return_value=True)
    db.r.hget = Mock()
    db.r.hset = Mock()
    db.r.hmget = Mock(return_value=[None])

    # simulate adding a new MAC and IPv4 address
    assert db.add_mac_addr_to_profile(profileid_ipv4, mac_addr, "eth0") is True

    # Ensure the IP is associated in the 'MAC' hash
    db.r.hmget.assert_called_with("MAC", mac_addr)
    db.r.hset.assert_any_call("MAC", mac_addr, json.dumps([ipv4]))


def test_add_mac_addr_with_existing_ipv4():
    """
    adding an ipv4 to a cached ipv4
    """
    db = ModuleFactory().create_db_manager_obj(6379, flush_db=True)
    ipv4 = "192.168.1.5"
    mac_addr = "00:00:5e:00:53:af"
    db.rdb.is_gw_mac = Mock(return_value=False)
    db.rdb._should_associate_this_mac_with_this_ip = Mock(return_value=True)
    db.r.hget = Mock()
    db.r.hset = Mock()
    db.r.hmget = Mock(return_value=[json.dumps([ipv4])])

    new_profile = "profile_192.168.1.6"

    # try to add a new profile with the same MAC but another IPv4 address
    assert db.add_mac_addr_to_profile(new_profile, mac_addr, "eth0") is False


def test_add_mac_addr_with_ipv6_association():
    """
    adding an ipv6 to a cached ipv4
    """
    db = ModuleFactory().create_db_manager_obj(6379, flush_db=True)
    ipv4 = "192.168.1.5"
    profile_ipv4 = "profile_192.168.1.5"
    mac_addr = "00:00:5e:00:53:af"

    # mock existing entry with ipv6
    db.rdb.is_gw_mac = Mock(return_value=False)
    db.rdb._should_associate_this_mac_with_this_ip = Mock(return_value=True)
    db.rdb.update_mac_of_profile = Mock()
    db.r.hmget = Mock(return_value=[json.dumps([ipv4])])
    db.r.hset = Mock()
    db.r.hget = Mock()

    ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    profile_ipv6 = f"profile_{ipv6}"
    # try to associate an ipv6 with the same MAC address
    assert db.add_mac_addr_to_profile(profile_ipv6, mac_addr, "eth0")

    expected_calls = [
        call(profile_ipv4, mac_addr),  # call with the ipv4 profileid
        call(profile_ipv6, mac_addr),  # call with the ipv6 profileid
    ]
    db.rdb.update_mac_of_profile.assert_has_calls(
        expected_calls, any_order=True
    )


def test_get_the_other_ip_version():
    db = ModuleFactory().create_db_manager_obj(6379, flush_db=True)
    # profileid is ipv4
    ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    db.set_ipv6_of_profile(profileid, ipv6)
    # the other ip version is ipv6
    other_ip = json.loads(db.get_the_other_ip_version(profileid))
    assert other_ip == ipv6
