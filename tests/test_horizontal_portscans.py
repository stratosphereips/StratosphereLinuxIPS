# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import pytest
import random
from unittest.mock import Mock
from tests.module_factory import ModuleFactory
from slips_files.core.structures.evidence import (
    Proto,
    EvidenceType,
    ProfileID,
    TimeWindow,
)

random_ports = {
    1234: 1,
    2222: 1,
    12234: 1,
    5555: 1,
}


def generate_random_ip():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))


def enough_dstips_to_reach_the_threshold():
    """
    returns conns to dport that are not enough
    to reach the minimum dports to trigger the first scan
    """
    module = ModuleFactory().create_horizontal_portscan_obj()
    # get a random list of ints(ports) that are below the threshold
    # Generate a random number between 0 and threshold
    amount_of_dstips: int = random.randint(
        module.minimum_dstips_to_set_evidence,
        module.minimum_dstips_to_set_evidence + 100,
    )
    dport = 5555
    res = {dport: {"dstips": {"8.8.8.8": {"dstports": random_ports}}}}

    for _ in range(amount_of_dstips + 1):
        res[dport]["dstips"].update(
            {generate_random_ip(): {"dstports": random_ports}}
        )

    return res


@pytest.mark.parametrize(
    "prev_bucket, cur_amount_of_dstips, expected",
    [
        (0, 5, False),  # log10(5)=0 -> same bucket
        (0, 9, False),  # still bucket 0
        (0, 10, True),  # crosses 0 → 1
        (1, 15, False),  # stays in bucket 1
        (1, 99, False),  # still bucket 1
        (1, 100, True),  # crosses 1 → 2
    ],
)
def test_check_if_enough_dstips_to_trigger_an_evidence(
    prev_bucket, cur_amount_of_dstips, expected
):
    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dport = 5555

    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()

    twid_identifier = f"{profileid}_{timewindow}:dport:{dport}"
    horizontal_ps.cached_thresholds_per_tw[twid_identifier] = prev_bucket

    enough = horizontal_ps.check_if_enough_dstips_to_trigger_an_evidence(
        profileid, timewindow, dport, cur_amount_of_dstips
    )

    assert enough is expected


def test_check_if_enough_dstips_to_trigger_an_evidence_no_cache():
    """
    Test the check_if_enough_dstips_to_trigger_an_evidence
    method when there is no cached threshold.
    """
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    horizontal_ps.cached_thresholds_per_tw = {}
    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dport = 5555

    cur_amount_of_dstips = 10

    enough = horizontal_ps.check_if_enough_dstips_to_trigger_an_evidence(
        profileid, timewindow, dport, cur_amount_of_dstips
    )
    assert enough is True


def test_should_set_evidence_less_than_minimum():
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dport = 5555

    cur_amount_of_dstips = 3
    enough = horizontal_ps.should_set_evidence(
        cur_amount_of_dstips, profileid, timewindow, dport
    )
    assert enough is False


def not_enough_dstips_to_reach_the_threshold():
    """
    returns conns to dport that are not enough
    to reach the minimum dports to trigger the first scan
    """
    module = ModuleFactory().create_horizontal_portscan_obj()
    # get a random list of ints(ports) that are below the threshold
    # Generate a random number between 0 and threshold
    amount_of_dstips: int = random.randint(
        0, module.minimum_dstips_to_set_evidence - 1
    )
    dport = 5555
    res = {dport: {"dstips": {"8.8.8.8": {"dstports": random_ports}}}}

    for _ in range(amount_of_dstips - 1):
        res[dport]["dstips"].update(
            {generate_random_ip(): {"dstports": random_ports}}
        )

    return res


def test_set_evidence_horizontal_portscan_empty_port_info():
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    evidence = {
        "protocol": "TCP",
        "profileid": "profile_1.1.1.1",
        "twid": "timewindow0",
        "uids": ["uid1", "uid2"],
        "dport": 80,
        "pkts_sent": 100,
        "first_timestamp": "1234.56",
        "state": "Not Established",
        "amount_of_dips": 10,
    }

    horizontal_ps.db.get_port_info.return_value = ""
    horizontal_ps.db.set_evidence.return_value = None

    horizontal_ps.set_evidence_horizontal_portscan(evidence)

    horizontal_ps.db.set_evidence.assert_called_once()
    call_args = horizontal_ps.db.set_evidence.call_args[0][0]
    assert call_args.description.startswith(
        "Horizontal port scan to port  80/TCP."
    )


def test_set_evidence_horizontal_portscan():
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    evidence = {
        "protocol": "TCP",
        "profileid": "profile_1.1.1.1",
        "twid": "timewindow0",
        "uids": ["uid1", "uid2"],
        "dport": 80,
        "pkts_sent": 100,
        "first_timestamp": "1234.56",
        "state": "Not Established",
        "amount_of_dips": 10,
    }

    horizontal_ps.db.get_port_info.return_value = "HTTP"
    horizontal_ps.db.set_evidence.return_value = None

    horizontal_ps.set_evidence_horizontal_portscan(evidence)

    horizontal_ps.db.set_evidence.assert_called_once()
    call_args = horizontal_ps.db.set_evidence.call_args[0][0]
    assert call_args.evidence_type == EvidenceType.HORIZONTAL_PORT_SCAN
    assert call_args.attacker.value == "1.1.1.1"
    assert call_args.confidence == 1
    assert call_args.description.startswith(
        "Horizontal port scan to port HTTP 80/TCP."
    )
    assert call_args.profile.ip == "1.1.1.1"
    assert call_args.timewindow.number == 0
    assert set(call_args.uid) == {"uid2", "uid1"}
    assert call_args.timestamp == "1234.56"
    assert call_args.proto == Proto("tcp")
    assert call_args.dst_port == 80


def test_set_evidence_horizontal_portscan_empty_uids():
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    evidence = {
        "protocol": "TCP",
        "profileid": "profile_1.1.1.1",
        "twid": "timewindow0",
        "uids": [],
        "dport": 80,
        "pkts_sent": 100,
        "first_timestamp": "1234.56",
        "state": "Not Established",
        "amount_of_dips": 10,
    }
    horizontal_ps.db.get_port_info.return_value = "HTTP"
    horizontal_ps.db.set_evidence.return_value = None
    horizontal_ps.set_evidence_horizontal_portscan(evidence)
    assert horizontal_ps.db.set_evidence.call_count == 1
    call_args = horizontal_ps.db.set_evidence.call_args[0][0]
    assert call_args.uid == []


def test_check_valid_scan():
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    horizontal_ps.set_evidence_horizontal_portscan = Mock()
    dport = 5555
    total_pkts = 20
    ip = "10.0.0.1"

    profileid = ProfileID(ip=ip)
    twid = TimeWindow(number=0)
    horizontal_ps.db.get_dstports_of_not_established_flows.return_value = [
        (dport, total_pkts),
    ]
    horizontal_ps.should_set_evidence = Mock(return_value=True)

    horizontal_ps.check(profileid, twid)
    # once for each proto
    assert horizontal_ps.set_evidence_horizontal_portscan.call_count == 2


def test_check_invalid_profileid():
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    profileid = None
    twid = "timewindow0"
    with pytest.raises(Exception):
        horizontal_ps.check(profileid, twid)


def test_check_broadcast_or_multicast_address():
    """are_detection_modules_interested_in_this_ip should return False"""
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    ip = "255.255.255.255"
    profileid = ProfileID(ip=ip)
    twid = TimeWindow(number=0)
    assert horizontal_ps.check(profileid, twid) is False
    horizontal_ps.db.get_dstports_of_not_established_flows.assert_not_called()


def test_check_does_not_set_evidence_when_should_set_evidence_is_false():
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()

    horizontal_ps.set_evidence_horizontal_portscan = Mock()
    horizontal_ps.should_set_evidence = Mock(return_value=False)

    ip = "10.0.0.1"
    profileid = ProfileID(ip=ip)
    twid = TimeWindow(number=0)

    horizontal_ps.db.get_dstports_of_not_established_flows.return_value = [
        (80, 100)
    ]
    horizontal_ps.db.get_total_dstips_for_not_estab_flows_on_port.return_value = (
        999
    )

    horizontal_ps.check(profileid, twid)

    horizontal_ps.set_evidence_horizontal_portscan.assert_not_called()
