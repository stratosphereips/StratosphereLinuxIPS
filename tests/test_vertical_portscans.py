from typing import Dict
import pytest
import random
import binascii
import base64
import os
import unittest

from tests.module_factory import ModuleFactory
from slips_files.common.slips_utils import utils
from slips_files.core.evidence_structure.evidence import Proto, Evidence


def get_random_uid():
    return base64.b64encode(binascii.b2a_hex(os.urandom(9))).decode("utf-8")


def not_enough_dports_to_reach_the_threshold(mock_db):
    """
    returns a dict with conns to dport that are not enough
    to reach the minimum dports to trigger the first scan
    """
    module = ModuleFactory().create_vertical_portscan_obj(mock_db)

    # get a random list of ints(ports) that are below the threshold
    # Generate a random number between 0 and threshold
    amount_of_dports: int = random.randint(
        0, module.port_scan_minimum_dports - 1
    )

    ip: str = "8.8.8.8"
    res = {ip: {"stime": "1700828217.314165", "uid": [], "dstports": {}}}

    # Generate x random integers and append them to the list
    for _ in range(amount_of_dports):
        random_port = random.randint(0, 65535)
        res[ip]["dstports"].update({random_port: 1})

    # Return the list of random integers
    return res


def enough_dports_to_reach_the_threshold(mock_db) -> Dict[str, Dict[int, int]]:
    """
    returns conns to dport that are not enough
    to reach the minimum dports to trigger the first scan
    """
    module = ModuleFactory().create_vertical_portscan_obj(mock_db)

    # get a random list of ints(ports) that are below the threshold
    # Generate a random number between 0 and threshold
    amount_of_dports: int = random.randint(
        module.port_scan_minimum_dports, 100
    )

    ip: str = "8.8.8.8"
    res = {ip: {"stime": "1700828217.314165", "uid": [], "dstports": {}}}

    # Generate x random integers and append them to the list
    for _ in range(amount_of_dports):
        random_port = random.randint(0, 65535)
        res[ip]["dstports"].update({random_port: 1})

    # Return the list of random integers
    return res


def not_enough_dports_to_combine_1_evidence(mock_db):
    """
    returns dports that are not enough to combine an evidence
    any number of dports within the range threshold -> threshold +15 is ok
    here, aka won't be enough
    :param key:
    """
    module = ModuleFactory().create_vertical_portscan_obj(mock_db)

    # get a random list of ints(ports) that are below the threshold
    # Generate a random number between 0 and threshold
    amount_of_dports: int = random.randint(
        module.port_scan_minimum_dports, 100
    )

    ip: str = "8.8.8.8"
    res = {ip: {"stime": "1700828217.314165", "uid": [], "dstports": {}}}

    # Generate x random integers and append them to the list
    for _ in range(amount_of_dports):
        random_port = random.randint(0, 65535)
        res[ip]["dstports"].update({random_port: 1})

    # Return the list of random integers
    return res


@pytest.mark.parametrize(
    "get_test_conns, expected_return_val",
    [
        (not_enough_dports_to_reach_the_threshold, False),
        (enough_dports_to_reach_the_threshold, True),
    ],
)
def test_min_dports_threshold(
    get_test_conns, expected_return_val: bool, mock_db
):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)

    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dstip = "8.8.8.8"

    conns: dict = get_test_conns(mock_db)
    mock_db.get_data_from_profile_tw.return_value = conns

    cache_key = vertical_ps.get_cache_key(profileid, timewindow, dstip)
    amount_of_dports = len(conns[dstip]["dstports"])

    assert (
        vertical_ps.check_if_enough_dports_to_trigger_an_evidence(
            cache_key, amount_of_dports
        )
        == expected_return_val
    )


@pytest.mark.parametrize(
    "number_of_pending_evidence, expected_return_val",
    [
        (0, True),
        (1, False),
        (2, False),
        (3, True),
        (6, True),
    ],
)
def test_combining_evidence(
    number_of_pending_evidence, expected_return_val: bool, mock_db
):
    """
    first evidence will be alerted, the rest will be combined
    """
    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dstip = "8.8.8.8"

    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)
    key: str = vertical_ps.get_cache_key(profileid, timewindow, dstip)
    # get a random bunch of dstips, this dict is not important
    dstips: dict = enough_dports_to_reach_the_threshold(mock_db)
    amount_of_dports = len(dstips[dstip]["dstports"])

    pkts_sent = sum(dstips[dstip]["dstports"].values())

    for evidence_ctr in range(number_of_pending_evidence + 1):
        # as if there's 1 pending evience
        # module.pending_vertical_ps_evidence[key].append(1)
        # this will add 2 evidence to the pending evidence list
        evidence = {
            "timestamp": dstips[dstip]["stime"],
            "pkts_sent": pkts_sent,
            "protocol": "TCP",
            "profileid": profileid,
            "twid": timewindow,
            "uid": dstips[dstip]["uid"],
            "amount_of_dports": amount_of_dports,
            "dstip": dstip,
            "state": "Not Established",
        }
        # in the first iteration, enough_to_combine is gonna be True bc
        # it's the first evidence ever
        # next 2 should be false

        enough_to_combine = (
            vertical_ps.decide_if_time_to_set_evidence_or_combine(
                evidence, key
            )
        )

        if evidence_ctr == 0:
            continue

    assert enough_to_combine == expected_return_val


@pytest.mark.parametrize(
    "prev_amount_of_dports, cur_amount_of_dports, expected_return_val",
    [
        (0, 5, True),
        (5, 6, False),
        (5, 8, False),
        (5, 15, True),
        (15, 20, True),
    ],
)
def test_check_if_enough_dports_to_trigger_an_evidence(
    mock_db, prev_amount_of_dports, cur_amount_of_dports, expected_return_val
):
    """
    slip sdetects can based on the number of current dports scanned to the
    number of the ports scanned before
        we make sure the amount of dports reported each evidence
        is higher than the previous one +5
    """
    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dstip = "8.8.8.8"

    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)

    key: str = vertical_ps.get_cache_key(profileid, timewindow, dstip)
    vertical_ps.cached_tw_thresholds[key] = prev_amount_of_dports

    enough: bool = vertical_ps.check_if_enough_dports_to_trigger_an_evidence(
        key, cur_amount_of_dports
    )
    assert enough == expected_return_val


@pytest.mark.parametrize(
    "expected_dstips",
    [
        (
            {
                "8.8.8.8": {
                    "totalflows": 10,
                    "totalpkt": 100,
                    "totalbytes": 1000,
                    "stime": "1700828217.314165",
                    "uid": ["uid1", "uid2"],
                    "dstports": {"80": 50, "443": 50},
                }
            }
        ),
        ({}),
    ],
)
def test_get_not_established_dst_ips(mock_db, expected_dstips):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"
    protocol = "TCP"
    state = "Not Established"

    mock_db.get_data_from_profile_tw.return_value = expected_dstips

    dstips = vertical_ps.get_not_established_dst_ips(
        protocol, state, profileid, twid
    )
    assert dstips == expected_dstips


def test_get_cache_key(mock_db):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"
    dstip = "8.8.8.8"

    expected_key = "profile_1.1.1.1:timewindow0:dstip:8.8.8.8:VerticalPortscan"
    cache_key = vertical_ps.get_cache_key(profileid, twid, dstip)
    assert cache_key == expected_key


def test_check_no_vertical_portscan(mock_db):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"

    mock_db.get_data_from_profile_tw.return_value = {}
    mock_set_evidence = mock_db.set_evidence

    vertical_ps.check(profileid, twid)

    mock_set_evidence.assert_not_called()


def test_check_vertical_portscan_tcp_udp(mock_db):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"

    tcp_dstips = enough_dports_to_reach_the_threshold(mock_db)
    udp_dstips = enough_dports_to_reach_the_threshold(mock_db)

    mock_db.get_data_from_profile_tw.side_effect = [tcp_dstips, udp_dstips]
    mock_set_evidence = mock_db.set_evidence

    vertical_ps.check(profileid, twid)

    assert mock_set_evidence.call_count == 1


def test_combine_evidence_no_pending(mock_db):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)
    vertical_ps.pending_vertical_ps_evidence = {}
    mock_set_evidence = mock_db.set_evidence
    vertical_ps.combine_evidence()
    mock_set_evidence.assert_not_called()


def test_set_evidence_vertical_portscan_udp(mock_db):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)

    evidence = {
        "timestamp": 1700828217.314165,
        "pkts_sent": 100,
        "protocol": "UDP",
        "profileid": "profile_1.1.1.1",
        "twid": "timewindow0",
        "uid": ["uid1", "uid2"],
        "amount_of_dports": 10,
        "dstip": "8.8.8.8",
    }

    mock_set_evidence = mock_db.set_evidence
    expected_confidence = 0.5
    calc_confidence = (
        "slips_files.common.slips_utils.utils.calculate_confidence"
    )
    with unittest.mock.patch(calc_confidence) as mock_calculate_confidence:
        mock_calculate_confidence.return_value = expected_confidence
        vertical_ps.set_evidence_vertical_portscan(evidence)

    mock_set_evidence.assert_called_once()
    evidence: Evidence = mock_set_evidence.call_args[0][0]
    assert evidence.proto == Proto.UDP


def test_decide_if_time_to_set_evidence_or_combine_empty(mock_db):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)
    evidence = {
        "timestamp": 1700828217.314165,
        "pkts_sent": 100,
        "protocol": "TCP",
        "profileid": "profile_1.1.1.1",
        "twid": "timewindow0",
        "uid": ["uid1", "uid2"],
        "amount_of_dports": 10,
        "dstip": "8.8.8.8",
        "state": "Not Established",
    }
    cache_key = vertical_ps.get_cache_key(
        evidence["profileid"], evidence["twid"], evidence["dstip"]
    )

    assert vertical_ps.alerted_once_vertical_ps == {}
    enough = vertical_ps.decide_if_time_to_set_evidence_or_combine(
        evidence, cache_key
    )

    assert enough
    assert vertical_ps.alerted_once_vertical_ps[cache_key]


def test_check_if_enough_dports_to_trigger_an_evidence_equal(mock_db):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)
    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dstip = "8.8.8.8"
    amount_of_dports = 10
    cache_key = vertical_ps.get_cache_key(profileid, timewindow, dstip)
    vertical_ps.cached_tw_thresholds[cache_key] = amount_of_dports

    enough = vertical_ps.check_if_enough_dports_to_trigger_an_evidence(
        cache_key, amount_of_dports
    )

    assert not enough


def test_get_cache_key_empty_values(mock_db):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)
    profileid = ""
    twid = ""
    dstip = ""

    cache_key = vertical_ps.get_cache_key(profileid, twid, dstip)

    assert cache_key == "::dstip::VerticalPortscan"


def test_combine_evidence_multiple_keys(mock_db):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)
    vertical_ps.pending_vertical_ps_evidence = {
        "profile_1.1.1.1-timewindow0-Not Established-TCP-8.8.8.8": [
            (1700828217.314165, 100, ["uid1", "uid2"], 10),
            (1700828217.314165, 200, ["uid3", "uid4"], 10),
            (1700828217.314165, 300, ["uid5", "uid6"], 10),
        ],
        "profile_2.2.2.2-timewindow1-Not Established-UDP-9.9.9.9": [
            (1700828217.314165, 400, ["uid7", "uid8"], 20),
            (1700828217.314165, 500, ["uid9", "uid10"], 20),
            (1700828217.314165, 600, ["uid11", "uid12"], 20),
        ],
    }

    mock_set_evidence = mock_db.set_evidence
    vertical_ps.combine_evidence()
    assert mock_set_evidence.call_count == 2


def test_decide_if_time_to_set_evidence_or_combine_new_cache_key(mock_db):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)
    evidence = {
        "timestamp": 1700828217.314165,
        "pkts_sent": 100,
        "protocol": "TCP",
        "profileid": "profile_1.1.1.1",
        "twid": "timewindow0",
        "uid": ["uid1", "uid2"],
        "amount_of_dports": 10,
        "dstip": "8.8.8.8",
        "state": "Not Established",
    }
    # the goal is to have a key that is not in alerted_once_vertical_ps
    cache_key = "new_cache_key"

    mock_set_evidence = mock_db.set_evidence

    enough = vertical_ps.decide_if_time_to_set_evidence_or_combine(
        evidence, cache_key
    )

    assert enough
    assert vertical_ps.alerted_once_vertical_ps[cache_key]
    mock_set_evidence.assert_called_once()


def test_check_no_connections(mock_db):
    """
    tests vertical_ps.check()
    """
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"

    mock_db.get_data_from_profile_tw.return_value = {}
    mock_set_evidence = mock_db.set_evidence

    vertical_ps.check(profileid, twid)

    mock_set_evidence.assert_not_called()


def test_get_not_established_dst_ips_invalid_protocol(mock_db):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"
    protocol = "INVALID"
    state = "Not Established"

    mock_db.get_data_from_profile_tw.return_value = {}

    dstips = vertical_ps.get_not_established_dst_ips(
        protocol, state, profileid, twid
    )

    assert dstips == {}


@pytest.mark.parametrize(
    "amount_of_dports, expected_return_value",
    [
        (65536, True),
        (1, False),
    ],
)
def test_check_if_enough_dports_to_trigger_an_evidence_large_values(
    mock_db, amount_of_dports, expected_return_value
):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)
    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dstip = "8.8.8.8"
    cache_key = vertical_ps.get_cache_key(profileid, timewindow, dstip)

    enough = vertical_ps.check_if_enough_dports_to_trigger_an_evidence(
        cache_key, amount_of_dports
    )
    assert expected_return_value == enough


def test_get_not_established_dst_ips_db_exception(mock_db):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)
    protocol = "TCP"
    state = "Not Established"
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"

    mock_db.get_data_from_profile_tw.side_effect = Exception("Database error")

    with pytest.raises(Exception):
        vertical_ps.get_not_established_dst_ips(
            protocol, state, profileid, twid
        )


def test_check_overlapping_dstports(mock_db):
    """tests the check() function"""
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"

    tcp_dstips: Dict[str, Dict[int, int]]
    udp_dstips: Dict[str, Dict[int, int]]
    tcp_dstips = enough_dports_to_reach_the_threshold(mock_db)
    udp_dstips = enough_dports_to_reach_the_threshold(mock_db)

    common_dports = set(tcp_dstips["8.8.8.8"]["dstports"].keys()) & set(
        udp_dstips["8.8.8.8"]["dstports"].keys()
    )
    for dport in common_dports:
        tcp_dstips["8.8.8.8"]["dstports"][dport] += udp_dstips["8.8.8.8"][
            "dstports"
        ][dport]

    mock_db.get_data_from_profile_tw.side_effect = [tcp_dstips, udp_dstips]
    mock_set_evidence = mock_db.set_evidence

    vertical_ps.check(profileid, twid)

    assert mock_set_evidence.call_count == 1


def test_set_evidence_vertical_portscan_confidence_exception(
    mock_db, monkeypatch
):
    vertical_ps = ModuleFactory().create_vertical_portscan_obj(mock_db)

    evidence = {
        "timestamp": 1700828217.314165,
        "pkts_sent": 100,
        "protocol": "TCP",
        "profileid": "profile_1.1.1.1",
        "twid": "timewindow0",
        "uid": ["uid1", "uid2"],
        "amount_of_dports": 10,
        "dstip": "8.8.8.8",
    }

    mock_set_evidence = mock_db.set_evidence

    def mock_calculate_confidence(pkts_sent):
        raise ValueError("Invalid packet count")

    monkeypatch.setattr(
        utils, "calculate_confidence", mock_calculate_confidence
    )

    with pytest.raises(ValueError):
        vertical_ps.set_evidence_vertical_portscan(evidence)
    mock_set_evidence.assert_not_called()
