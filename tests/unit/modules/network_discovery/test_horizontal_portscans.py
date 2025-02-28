# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
import random
from unittest.mock import MagicMock, patch
from modules.network_discovery.horizontal_portscan import HorizontalPortscan
from tests.module_factory import ModuleFactory
from slips_files.core.structures.evidence import (
    Proto,
    EvidenceType,
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
    "prev_amount_of_dstips, cur_amount_of_dstips, expected_return_val",
    [
        (0, 5, True),
        (5, 6, False),
        (5, 15, False),
        (15, 29, False),
        (15, 30, True),
    ],
)
def test_check_if_enough_dstips_to_trigger_an_evidence(
    prev_amount_of_dstips, cur_amount_of_dstips, expected_return_val
):
    """
    slip sdetects can based on the number of current dports scanned to the
    number of the ports scanned before
        we make sure the amount of dports reported each evidence
        is higher than the previous one +5
    """
    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dport = 5555

    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()

    key: str = horizontal_ps.get_twid_identifier(profileid, timewindow, dport)
    horizontal_ps.cached_thresholds_per_tw[key] = prev_amount_of_dstips

    enough: bool = horizontal_ps.check_if_enough_dstips_to_trigger_an_evidence(
        key, cur_amount_of_dstips
    )
    assert enough == expected_return_val


def test_check_if_enough_dstips_to_trigger_an_evidence_no_cache():
    """
    Test the check_if_enough_dstips_to_trigger_an_evidence
    method when there is no cached threshold.
    """
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dport = 5555

    key = horizontal_ps.get_twid_identifier(profileid, timewindow, dport)
    cur_amount_of_dstips = 10

    enough = horizontal_ps.check_if_enough_dstips_to_trigger_an_evidence(
        key, cur_amount_of_dstips
    )
    assert enough is True


def test_check_if_enough_dstips_to_trigger_an_evidence_less_than_minimum():
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dport = 5555

    key = horizontal_ps.get_twid_identifier(profileid, timewindow, dport)
    cur_amount_of_dstips = 3

    enough = horizontal_ps.check_if_enough_dstips_to_trigger_an_evidence(
        key, cur_amount_of_dstips
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


def test_check_if_enough_dstips_to_trigger_an_evidence_equal_min_dips():
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dport = 80
    key = horizontal_ps.get_twid_identifier(profileid, timewindow, dport)
    amount_of_dips = horizontal_ps.minimum_dstips_to_set_evidence
    enough = horizontal_ps.check_if_enough_dstips_to_trigger_an_evidence(
        key, amount_of_dips
    )
    assert enough is True


@pytest.mark.parametrize(
    "get_test_conns, expected_return_val",
    [
        (not_enough_dstips_to_reach_the_threshold, False),
        (enough_dstips_to_reach_the_threshold, True),
    ],
)
def test_check_if_enough_dstips_to_trigger_an_evidence_min_dstips_threshold(
    get_test_conns,
    expected_return_val: bool,
):
    """
    test by mocking the connections returned from the database
    """
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()

    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dport = 5555

    dports: dict = get_test_conns()
    horizontal_ps.db.get_data_from_profile_tw.return_value = dports

    cache_key = horizontal_ps.get_twid_identifier(profileid, timewindow, dport)
    amount_of_dips = len(dports[dport]["dstips"])

    assert (
        horizontal_ps.check_if_enough_dstips_to_trigger_an_evidence(
            cache_key, amount_of_dips
        )
        == expected_return_val
    )


def test_get_not_estab_dst_ports():
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"
    protocol = "TCP"
    state = "Not Established"

    mock_dports = {
        80: {"dstips": {"8.8.8.8": {"dstports": {80: 10}}}},
        443: {
            "dstips": {
                "8.8.8.8": {"dstports": {443: 20}},
                "1.1.1.1": {"dstports": {443: 30}},
            }
        },
    }
    horizontal_ps.db.get_data_from_profile_tw.return_value = mock_dports

    dports = horizontal_ps.get_not_estab_dst_ports(
        protocol, state, profileid, twid
    )
    assert dports == mock_dports


def test_get_not_estab_dst_ports_missing_dstports():
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"
    protocol = "TCP"
    state = "Not Established"

    mock_dports = {80: {"dstips": {"8.8.8.8": {}}}}
    horizontal_ps.db.get_data_from_profile_tw.return_value = mock_dports

    dports = horizontal_ps.get_not_estab_dst_ports(
        protocol, state, profileid, twid
    )
    assert dports == mock_dports


def test_get_uids_empty_dstips():
    """
    Test the get_uids method with an empty dstips dictionary.
    """
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    dstips = {}
    uids = horizontal_ps.get_uids(dstips)
    assert uids == []


def test_get_uids():
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    dstips = {
        "1.1.1.1": {"uid": ["uid1", "uid2"]},
        "2.2.2.2": {"uid": ["uid3", "uid4", "uid5"]},
        "3.3.3.3": {"uid": []},
    }
    uids = horizontal_ps.get_uids(dstips)
    assert set(uids) == {"uid1", "uid2", "uid3", "uid4", "uid5"}


def test_get_uids_duplicate():
    """
    Test the get_uids method with a dstips dictionary that has
    duplicate uids
    """
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    dstips = {
        "1.1.1.1": {"uid": ["uid1", "uid2", "uid1"]},
        "2.2.2.2": {"uid": ["uid3", "uid4", "uid5"]},
        "3.3.3.3": {"uid": []},
    }
    uids = horizontal_ps.get_uids(dstips)
    assert set(uids) == {"uid1", "uid2", "uid3", "uid4", "uid5"}


def test_get_not_estab_dst_ports_no_data():
    """
    Test the get_not_estab_dst_ports method when there is no data.
    """
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"
    protocol = "TCP"
    state = "Not Established"

    horizontal_ps.db.get_data_from_profile_tw.return_value = {}

    dports = horizontal_ps.get_not_estab_dst_ports(
        protocol, state, profileid, twid
    )
    assert dports == {}


def test_get_packets_sent():
    horizontal_ps = HorizontalPortscan(MagicMock())
    dstips = {
        "1.1.1.1": {"pkts": 100, "spkts": 50},
        "2.2.2.2": {"pkts": 200, "spkts": 150},
        "3.3.3.3": {"pkts": 300},  # No spkts key
    }

    pkts_sent = horizontal_ps.get_packets_sent(dstips)
    assert pkts_sent == 500


def test_get_packets_sent_empty_dstips():
    """
    Test the get_packets_sent method with an empty dstips dictionary.
    """
    horizontal_ps = HorizontalPortscan(MagicMock())
    dstips = {}
    pkts_sent = horizontal_ps.get_packets_sent(dstips)
    assert pkts_sent == 0


def test_get_packets_sent_invalid_values():
    horizontal_ps = HorizontalPortscan(MagicMock())
    dstips = {
        "1.1.1.1": {"pkts": "invalid", "spkts": 50},
        "2.2.2.2": {"pkts": 200, "spkts": "invalid"},
        "3.3.3.3": {"pkts": 300},
    }
    with pytest.raises(ValueError):
        horizontal_ps.get_packets_sent(dstips)


def test_get_twid_identifier():
    horizontal_ps = HorizontalPortscan(MagicMock())
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"
    dport = 80

    cache_key = horizontal_ps.get_twid_identifier(profileid, twid, dport)
    expected_key = f"{profileid}:{twid}:dport:{dport}"
    assert cache_key == expected_key


def test_get_cache_key_empty_dport():
    horizontal_ps = HorizontalPortscan(MagicMock())
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"
    dport = ""

    cache_key = horizontal_ps.get_twid_identifier(profileid, twid, dport)
    assert cache_key is False


def test_get_cache_key_none_dport():
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"
    dport = None

    cache_key = horizontal_ps.get_twid_identifier(profileid, twid, dport)
    assert cache_key is False


@patch(
    "modules.network_discovery.horizontal_portscan.HorizontalPortscan.get_not_estab_dst_ports"
)
def test_check_broadcast_or_multicast_address(
    mock_get_not_estab_dst_ports,
):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    horizontal_ps.db.get_field_separator.return_value = "_"
    profileid = "profile_255.255.255.255"
    twid = "timewindow0"
    horizontal_ps.check(profileid, twid)
    mock_get_not_estab_dst_ports.assert_not_called()


def test_set_evidence_horizontal_portscan_empty_port_info():
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    evidence = {
        "protocol": "TCP",
        "profileid": "profile_1.1.1.1",
        "twid": "timewindow0",
        "uids": ["uid1", "uid2"],
        "dport": 80,
        "pkts_sent": 100,
        "timestamp": "1234.56",
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


def test_set_evidence_horizontal_portscan_no_uids():
    """
    Test the set_evidence_horizontal_portscan method when there are no uids.
    """
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    evidence = {
        "protocol": "TCP",
        "profileid": "profile_1.1.1.1",
        "twid": "timewindow0",
        "uids": [],
        "dport": 80,
        "pkts_sent": 100,
        "timestamp": "1234.56",
        "state": "Not Established",
        "amount_of_dips": 10,
    }

    horizontal_ps.db.get_port_info.return_value = "HTTP"
    horizontal_ps.db.set_evidence.return_value = None

    horizontal_ps.set_evidence_horizontal_portscan(evidence)

    horizontal_ps.db.set_evidence.assert_called_once()
    call_args = horizontal_ps.db.set_evidence.call_args[0][0]
    assert call_args.uid == []


def test_set_evidence_horizontal_portscan():
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    evidence = {
        "protocol": "TCP",
        "profileid": "profile_1.1.1.1",
        "twid": "timewindow0",
        "uids": ["uid1", "uid2"],
        "dport": 80,
        "pkts_sent": 100,
        "timestamp": "1234.56",
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
        "timestamp": "1234.56",
        "state": "Not Established",
        "amount_of_dips": 10,
    }
    horizontal_ps.db.get_port_info.return_value = "HTTP"
    horizontal_ps.db.set_evidence.return_value = None
    horizontal_ps.set_evidence_horizontal_portscan(evidence)
    assert horizontal_ps.db.set_evidence.call_count == 1
    call_args = horizontal_ps.db.set_evidence.call_args[0][0]
    assert call_args.uid == []


@pytest.mark.parametrize(
    "ip, expected_val",
    [
        ("224.0.0.1", False),
        ("255.255.255.255", False),
        ("invalid", False),
        ("1.1.1.1", True),
    ],
)
def test_is_valid_saddr(ip, expected_val):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    horizontal_ps.db.get_field_separator.return_value = "_"

    profileid = f"profile_{ip}"
    assert horizontal_ps.is_valid_saddr(profileid) == expected_val


def test_check_valid_ip():
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    horizontal_ps.db.get_field_separator.return_value = "_"

    profileid = "profile_10.0.0.1"
    twid = "timewindow0"

    with patch.object(horizontal_ps, "get_not_estab_dst_ports"):
        horizontal_ps.check(profileid, twid)


def test_check_invalid_profileid():
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    profileid = None
    twid = "timewindow0"
    with pytest.raises(Exception):
        horizontal_ps.check(profileid, twid)


def test_is_valid_twid():
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj()
    twid = ""
    assert not horizontal_ps.is_valid_twid(twid)
