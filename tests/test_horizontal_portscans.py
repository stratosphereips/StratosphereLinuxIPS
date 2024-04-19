import pytest
import random
from unittest.mock import MagicMock, patch
from modules.network_discovery.horizontal_portscan import HorizontalPortscan
from tests.module_factory import ModuleFactory
from slips_files.core.evidence_structure.evidence import (
    Proto,
    EvidenceType,
    IDEACategory,
    Tag,
)

random_ports = {
    1234: 1,
    2222: 1,
    12234: 1,
    5555: 1,
}


def generate_random_ip():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))


def enough_dstips_to_reach_the_threshold(mock_db):
    """
    returns conns to dport that are not enough
    to reach the minimum dports to trigger the first scan
    """
    module = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    # get a random list of ints(ports) that are below the threshold
    # Generate a random number between 0 and threshold
    amount_of_dstips: int = random.randint(
        module.minimum_dstips_to_set_evidence, module.minimum_dstips_to_set_evidence + 100
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
        (5, 8, False),
        (5, 15, True),
        (15, 20, True),
    ],
)
def test_check_if_enough_dstips_to_trigger_an_evidence(
    mock_db, prev_amount_of_dstips, cur_amount_of_dstips, expected_return_val
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

    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)

    key: str = horizontal_ps.get_cache_key(profileid, timewindow, dport)
    horizontal_ps.cached_thresholds_per_tw[key] = prev_amount_of_dstips

    enough: bool = horizontal_ps.check_if_enough_dstips_to_trigger_an_evidence(
        key, cur_amount_of_dstips
    )
    assert enough == expected_return_val


def test_check_if_enough_dstips_to_trigger_an_evidence_no_cache(mock_db):
    """
    Test the check_if_enough_dstips_to_trigger_an_evidence
    method when there is no cached threshold.
    """
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dport = 5555

    key = horizontal_ps.get_cache_key(profileid, timewindow, dport)
    cur_amount_of_dstips = 10

    enough = horizontal_ps.check_if_enough_dstips_to_trigger_an_evidence(
        key, cur_amount_of_dstips
    )
    assert enough is True


def test_check_if_enough_dstips_to_trigger_an_evidence_less_than_minimum(
    mock_db,
):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dport = 5555

    key = horizontal_ps.get_cache_key(profileid, timewindow, dport)
    cur_amount_of_dstips = 3

    enough = horizontal_ps.check_if_enough_dstips_to_trigger_an_evidence(
        key, cur_amount_of_dstips
    )
    assert enough is False


def not_enough_dstips_to_reach_the_threshold(mock_db):
    """
    returns conns to dport that are not enough
    to reach the minimum dports to trigger the first scan
    """
    module = ModuleFactory().create_horizontal_portscan_obj(mock_db)
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


def test_check_if_enough_dstips_to_trigger_an_evidence_equal_min_dips(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dport = 80
    key = horizontal_ps.get_cache_key(profileid, timewindow, dport)
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
    get_test_conns, expected_return_val: bool, mock_db
):
    """
    test by mocking the connections returned from the database
    """
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)

    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dport = 5555

    dports: dict = get_test_conns(mock_db)
    mock_db.get_data_from_profile_tw.return_value = dports

    cache_key = horizontal_ps.get_cache_key(profileid, timewindow, dport)
    amount_of_dips = len(dports[dport]["dstips"])

    assert (
        horizontal_ps.check_if_enough_dstips_to_trigger_an_evidence(
            cache_key, amount_of_dips
        )
        == expected_return_val
    )


def test_get_not_estab_dst_ports(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
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
    mock_db.get_data_from_profile_tw.return_value = mock_dports

    dports = horizontal_ps.get_not_estab_dst_ports(
        protocol, state, profileid, twid
    )
    assert dports == mock_dports


def test_get_not_estab_dst_ports_missing_dstports(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"
    protocol = "TCP"
    state = "Not Established"

    mock_dports = {80: {"dstips": {"8.8.8.8": {}}}}
    mock_db.get_data_from_profile_tw.return_value = mock_dports

    dports = horizontal_ps.get_not_estab_dst_ports(
        protocol, state, profileid, twid
    )
    assert dports == mock_dports


def test_get_uids_empty_dstips(mock_db):
    """
    Test the get_uids method with an empty dstips dictionary.
    """
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    dstips = {}
    uids = horizontal_ps.get_uids(dstips)
    assert uids == []


def test_get_uids(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    dstips = {
        "1.1.1.1": {"uid": ["uid1", "uid2"]},
        "2.2.2.2": {"uid": ["uid3", "uid4", "uid5"]},
        "3.3.3.3": {"uid": []},
    }
    uids = horizontal_ps.get_uids(dstips)
    assert set(uids) == {"uid1", "uid2", "uid3", "uid4", "uid5"}


def test_get_uids_duplicate(mock_db):
    """
    Test the get_uids method with a dstips dictionary that has
    duplicate uids
    """
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    dstips = {
        "1.1.1.1": {"uid": ["uid1", "uid2", "uid1"]},
        "2.2.2.2": {"uid": ["uid3", "uid4", "uid5"]},
        "3.3.3.3": {"uid": []},
    }
    uids = horizontal_ps.get_uids(dstips)
    assert set(uids) == {"uid1", "uid2", "uid3", "uid4", "uid5"}


def test_get_not_estab_dst_ports_no_data(mock_db):
    """
    Test the get_not_estab_dst_ports method when there is no data.
    """
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"
    protocol = "TCP"
    state = "Not Established"

    mock_db.get_data_from_profile_tw.return_value = {}

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


def test_get_packets_sent_invalid_values(mock_db):
    horizontal_ps = HorizontalPortscan(MagicMock())
    dstips = {
        "1.1.1.1": {"pkts": "invalid", "spkts": 50},
        "2.2.2.2": {"pkts": 200, "spkts": "invalid"},
        "3.3.3.3": {"pkts": 300},
    }
    with pytest.raises(ValueError):
        horizontal_ps.get_packets_sent(dstips)


def test_get_cache_key():
    horizontal_ps = HorizontalPortscan(MagicMock())
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"
    dport = 80

    cache_key = horizontal_ps.get_cache_key(profileid, twid, dport)
    expected_key = f"{profileid}:{twid}:dport:{dport}:HorizontalPortscan"
    assert cache_key == expected_key


def test_get_cache_key_empty_dport():
    horizontal_ps = HorizontalPortscan(MagicMock())
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"
    dport = ""

    cache_key = horizontal_ps.get_cache_key(profileid, twid, dport)
    assert cache_key is False


def test_get_cache_key_none_dport(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    profileid = "profile_1.1.1.1"
    twid = "timewindow0"
    dport = None

    cache_key = horizontal_ps.get_cache_key(profileid, twid, dport)
    assert cache_key is False


@patch(
    "modules.network_discovery.horizontal_portscan.HorizontalPortscan.get_not_estab_dst_ports"
)
def test_check_broadcast_or_multicast_address(
    mock_get_not_estab_dst_ports, mock_db
):
    mock_db.get_field_separator.return_value = "_"
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    profileid = "profile_255.255.255.255"
    twid = "timewindow0"
    horizontal_ps.check(profileid, twid)
    mock_get_not_estab_dst_ports.assert_not_called()


def test_decide_if_time_to_set_evidence_or_combine_empty_alerted(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    horizontal_ps.alerted_once_horizontal_ps = {}
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

    mock_db.get_port_info.return_value = "HTTP"
    mock_db.set_evidence.return_value = None

    cache_key = horizontal_ps.get_cache_key(
        evidence["profileid"], evidence["twid"], evidence["dport"]
    )
    result = horizontal_ps.decide_if_time_to_set_evidence_or_combine(
        evidence, cache_key
    )

    assert result is True
    assert horizontal_ps.alerted_once_horizontal_ps[cache_key] is True
    mock_db.set_evidence.assert_called_once()


def test_set_evidence_horizontal_portscan_empty_port_info(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
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

    mock_db.get_port_info.return_value = ""
    mock_db.set_evidence.return_value = None

    horizontal_ps.set_evidence_horizontal_portscan(evidence)

    mock_db.set_evidence.assert_called_once()
    call_args = mock_db.set_evidence.call_args[0][0]
    assert call_args.description.startswith(
        "Horizontal port scan to port  80/TCP."
    )


def test_set_evidence_horizontal_portscan_no_uids(mock_db):
    """
    Test the set_evidence_horizontal_portscan method when there are no uids.
    """
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
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

    mock_db.get_port_info.return_value = "HTTP"
    mock_db.set_evidence.return_value = None

    horizontal_ps.set_evidence_horizontal_portscan(evidence)

    mock_db.set_evidence.assert_called_once()
    call_args = mock_db.set_evidence.call_args[0][0]
    assert call_args.uid == []


def test_set_evidence_horizontal_portscan(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
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

    mock_db.get_port_info.return_value = "HTTP"
    mock_db.set_evidence.return_value = None

    horizontal_ps.set_evidence_horizontal_portscan(evidence)

    mock_db.set_evidence.assert_called_once()
    call_args = mock_db.set_evidence.call_args[0][0]
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
    assert call_args.category == IDEACategory.RECON_SCANNING
    assert call_args.conn_count == 100
    assert call_args.proto == Proto("tcp")
    assert call_args.source_target_tag == Tag.RECON
    assert call_args.port == 80


def test_set_evidence_horizontal_portscan_empty_uids(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
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
    mock_db.get_port_info.return_value = "HTTP"
    mock_db.set_evidence.return_value = None
    horizontal_ps.set_evidence_horizontal_portscan(evidence)
    assert mock_db.set_evidence.call_count == 1
    call_args = mock_db.set_evidence.call_args[0][0]
    assert call_args.uid == []


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
def test_combine_evidence(
    number_of_pending_evidence, expected_return_val: bool, mock_db
):
    """
    first evidence will be alerted, the rest will be combined
    """
    profileid = "profile_1.1.1.1"
    timewindow = "timewindow0"
    dstip = "8.8.8.8"
    dport = 5555

    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    key: str = horizontal_ps.get_cache_key(profileid, timewindow, dstip)

    for evidence_ctr in range(number_of_pending_evidence + 1):
        # this will add 2 evidence to the pending evidence list
        evidence = {
            "protocol": "TCP",
            "profileid": profileid,
            "twid": timewindow,
            "uids": [],
            "uid": [],
            "dport": dport,
            "pkts_sent": 5,
            "timestamp": "1234.54",
            "stime": "1234.54",
            "state": "Not Established",
            "amount_of_dips": 70,
        }
        # in the first iteration, enough_to_combine is gonna be True bc
        # it's the first evidence ever
        # next 2 should be false

        enough_to_combine: bool = (
            horizontal_ps.decide_if_time_to_set_evidence_or_combine(
                evidence, key
            )
        )

        if evidence_ctr == 0:
            continue

    assert enough_to_combine == expected_return_val


def test_combine_evidence_different_keys(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    horizontal_ps.pending_horizontal_ps_evidence = {
        "profile_1.1.1.1-timewindow0-Not Established-TCP-80": [
            (1, 10, ["uid1"], 5)
        ],
        "profile_2.2.2.2-timewindow1-Not Established-UDP-53": [
            (2, 20, ["uid2", "uid3"], 10)
        ],
        "profile_3.3.3.3-timewindow2-Not Established-TCP-443": [
            (3, 30, ["uid4"], 15),
            (4, 40, ["uid5"], 20),
            (5, 50, ["uid6"], 25),
        ],
    }
    mock_db.get_port_info.return_value = "HTTP"
    mock_db.set_evidence.return_value = None

    horizontal_ps.combine_evidence()

    assert mock_db.set_evidence.call_count == 3
    assert horizontal_ps.pending_horizontal_ps_evidence == {}


def test_combine_evidence_empty_pending_evidence(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    horizontal_ps.pending_horizontal_ps_evidence = {}
    mock_db.get_port_info.return_value = "HTTP"
    mock_db.set_evidence.return_value = None

    horizontal_ps.combine_evidence()

    assert mock_db.set_evidence.call_count == 0
    assert horizontal_ps.pending_horizontal_ps_evidence == {}


def test_combine_evidence_single_pending_evidence(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    horizontal_ps.pending_horizontal_ps_evidence = {
        "profile_1.1.1.1-timewindow0-Not Established-TCP-80": [
            (1, 10, ["uid1"], 5)
        ]
    }
    mock_db.get_port_info.return_value = "HTTP"
    mock_db.set_evidence.return_value = None

    horizontal_ps.combine_evidence()

    assert mock_db.set_evidence.call_count == 1
    assert horizontal_ps.pending_horizontal_ps_evidence == {}


def test_combine_evidence_no_pending_evidence(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    horizontal_ps.pending_horizontal_ps_evidence = {}
    mock_db.get_port_info.return_value = "HTTP"
    mock_db.set_evidence.return_value = None

    horizontal_ps.combine_evidence()

    assert mock_db.set_evidence.call_count == 0
    assert horizontal_ps.pending_horizontal_ps_evidence == {}


def test_combine_evidence_multiple_keys(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    horizontal_ps.pending_horizontal_ps_evidence = {
        "profile_1.1.1.1-timewindow0-Not Established-TCP-80": [
            (1, 10, ["uid1"], 5),
            (2, 20, ["uid2"], 10),
            (3, 30, ["uid3"], 15),
        ],
        "profile_2.2.2.2-timewindow1-Not Established-UDP-53": [
            (4, 40, ["uid4"], 20),
            (5, 50, ["uid5"], 25),
            (6, 60, ["uid6"], 30),
        ],
    }
    mock_db.get_port_info.side_effect = ["HTTP", "DNS"]
    mock_db.set_evidence.return_value = None
    horizontal_ps.combine_evidence()
    assert mock_db.set_evidence.call_count == 2
    assert horizontal_ps.pending_horizontal_ps_evidence == {}


def test_combine_evidence_empty_port_info(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    horizontal_ps.pending_horizontal_ps_evidence = {
        "profile_1.1.1.1-timewindow0-Not Established-TCP-80": [
            (1, 10, ["uid1"], 5),
            (2, 20, ["uid2"], 10),
            (3, 30, ["uid3"], 15),
        ]
    }
    mock_db.get_port_info.return_value = ""
    mock_db.set_evidence.return_value = None
    horizontal_ps.combine_evidence()
    assert mock_db.set_evidence.call_count == 1
    assert horizontal_ps.pending_horizontal_ps_evidence == {}


def test_check_multicast_address(mock_db):
    mock_db.get_field_separator.return_value = "_"
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)

    profileid = "profile_224.0.0.1"
    twid = "timewindow0"

    with patch.object(
        horizontal_ps, "get_not_estab_dst_ports"
    ) as mock_get_not_estab_dst_ports:
        horizontal_ps.check(profileid, twid)
        mock_get_not_estab_dst_ports.assert_not_called()


def test_get_resolved_ips(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    dstips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]

    mock_db.get_dns_resolution.side_effect = [
        {"domains": ["example.com"]},
        {"domains": []},
        {"domains": ["test.com", "another.com"]},
    ]

    resolved_ips = horizontal_ps.get_resolved_ips(dstips)
    assert sorted(resolved_ips) == ["1.1.1.1", "3.3.3.3"]


def test_get_resolved_ips_empty_list(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    dstips = []

    resolved_ips = horizontal_ps.get_resolved_ips(dstips)
    assert resolved_ips == []


def test_get_resolved_ips_invalid_ip(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    dstips = ["1.1.1.1", "256.256.256.256", "3.3.3.3"]
    mock_db.get_dns_resolution.side_effect = [
        {"domains": ["example.com"]},
        {},
        {"domains": ["test.com"]},
    ]

    resolved_ips = horizontal_ps.get_resolved_ips(dstips)
    assert sorted(resolved_ips) == ["1.1.1.1", "3.3.3.3"]


def test_get_resolved_ips_mixed_list(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    dstips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    mock_db.get_dns_resolution.side_effect = [
        {"domains": ["example.com"]},
        {"domains": []},
        {"domains": ["test.com"]},
    ]
    resolved_ips = horizontal_ps.get_resolved_ips(dstips)
    assert sorted(resolved_ips) == ["1.1.1.1", "3.3.3.3"]


def test_check_valid_ip(mock_db):
    mock_db.get_field_separator.return_value = "_"
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)

    profileid = "profile_10.0.0.1"
    twid = "timewindow0"

    with patch.object(horizontal_ps, "get_not_estab_dst_ports"):
        horizontal_ps.check(profileid, twid)


def test_check_invalid_profileid(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    profileid = None
    twid = "timewindow0"
    with pytest.raises(Exception):
        horizontal_ps.check(profileid, twid)


def test_check_invalid_twid(mock_db):
    horizontal_ps = ModuleFactory().create_horizontal_portscan_obj(mock_db)
    profileid = "profile_1.1.1.1"
    twid = ""
    with pytest.raises(Exception):
        horizontal_ps.check(profileid, twid)
