# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from dataclasses import asdict
from unittest.mock import patch, MagicMock, call, Mock
import json
from tests.module_factory import ModuleFactory
from slips_files.core.flows.zeek import HTTP, DNS, Conn
from unittest.mock import ANY
import pytest


@pytest.mark.parametrize(
    "hget_return_value, expected_out_tuples",
    [  # Testcase 1: Existing OutTuples
        (
            b'[("1.2.3.4", 80, "6.7.8.9", 12345)]',
            b'[("1.2.3.4", 80, "6.7.8.9", 12345)]',
        ),
        # Testcase 2: No OutTuples found
        (
            None,
            None,
        ),
        # Testcase 3: Empty OutTuples list
        (
            b"[]",
            b"[]",
        ),
    ],
)
def test_get_outtuples_from_profile_tw(hget_return_value, expected_out_tuples):
    handler = ModuleFactory().create_profile_handler_obj()
    profileid = "profile_1"
    twid = "timewindow1"
    handler.r.hget.return_value = hget_return_value
    out_tuples = handler.get_outtuples_from_profile_tw(profileid, twid)
    handler.r.hget.assert_called_once_with(
        profileid + handler.separator + twid, "OutTuples"
    )
    assert out_tuples == expected_out_tuples


@pytest.mark.parametrize(
    "hget_return_value, expected_in_tuples",
    [  # Testcase 1: Existing InTuples
        (
            b'[("5.6.7.8", 90, "1.2.3.4", 54321)]',
            b'[("5.6.7.8", 90, "1.2.3.4", 54321)]',
        ),
        # Testcase 2: No InTuples found
        (
            None,
            None,
        ),
        # Testcase 3: Empty InTuples list
        (
            b"[]",
            b"[]",
        ),
    ],
)
def test_get_intuples_from_profile_tw(hget_return_value, expected_in_tuples):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"
    twid = "timewindow1"

    handler.r.hget.return_value = hget_return_value
    in_tuples = handler.get_intuples_from_profile_tw(profileid, twid)
    handler.r.hget.assert_called_once_with(
        profileid + handler.separator + twid, "InTuples"
    )
    assert in_tuples == expected_in_tuples


@pytest.mark.parametrize(
    "hget_return_value, expected_dhcp_flows",
    [  # Testcase 1: Existing DHCP flows
        (
            b'{"192.168.1.100": "abc123"}',
            {"192.168.1.100": "abc123"},
        ),
        # Testcase 2: No DHCP flows found
        (None, None),
        # Testcase 3: Empty DHCP flows dictionary
        (b"{}", {}),
    ],
)
def test_get_dhcp_flows(hget_return_value, expected_dhcp_flows):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"
    twid = "timewindow1"

    handler.r.hget.return_value = hget_return_value
    dhcp_flows = handler.get_dhcp_flows(profileid, twid)
    handler.r.hget.assert_called_once_with("DHCP_flows", f"{profileid}_{twid}")
    assert dhcp_flows == expected_dhcp_flows


@pytest.mark.parametrize(
    "cached_flows, expected_hset_call",
    [
        # Testcase 1: No cached flows
        (
            {},
            (
                "DHCP_flows",
                "profile_1_timewindow1",
                '{"192.168.1.100": "abc123"}',
            ),
        ),
        # Testcase 2: Existing cached flows
        (
            {"192.168.1.101": "def456"},
            (
                "DHCP_flows",
                "profile_1_timewindow1",
                '{"192.168.1.101": "def456", ' '"192.168.1.100": "abc123"}',
            ),
        ),
    ],
)
def test_set_dhcp_flow(cached_flows, expected_hset_call):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.get_dhcp_flows = MagicMock(return_value=cached_flows)

    profileid = "profile_1"
    twid = "timewindow1"
    requested_addr = "192.168.1.100"
    uid = "abc123"
    handler.set_dhcp_flow(profileid, twid, requested_addr, uid)

    handler.r.hset.assert_called_once_with(*expected_hset_call)


@pytest.mark.parametrize(
    "flags, packet_count, expected_state",
    [
        # Testcase1: Established states
        ("SA_SA", 10, "Established"),
        ("PA_PA", 10, "Established"),
        ("S1", 10, "Established"),
        ("EST", 10, "Established"),
        ("RST", 10, "Established"),
        ("FIN", 10, "Established"),
        # Testcase2: Not Established states
        ("S_RA", 10, "Not Established"),
        ("S0", 10, "Not Established"),
        ("INT", 10, "Not Established"),
        ("RST", 3, "Not Established"),
        ("FIN", 3, "Not Established"),
        # Testcase3: ICMP states
        ("ECO", 10, "Established"),
        ("UNK", 10, "Established"),
        # Testcase4: Other states
        ("CON", 10, "Established"),
        ("ECO", 10, "Established"),
        ("ECR", 10, "Not Established"),
        ("URH", 10, "Not Established"),
        ("URP", 10, "Not Established"),
    ],
)
def test_get_final_state_from_flags(flags, packet_count, expected_state):
    handler = ModuleFactory().create_profile_handler_obj()

    final_state = handler.get_final_state_from_flags(flags, packet_count)
    assert final_state == expected_state


@pytest.mark.parametrize(
    "hget_return_value, expected_data",
    [  # Testcase 1: Data exists
        (
            json.dumps(
                {
                    "80": {
                        "totalflows": 10,
                        "totalpkt": 100,
                        "totalbytes": 10240,
                    }
                }
            ).encode(),
            {"80": {"totalflows": 10, "totalpkt": 100, "totalbytes": 10240}},
        ),
        # Testcase 2: Data does not exist
        (None, {}),
        # Testcase 3: Empty data
        (b"{}", {}),
    ],
)
def test_get_data_from_profile_tw(hget_return_value, expected_data):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"
    twid = "timewindow1"
    direction = "Dst"
    state = "Established"
    protocol = "TCP"
    role = "Client"
    type_data = "Ports"

    expected_key = "DstPortsClientTCPEstablished"

    handler.r.hget.return_value = hget_return_value

    data = handler.get_data_from_profile_tw(
        profileid, twid, direction, state, protocol, role, type_data
    )

    handler.r.hget.assert_called_once_with(
        f"{profileid}{handler.separator}{twid}", expected_key
    )
    assert data == expected_data


@pytest.mark.parametrize(
    "old_data, pkts, dport, spkts, totbytes, ip, "
    "starttime, uid, expected_data",
    [
        # Test case 1: Empty old data
        (
            {},
            10,
            80,
            5,
            1024,
            "1.2.3.4",
            "1678886400.0",
            "abc123",
            {
                "1.2.3.4": {
                    "totalflows": 1,
                    "totalpkt": 10,
                    "totalbytes": 1024,
                    "stime": "1678886400.0",
                    "uid": ["abc123"],
                    "dstports": {"80": 5},
                }
            },
        ),
        # Test case 2: Existing IP with different dport
        (
            {
                "1.2.3.4": {
                    "totalflows": 1,
                    "totalpkt": 5,
                    "totalbytes": 512,
                    "stime": "1678886300.0",
                    "uid": ["def456"],
                    "dstports": {"443": 3},
                }
            },
            10,
            80,
            5,
            1024,
            "1.2.3.4",
            "1678886400.0",
            "abc123",
            {
                "1.2.3.4": {
                    "totalflows": 2,
                    "totalpkt": 15,
                    "totalbytes": 1536,
                    "stime": "1678886300.0",
                    "uid": ["def456", "abc123"],
                    "dstports": {"443": 3, "80": 5},
                }
            },
        ),
        # Test case 3: Existing IP with same dport
        (
            {
                "1.2.3.4": {
                    "totalflows": 1,
                    "totalpkt": 5,
                    "totalbytes": 512,
                    "stime": "1678886300.0",
                    "uid": ["def456"],
                    "dstports": {"80": 3},
                }
            },
            10,
            80,
            5,
            1024,
            "1.2.3.4",
            "1678886400.0",
            "abc123",
            {
                "1.2.3.4": {
                    "totalflows": 2,
                    "totalpkt": 15,
                    "totalbytes": 1536,
                    "stime": "1678886300.0",
                    "uid": ["def456", "abc123"],
                    "dstports": {"80": 8},
                }
            },
        ),
    ],
)
def test_update_ip_info(
    old_data, pkts, dport, spkts, totbytes, ip, starttime, uid, expected_data
):
    handler = ModuleFactory().create_profile_handler_obj()

    updated_data = handler.update_ip_info(
        old_data, pkts, dport, spkts, totbytes, ip, starttime, uid
    )

    assert updated_data == expected_data


@pytest.mark.parametrize(
    "hget_return_value, expected_hset_call",
    [
        # Testcase 1: No previous data
        (
            None,
            (
                "profile_1_timewindow1",
                "DstIPs",
                json.dumps({"192.168.1.100": 1}),
            ),
        ),
        # Testcase 2: Existing data
        (
            b'{"192.168.1.100": 2}',
            (
                "profile_1_timewindow1",
                "DstIPs",
                json.dumps({"192.168.1.100": 3}),
            ),
        ),
    ],
)
def test_update_times_contacted(hget_return_value, expected_hset_call):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"
    twid = "timewindow1"
    ip = "192.168.1.100"
    direction = "Dst"

    handler.r.hget.return_value = hget_return_value
    handler.update_times_contacted(ip, direction, profileid, twid)
    handler.r.hset.assert_called_once_with(*expected_hset_call)


@pytest.mark.parametrize(
    "all_flows, expected_contacted_ips",
    [
        # Testcase 1: Empty all_flows dictionary
        ({}, {}),
        # Testcase 2: Non-empty all_flows dictionary
        (
            {
                "uid1": {"daddr": "192.168.1.100"},
                "uid2": {"daddr": "10.0.0.1"},
                "uid3": {"daddr": "192.168.1.101"},
            },
            {
                "192.168.1.100": "uid1",
                "10.0.0.1": "uid2",
                "192.168.1.101": "uid3",
            },
        ),
        # Testcase 3: all_flows with duplicate daddr
        (
            {
                "uid1": {"daddr": "192.168.1.100"},
                "uid2": {"daddr": "10.0.0.1"},
                "uid3": {"daddr": "192.168.1.100"},
            },
            {
                "192.168.1.100": "uid3",
                "10.0.0.1": "uid2",
            },
        ),
    ],
)
def test_get_all_contacted_ips_in_profileid_twid(
    all_flows, expected_contacted_ips
):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"
    twid = "timewindow1"

    handler.get_all_flows_in_profileid_twid = MagicMock(return_value=all_flows)

    contacted_ips = handler.get_all_contacted_ips_in_profileid_twid(
        profileid, twid
    )

    assert contacted_ips == expected_contacted_ips


@pytest.mark.parametrize(
    "blocked_tws, expected_hset_call",
    [
        # Testcase 1: No previous blocked TWs
        ([], ("BlockedProfTW", "profile_1", json.dumps(["timewindow3"]))),
        # Testcase 2: Existing blocked TWs
        (
            ["timewindow1", "timewindow2"],
            (
                "BlockedProfTW",
                "profile_1",
                json.dumps(["timewindow1", "timewindow2", "timewindow3"]),
            ),
        ),
    ],
)
def test_mark_profile_and_timewindow_as_blocked(
    blocked_tws, expected_hset_call
):
    handler = ModuleFactory().create_profile_handler_obj()
    handler.get_blocked_timewindows_of_profile = MagicMock(
        return_value=blocked_tws
    )

    profileid = "profile_1"
    twid = "timewindow3"

    handler.mark_profile_and_timewindow_as_blocked(profileid, twid)
    handler.r.hset.assert_called_once_with(*expected_hset_call)


@pytest.mark.parametrize(
    "hget_return_value, expected_tws",
    [  # Testcase 1: TWs exist for the profile
        (
            json.dumps(["timewindow1", "timewindow2"]).encode(),
            b'["timewindow1", "timewindow2"]',
        ),
        # Testcase 2: No TWs exist for the profile
        (None, None),
    ],
)
def test_get_blocked_profiles_and_timewindows(hget_return_value, expected_tws):
    handler = ModuleFactory().create_profile_handler_obj()
    handler.r.hgetall.return_value = hget_return_value
    tws = handler.get_blocked_profiles_and_timewindows()
    handler.r.hgetall.assert_called_once_with("BlockedProfTW")
    assert tws == expected_tws


@pytest.mark.parametrize(
    "zrank_return_value, expected_was_modified",
    [
        # Testcase 1: TW was modified
        (1, True),
        # Testcase 2: TW was not modified
        (None, False),
    ],
)
def test_was_profile_and_tw_modified(
    zrank_return_value, expected_was_modified
):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"
    twid = "timewindow1"
    handler.r.zrank.return_value = zrank_return_value

    was_modified = handler.was_profile_and_tw_modified(profileid, twid)

    handler.r.zrank.assert_called_with(
        "ModifiedTW", f"{profileid}{handler.separator}{twid}"
    )
    assert was_modified == expected_was_modified


@pytest.mark.parametrize(
    "hget_return_value, expected_total_flows",
    [  # Test case 1: Total flows exist
        (b"1000", b"1000"),
        # Test case 2: Total flows do not exist
        (None, None),
    ],
)
def test_get_total_flows(hget_return_value, expected_total_flows):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.r.hget.return_value = hget_return_value

    total_flows = handler.get_total_flows()

    handler.r.hget.assert_called_once_with("analysis", "total_flows")
    assert total_flows == expected_total_flows


@pytest.mark.parametrize(
    "ip, sismember_return_value, expected_profileid",
    [
        # Testcase 1: IP exists in profiles set
        ("1.2.3.4", True, "profile_1.2.3.4"),
        # Testcase 2: IP does not exist in profiles set
        ("5.6.7.8", False, False),
    ],
)
def test_get_profileid_from_ip(ip, sismember_return_value, expected_profileid):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.r.sismember.return_value = sismember_return_value

    profileid = handler.get_profileid_from_ip(ip)

    handler.r.sismember.assert_called_once_with("profiles", f"profile_{ip}")
    assert profileid == expected_profileid


@pytest.mark.parametrize(
    "smembers_return_value, expected_profiles",
    [
        # Test Case 1: No profiles exist
        (set(), {}),
        # Test Case 2: One profile exists
        ({"profile_1"}, {"profile_1"}),
        # Test Case 3: Multiple profiles exist
        (
            {"profile_1", "profile_2", "profile_3"},
            {"profile_1", "profile_2", "profile_3"},
        ),
    ],
)
def test_get_profiles(smembers_return_value, expected_profiles):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.r.smembers.return_value = smembers_return_value

    profiles = handler.get_profiles()
    handler.r.smembers.assert_called_once_with("profiles")
    assert profiles == expected_profiles


@pytest.mark.parametrize(
    "profileid, expected_num_tws, "
    "expected_get_tws_from_profile_return_value",
    [  # Testcase 1: Profile with multiple timewindows
        (
            "profile_1",
            2,
            [("timewindow1", 1600000000.0), ("timewindow2", 1600000100.0)],
        ),
        # Testcase 2: Profile with no timewindows
        (
            "profile_2",
            0,
            [],
        ),
    ],
)
def test_get_number_of_tws_in_profile(
    profileid, expected_num_tws, expected_get_tws_from_profile_return_value
):
    handler = ModuleFactory().create_profile_handler_obj()
    handler.get_tws_from_profile = MagicMock(
        return_value=expected_get_tws_from_profile_return_value
    )

    num_tws = handler.get_number_of_tws_in_profile(profileid)
    handler.get_tws_from_profile.assert_called_once_with(profileid)
    assert num_tws == expected_num_tws


@pytest.mark.parametrize(
    "profileid, twid, expected_srcips, expected_hget_call",
    [  # Testcase 1: Existing SrcIPs data
        (
            "profile_1",
            "timewindow1",
            b'{"1.2.3.4": 3, "5.6.7.8": 1}',
            call("profile_1_timewindow1", "SrcIPs"),
        ),
        # Testcase 2: No SrcIPs data
        (
            "profile_2",
            "timewindow2",
            None,
            call("profile_2_timewindow2", "SrcIPs"),
        ),
    ],
)
def test_get_srcips_from_profile_tw(
    profileid, twid, expected_srcips, expected_hget_call
):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.r.hget.return_value = expected_srcips
    srcips = handler.get_srcips_from_profile_tw(profileid, twid)
    handler.r.hget.assert_called_once_with(*expected_hget_call.args)
    assert srcips == expected_srcips


@pytest.mark.parametrize(
    "profileid, zrange_return_value, expected_tws",
    [  # Testcase 1: Profile with multiple timewindows
        (
            "profile_1",
            [("timewindow1", 1600000000.0), ("timewindow2", 1600000100.0)],
            [("timewindow1", 1600000000.0), ("timewindow2", 1600000100.0)],
        ),
        # Testcase 2: Profile with no timewindows
        (
            "profile_2",
            [],
            [],
        ),
        # Testcase 3: No profile ID provided
        (None, None, False),
    ],
)
def test_get_tws_from_profile(profileid, zrange_return_value, expected_tws):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.r.zrange.return_value = zrange_return_value

    tws = handler.get_tws_from_profile(profileid)

    assert handler.r.zrange.called is bool(profileid)
    assert tws == expected_tws


@pytest.mark.parametrize(
    "profileid, twid, expected_dstips, expected_hget_call",
    [  # Testcase 1: Existing DstIPs data
        (
            "profile_1",
            "timewindow1",
            b'{"8.8.8.8": 1}',
            call("profile_1_timewindow1", "DstIPs"),
        ),
        # Testcase 2: No DstIPs data
        (
            "profile_2",
            "timewindow2",
            None,
            call("profile_2_timewindow2", "DstIPs"),
        ),
        # Testcase 3: Empty DstIPs data
        (
            "profile_3",
            "timewindow3",
            b"{}",
            call("profile_3_timewindow3", "DstIPs"),
        ),
    ],
)
def test_get_dstips_from_profile_tw(
    profileid, twid, expected_dstips, expected_hget_call
):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.r.hget.return_value = expected_dstips
    dstips = handler.get_dstips_from_profile_tw(profileid, twid)
    handler.r.hget.assert_called_once_with(*expected_hget_call.args)
    assert dstips == expected_dstips


@pytest.mark.parametrize(
    "sismember_return_value, expected_has_profile",
    [  # Testcase 1: Profile exists
        (True, True),
        # Testcase 2: Profile does not exist
        (False, False),
    ],
)
def test_has_profile(sismember_return_value, expected_has_profile):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"

    handler.r.sismember.return_value = sismember_return_value
    has_profile = handler.has_profile(profileid)
    handler.r.sismember.assert_called_once_with("profiles", profileid)
    assert has_profile == expected_has_profile


@pytest.mark.parametrize(
    "scard_return_value, expected_profiles_len",
    [  # Test Case 1: No profiles exist
        (0, 0),
        # Test Case 2: One profile exists
        (1, 1),
        # Test Case 3: Multiple profiles exist
        (3, 3),
    ],
)
def test_get_profiles_len(scard_return_value, expected_profiles_len):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.r.scard.return_value = scard_return_value

    profiles_len = handler.get_profiles_len()
    handler.r.scard.assert_called_once_with("profiles")
    assert profiles_len == expected_profiles_len


@pytest.mark.parametrize(
    "zrange_return_value, expected_twid, expected_starttime",
    [  # Testcase 1: Profile with one timewindow
        (
            [("timewindow2", 1100.0)],
            "timewindow2",
            1100.0,
        ),
        # Testcase 2: Profile with a large timewindow index
        (
            [("timewindow10", 2000.0)],
            "timewindow10",
            2000.0,
        ),
    ],
)
def test_get_last_twid_of_profile(
    zrange_return_value, expected_twid, expected_starttime
):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"

    handler.r.zrange.return_value = zrange_return_value
    twid, starttime = handler.get_last_twid_of_profile(profileid)
    handler.r.zrange.assert_called_once_with(
        f"tws{profileid}", -1, -1, withscores=True
    )
    assert twid == expected_twid
    assert starttime == expected_starttime


@pytest.mark.parametrize(
    "zrange_return_value, expected_twid, expected_starttime_of_tw",
    [  # Testcase 1: Profile with one timewindow
        (
            [("timewindow1", 900.0)],
            "timewindow1",
            900.0,
        ),
        # Testcase 2: Profile with a negative timewindow
        (
            [("timewindow-1", 800.0)],
            "timewindow-1",
            800.0,
        ),
    ],
)
def test_get_first_twid_for_profile(
    zrange_return_value, expected_twid, expected_starttime_of_tw
):
    handler = ModuleFactory().create_profile_handler_obj()
    profileid = "profile_1"

    handler.r.zrange.return_value = zrange_return_value
    twid, starttime_of_tw = handler.get_first_twid_for_profile(profileid)
    handler.r.zrange.assert_called_once_with(
        f"tws{profileid}", 0, 0, withscores=True
    )
    assert twid == expected_twid
    assert starttime_of_tw == expected_starttime_of_tw


@pytest.mark.parametrize(
    "profileid, timewindow, startoftw, expected_zadd_call, "
    "expected_update_threat_level_call",
    [  # Testcase 1: Normal case
        (
            "profile_1",
            "timewindow2",
            1100.0,
            call("tws" + "profile_1", {"timewindow2": 1100.0}),
            call("profile_1", "info", 0.5),
        ),
        # Testcase 2: Negative timewindow ID
        (
            "profile_2",
            "timewindow-1",
            900.0,
            call("tws" + "profile_2", {"timewindow-1": 900.0}),
            call("profile_2", "info", 0.5),
        ),
        # Testcase 3: Large timewindow ID
        (
            "profile_3",
            "timewindow100",
            10000.0,
            call("tws" + "profile_3", {"timewindow100": 10000.0}),
            call("profile_3", "info", 0.5),
        ),
    ],
)
def test_add_new_tw(
    profileid,
    timewindow,
    startoftw,
    expected_zadd_call,
    expected_update_threat_level_call,
):
    handler = ModuleFactory().create_profile_handler_obj()
    handler.update_threat_level = MagicMock()

    handler.add_new_tw(profileid, timewindow, startoftw)

    handler.r.zadd.assert_called_once_with(*expected_zadd_call.args)
    handler.update_threat_level.assert_called_once_with(
        *expected_update_threat_level_call.args
    )


@pytest.mark.parametrize(
    "zscore_return_value, expected_start_time",
    [  # Testcase 1: TW exists and has a start time
        (1100.0, 1100.0),
        # Testcase 2: TW does not exist
        (None, None),
    ],
)
def test_get_tw_start_time(zscore_return_value, expected_start_time):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"
    twid = "timewindow2"

    handler.r.zscore.return_value = zscore_return_value

    start_time = handler.get_tw_start_time(profileid, twid)

    handler.r.zscore.assert_called_once_with(
        f"tws{profileid}", twid.encode("utf-8")
    )
    assert start_time == expected_start_time


@pytest.mark.parametrize(
    "profileid, zcard_return_value, expected_num_tws",
    [  # Testcase 1: Profile with 3 timewindows
        ("profile_1", 3, 3),
        # Testcase 2: Profile with no timewindows
        ("profile_2", 0, 0),
    ],
)
def test_get_number_of_tws_with_profileid(
    profileid, zcard_return_value, expected_num_tws
):
    handler = ModuleFactory().create_profile_handler_obj()
    handler.r.zcard.return_value = zcard_return_value
    num_tws = handler.get_number_of_tws(profileid)

    handler.r.zcard.assert_called_once_with(f"tws{profileid}")
    assert num_tws == expected_num_tws


def test_get_number_of_tws_without_profileid():
    handler = ModuleFactory().create_profile_handler_obj()
    num_tws = handler.get_number_of_tws(None)
    handler.r.zcard.assert_not_called()
    assert num_tws is False


@pytest.mark.parametrize(
    "time, expected_modified_tws, zrangebyscore_return_value",
    [  # Testcase 1: Modified TWs exist after given time
        (
            1200.0,
            [("profile_1_timewindow2", 1250.0)],
            [("profile_1_timewindow2", 1250.0)],
        ),
        # Testcase 2: No modified TWs after given time
        (
            1300.0,
            [],
            [],
        ),
        # Testcase 3: Get all modified TWs since the beginning
        (
            0,
            [("profile_1_timewindow1", 1100.0)],
            [("profile_1_timewindow1", 1100.0)],
        ),
    ],
)
def test_get_modified_tw_since_time(
    time, expected_modified_tws, zrangebyscore_return_value
):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.r.zrangebyscore.return_value = zrangebyscore_return_value

    modified_tws = handler.get_modified_tw_since_time(time)

    handler.r.zrangebyscore.assert_called_once_with(
        "ModifiedTW", time, float("+inf"), withscores=True
    )
    assert modified_tws == expected_modified_tws


@pytest.mark.parametrize(
    "hmget_return_value, expected_software",
    [  # Test case 1: Software data exists
        (
            [
                json.dumps(
                    {
                        "Software1": {
                            "version-major": 1,
                            "version-minor": 2,
                            "uid": "abc123",
                        }
                    }
                )
            ],
            {
                "Software1": {
                    "version-major": 1,
                    "version-minor": 2,
                    "uid": "abc123",
                }
            },
        ),
        # Test case 2: No software data exists
        ([None], None),
        # Test case 3: Empty software data
        ([b"{}"], {}),
        # Test case 4: Multiple software entries
        (
            [
                json.dumps(
                    {
                        "Software1": {
                            "version-major": 1,
                            "version-minor": 2,
                            "uid": "abc123",
                        },
                        "Software2": {
                            "version-major": 3,
                            "version-minor": 0,
                            "uid": "def456",
                        },
                    }
                )
            ],
            {
                "Software1": {
                    "version-major": 1,
                    "version-minor": 2,
                    "uid": "abc123",
                },
                "Software2": {
                    "version-major": 3,
                    "version-minor": 0,
                    "uid": "def456",
                },
            },
        ),
    ],
)
def test_get_software_from_profile(hmget_return_value, expected_software):
    handler = ModuleFactory().create_profile_handler_obj()
    profileid = "profile_1"
    handler.r.hmget.return_value = hmget_return_value

    software = handler.get_software_from_profile(profileid)

    handler.r.hmget.assert_called_once_with(profileid, "used_software")
    assert software == expected_software


@pytest.mark.parametrize(
    "hmget_return_value, expected_user_agent",
    [  # Testcase 1: User agent exists
        (
            ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)"],
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        ),
        # Testcase 2: User agent does not exist
        ([None], None),
    ],
)
def test_get_first_user_agent(hmget_return_value, expected_user_agent):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"

    handler.r.hmget.return_value = hmget_return_value

    user_agent = handler.get_first_user_agent(profileid)
    handler.r.hmget.assert_called_once_with(profileid, "first user-agent")
    assert user_agent == expected_user_agent


@pytest.mark.parametrize(
    "get_first_user_agent_return_value, " "expected_user_agent",
    [  # Testcase 1: Valid user agent JSON
        (
            json.dumps(
                {
                    "os_name": "Windows",
                    "os_type": "NT",
                    "browser": "Firefox",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                }
            ),
            {
                "os_name": "Windows",
                "os_type": "NT",
                "browser": "Firefox",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            },
        ),
        # Testcase 2: User agent is a string,
        # no deserialization needed
        (
            "OpenSSH_8.6",
            "OpenSSH_8.6",
        ),
        # Testcase 3: First user agent is None
        (None, None),
    ],
)
def test_get_user_agent_from_profile(
    get_first_user_agent_return_value, expected_user_agent
):
    handler = ModuleFactory().create_profile_handler_obj()
    profileid = "profile_1"

    handler.get_first_user_agent = MagicMock(
        return_value=get_first_user_agent_return_value
    )

    user_agent = handler.get_user_agent_from_profile(profileid)

    handler.get_first_user_agent.assert_called_once_with(profileid)
    assert user_agent == expected_user_agent


@pytest.mark.parametrize(
    "get_profile_modules_labels_return_value, " "module, label, expected_data",
    [
        # Testcase 1: No existing module labels
        ({}, "test_module", "test_label", {"test_module": "test_label"}),
        # Testcase 2: Existing module labels, adding a new one
        (
            {"module1": "label1"},
            "test_module",
            "test_label",
            {"module1": "label1", "test_module": "test_label"},
        ),
        # Testcase 3: Existing module labels,
        # overwriting an existing one
        (
            {"test_module": "old_label"},
            "test_module",
            "new_label",
            {"test_module": "new_label"},
        ),
    ],
)
def test_set_profile_module_label(
    get_profile_modules_labels_return_value, module, label, expected_data
):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.get_modules_labels_of_a_profile = MagicMock(
        return_value=get_profile_modules_labels_return_value
    )

    profileid = "profile_1"

    handler.set_module_label_for_profile(profileid, module, label)

    expected_data_str = json.dumps(expected_data)
    handler.r.hset.assert_called_once_with(
        profileid, "modules_labels", expected_data_str
    )


@pytest.mark.parametrize(
    "prev_symbols, expected_prev_symbols, publish_called",
    [
        (None, {"1.2.3.4-80-TCP": ("A", (1.0, 1000.0))}, False),  # first time
        (
            b'{"1.2.3.4-80-TCP": ["AB", [0.5, 900.0]]}',
            # AB are the old ones, A is the new one, so we expect AB then A
            # (ABA)
            {"1.2.3.4-80-TCP": ("ABA", (1.0, 1000.0))},
            True,  # not first time
        ),
    ],
)
def test_add_tuple(prev_symbols, expected_prev_symbols, publish_called):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.publish_new_letter = MagicMock()
    handler.mark_profile_tw_as_modified = MagicMock()

    profileid = "profile_1"
    twid = "timewindow1"
    tupleid = "1.2.3.4-80-TCP"
    symbol = ("A", (1.0, 1000.0))
    role = "Client"
    flow = MagicMock()

    handler.r.hget.return_value = prev_symbols

    handler.add_tuple(profileid, twid, tupleid, symbol, role, flow)

    expected_prev_symbols_str = json.dumps(expected_prev_symbols)
    profileid_twid = f"{profileid}{handler.separator}{twid}"

    handler.r.hset.assert_called_once_with(
        profileid_twid, "OutTuples", expected_prev_symbols_str
    )
    handler.mark_profile_tw_as_modified.assert_called_once_with(
        profileid, twid, flow.starttime
    )
    if publish_called:
        handler.publish_new_letter.assert_called_once_with(
            "ABA", profileid, twid, tupleid, flow
        )
    else:
        handler.publish_new_letter.assert_not_called()


@pytest.mark.parametrize(
    "close_all, zrangebyscore_return_value, expected_calls",
    [  # Testcase1: close all is false
        (
            False,
            [("profile_1_timewindow1", 900.0)],
            [call("profile_1_timewindow1")],
        ),
        # Testcase2: close all is true
        (
            True,
            [
                ("profile_1_timewindow1", 900.0),
                ("profile_2_timewindow2", 1100.0),
            ],
            [call("profile_1_timewindow1"), call("profile_2_timewindow2")],
        ),
    ],
)
def test_check_tw_to_close(
    close_all, zrangebyscore_return_value, expected_calls
):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.get_slips_internal_time = MagicMock(return_value=1000.0)
    handler.width = 100
    handler.mark_profile_tw_as_closed = MagicMock()

    handler.r.zrangebyscore.return_value = zrangebyscore_return_value

    handler.check_tw_to_close(close_all=close_all)

    handler.mark_profile_tw_as_closed.assert_has_calls(expected_calls)


@pytest.mark.parametrize(
    "sadd_return_value, zrem_return_value, publish_call_count",
    [  # Testcase 1: Successful execution
        (
            1,
            1,
            1,
        ),
        # Testcase 2: Profile/TW already marked as closed
        (
            0,
            0,
            1,
        ),
    ],
)
def test_mark_profile_tw_as_closed(
    sadd_return_value, zrem_return_value, publish_call_count
):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.r.sadd.return_value = sadd_return_value
    handler.r.zrem.return_value = zrem_return_value
    handler.publish = MagicMock()

    profileid_tw = "profile_1_timewindow1"

    handler.mark_profile_tw_as_closed(profileid_tw)

    handler.r.sadd.assert_called_once_with("ClosedTW", profileid_tw)
    handler.r.zrem.assert_called_once_with("ModifiedTW", profileid_tw)
    assert handler.publish.call_count == publish_call_count


@pytest.mark.parametrize(
    "first_index, zcard_return_value, zrange_return_value, "
    "expected_data, expected_last_index",
    [  # Testcase 1: Get all lines
        (
            0,
            2,
            [b'{"event": "login"}', b'{"event": "logout"}'],
            [b'{"event": "login"}', b'{"event": "logout"}'],
            2,
        ),
        # Testcase 2: Get lines from index 1
        (
            1,
            3,
            [b'{"event": "logout"}', b'{"event": "download"}'],
            [b'{"event": "logout"}', b'{"event": "download"}'],
            3,
        ),
        # Testcase 3: first_index is equal
        # to the number of lines
        (
            2,
            2,
            [],
            [],
            2,
        ),
        # Testcase 4: first_index is greater than
        # the number of lines
        (3, 2, [], [], 2),
    ],
)
def test_get_timeline_last_lines(
    first_index,
    zcard_return_value,
    zrange_return_value,
    expected_data,
    expected_last_index,
):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"
    twid = "timewindow1"

    handler.r.zcard.return_value = zcard_return_value
    handler.r.zrange.return_value = zrange_return_value
    data, last_index = handler.get_timeline_last_lines(
        profileid, twid, first_index
    )

    key = str(
        profileid + handler.separator + twid + handler.separator + "timeline"
    )
    handler.r.zcard.assert_called_once_with(key)
    handler.r.zrange.assert_called_once_with(
        key, first_index, zcard_return_value - 1
    )
    assert data == expected_data
    assert last_index == expected_last_index


@pytest.mark.parametrize(
    "profileid, ip, expected_hset_call",
    [  # Test Case 1: Single IPv6 address
        (
            "profile_1",
            ["2001:db8::1"],
            ("profile_1", "IPv6", '["2001:db8::1"]'),
        ),
        # Test Case 2: Multiple IPv6 addresses
        (
            "profile_2",
            ["2001:db8::1", "2001:db8::2"],
            ("profile_2", "IPv6", '["2001:db8::1", "2001:db8::2"]'),
        ),
        # Test Case 3: Empty list of IPv6 addresses
        ("profile_3", [], ("profile_3", "IPv6", "[]")),
    ],
)
def test_set_ipv6_of_profile(profileid, ip, expected_hset_call):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.set_ipv6_of_profile(profileid, ip)
    handler.r.hset.assert_called_once_with(*expected_hset_call)


@pytest.mark.parametrize(
    "profileid, ip, expected_hset_call",
    [  # Test Case 1: Valid IPv4 address
        ("profile_1", "192.168.1.1", ("profile_1", "IPv4", '["192.168.1.1"]')),
        # Test Case 2: Another valid IPv4 address
        ("profile_2", "10.0.0.1", ("profile_2", "IPv4", '["10.0.0.1"]')),
        # Test Case 3: Special case - 0.0.0.0
        ("profile_3", "0.0.0.0", ("profile_3", "IPv4", '["0.0.0.0"]')),
    ],
)
def test_set_ipv4_of_profile(profileid, ip, expected_hset_call):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.set_ipv4_of_profile(profileid, ip)
    handler.r.hset.assert_called_once_with(*expected_hset_call)


@pytest.mark.parametrize(
    "get_modified_tw_since_time_return_value, "
    "expected_profiles, expected_last_modified_time",
    [
        # Testcase 1: No modified TWs
        ([], [], 0),
        # Testcase 2: One modified TW
        (
            [("profile_1_timewindow2", 1250.0)],
            {"1"},
            1250.0,
        ),
        # Testcase 3: Multiple modified TWs, same profile
        (
            [
                ("profile_1_timewindow1", 1200.0),
                ("profile_1_timewindow2", 1250.0),
            ],
            {"1"},
            1250.0,
        ),
        # Testcase 4: Multiple modified TWs, different profiles
        (
            [
                ("profile_1_timewindow2", 1250.0),
                ("profile_2_timewindow1", 1300.0),
            ],
            {"1", "2"},
            1300.0,
        ),
    ],
)
def test_get_modified_profiles_since(
    get_modified_tw_since_time_return_value,
    expected_profiles,
    expected_last_modified_time,
):
    handler = ModuleFactory().create_profile_handler_obj()
    handler.get_modified_tw_since_time = MagicMock(
        return_value=get_modified_tw_since_time_return_value
    )
    time = 1200.0

    profiles, last_modified_time = handler.get_modified_profiles_since(time)

    handler.get_modified_tw_since_time.assert_called_once_with(time)
    assert profiles == expected_profiles
    assert last_modified_time == expected_last_modified_time


@pytest.mark.parametrize(
    "profileid, mac, expected_hset_call",
    [  # Test case 1: Valid profileid and MAC address
        (
            "profile_192.168.1.100",
            "00:11:22:33:44:55",
            ("profile_192.168.1.100", "MAC", "00:11:22:33:44:55"),
        ),
        # Test case 2: Valid profileid, None MAC address
        (
            "profile_192.168.1.100",
            None,
            ("profile_192.168.1.100", "MAC", None),
        ),
        # Test case 3: None profileid, valid MAC address
        (
            None,
            "00:11:22:33:44:55",
            (None, "MAC", "00:11:22:33:44:55"),
        ),
        # Test case 4: Both None
        (None, None, (None, "MAC", None)),
    ],
)
def test_update_mac_of_profile(profileid, mac, expected_hset_call):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.update_mac_of_profile(profileid, mac)
    handler.r.hset.assert_called_once_with(*expected_hset_call)


@pytest.mark.parametrize(
    "hget_return_value, expected_mac_addr",
    [  # Testcase 1: MAC address exists
        ("00:11:22:33:44:55", "00:11:22:33:44:55"),
        # Testcase 2: MAC address does not exist
        (None, None),
    ],
)
def test_get_mac_addr_from_profile(hget_return_value, expected_mac_addr):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"

    handler.r.hget.return_value = hget_return_value
    result = handler.get_mac_addr_from_profile(profileid)
    handler.r.hget.assert_called_once_with(profileid, "MAC")
    assert result == expected_mac_addr


@pytest.mark.parametrize(
    "user_agent, expected_hset_call",
    [  # Test case 1: Typical user agent dictionary
        (
            {
                "user_agent": "Mozilla/5.0",
                "os_type": "Windows",
                "os_name": "Windows 10",
                "agent_name": "Chrome",
            },
            call(
                "profile_1",
                "first user-agent",
                {
                    "user_agent": "Mozilla/5.0",
                    "os_type": "Windows",
                    "os_name": "Windows 10",
                    "agent_name": "Chrome",
                },
            ),
        ),
        # Test case 2: User agent string
        (
            "OpenSSH_8.6",
            call("profile_1", "first user-agent", "OpenSSH_8.6"),
        ),
        # Test case 3: User agent is None
        (
            None,
            call("profile_1", "first user-agent", None),
        ),
    ],
)
def test_add_user_agent_to_profile(user_agent, expected_hset_call):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"

    handler.add_user_agent_to_profile(profileid, user_agent)
    handler.r.hset.assert_called_once_with(*expected_hset_call.args)


@pytest.mark.parametrize(
    "hget_return_value, expected_user_agents_count",
    [  # Test case 1: Valid user agent count
        (b"3", 3),
        # Test case 2: Zero user agent count
        (b"0", 0),
    ],
)
def test_get_user_agents_count(hget_return_value, expected_user_agents_count):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"

    handler.r.hget.return_value = hget_return_value
    result = handler.get_user_agents_count(profileid)
    handler.r.hget.assert_called_once_with(profileid, "user_agents_count")
    assert result == expected_user_agents_count


@pytest.mark.parametrize(
    "cached_ipv6, ipv6_to_add, expected_result",
    [
        # Testcase 1: No cached IPv6
        (None, "2001:db8::1", ["2001:db8::1"]),
        # Testcase 2: Existing cached IPv6
        (
            json.dumps(["2001:db8::2"]),
            "2001:db8::1",
            ["2001:db8::1", "2001:db8::2"],
        ),
    ],
)
def test_add_to_the_list_of_ipv6(cached_ipv6, ipv6_to_add, expected_result):
    handler = ModuleFactory().create_profile_handler_obj()

    result = handler.add_to_the_list_of_ipv6(ipv6_to_add, cached_ipv6)
    assert set(result) == set(expected_result)


def test_set_mac_vendor_to_profile_no_existing_vendor_mac_match():
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"
    mac_addr = "00:11:22:33:44:55"
    mac_vendor = "Cisco"
    handler.get_mac_vendor_from_profile = MagicMock(return_value=None)
    handler.get_mac_addr_from_profile = MagicMock(
        return_value="00:11:22:33:44:55"
    )

    result = handler.set_mac_vendor_to_profile(profileid, mac_addr, mac_vendor)

    assert result is True
    handler.r.hset.assert_called_once_with(profileid, "MAC_vendor", mac_vendor)


def test_set_mac_vendor_to_profile_existing_vendor():
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"
    mac_addr = "00:11:22:33:44:55"
    mac_vendor = "Cisco"
    handler.get_mac_vendor_from_profile = MagicMock(
        return_value="ExistingVendor"
    )
    handler.get_mac_addr_from_profile = MagicMock(return_value=mac_addr)

    result = handler.set_mac_vendor_to_profile(profileid, mac_addr, mac_vendor)

    assert result is False
    handler.r.hset.assert_not_called()


def test_set_mac_vendor_to_profile_no_existing_vendor_mac_mismatch():
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"
    mac_addr = "00:11:22:33:44:55"
    mac_vendor = "Cisco"
    handler.get_mac_vendor_from_profile = MagicMock(return_value=None)
    handler.get_mac_addr_from_profile = MagicMock(
        return_value="aa:bb:cc:dd:ee:ff"
    )

    result = handler.set_mac_vendor_to_profile(profileid, mac_addr, mac_vendor)

    assert result is False
    handler.r.hset.assert_not_called()


def test_add_mac_addr_to_profile_no_existing_mac():
    """
    testing when no cached_ips found in the db
    """
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_192.168.1.100"
    mac_addr = "00:11:22:33:44:55"
    handler._determine_gw_mac = Mock()
    handler._is_gw_mac = MagicMock(return_value=False)
    handler.get_gateway_ip = MagicMock(return_value="192.168.1.1")

    handler.r.hmget.return_value = [None]
    handler.update_mac_of_profile = MagicMock()
    result = handler.add_mac_addr_to_profile(profileid, mac_addr)

    handler.r.hmget.assert_called_once_with("MAC", mac_addr)
    handler.r.hset.assert_called_once_with(
        "MAC", mac_addr, json.dumps([profileid.split("_")[1]])
    )
    handler.update_mac_of_profile.assert_called_once_with(profileid, mac_addr)
    assert result is True


def test_add_mac_addr_to_profile_existing_mac():
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_192.168.1.100"
    mac_addr = "00:11:22:33:44:55"
    handler._determine_gw_mac = Mock()
    handler._is_gw_mac = MagicMock(return_value=False)
    handler.get_gateway_ip = MagicMock(return_value="192.168.1.1")
    # mimic having an ip for the given mac
    # this should make [incoming_ip in cached_ips] True
    handler.r.hmget.return_value = [json.dumps([profileid.split("_")[1]])]
    handler.update_mac_of_profile = MagicMock()
    result = handler.add_mac_addr_to_profile(profileid, mac_addr)
    assert result is False

    handler.r.hmget.assert_called_once_with("MAC", mac_addr)
    handler.r.hset.assert_not_called()
    handler.update_mac_of_profile.assert_not_called()


def test_add_user_agent_to_profile_first_one():
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_192.168.1.100"
    user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/58.0.3029.110 "
        "Safari/537.36"
    )

    handler.r.hexists.return_value = False

    handler.add_all_user_agent_to_profile(profileid, user_agent)

    handler.r.hexists.assert_called_once_with(profileid, "past_user_agents")
    handler.r.hset.assert_has_calls(
        [
            call(profileid, "past_user_agents", json.dumps([user_agent])),
            call(profileid, "user_agents_count", 1),
        ]
    )


def test_add_all_user_agent_to_profile_existing_ua():
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_192.168.1.100"
    existing_user_agent = "other_user_agent"
    new_user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/58.0.3029.110 Safari/537.36"
    )

    handler.r.hexists.return_value = True
    handler.r.hget.return_value = json.dumps([existing_user_agent]).encode()
    handler.get_user_agents_count = MagicMock(return_value=1)

    handler.add_all_user_agent_to_profile(profileid, new_user_agent)

    handler.r.hexists.assert_called_once_with(profileid, "past_user_agents")
    handler.r.hget.assert_called_once_with(profileid, "past_user_agents")
    handler.r.hset.assert_has_calls(
        [
            call(
                profileid,
                "past_user_agents",
                json.dumps([existing_user_agent, new_user_agent]),
            ),
            call(profileid, "user_agents_count", 2),
        ]
    )


def test_add_existing_user_agent_to_profile():
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_192.168.1.100"
    # the return of past_user_agents
    user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/58.0.3029.110 Safari/537.36"
    )

    handler.r.hexists.return_value = True
    handler.r.hget.return_value = json.dumps([user_agent]).encode()

    handler.add_all_user_agent_to_profile(profileid, user_agent)
    # user_agent not in user_agents
    handler.r.hexists.assert_called_once_with(profileid, "past_user_agents")
    handler.r.hget.assert_called_once_with(profileid, "past_user_agents")
    assert not handler.r.hset.called


@pytest.mark.parametrize(
    "hget_return_value, expected_data",
    [  # Testcase1: data exists
        (
            json.dumps({"module1": "label1", "module2": "label2"}).encode(),
            {"module1": "label1", "module2": "label2"},
        ),
        # Testcase2: data does not exist
        (None, {}),
    ],
)
def test_get_profile_modules_labels(hget_return_value, expected_data):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"

    handler.r.hget.return_value = hget_return_value

    data = handler.get_modules_labels_of_a_profile(profileid)
    handler.r.hget.assert_called_once_with(profileid, "modules_labels")
    assert data == expected_data


@pytest.mark.parametrize(
    "hget_return_value, expected_mac_vendor",
    [  # Testcase 1: MAC vendor exists
        ("Cisco", "Cisco"),
        # Testcase 2: MAC vendor does not exist
        (None, None),
    ],
)
def test_get_mac_vendor_from_profile(hget_return_value, expected_mac_vendor):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"

    handler.r.hget.return_value = hget_return_value

    mac_vendor = handler.get_mac_vendor_from_profile(profileid)

    handler.r.hget.assert_called_once_with(profileid, "MAC_vendor")
    assert mac_vendor == expected_mac_vendor


def test_add_host_name_to_profile_when_hostname_does_not_exist():
    handler = ModuleFactory().create_profile_handler_obj()

    handler.get_hostname_from_profile = MagicMock(return_value=None)

    hostname = "new_hostname.com"
    profileid = "profile_1"

    handler.add_host_name_to_profile(hostname, profileid)

    handler.r.hset.assert_called_once_with(profileid, "host_name", hostname)


def test_add_host_name_to_profile_when_hostname_exists():
    handler = ModuleFactory().create_profile_handler_obj()

    handler.get_hostname_from_profile = MagicMock(
        return_value="existing_hostname.com"
    )

    hostname = "new_hostname.com"
    profileid = "profile_1"

    handler.add_host_name_to_profile(hostname, profileid)

    handler.r.hset.assert_not_called()


def test_get_ipv6_from_ipv4():
    handler = ModuleFactory().create_profile_handler_obj()
    handler.get_ipv6_from_profile = MagicMock(return_value="2001:db8::1")
    handler.get_ipv4_from_profile = MagicMock()

    profileid = "profile_192.168.1.100"
    ip = handler.get_the_other_ip_version(profileid)

    handler.get_ipv6_from_profile.assert_called_once_with(profileid)
    handler.get_ipv4_from_profile.assert_not_called()
    assert ip == "2001:db8::1"


def test_get_ipv4_from_ipv6():
    handler = ModuleFactory().create_profile_handler_obj()
    handler.get_ipv6_from_profile = MagicMock()
    handler.get_ipv4_from_profile = MagicMock(return_value="192.168.1.100")

    profileid = "profile_2001:db8::1"
    ip = handler.get_the_other_ip_version(profileid)

    handler.get_ipv4_from_profile.assert_called_once_with(profileid)
    handler.get_ipv6_from_profile.assert_not_called()
    assert ip == "192.168.1.100"


def test_invalid_ip():
    handler = ModuleFactory().create_profile_handler_obj()
    handler.get_ipv6_from_profile = MagicMock()
    handler.get_ipv4_from_profile = MagicMock()

    profileid = "profile_invalid_ip"
    ip = handler.get_the_other_ip_version(profileid)

    handler.get_ipv6_from_profile.assert_not_called()
    handler.get_ipv4_from_profile.assert_not_called()
    assert ip is False


@pytest.mark.parametrize(
    "role, flow_state, "
    "expected_update_times_contacted_call, "
    "expected_update_ip_info_call, "
    "expected_hset_key",
    [  # Testcase 1: Client role, Not Established state
        (
            "Client",
            "S0",
            call("1.2.3.4", "Dst", "profile_5.6.7.8", "timewindow1"),
            call(
                {},
                1,
                "80",
                1,
                100,
                "1.2.3.4",
                "1000.0",
                "abc123",
            ),
            "DstIPsClientTCPNot Established",
        ),
        # Testcase 2: Server role, Established state
        (
            "Server",
            "EST",
            call("5.6.7.8", "Src", "profile_5.6.7.8", "timewindow1"),
            call(
                {},
                1,
                "80",
                1,
                100,
                "5.6.7.8",
                "1000.0",
                "abc123",
            ),
            "SrcIPsServerTCPEstablished",
        ),
    ],
)
def test_add_ips(
    role,
    flow_state,
    expected_update_times_contacted_call,
    expected_update_ip_info_call,
    expected_hset_key,
):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.ask_for_ip_info = MagicMock()
    handler.update_times_contacted = MagicMock()
    handler.get_data_from_profile_tw = MagicMock(return_value={})
    handler.update_ip_info = MagicMock(return_value={"updated_data": True})

    handler.set_new_ip = MagicMock()

    profileid = "profile_5.6.7.8"
    twid = "timewindow1"
    flow = Conn(
        starttime=str(1000.0),
        uid="abc123",
        saddr="5.6.7.8",
        daddr="1.2.3.4",
        dur=0.0,
        proto="TCP",
        appproto="",
        sport="1234",
        dport="80",
        spkts=1,
        dpkts=0,
        sbytes=100,
        dbytes=0,
        smac="",
        dmac="",
        state=flow_state,
        history="",
    )
    handler.add_ips(profileid, twid, flow, role)

    expected_ask_for_ip_info_calls = [
        call(
            "5.6.7.8",
            "profile_5.6.7.8",
            "timewindow1",
            flow,
            "srcip",
            daddr="1.2.3.4",
        ),
        call(
            "1.2.3.4",
            "profile_5.6.7.8",
            "timewindow1",
            flow,
            "dstip",
        ),
    ]

    handler.ask_for_ip_info.assert_has_calls(expected_ask_for_ip_info_calls)
    handler.update_times_contacted.assert_called_once_with(
        *expected_update_times_contacted_call.args
    )
    handler.update_ip_info.assert_called_once_with(
        *expected_update_ip_info_call.args
    )
    handler.r.hset.assert_called_once_with(
        f"{profileid}{handler.separator}{twid}",
        expected_hset_key,
        json.dumps({"updated_data": True}),
    )


@pytest.mark.parametrize(
    "profileid, twid, flow, expected_calls, expect_set_dns_resolution",
    [
        (
            "profile_192.168.1.5",
            "timewindow1",
            DNS(
                saddr="192.168.1.5",
                starttime=1000.0,
                uid="abc123",
                daddr="8.8.8.8",
                dport="",
                sport="",
                proto="",
                query="www.example.com",
                qclass_name="IN",
                qtype_name="A",
                rcode_name="NOERROR",
                answers=["1.2.3.4"],
                TTLs=[3600],
            ),
            [
                call(
                    "profile_192.168.1.5",
                    "timewindow1",
                    "dstip",
                    1000.0,
                    "abc123",
                    "8.8.8.8",
                    lookup="www.example.com",
                ),
                call(
                    "profile_192.168.1.5",
                    "timewindow1",
                    "dstip",
                    1000.0,
                    "abc123",
                    "8.8.8.8",
                    lookup="1.2.3.4",
                    extra_info={
                        "is_dns_response": True,
                        "dns_query": "www.example.com",
                    },
                ),
            ],
            True,
        ),
        (
            "profile_1",
            "timewindow1",
            DNS(
                saddr="192.168.1.5",
                starttime=1000.0,
                uid="abc123",
                daddr="8.8.8.8",
                query="www.example.com",
                dport="",
                sport="",
                proto="",
                qclass_name="IN",
                qtype_name="A",
                rcode_name="NOERROR",
                answers=[],
                TTLs=[3600],
            ),
            [
                call(
                    "profile_1",
                    "timewindow1",
                    "dstip",
                    1000.0,
                    "abc123",
                    "8.8.8.8",
                    lookup="www.example.com",
                )
            ],
            False,
        ),
        (
            "profile_1",
            "timewindow1",
            DNS(
                saddr="192.168.1.5",
                starttime=1000.0,
                uid="abc123",
                daddr="8.8.8.8",
                query="www.example.com",
                qclass_name="IN",
                qtype_name="A",
                dport="",
                sport="",
                proto="",
                rcode_name="NOERROR",
                answers=["1.2.3.4", "TXT some text"],
                TTLs=["3600"],
            ),
            [
                call(
                    "profile_1",
                    "timewindow1",
                    "dstip",
                    1000.0,
                    "abc123",
                    "8.8.8.8",
                    lookup="www.example.com",
                ),
                call(
                    "profile_1",
                    "timewindow1",
                    "dstip",
                    1000.0,
                    "abc123",
                    "8.8.8.8",
                    lookup="1.2.3.4",
                    extra_info={
                        "is_dns_response": True,
                        "dns_query": "www.example.com",
                    },
                ),
            ],
            True,
        ),
    ],
)
def test_add_out_dns(
    profileid, twid, flow, expected_calls, expect_set_dns_resolution
):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.publish = MagicMock()
    handler.give_threat_intelligence = MagicMock()
    handler.set_dns_resolution = MagicMock()

    handler.add_out_dns(profileid, twid, flow)

    handler.publish.assert_called_once_with("new_dns", ANY)
    expected_dns_flow = {
        "profileid": profileid,
        "twid": twid,
        "flow": asdict(flow),
    }
    # get the actual dns flow argument passed to publish
    actual_dns_flow_arg = handler.publish.call_args[0][
        1
    ]  # second argument of the first call
    actual_dns_flow = json.loads(
        actual_dns_flow_arg
    )  # parse it as a dictionary
    assert actual_dns_flow == expected_dns_flow

    if expect_set_dns_resolution:
        handler.set_dns_resolution.assert_called_once_with(
            flow.query,
            flow.answers,
            flow.starttime,
            flow.uid,
            flow.qtype_name,
            profileid.split("_")[1],
            twid,
        )
    else:
        handler.set_dns_resolution.assert_not_called()

    handler.give_threat_intelligence.assert_has_calls(expected_calls)


@pytest.mark.parametrize(
    "host, uri, expected_give_threat_intelligence_calls",
    [  # Testcase 1: Host and URI are present
        (
            "www.example.com",
            "/index.html",
            [
                call(
                    "profile_1",
                    "timewindow1",
                    "dst",
                    "1678886400.0",
                    "abc123",
                    "1.2.3.4",
                    lookup="www.example.com",
                ),
                call(
                    "profile_1",
                    "timewindow1",
                    "dst",
                    "1678886400.0",
                    "abc123",
                    "1.2.3.4",
                    lookup="http://www.example.com/index.html",
                ),
            ],
        ),
        # Testcase 2: Host is empty, URI is present
        (
            "",
            "/index.html",
            [
                call(
                    "profile_1",
                    "timewindow1",
                    "dstip",
                    "1678886400.0",
                    "abc123",
                    "1.2.3.4",
                    lookup="http://1.2.3.4/index.html",
                ),
            ],
        ),
        # Testcase 3: Host is present, URI is empty
        (
            "www.example.com",
            "",
            [
                call(
                    "profile_1",
                    "timewindow1",
                    "dst",
                    "1678886400.0",
                    "abc123",
                    "1.2.3.4",
                    lookup="www.example.com",
                ),
                call(
                    "profile_1",
                    "timewindow1",
                    "dst",
                    "1678886400.0",
                    "abc123",
                    "1.2.3.4",
                    lookup="http://www.example.com",
                ),
            ],
        ),
        # Testcase 4: Both Host and URI are empty
        (
            "",
            "",
            [
                call(
                    "profile_1",
                    "timewindow1",
                    "dstip",
                    "1678886400.0",
                    "abc123",
                    "1.2.3.4",
                    lookup="http://1.2.3.4",
                ),
            ],
        ),
    ],
)
def test_add_out_http(host, uri, expected_give_threat_intelligence_calls):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.publish = MagicMock()
    handler.give_threat_intelligence = MagicMock()

    profileid = "profile_1"
    twid = "timewindow1"
    flow = HTTP(
        starttime="1678886400.0",
        uid="abc123",
        saddr="192.168.1.5",
        daddr="1.2.3.4",
        method="GET",
        host=host,
        uri=uri,
        version=1,  # convert "1.1" to integer version 1
        user_agent="Mozilla/5.0",
        request_body_len=1024,
        response_body_len=2048,
        status_code="200",
        status_msg="OK",
        resp_mime_types="text/html",
        resp_fuids="def456",
        type_="http",
    )

    handler.add_out_http(profileid, twid, flow)
    handler.publish.assert_any_call("new_http", ANY)
    handler.publish.assert_any_call("new_url", ANY)
    expected_http_flow = {
        "profileid": profileid,
        "twid": twid,
        "flow": asdict(flow),
    }
    # get the actual dns flow argument passed to publish
    actual_dns_flow_arg = handler.publish.call_args[0][
        1
    ]  # second argument of the first call
    actual_dns_flow = json.loads(
        actual_dns_flow_arg
    )  # parse it as a dictionary
    assert actual_dns_flow == expected_http_flow

    handler.give_threat_intelligence.assert_has_calls(
        expected_give_threat_intelligence_calls
    )


@pytest.mark.parametrize(
    "hmget_return_value, expected_ipv4",
    [  # Testcase 1: IPv4 exists
        (["192.168.1.100"], "192.168.1.100"),
        # Testcase 2: IPv4 does not exist
        ([None], None),
    ],
)
def test_get_ipv4_from_profile(hmget_return_value, expected_ipv4):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"

    handler.r.hmget.return_value = hmget_return_value

    ipv4 = handler.get_ipv4_from_profile(profileid)
    handler.r.hmget.assert_called_once_with(profileid, "IPv4")
    assert ipv4 == expected_ipv4


def test_get_tw_of_ts():
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"
    time = 1150.0

    handler.r.zrangebyscore.return_value = [("timewindow2", 1100.0)]

    data = handler.get_tw_of_ts(profileid, time)

    handler.r.zrangebyscore.assert_called_with(
        f"tws{profileid}",
        float("-inf"),
        float(time),
        withscores=True,
        start=0,
        num=-1,
    )
    assert data == ("timewindow2", 1100.0)


@pytest.mark.parametrize(
    "flowtime, width, hget_return_value, expected_twid, "
    "expected_tw_start, expected_add_new_tw_call",
    [
        # Testcase 1: Normal case, existing start time
        (
            26,
            5,
            "0",
            "timewindow6",
            25,
            call("profile_1", "timewindow6", 25),
        ),
        # Testcase 2: Flow time equals start time of a TW
        (
            1600000100.0,
            100.0,
            "1600000000.0",
            "timewindow2",
            1600000100.0,
            call("profile_1", "timewindow2", 1600000100.0),
        ),
        # Testcase 3: First timewindow, no existing start time
        (
            1600000050.0,
            100.0,
            None,
            "timewindow1",
            1600000050.0,
            call("profile_1", "timewindow1", 1600000050.0),
        ),
    ],
)
def test_get_timewindow(
    flowtime,
    width,
    hget_return_value,
    expected_twid,
    expected_tw_start,
    expected_add_new_tw_call,
):
    handler = ModuleFactory().create_profile_handler_obj()
    profileid = "profile_1"
    handler.add_new_tw = MagicMock()
    handler.width = width
    handler.r.hget.return_value = hget_return_value

    twid = handler.get_timewindow(flowtime, profileid)

    handler.r.hget.assert_called_once_with("analysis", "file_start")
    handler.add_new_tw.assert_called_once_with(*expected_add_new_tw_call.args)
    assert twid == expected_twid


@pytest.mark.parametrize(
    "profile_tws, twid, expected_result",
    [  # Testcase 1: TW is in the blocked list
        (["timewindow1", "timewindow2"], "timewindow1", True),
        # Testcase 2: TW is not in the blocked list
        (["timewindow1"], "timewindow2", False),
        # Testcase 3: No blocked TWs
        ([], "timewindow1", False),
    ],
)
def test_is_blocked_profile_and_tw(profile_tws, twid, expected_result):
    handler = ModuleFactory().create_profile_handler_obj()
    handler.get_blocked_timewindows_of_profile = MagicMock(
        return_value=profile_tws
    )

    profileid = "profile_1"

    result = handler.is_blocked_profile_and_tw(profileid, twid)

    handler.get_blocked_timewindows_of_profile.assert_called_once_with(
        profileid
    )
    assert result == expected_result


@pytest.mark.parametrize(
    "timestamp, expected_zadd_call",
    [  # Testcase 1: Normal timestamp
        (
            1000.0,
            call("ModifiedTW", {"profile_1_timewindow1": 1000.0}),
        ),
        # Testcase 2: Timestamp as string
        (
            "1000.0",
            call("ModifiedTW", {"profile_1_timewindow1": 1000.0}),
        ),
        # Testcase 3: Timestamp is None
        (
            None,
            call("ModifiedTW", {"profile_1_timewindow1": 1000.0}),
        ),
    ],
)
def test_mark_profile_tw_as_modified(timestamp, expected_zadd_call):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.publish = MagicMock()
    handler.check_tw_to_close = MagicMock()

    profileid = "profile_1"
    twid = "timewindow1"
    with patch("time.time", return_value=1000.0):
        handler.mark_profile_tw_as_modified(profileid, twid, timestamp)

    handler.r.zadd.assert_called_once_with(*expected_zadd_call.args)
    handler.publish.assert_called_once_with(
        "tw_modified", "profile_1:timewindow1"
    )
    handler.check_tw_to_close.assert_called_once()


def test_mark_profile_as_gateway():
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"

    handler.mark_profile_as_gateway(profileid)
    handler.r.hset.assert_called_once_with(profileid, "gateway", "true")


@pytest.mark.parametrize(
    "hget_return_value, expected_hostname",
    [  # Testcase 1: Hostname exists
        ("myhost.local", "myhost.local"),
        # Testcase 2: Hostname does not exist
        (None, None),
    ],
)
def test_get_hostname_from_profile(hget_return_value, expected_hostname):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"

    handler.r.hget.return_value = hget_return_value

    hostname = handler.get_hostname_from_profile(profileid)

    handler.r.hget.assert_called_once_with(profileid, "host_name")
    assert hostname == expected_hostname


@pytest.mark.parametrize(
    "existing_software, expected_hset_call",
    [
        # Test case 1: No existing software
        (
            {},  # No software in profile
            (
                "profile_1",
                "used_software",
                '{"Apache": {"version-major": 2, "version-minor": 4, "uid": "abc123"}}',
            ),
        ),
        # Test case 2: Existing software, different software
        (
            {
                "Nginx": {
                    "version-major": 1,
                    "version-minor": 19,
                    "uid": "def456",
                }
            },
            (
                "profile_1",
                "used_software",
                '{"Nginx": {"version-major": 1, "version-minor": 19, "uid": "def456"}, '
                '"Apache": {"version-major": 2, "version-minor": 4, "uid": "abc123"}}',
            ),
        ),
        # Test case 3: Existing software, same software with different version
        (
            {
                "Apache": {
                    "version-major": 2,
                    "version-minor": 2,
                    "uid": "ghi789",
                }
            },
            None,  # No hset call because the software is the same
        ),
    ],
)
def test_add_software_to_profile(existing_software, expected_hset_call):
    handler = ModuleFactory().create_profile_handler_obj()

    # Mocking get_software_from_profile to return the provided existing_software
    handler.get_software_from_profile = MagicMock(
        return_value=existing_software
    )

    profileid = "profile_1"
    flow = MagicMock()
    flow.software = "Apache"
    flow.version_major = 2
    flow.version_minor = 4
    flow.uid = "abc123"

    handler.add_software_to_profile(profileid, flow)

    # Check that hset is called with the expected arguments if new software is added
    if expected_hset_call:
        handler.r.hset.assert_called_once_with(*expected_hset_call)
    else:
        handler.r.hset.assert_not_called()


def test_add_profile_new_profile():
    handler = ModuleFactory().create_profile_handler_obj()

    handler.set_new_ip = MagicMock()
    handler.publish = MagicMock()
    handler.update_threat_level = MagicMock()

    profileid = "profile_1"
    starttime = 1678886400.0
    duration = 3600.0

    handler.r.sismember.return_value = False

    result = handler.add_profile(profileid, starttime)
    assert result is True

    handler.r.sadd.assert_called_once_with("profiles", profileid)
    handler.r.hset.assert_has_calls(
        [
            call(profileid, "starttime", starttime),
            call(profileid, "duration", duration),
            call(profileid, "confidence", 0.05),
        ]
    )
    ip = profileid.split(handler.separator)[1]
    handler.set_new_ip.assert_called_once_with(ip)
    handler.publish.assert_called_once_with("new_profile", ip)
    handler.update_threat_level.assert_called_once_with(
        profileid, "info", 0.05
    )


def test_add_profile_existing_profile():
    handler = ModuleFactory().create_profile_handler_obj()

    handler.set_new_ip = MagicMock()
    handler.publish = MagicMock()
    handler.update_threat_level = MagicMock()

    profileid = "profile_1"
    starttime = 1678886400.0
    handler.r.sismember.return_value = True

    result = handler.add_profile(profileid, starttime)
    assert result is False

    handler.r.sadd.assert_not_called()
    handler.r.hset.assert_not_called()
    handler.set_new_ip.assert_not_called()
    handler.publish.assert_not_called()
    handler.update_threat_level.assert_not_called()


def test_mark_profile_as_dhcp_profile_not_exist():
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"

    handler.r.hmget.return_value = None

    result = handler.mark_profile_as_dhcp(profileid)

    handler.r.hset.assert_not_called()
    assert result is False


def test_mark_profile_as_dhcp_profile_already_dhcp():
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"

    handler.r.hmget.return_value = b'{"dhcp": "true"}'

    result = handler.mark_profile_as_dhcp(profileid)

    handler.r.hset.assert_not_called()
    assert result is None


@pytest.mark.parametrize(
    "hget_return_value, expected_first_flow_time",
    [  # Testcase 1: First flow time exists
        ("1600000000.0", "1600000000.0"),
        # Testcase 2: First flow time does not exist
        (None, None),
    ],
)
def test_get_first_flow_time(hget_return_value, expected_first_flow_time):
    handler = ModuleFactory().create_profile_handler_obj()

    handler.r.hget.return_value = hget_return_value

    first_flow_time = handler.get_first_flow_time()
    handler.r.hget.assert_called_once_with("analysis", "file_start")
    assert first_flow_time == expected_first_flow_time


@pytest.mark.parametrize(
    "hmget_return_value, expected_ipv6",
    [  # Testcase 1: IPv6 address exists
        (
            [json.dumps(["2001:db8::1"])],
            '["2001:db8::1"]',
        ),
        # Testcase 2: IPv6 address does not exist
        ([None], None),
    ],
)
def test_get_ipv6_from_profile(hmget_return_value, expected_ipv6):
    handler = ModuleFactory().create_profile_handler_obj()

    profileid = "profile_1"

    handler.r.hmget.return_value = hmget_return_value

    ipv6 = handler.get_ipv6_from_profile(profileid)

    handler.r.hmget.assert_called_once_with(profileid, "IPv6")
    assert ipv6 == expected_ipv6
