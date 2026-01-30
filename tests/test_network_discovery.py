# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
from unittest.mock import (
    Mock,
)

from slips_files.core.flows.zeek import (
    DHCP,
)
from slips_files.core.structures.evidence import (
    EvidenceType,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "flow_info, existing_dhcp_flows, "
    "expected_set_dhcp_flow_calls, "
    "expected_get_dhcp_flows_calls",
    [
        # Testcase 1: First DHCP request in timewindow
        (
            {
                "flow": DHCP(
                    starttime="1726676568.14378",
                    uids=["1234"],
                    client_addr="",
                    server_addr="",
                    host_name="",
                    smac="",
                    requested_addr="192.168.1.100",
                ),
                "twid": "timewindow5",
            },
            {},
            1,
            1,
        ),
        # Testcase 2: Multiple DHCP requests,
        # but not enough to trigger evidence
        (
            {
                "flow": DHCP(
                    starttime="1726676568.14378",
                    uids=["1234"],
                    client_addr="192.168.1.2",
                    server_addr="",
                    host_name="",
                    smac="",
                    requested_addr="192.168.1.101",
                ),
                "twid": "timewindow5",
            },
            {
                "192.168.1.100": ["uid1234", "uid2345"],
                "192.168.1.102": ["uid3456", "uid4567"],
            },
            1,
            2,
        ),
    ],
)
def test_check_dhcp_scan_no_evidence(
    flow_info,
    existing_dhcp_flows,
    expected_set_dhcp_flow_calls,
    expected_get_dhcp_flows_calls,
):
    network_discovery = ModuleFactory().create_network_discovery_obj()
    network_discovery.minimum_requested_addrs = 4

    network_discovery.db.get_dhcp_flows = Mock()
    network_discovery.db.get_dhcp_flows.return_value = existing_dhcp_flows
    network_discovery.db.set_dhcp_flow = Mock()
    network_discovery.db.set_evidence = Mock()
    profileid = flow_info["flow"].saddr
    network_discovery.check_dhcp_scan(
        profileid, flow_info["twid"], flow_info["flow"]
    )

    assert (
        network_discovery.db.get_dhcp_flows.call_count
        == expected_get_dhcp_flows_calls
    )
    assert (
        network_discovery.db.set_dhcp_flow.call_count
        == expected_set_dhcp_flow_calls
    )
    assert network_discovery.db.set_evidence.call_count == 0

    network_discovery.db.set_dhcp_flow.assert_called_with(
        profileid,
        flow_info["twid"],
        flow_info["flow"].requested_addr,
        flow_info["flow"].uids,
    )


def test_check_dhcp_scan_with_evidence():
    flow = DHCP(
        starttime="1726676568.14378",
        uids=["1234"],
        client_addr="192.168.1.2",
        server_addr="",
        host_name="",
        smac="",
        requested_addr="192.168.1.104",
    )
    twid = "timewindow5"

    existing_dhcp_flows = {
        "192.168.1.100": ["uid1234"],
        "192.168.1.101": ["uid5678"],
        "192.168.1.102": ["uid3456"],
        "192.168.1.103": ["uid7890"],
    }

    network_discovery = ModuleFactory().create_network_discovery_obj()
    network_discovery.minimum_requested_addrs = 4

    network_discovery.db.get_dhcp_flows = Mock()
    network_discovery.db.get_dhcp_flows.return_value = existing_dhcp_flows
    network_discovery.db.set_dhcp_flow = Mock()
    network_discovery.db.set_evidence = Mock()
    profileid = f"profile_{flow.saddr}"
    network_discovery.check_dhcp_scan(profileid, twid, flow)

    assert network_discovery.db.get_dhcp_flows.call_count == 2
    assert network_discovery.db.set_dhcp_flow.call_count == 1
    assert network_discovery.db.set_evidence.call_count == 1
    network_discovery.db.set_dhcp_flow.assert_called_with(
        profileid,
        twid,
        flow.requested_addr,
        flow.uids,
    )

    called_evidence = network_discovery.db.set_evidence.call_args[0][0]
    assert called_evidence.evidence_type == EvidenceType.DHCP_SCAN
    assert called_evidence.attacker.value == flow.saddr
    assert called_evidence.profile.ip == flow.saddr
    assert called_evidence.timewindow.number == int(
        twid.replace("timewindow", "")
    )
    assert set(called_evidence.uid) == set(
        sum((v for v in existing_dhcp_flows.values()), []) + flow.uids
    )
    assert called_evidence.timestamp == flow.starttime


@pytest.mark.parametrize(
    "timestamp, profileid, twid, uids, "
    "number_of_requested_addrs, expected_description",
    [
        # Testcase 1: Minimum DHCP requests
        (
            "2023-04-01 12:00:00",
            "profile_192.168.1.100",
            "timewindow5",
            ["uid1234", "uid5678"],
            4,
            "Performing a DHCP scan by requesting 4 "
            "different IP addresses. Confidence: 0.8. by Slips",
        ),
        # Testcase 2: Multiple DHCP requests
        (
            "2023-04-01 13:00:00",
            "profile_10.0.0.1",
            "timewindow10",
            ["uid9012", "uid1357"],
            8,
            "Performing a DHCP scan by requesting 8 "
            "different IP addresses. Confidence: 0.8. by Slips",
        ),
        # Testcase 3: Large number of DHCP requests
        (
            "2023-04-02 10:00:00",
            "profile_172.16.1.50",
            "timewindow25",
            ["uid1111", "uid2222", "uid3333"],
            16,
            "Performing a DHCP scan by requesting 16 "
            "different IP addresses. Confidence: 0.8. by Slips",
        ),
    ],
)
def test_set_evidence_dhcp_scan(
    timestamp,
    profileid,
    twid,
    uids,
    number_of_requested_addrs,
    expected_description,
):
    network_discovery = ModuleFactory().create_network_discovery_obj()
    network_discovery.db.set_evidence = Mock()
    saddr = profileid.split("_")[-1]
    flow = DHCP(
        starttime=timestamp,
        uids=uids,
        client_addr=saddr,
        server_addr="",
        host_name="",
        smac="",
        requested_addr="",
    )

    network_discovery.set_evidence_dhcp_scan(
        profileid, twid, flow, number_of_requested_addrs
    )

    assert network_discovery.db.set_evidence.call_count == 1

    called_evidence = network_discovery.db.set_evidence.call_args[0][0]
    assert called_evidence.evidence_type == EvidenceType.DHCP_SCAN
    assert called_evidence.attacker.value == profileid.split("_")[-1]
    assert called_evidence.profile.ip == profileid.split("_")[-1]
    assert called_evidence.timewindow.number == int(
        twid.replace("timewindow", "")
    )
    assert set(called_evidence.uid) == set(uids)
    assert called_evidence.timestamp == timestamp
    assert called_evidence.description == expected_description
