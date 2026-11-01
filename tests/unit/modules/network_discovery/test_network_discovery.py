# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
from dataclasses import replace
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


@pytest.mark.parametrize("count", [1, 3])
def test_check_dhcp_scan_no_evidence(count: int) -> None:
    """Small DHCP request sets stay local and below the evidence threshold.

    Parameters:
        count: Number of distinct requested addresses below the threshold.
    """
    module = ModuleFactory().create_network_discovery_obj()
    for i in range(count):
        flow = DHCP(starttime=1000+i, uids=[f"dhcp-{i}"], client_addr="192.0.2.1", server_addr="", host_name="", smac="02:00:00:00:00:01", requested_addr=f"192.0.2.{i+2}")
        module.check_dhcp_scan("profile_192.0.2.1", "timewindow1", flow)
    module.db.get_dhcp_requested_addrs.assert_not_called()
    module.db.add_dhcp_requested_addr.assert_not_called()
    module.db.set_evidence.assert_not_called()
    assert len(next(iter(module.dhcp_groups.values())).addresses) == count



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

    network_discovery.db.get_dhcp_requested_addrs = Mock()
    network_discovery.db.get_dhcp_requested_addrs.return_value = (
        existing_dhcp_flows
    )
    network_discovery.db.add_dhcp_requested_addr = Mock()
    network_discovery.db.set_evidence = Mock()
    profileid = f"profile_{flow.saddr}"
    for address, uids in existing_dhcp_flows.items():
        network_discovery.check_dhcp_scan(profileid, twid, replace(flow, requested_addr=address, uids=uids))
    network_discovery.check_dhcp_scan(profileid, twid, flow)
    network_discovery.db.get_dhcp_requested_addrs.assert_not_called()
    network_discovery.db.add_dhcp_requested_addr.assert_not_called()
    assert network_discovery.db.set_evidence.call_count == 1

    called_evidence = network_discovery.db.set_evidence.call_args[0][0]
    assert called_evidence.evidence_type == EvidenceType.DHCP_SCAN
    assert called_evidence.attacker.value == flow.saddr
    assert called_evidence.profile.ip == flow.saddr
    assert called_evidence.timewindow.number == int(
        twid.replace("timewindow", "")
    )
    assert set(called_evidence.uid) == {uids[0] for uids in existing_dhcp_flows.values()}
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
