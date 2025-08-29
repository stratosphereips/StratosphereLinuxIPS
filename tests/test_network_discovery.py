# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
from unittest.mock import (
    Mock,
)

from slips_files.core.flows.zeek import (
    Notice,
    DHCP,
)
from slips_files.core.structures.evidence import (
    Victim,
    EvidenceType,
    IoCType,
    Direction,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "msg, note, saddr, uid, " "twid, timestamp, expected_evidence_type",
    [
        # testcase1: ICMP Timestamp Scan
        (
            "ICMP TimestampScan detected on 30 hosts",
            "TimestampScan",
            "192.168.1.100",
            "uid1234",
            "timewindow5",
            "2023-04-01 12:00:00",
            EvidenceType.ICMP_TIMESTAMP_SCAN,
        ),
        # testcase2: ICMP Address Scan
        (
            "ICMP AddressScan detected on 50 hosts",
            "ICMPAddressScan",
            "10.0.0.1",
            "uid5678",
            "timewindow10",
            "2023-04-01 13:00:00",
            EvidenceType.ICMP_ADDRESS_SCAN,
        ),
        # testcase3: ICMP Address Mask Scan
        (
            "ICMP AddressMaskScan detected on 40 hosts",
            "AddressMaskScan",
            "172.16.0.1",
            "uid9012",
            "timewindow15",
            "2023-04-01 14:00:00",
            EvidenceType.ICMP_ADDRESS_MASK_SCAN,
        ),
    ],
)
def test_check_icmp_sweep_valid_scans(
    msg,
    note,
    saddr,
    uid,
    twid,
    timestamp,
    expected_evidence_type,
):
    network_discovery = ModuleFactory().create_network_discovery_obj()
    network_discovery.db.set_evidence = Mock()
    flow = Notice(
        starttime=timestamp,
        saddr=saddr,
        daddr="",
        sport="",
        dport="",
        note=note,
        msg=msg,
        scanned_port="",
        dst="",
        scanning_ip="",
        uid=uid,
    )
    network_discovery.check_icmp_sweep(twid, flow)
    assert network_discovery.db.set_evidence.call_count == 1
    called_evidence = network_discovery.db.set_evidence.call_args[0][0]
    assert called_evidence.evidence_type == expected_evidence_type
    assert called_evidence.attacker.value == saddr
    assert called_evidence.profile.ip == saddr
    assert called_evidence.timewindow.number == int(
        twid.replace("timewindow", "")
    )
    assert called_evidence.uid == [uid]
    assert called_evidence.timestamp == timestamp


def test_check_icmp_sweep_unsupported_scan():
    network_discovery = ModuleFactory().create_network_discovery_obj()
    network_discovery.db.set_evidence = Mock()
    flow = Notice(
        starttime="1726667146.6951945",
        saddr="192.168.1.50",
        daddr="1.1.1.1",
        sport=0,
        dport=0,
        note="OtherScan",
        msg="Some other scan detected on 20 hosts",
        scanned_port="",
        dst="",
        scanning_ip="",
    )
    network_discovery.check_icmp_sweep("timewindow1", flow)

    assert network_discovery.db.set_evidence.call_count == 0


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
    "number_of_scanned_ips, timestamp, pkts_sent, protocol, "
    "profileid, twid, icmp_flows_uids, attack, scanned_ip, "
    "expected_description, expected_victim",
    [
        # Testcase 1: Single IP scan, low packet count
        (
            1,
            "2023-04-01 12:00:00",
            3,
            "ICMP",
            "profile_192.168.1.100",
            "timewindow5",
            ["uid1234"],
            EvidenceType.ICMP_TIMESTAMP_SCAN,
            "192.168.1.1",
            "ICMP scanning 192.168.1.1 ICMP scan type: "
            "ICMP_TIMESTAMP_SCAN. Total packets sent: "
            "3 over 1 flows. Confidence: 0.3. by Slips",
            Victim(
                value="192.168.1.1",
                direction=Direction.DST,
                ioc_type=IoCType.IP,
            ),
        ),
        # Testcase 2: Multiple IP scan, high packet count
        (
            5,
            "2023-04-01 13:00:00",
            100,
            "ICMP",
            "profile_10.0.0.1",
            "timewindow10",
            ["uid5678", "uid5679", "uid5680", "uid5681", "uid5682"],
            EvidenceType.ICMP_ADDRESS_SCAN,
            False,
            "ICMP scanning 5 different IPs. ICMP scan type: ICMP_ADDRESS_SCAN. "
            "Total packets sent: 100 over 5 flows. Confidence: 1. by Slips",
            None,
        ),
        # Testcase 3: Single IP scan, different attack type
        (
            1,
            "2023-04-02 10:00:00",
            25,
            "ICMP",
            "profile_172.16.0.10",
            "timewindow15",
            ["uid9012", "uid9013", "uid9014"],
            EvidenceType.ICMP_ADDRESS_MASK_SCAN,
            "172.16.0.1",
            "ICMP scanning 172.16.0.1 ICMP scan type: ICMP_ADDRESS_MASK_SCAN. "
            "Total packets sent: 25 over 3 flows. Confidence: 1. by Slips",
            Victim(
                value="172.16.0.1",
                direction=Direction.DST,
                ioc_type=IoCType.IP,
            ),
        ),
    ],
)
def test_set_evidence_icmp_scan(
    number_of_scanned_ips,
    timestamp,
    pkts_sent,
    protocol,
    profileid,
    twid,
    icmp_flows_uids,
    attack,
    scanned_ip,
    expected_description,
    expected_victim,
):
    network_discovery = ModuleFactory().create_network_discovery_obj()
    network_discovery.db.set_evidence = Mock()
    network_discovery.set_evidence_icmp_scan(
        number_of_scanned_ips,
        timestamp,
        pkts_sent,
        protocol,
        profileid,
        twid,
        icmp_flows_uids,
        attack,
        scanned_ip,
    )

    assert network_discovery.db.set_evidence.call_count == 1

    called_evidence = network_discovery.db.set_evidence.call_args[0][0]
    assert called_evidence.evidence_type == attack
    assert called_evidence.attacker.value == profileid.split("_")[1]
    assert called_evidence.profile.ip == profileid.split("_")[1]
    assert called_evidence.timewindow.number == int(
        twid.replace("timewindow", "")
    )
    assert set(called_evidence.uid) == set(icmp_flows_uids)
    assert called_evidence.timestamp == timestamp
    assert called_evidence.description == expected_description
    assert called_evidence.victim == expected_victim


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


@pytest.mark.parametrize(
    "profileid, twid, sports, expected_set_evidence_calls, "
    "expected_cache_det_thresholds",
    [
        # Testcase 1: No ICMP scans
        (
            "profile_192.168.1.100",
            "timewindow5",
            {},
            0,
            {},
        ),
        # Testcase 2: Single IP ICMP Timestamp Scan,
        # below minimum flows
        (
            "profile_192.168.1.100",
            "timewindow5",
            {
                "0x0013": {
                    "dstips": {
                        "192.168.1.1": {
                            "uid": ["uid1234"],
                            "spkts": 5,
                            "stime": "2023-04-01 12:00:00",
                        }
                    }
                }
            },
            0,
            {},
        ),
        # Testcase 3: Single IP ICMP Timestamp Scan,
        # meets minimum flows
        (
            "profile_192.168.1.100",
            "timewindow5",
            {
                "0x0013": {
                    "dstips": {
                        "192.168.1.1": {
                            "uid": [
                                "uid1234",
                                "uid1235",
                                "uid1236",
                                "uid1237",
                                "uid1238",
                            ],
                            "spkts": 10,
                            "stime": "2023-04-01 12:00:00",
                        }
                    }
                }
            },
            1,
            {
                "profile_192.168.1.100:timewindow5:dstip:"
                "192.168.1.1:0x0013:ICMP_TIMESTAMP_SCAN": 5
            },
        ),
        # Testcase 4: Multiple IP ICMP Address Scan,
        # below minimum scanned IPs
        (
            "profile_10.0.0.1",
            "timewindow10",
            {
                "0x0008": {
                    "dstips": {
                        "192.168.1.2": {
                            "uid": ["uid5678"],
                            "spkts": 5,
                            "stime": "2023-04-01 13:00:00",
                        },
                        "192.168.1.3": {
                            "uid": ["uid5679"],
                            "spkts": 6,
                            "stime": "2023-04-01 13:00:01",
                        },
                    }
                }
            },
            0,
            {},
        ),
        # Testcase 5: Multiple IP ICMP Address Scan,
        # meets minimum scanned IPs
        (
            "profile_10.0.0.1",
            "timewindow10",
            {
                "0x0008": {
                    "dstips": {
                        "192.168.1.2": {
                            "uid": ["uid5678"],
                            "spkts": 5,
                            "stime": "2023-04-01 13:00:00",
                        },
                        "192.168.1.3": {
                            "uid": ["uid5679"],
                            "spkts": 6,
                            "stime": "2023-04-01 13:00:01",
                        },
                        "192.168.1.4": {
                            "uid": ["uid5680"],
                            "spkts": 7,
                            "stime": "2023-04-01 13:00:02",
                        },
                        "192.168.1.5": {
                            "uid": ["uid5681"],
                            "spkts": 8,
                            "stime": "2023-04-01 13:00:03",
                        },
                        "192.168.1.6": {
                            "uid": ["uid5682"],
                            "spkts": 9,
                            "stime": "2023-04-01 13:00:04",
                        },
                    }
                }
            },
            1,
            {"profile_10.0.0.1:timewindow10:ICMP_ADDRESS_SCAN": 5},
        ),
    ],
)
def test_check_icmp_scan(
    profileid,
    twid,
    sports,
    expected_set_evidence_calls,
    expected_cache_det_thresholds,
):
    network_discovery = ModuleFactory().create_network_discovery_obj()
    network_discovery.pingscan_minimum_flows = 5
    network_discovery.pingscan_minimum_scanned_ips = 5
    network_discovery.cache_det_thresholds = {}

    network_discovery.db.get_data_from_profile_tw = Mock()
    network_discovery.db.get_data_from_profile_tw.return_value = sports

    network_discovery.db.set_evidence = Mock()

    network_discovery.check_icmp_scan(profileid, twid)

    assert network_discovery.db.get_data_from_profile_tw.call_count == 1
    assert (
        network_discovery.db.set_evidence.call_count
        == expected_set_evidence_calls
    )
    assert (
        network_discovery.cache_det_thresholds == expected_cache_det_thresholds
    )
