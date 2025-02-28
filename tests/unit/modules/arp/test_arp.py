# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/arp.py"""

from tests.module_factory import ModuleFactory
import json
import ipaddress
import pytest
from slips_files.core.structures.evidence import EvidenceType
from slips_files.core.flows.zeek import ARP

profileid = "profile_192.168.1.1"
twid = "timewindow1"


@pytest.mark.parametrize(
    "daddr, saddr, expected_result",
    [
        # Test case 1: IP outside local network
        ("1.1.1.1", "192.168.1.1", True),
        # Test case 2: IP inside local network
        ("192.168.1.2", "192.168.1.1", False),
        # Test case 3: Multicast address
        ("224.0.0.1", "192.168.1.1", False),
        # Test case 4: Link-local address
        ("169.254.1.1", "192.168.1.1", False),
        # Test case 5: Same subnet, different IP
        ("192.168.1.100", "192.168.1.1", False),
        # Test case 6: ARP probe (source 0.0.0.0)
        ("192.168.1.2", "0.0.0.0", False),
        # Test case 7: ARP probe (destination 0.0.0.0)
        ("0.0.0.0", "192.168.1.1", False),
    ],
)
def test_check_dstip_outside_localnet(daddr, saddr, expected_result):
    arp = ModuleFactory().create_arp_obj()
    flow = ARP(
        starttime="1726238443.1344972",
        uid="123",
        saddr=saddr,
        daddr=daddr,
        smac="",
        dmac="",
        src_hw="",
        dst_hw="",
        operation="",
    )
    twid = "timewindow1"

    arp.home_network = [ipaddress.IPv4Network("192.168.0.0/16")]

    result = arp.check_dstip_outside_localnet(twid, flow)
    assert result == expected_result


@pytest.mark.parametrize(
    "dst_mac, dst_hw, src_mac, src_hw, expected_result",
    [
        # Test case 1: Valid unsolicited ARP
        (
            "ff:ff:ff:ff:ff:ff",
            "ff:ff:ff:ff:ff:ff",
            "44:11:44:11:44:11",
            "44:11:44:11:44:11",
            True,
        ),
        # Test case 2: Invalid dst_mac
        (
            "00:11:22:33:44:55",
            "ff:ff:ff:ff:ff:ff",
            "44:11:44:11:44:11",
            "44:11:44:11:44:11",
            None,
        ),
        # Test case 3: Invalid dst_hw
        (
            "ff:ff:ff:ff:ff:ff",
            "00:11:22:33:44:55",
            "44:11:44:11:44:11",
            "44:11:44:11:44:11",
            None,
        ),
        # Test case 4: Invalid src_mac
        # (all zeros)
        (
            "ff:ff:ff:ff:ff:ff",
            "ff:ff:ff:ff:ff:ff",
            "00:00:00:00:00:00",
            "44:11:44:11:44:11",
            None,
        ),
        # Test case 5: Invalid src_hw
        # (all zeros)
        (
            "ff:ff:ff:ff:ff:ff",
            "ff:ff:ff:ff:ff:ff",
            "44:11:44:11:44:11",
            "00:00:00:00:00:00",
            None,
        ),
        # Test case 6: Alternative valid case
        # (dst_hw all zeros)
        (
            "ff:ff:ff:ff:ff:ff",
            "00:00:00:00:00:00",
            "44:11:44:11:44:11",
            "44:11:44:11:44:11",
            None,
        ),
    ],
)
def test_detect_unsolicited_arp(
    dst_mac, dst_hw, src_mac, src_hw, expected_result
):
    arp = ModuleFactory().create_arp_obj()
    flow = ARP(
        starttime="1726238443.1344972",
        uid="123",
        saddr="192.168.1.1",
        daddr="1.1.1.1",
        smac=src_mac,
        dmac=dst_mac,
        src_hw=src_hw,
        dst_hw=dst_hw,
        operation="",
    )
    twid = "timewindow1"

    result = arp.detect_unsolicited_arp(twid, flow)
    assert result == expected_result


def test_detect_mitm_arp_attack_with_original_ip():
    arp = ModuleFactory().create_arp_obj()
    flow = ARP(
        starttime="1726238443.1344972",
        uid="123",
        saddr="192.168.1.3",
        daddr="1.1.1.1",
        smac="44:11:44:11:44:11",
        dmac="",
        src_hw="",
        dst_hw="",
        operation="",
    )

    twid = "timewindow1"
    original_ip = "192.168.1.1"
    gateway_ip = "192.168.1.254"
    gateway_mac = "aa:bb:cc:dd:ee:ff"

    arp.db.get_ip_of_mac.return_value = json.dumps([f"profile_{original_ip}"])
    arp.db.get_gateway_ip.return_value = gateway_ip
    arp.db.get_gateway_mac.return_value = gateway_mac

    result = arp.detect_mitm_arp_attack(twid, flow)
    assert result is True


def test_detect_mitm_arp_attack_same_ip():
    arp = ModuleFactory().create_arp_obj()
    flow = ARP(
        starttime="1726238443.1344972",
        uid="123",
        saddr="192.168.1.1",
        daddr="1.1.1.1",
        smac="44:11:44:11:44:11",
        dmac="",
        src_hw="",
        dst_hw="",
        operation="",
    )
    twid = "timewindow1"
    original_ip = "192.168.1.1"
    gateway_ip = "192.168.1.254"
    gateway_mac = "aa:bb:cc:dd:ee:ff"

    arp.db.get_ip_of_mac.return_value = json.dumps([f"profile_{original_ip}"])
    arp.db.get_gateway_ip.return_value = gateway_ip
    arp.db.get_gateway_mac.return_value = gateway_mac

    result = arp.detect_mitm_arp_attack(twid, flow)
    assert result is None


def test_detect_mitm_arp_attack_gateway_mac():
    arp = ModuleFactory().create_arp_obj()
    flow = ARP(
        starttime="1726238443.1344972",
        uid="123",
        saddr="192.168.1.3",
        daddr="1.1.1.1",
        smac="44:11:44:11:44:11",
        dmac="",
        src_hw="",
        dst_hw="",
        operation="",
    )
    twid = "timewindow1"
    original_ip = "192.168.1.1"
    gateway_ip = "192.168.1.254"
    gateway_mac = "44:11:44:11:44:11"

    arp.db.get_ip_of_mac.return_value = json.dumps([f"profile_{original_ip}"])
    arp.db.get_gateway_ip.return_value = gateway_ip
    arp.db.get_gateway_mac.return_value = gateway_mac

    result = arp.detect_mitm_arp_attack(twid, flow)
    assert result is True


def test_detect_mitm_arp_attack_gateway_ip_as_victim():
    arp = ModuleFactory().create_arp_obj()
    flow = ARP(
        starttime="1726238443.1344972",
        uid="123",
        saddr="192.168.1.3",
        daddr="1.1.1.1",
        smac="44:11:44:11:44:11",
        dmac="",
        src_hw="",
        dst_hw="",
        operation="",
    )
    twid = "timewindow1"
    original_ip = "192.168.1.254"
    gateway_ip = "192.168.1.254"
    gateway_mac = "aa:bb:cc:dd:ee:ff"

    arp.db.get_ip_of_mac.return_value = json.dumps([f"profile_{original_ip}"])
    arp.db.get_gateway_ip.return_value = gateway_ip
    arp.db.get_gateway_mac.return_value = gateway_mac

    result = arp.detect_mitm_arp_attack(twid, flow)
    assert result is True


def test_detect_mitm_arp_attack_no_original_ip():
    arp = ModuleFactory().create_arp_obj()
    flow = ARP(
        starttime="1726238443.1344972",
        uid="123",
        saddr="192.168.1.3",
        daddr="1.1.1.1",
        smac="44:11:44:11:44:11",
        dmac="",
        src_hw="",
        dst_hw="",
        operation="",
    )
    twid = "timewindow1"
    gateway_ip = "192.168.1.254"
    gateway_mac = "aa:bb:cc:dd:ee:ff"

    arp.db.get_ip_of_mac.return_value = None
    arp.db.get_gateway_ip.return_value = gateway_ip
    arp.db.get_gateway_mac.return_value = gateway_mac

    result = arp.detect_mitm_arp_attack(twid, flow)
    assert result is None


def test_set_evidence_arp_scan():
    """Tests set_evidence_arp_scan function"""

    ARP = ModuleFactory().create_arp_obj()
    ts = "1632214645.783595"
    uids = ["5678", "1234"]

    ARP.set_evidence_arp_scan(ts, profileid, twid, uids)

    ARP.db.set_evidence.assert_called_once()
    call_args = ARP.db.set_evidence.call_args[0]
    evidence = call_args[0]
    assert evidence.evidence_type == EvidenceType.ARP_SCAN
    assert evidence.attacker.value == "192.168.1.1"
    assert set(evidence.uid) == set(uids)


@pytest.mark.parametrize(
    "operation, dst_hw, expected_result",
    [
        # Test case 1: Valid gratuitous ARP
        # (reply, broadcast dst_hw)
        ("reply", "ff:ff:ff:ff:ff:ff", True),
        # Test case 2: Valid gratuitous ARP
        # (reply, all-zero dst_hw)
        ("reply", "00:00:00:00:00:00", True),
        # Test case 3: Not gratuitous (request)
        ("request", "ff:ff:ff:ff:ff:ff", False),
        # Test case 4: Not gratuitous (unicast dst_hw)
        ("reply", "00:11:22:33:44:55", False),
    ],
)
def test_check_if_gratutitous_arp(operation, dst_hw, expected_result):
    flow = ARP(
        starttime="1726238443.1344972",
        uid="123",
        saddr="192.168.1.3",
        daddr="1.1.1.1",
        smac="44:11:44:11:44:11",
        dmac="",
        src_hw="",
        dst_hw=dst_hw,
        operation=operation,
    )
    arp = ModuleFactory().create_arp_obj()
    result = arp.check_if_gratutitous_arp(flow)
    assert result == expected_result


# def test_wait_for_arp_scans():
#     ARP = ModuleFactory().create_arp_obj()
#     ARP.pending_arp_scan_evidence = Queue()
#     ARP.time_to_wait = 0.1
#     evidence1 = (
#         "1636305825.755132",
#         "profile_192.168.1.1",
#         "timewindow1",
#         ["uid1"],
#         5,
#     )
#     evidence2 = (
#         "1636305826.755132",
#         "profile_192.168.1.1",
#         "timewindow1",
#         ["uid2"],
#         6,
#     )
#     evidence3 = (
#         "1636305827.755132",
#         "profile_192.168.1.2",
#         "timewindow1",
#         ["uid3"],
#         7,
#     )
#
#     ARP.pending_arp_scan_evidence.put(evidence1)
#     ARP.pending_arp_scan_evidence.put(evidence2)
#     ARP.pending_arp_scan_evidence.put(evidence3)
#
#     ARP.set_evidence_arp_scan = MagicMock()
#
#     thread = threading.Thread(target=ARP.wait_for_arp_scans)
#     thread.daemon = True
#     thread.start()
#
#     time.sleep(1)
#     expected_calls = [
#         call(
#             "1636305826.755132",
#             "profile_192.168.1.1",
#             "timewindow1",
#             ["uid1", "uid2"],
#             6,
#         ),
#         call(
#             "1636305827.755132",
#             "profile_192.168.1.2",
#             "timewindow1",
#             ["uid3"],
#             7,
#         ),
#     ]
#     (
#         ARP.set_evidence_arp_scan.assert_has_calls(
#             expected_calls, any_order=True
#         )
#     )
#     assert ARP.set_evidence_arp_scan.call_count == 2
#     assert ARP.pending_arp_scan_evidence.empty()
#     ARP.stop_thread = True
#     thread.join(timeout=1)
#
