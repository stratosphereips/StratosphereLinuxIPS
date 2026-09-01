# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/arp.py"""

from tests.module_factory import ModuleFactory
from unittest.mock import Mock
import json
import ipaddress
import queue
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


def _make_arp_request_flow(uid, saddr, daddr, ts):
    return ARP(
        starttime=ts,
        uid=uid,
        saddr=saddr,
        daddr=daddr,
        smac="44:11:44:11:44:11",
        dmac="ff:ff:ff:ff:ff:ff",
        src_hw="44:11:44:11:44:11",
        dst_hw="00:00:00:00:00:00",
        operation="request",
    )


def _trigger_arp_scan_threshold(arp, profileid, twid, base_ts=1726238443.0):
    """
    Sends enough different-daddr arp requests from the same
    profileid_twid to cross arp_scan_threshold, returns the flow
    that crossed the threshold.
    """
    result = False
    flow = None
    for i in range(arp.arp_scan_threshold):
        flow = _make_arp_request_flow(
            uid=f"uid{i}",
            saddr=profileid.replace("profile_", ""),
            daddr=f"1.1.1.{i}",
            ts=str(base_ts + i),
        )
        result = arp.check_arp_scan(profileid, twid, flow)
    assert result is True
    return flow


def _seed_cache_near_threshold(arp, profileid, twid, base_ts=1726238500.0):
    """
    Directly seeds cache_arp_requests with threshold-1 daddrs so the
    next check_arp_scan() call for a new daddr crosses the threshold,
    without going through the (evidence-clearing) alert path again.
    """
    key = f"{profileid}_{twid}"
    arp.cache_arp_requests[key] = {
        f"2.2.2.{i}": {"uids": [f"seed_uid{i}"], "ts": str(base_ts + i)}
        for i in range(arp.arp_scan_threshold - 1)
    }


def test_check_arp_scan_alerts_once_per_profileid_twid():
    """
    first time a profileid_twid crosses the threshold, evidence is set
    immediately. the second time (same profileid_twid), it should be
    queued instead of alerting again right away.
    """
    arp = ModuleFactory().create_arp_obj()
    arp.db.get_gateway_ip.return_value = "10.0.0.1"

    _trigger_arp_scan_threshold(arp, profileid, twid)
    assert arp.db.set_evidence.call_count == 1
    assert arp.alerted_once_arp_scan[f"{profileid}_{twid}"] is True

    # more requests for the same profileid_twid after already alerting,
    # should be queued, not alerted immediately
    _seed_cache_near_threshold(arp, profileid, twid)
    flow = _make_arp_request_flow(
        uid="uid_extra",
        saddr="192.168.1.1",
        daddr="1.1.1.99",
        ts="1726238500.5",
    )
    result = arp.check_arp_scan(profileid, twid, flow)
    assert result is True
    assert arp.db.set_evidence.call_count == 1
    assert arp.pending_arp_scan_evidence.qsize() == 1


def test_check_arp_scan_different_twid_alerts_independently():
    """each profileid_twid should be tracked and alerted separately."""
    arp = ModuleFactory().create_arp_obj()
    arp.db.get_gateway_ip.return_value = "10.0.0.1"

    _trigger_arp_scan_threshold(arp, profileid, "timewindow1")
    _trigger_arp_scan_threshold(arp, profileid, "timewindow2")

    assert arp.db.set_evidence.call_count == 2
    assert arp.alerted_once_arp_scan[f"{profileid}_timewindow1"] is True
    assert arp.alerted_once_arp_scan[f"{profileid}_timewindow2"] is True


def test_check_arp_scan_sets_evidence_immediately_when_queue_is_full():
    """
    once alerted_once_arp_scan is set and the pending evidence queue is
    full, new evidence should be set immediately instead of blocking or
    growing the queue.
    """
    arp = ModuleFactory().create_arp_obj()
    arp.db.get_gateway_ip.return_value = "10.0.0.1"

    _trigger_arp_scan_threshold(arp, profileid, twid)
    assert arp.db.set_evidence.call_count == 1

    # fill up the queue
    for i in range(arp.pending_arp_scan_evidence.maxsize):
        arp.pending_arp_scan_evidence.put_nowait(
            ("ts", profileid, twid, [f"uid{i}"])
        )
    assert arp.pending_arp_scan_evidence.full()

    _seed_cache_near_threshold(arp, profileid, twid)
    flow = _make_arp_request_flow(
        uid="uid_overflow",
        saddr="192.168.1.1",
        daddr="1.1.1.200",
        ts="1726238500.5",
    )
    result = arp.check_arp_scan(profileid, twid, flow)
    assert result is True

    # evidence was set immediately since the queue had no room
    assert arp.db.set_evidence.call_count == 2


def test_main_tw_closed_cleans_up_existing_entries():
    """when a tw closes, its entries in both cache dicts are removed."""
    arp = ModuleFactory().create_arp_obj()
    profileid_tw = f"{profileid}_{twid}"
    arp.cache_arp_requests[profileid_tw] = {"1.1.1.1": {}}
    arp.alerted_once_arp_scan[profileid_tw] = True

    arp.get_msg = Mock(
        side_effect=lambda channel: (
            {"data": profileid_tw} if channel == "tw_closed" else None
        )
    )

    arp.main()

    assert profileid_tw not in arp.cache_arp_requests
    assert profileid_tw not in arp.alerted_once_arp_scan


def test_main_tw_closed_with_no_matching_entries_does_not_raise():
    """
    closing a tw that never triggered an arp scan (so it has no entry in
    either cache dict) should not raise a KeyError.
    """
    arp = ModuleFactory().create_arp_obj()
    profileid_tw = f"{profileid}_{twid}"
    assert profileid_tw not in arp.cache_arp_requests
    assert profileid_tw not in arp.alerted_once_arp_scan

    arp.get_msg = Mock(
        side_effect=lambda channel: (
            {"data": profileid_tw} if channel == "tw_closed" else None
        )
    )

    arp.main()


def test_wait_for_arp_scans_combines_evidence_for_same_profileid_twid():
    """
    two pending evidence entries for the same profileid_twid should be
    combined (uids merged, latest ts kept) into a single
    set_evidence_arp_scan() call.
    """
    arp = ModuleFactory().create_arp_obj()
    arp.time_to_wait = 0.1
    arp.set_evidence_arp_scan = Mock()

    evidence1 = ("1636305825.755132", profileid, twid, ["uid1"])
    evidence2 = ("1636305826.755132", profileid, twid, ["uid2"])
    arp.pending_arp_scan_evidence.put(evidence1)
    arp.pending_arp_scan_evidence.put(evidence2)

    arp.should_stop = Mock(side_effect=[False, True])
    arp.wait_for_arp_scans()

    arp.set_evidence_arp_scan.assert_called_once_with(
        "1636305826.755132", profileid, twid, ["uid1", "uid2"]
    )


def test_wait_for_arp_scans_keeps_different_profileid_twid_separate():
    """
    evidence belonging to a different profileid_twid than the one that
    triggered the thread should be put back and not combined with it.
    """
    arp = ModuleFactory().create_arp_obj()
    arp.time_to_wait = 0.1
    arp.set_evidence_arp_scan = Mock()

    evidence1 = ("1636305825.755132", profileid, "timewindow1", ["uid1"])
    evidence2 = (
        "1636305827.755132",
        "profile_192.168.1.2",
        "timewindow1",
        ["uid2"],
    )
    arp.pending_arp_scan_evidence.put(evidence1)
    arp.pending_arp_scan_evidence.put(evidence2)

    arp.should_stop = Mock(side_effect=[False, True])
    arp.wait_for_arp_scans()

    arp.set_evidence_arp_scan.assert_called_once_with(
        "1636305825.755132", profileid, "timewindow1", ["uid1"]
    )
    # the unrelated evidence was put back in the queue, not dropped
    assert arp.pending_arp_scan_evidence.get_nowait() == evidence2


def test_wait_for_arp_scans_sets_evidence_for_unrelated_item_when_queue_full():
    """
    when draining, if a different profileid_twid's evidence can't be put
    back because the queue is full, it should get its own
    set_evidence_arp_scan() call instead of being silently dropped.
    """
    arp = ModuleFactory().create_arp_obj()
    arp.time_to_wait = 0.1
    arp.set_evidence_arp_scan = Mock()

    evidence1 = ("1636305825.755132", profileid, "timewindow1", ["uid1"])
    evidence2 = (
        "1636305827.755132",
        "profile_192.168.1.2",
        "timewindow1",
        ["uid2"],
    )
    arp.pending_arp_scan_evidence.put(evidence1)
    arp.pending_arp_scan_evidence.put(evidence2)
    # simulate the queue being full at the moment we try to put the
    # unrelated evidence back
    arp.pending_arp_scan_evidence.put_nowait = Mock(side_effect=queue.Full)

    arp.should_stop = Mock(side_effect=[False, True])
    arp.wait_for_arp_scans()

    arp.set_evidence_arp_scan.assert_any_call(
        "1636305825.755132", profileid, "timewindow1", ["uid1"]
    )
    arp.set_evidence_arp_scan.assert_any_call(
        "1636305827.755132", "profile_192.168.1.2", "timewindow1", ["uid2"]
    )
    assert arp.set_evidence_arp_scan.call_count == 2


def test_wait_for_arp_scans_survives_exception_and_continues():
    """
    an unexpected exception while processing one pending evidence should
    be caught and logged, not kill the thread, so the next pending
    evidence still gets processed.
    """
    arp = ModuleFactory().create_arp_obj()
    arp.time_to_wait = 0.1
    arp.print = Mock()
    arp.set_evidence_arp_scan = Mock(side_effect=[Exception("boom"), None])

    evidence1 = ("ts1", profileid, "timewindow1", ["uid1"])
    evidence2 = ("ts2", profileid, "timewindow2", ["uid2"])
    arp.pending_arp_scan_evidence.put(evidence1)
    arp.pending_arp_scan_evidence.put(evidence2)

    arp.should_stop = Mock(side_effect=[False, False, True])
    arp.wait_for_arp_scans()

    assert arp.set_evidence_arp_scan.call_count == 2
    arp.print.assert_called_once()
