# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/arp.py"""

from tests.module_factory import ModuleFactory
from unittest.mock import Mock
import json
import ipaddress
from pathlib import Path
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



@pytest.mark.parametrize("familiar,count,kind", [(False, 15, "ARP_SCAN"), (True, 15, None), (True, 40, "ARP_DISCOVERY")])
def test_arp_worker_emits_explained_decisions(familiar: bool, count: int, kind: str | None) -> None:
    """Persist only supported decisions, retaining source attribution and UIDs.

    Parameters:
        familiar: Establish prior successful source contacts.
        count: Distinct request targets.
        kind: Expected evidence type, if any.
    """
    arp = ModuleFactory().create_arp_obj()
    from tests.unit.modules.arp.test_scan_detector import request, train, SOURCE
    scope, _, _ = arp._scan_context("eth0", 1000)
    if familiar:
        train(arp.scan_detector, list(range(1, count + 1)), scope)
    for target in range(1, count + 1):
        arp.check_arp_scan(f"profile_{SOURCE}", "timewindow2", request(target, 1000))
    arp._scan_maintenance(force=True)
    if kind is None:
        arp.db.set_evidence.assert_not_called()
        return
    arp.db.set_evidence.assert_called_once()
    evidence = arp.db.set_evidence.call_args.args[0]
    assert evidence.evidence_type.name == kind
    assert evidence.profile.ip == SOURCE
    assert evidence.timewindow.number == 2
    assert len(set(evidence.uid)) == count
    assert evidence.detection_details["arp_scan"]["targets"] == count
    assert evidence.interface == "eth0"
    assert evidence.threat_level.name == ("INFO" if familiar else "LOW")


def test_network_context_is_cached_and_uses_packet_time() -> None:
    """A network change cannot lend its familiar contacts to an older flow."""
    arp = ModuleFactory().create_arp_obj()
    arp.live = True
    arp.db.get_network_state.return_value = {
        "gateway_mac": "02:00:00:00:00:02", "gateway_ip": "192.168.1.1",
        "local_network": "192.168.1.0/24", "changed_at": 200,
        "history": [{"gateway_mac": "02:00:00:00:00:01", "local_network": "192.168.1.0/24", "changed_at": 50}],
    }
    old = arp._scan_context("default", 100)[0]
    current = arp._scan_context("default", 300)[0]
    assert old != current
    assert old.startswith("gateway:02:00:00:00:00:01")
    assert current.startswith("gateway:02:00:00:00:00:02")
    arp.db.get_network_state.assert_called_once_with("eth0")
    assert arp._scan_context("default", 10)[0].startswith("run:")


def test_main_drains_messages_and_keeps_reply_context() -> None:
    """Learn from the actual channels and finish the candidate without a thread."""
    arp = ModuleFactory().create_arp_obj()
    from tests.unit.modules.arp.test_scan_detector import request, SOURCE
    from dataclasses import asdict
    messages = []
    for target in range(1, 16):
        flow = ARP(**vars(request(target, 1000)))
        messages.append({"data": json.dumps({"flow": asdict(flow), "profileid": f"profile_{SOURCE}", "twid": "timewindow1"})})
    arp.get_msg = Mock(side_effect=lambda channel: messages.pop(0) if channel == "new_arp" and messages else None)
    arp.check_dstip_outside_localnet = Mock()
    arp.main()
    arp._scan_maintenance(force=True)
    assert arp.db.set_evidence.call_count == 1
    assert arp.check_dstip_outside_localnet.call_count == 15
    assert "new_flow" in {call.args[0] for call in arp.get_msg.call_args_list}


def test_busy_private_checkpoint_retries_without_blocking_worker() -> None:
    """Keep the detector running while its separate checkpoint is temporarily busy."""
    arp = ModuleFactory().create_arp_obj()
    import sqlite3
    arp.history_store = Mock()
    arp.history_store.save.side_effect = [sqlite3.OperationalError("database is locked"), None]
    arp._scan_maintenance(force=True)
    arp._scan_maintenance(force=True)
    assert arp.history_store.save.call_count == 2
    assert any("will retry" in str(call) for call in arp.print.call_args_list)
    arp.history_store.save.side_effect = None
    arp.shutdown_gracefully()
    assert arp.history_store is None


def test_recorded_arp_scan_still_detected_without_live_database() -> None:
    """Replay the repository's actual malicious ARP log through the new worker.

    No processes or capture connections are started.
    """
    arp = ModuleFactory().create_arp_obj()
    from pathlib import Path
    for index, line in enumerate(Path("dataset/test15-arp-scan-zeek-folder/arp.log").read_text().splitlines()):
        raw = json.loads(line)
        flow = ARP(starttime=raw["ts"], uid=f"recorded-{index}", operation=raw["operation"],
            saddr=raw["orig_h"], daddr=raw["resp_h"], smac=raw["src_mac"], dmac=raw["dst_mac"],
            src_hw=raw["orig_hw"], dst_hw=raw["resp_hw"])
        if flow.operation == "request":
            arp.check_arp_scan(f"profile_{flow.saddr}", "timewindow1", flow)
        else:
            scope = arp._scan_context(flow.interface, float(flow.starttime))[0]
            arp.scan_detector.reply(flow, scope)
    arp._scan_maintenance(force=True)
    findings = [call.args[0] for call in arp.db.set_evidence.call_args_list]
    scans = [item for item in findings if item.evidence_type == EvidenceType.ARP_SCAN]
    assert any(item.profile.ip == "1.2.3.4" for item in scans)
    assert len(scans) <= 3
    assert all(len(item.uid) >= 10 for item in scans)


@pytest.mark.parametrize("live", [True, False])
def test_restart_restores_live_contacts_but_not_imported_run_history(tmp_path: Path, live: bool) -> None:
    """Reuse only the live network's private contacts after a restart.

    Parameters:
        tmp_path: Isolated output and permanent root.
        live: Whether this is live capture rather than an imported log.
    """
    arp = ModuleFactory().create_arp_obj()
    from unittest.mock import patch
    from modules.arp.scan_history import ARPHistoryStore
    from tests.unit.modules.arp.test_scan_detector import train, burst, SCOPE
    root = tmp_path / "permanent" if live else tmp_path / "offline"
    train(arp.scan_detector, list(range(1, 16)))
    store = ARPHistoryStore(root / arp.name / "contacts.sqlite")
    store.save(arp.scan_detector, 1000)
    store.close()
    arp.scan_detector.contacts.clear()
    arp.scan_detector.nodes.clear()
    arp.scan_detector.source_history.clear()
    arp.live = live
    arp.parent_output_dir = str(root)
    arp.conf.permanent_dir.return_value = str(root)
    with patch("modules.arp.arp.utils.drop_root_privs_permanently"), patch("modules.arp.arp.time.time", return_value=1000):
        arp.pre_main()
        try:
            findings = burst(arp.scan_detector, list(range(1, 16)), scope=SCOPE)
            assert any(item.scan for item in findings) is (not live)
        finally:
            arp.shutdown_gracefully()


@pytest.mark.parametrize("channel", ["new_flow", "new_arp"])
def test_malformed_pubsub_records_do_not_crash_arp_worker(channel: str) -> None:
    """Discard malformed records without stopping capture support.

    Parameters:
        channel: Existing pubsub channel carrying the malformed record.
    """
    arp = ModuleFactory().create_arp_obj()
    messages = [{"data": "[]"}, {"data": "null"}, {"data": "bad-json"}, {"data": '{"flow": []}'}]
    arp.get_msg = Mock(side_effect=lambda name: messages.pop(0) if name == channel and messages else None)
    arp.main()
    arp.db.set_evidence.assert_not_called()


def test_scan_details_survive_evidence_and_p2p_serialization() -> None:
    """Keep ARP decision facts through the actual evidence facade's annotation."""
    arp = ModuleFactory().create_arp_obj()
    from unittest.mock import Mock
    from tests.unit.modules.arp.test_scan_detector import burst
    from slips_files.core.database.database_manager import DBManager
    from slips_files.core.structures.evidence import dict_to_evidence
    from slips_files.common.slips_utils import utils
    findings = burst(arp.scan_detector, list(range(1, 16)))
    arp.set_evidence_arp_scan(findings[0])
    evidence = arp.db.set_evidence.call_args.args[0]
    manager = DBManager.__new__(DBManager)
    manager.rdb = Mock()
    manager.rdb.get_network_state.return_value = {"gateway_mac": "02:00:00:00:00:01", "local_network": "192.168.1.0/24"}
    manager.sqlite = Mock()
    manager.sqlite.is_evidence_whitelisted.return_value = False
    manager.conf = Mock()
    manager.conf.disabled_detections.return_value = []
    manager.trust_db = Mock()
    manager.output_dir = "output/arp-scan-context"
    manager.main_pid = 1234
    manager.source_module = arp.name
    manager._get_evidence_interface = Mock(return_value="eth0")
    manager.update_threat_level = Mock()
    assert manager.set_evidence(evidence)
    restored = dict_to_evidence(utils.to_dict(evidence))
    assert restored.detection_details["arp_scan"]["targets"] == 15
    assert restored.detection_provenance["module"] == arp.name
    assert restored.detection_provenance["evidence_type"] == "ARP_SCAN"
