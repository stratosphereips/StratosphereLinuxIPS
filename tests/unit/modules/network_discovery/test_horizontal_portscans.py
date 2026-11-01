"""End-to-end horizontal evidence regressions without Redis or live capture."""

from unittest.mock import Mock, patch

import pytest

from modules.network_discovery.scan_detector import ScanFlow
from slips_files.core.structures.evidence import EvidenceType, ProfileID, ThreatLevel, TimeWindow
from tests.module_factory import ModuleFactory


def conn(index: int, **changes: object) -> dict:
    """Return a TCP probe for a destination index with optional field overrides.

    Parameters:
        index: Destination address and UID suffix.
        changes: Fields overriding the probe defaults.

    Returns:
        Original-direction connection record.
    """
    flow = dict(uid=f"uid-{index}", saddr="192.168.1.2", daddr=f"10.0.0.{index + 1}",
                sport=40000 + index, dport=443, proto="tcp", starttime=1000 + index,
                dur=0, state="S0", history="S", spkts=1, dpkts=0, sbytes=0, dbytes=0)
    flow.update(changes)
    return flow


def send(module: object, flow: dict, window: int = 0) -> None:
    """Deliver a source event to the real evidence wrapper.

    Parameters:
        module: Detector wrapper under test.
        flow: Original-direction connection record.
        window: Slips evidence attribution window.
    """
    module.check(ProfileID(ip=flow["saddr"]), TimeWindow(number=window), flow)


@pytest.mark.parametrize("state,history,spkts,dpkts,sbytes,dbytes,duration", [
    ("SH", "F", 4, 0, 0, 0, 3.4),
    ("SH", "AF", 3, 0, 0, 0, 3),
    ("RSTRH", "Ar", 1, 1, 0, 0, 0.05),
    ("RSTR", "Fr", 1, 1, 0, 0, 0.01),
    ("SH", "DTF", 8, 0, 63, 0, 3.2),
    ("SH", "Fa", 1, 1, 0, 0, 0.01),
    ("OTH", "Dd", 8, 8, 500, 600, 30),
    ("S0", "S^", 1, 0, 0, 0, 0),
])
def test_leftover_sessions_are_not_syn_scans(state: object, history: object, spkts: object, dpkts: object, sbytes: object, dbytes: object, duration: object) -> None:
    """Verify leftover sessions are not syn scans.

    Parameters:
        state: Parameterized scenario value.
        history: Parameterized scenario value.
        spkts: Parameterized scenario value.
        dpkts: Parameterized scenario value.
        sbytes: Parameterized scenario value.
        dbytes: Parameterized scenario value.
        duration: Parameterized scenario value.
    """
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(30):
        send(module, conn(i, state=state, history=history, spkts=spkts, dpkts=dpkts,
                          sbytes=sbytes, dbytes=dbytes, dur=duration))
    module.db.set_evidence.assert_not_called()
    module.db.mark_ip_as_port_scanner.assert_not_called()


@pytest.mark.parametrize("state,history,expected", [
    ("S0", "S", ThreatLevel.HIGH),
    ("S0", "^S", ThreatLevel.HIGH),
    ("REJ", "Sr", ThreatLevel.HIGH),
    ("SF", "ShAFf", ThreatLevel.MEDIUM),
    ("OTH", "A", ThreatLevel.MEDIUM),
    ("SH", "F", ThreatLevel.MEDIUM),
])
def test_scans_detected_at_startup_and_across_timewindows(state: object, history: object, expected: object) -> None:
    """Verify scans detected at startup and across timewindows.

    Parameters:
        state: Parameterized scenario value.
        history: Parameterized scenario value.
        expected: Parameterized scenario value.
    """
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(10):
        send(module, conn(i, state=state, history=history), window=i // 5)
    module.db.set_evidence.assert_called_once()
    evidence = module.db.set_evidence.call_args.args[0]
    assert evidence.evidence_type == EvidenceType.HORIZONTAL_PORT_SCAN
    assert evidence.threat_level == expected
    assert evidence.profile.ip == "192.168.1.2"
    assert evidence.timewindow.number == 1
    assert len(evidence.uid) == 10
    assert evidence.timestamp == 1009
    assert "within 60 seconds" in evidence.description


def test_subsecond_scan_is_detected_without_waiting_for_another_flow() -> None:
    """Verify subsecond scan is detected without waiting for another flow."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(10):
        send(module, conn(i, starttime=1000 + i / 10000))
    module.db.set_evidence.assert_called_once()


@pytest.mark.parametrize("packets", [1, 1000])
def test_retries_do_not_inflate_targets_or_confidence(packets: object) -> None:
    """Verify retries do not inflate targets or confidence.

    Parameters:
        packets: Parameterized scenario value.
    """
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(100):
        send(module, conn(i, daddr="10.0.0.1", spkts=packets))
    module.db.set_evidence.assert_not_called()
    for i in range(1, 10):
        send(module, conn(i, starttime=1100 + i, spkts=packets))
    evidence = module.db.set_evidence.call_args.args[0]
    assert evidence.confidence == 0.85
    assert len(evidence.uid) == 10


def test_successful_reconnections_are_not_new_target_scans() -> None:
    """Verify successful reconnections are not new target scans."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(30):
        send(module, conn(i, history="ShADadFf", state="SF", sbytes=200, dbytes=200))
    for i in range(30):
        send(module, conn(i, uid=f"retry-{i}", starttime=1100 + i))
    module.db.set_evidence.assert_not_called()


def test_successful_retry_removes_failed_target() -> None:
    """Verify successful retry removes failed target."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(9):
        send(module, conn(i))
    send(module, conn(0, uid="successful-retry", starttime=1010,
                      history="ShADadFf", state="SF", sbytes=50, dbytes=50))
    send(module, conn(9, starttime=1011))
    module.db.set_evidence.assert_not_called()


def test_p2p_exclusion_recounts_targets_and_does_not_mark_scanner() -> None:
    """Verify p2p exclusion recounts targets and does not mark scanner."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    module.db.is_p2p_related_flow_batch.side_effect = lambda flows: [True] + [False] * (len(flows) - 1)
    for i in range(10):
        send(module, conn(i))
    module.db.set_evidence.assert_not_called()
    module.db.mark_ip_as_port_scanner.assert_not_called()
    module.db.is_p2p_related_flow_batch.assert_called_once()
    module.db.get_flow.assert_not_called()


def test_only_original_source_profile_is_counted() -> None:
    """Verify only original source profile is counted."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(20):
        flow = conn(i)
        module.check(ProfileID(ip=flow["daddr"]), TimeWindow(number=0), flow)
    assert not module.detector.groups
    module.db.set_evidence.assert_not_called()


@pytest.mark.parametrize("proto,history", [("tcp", "S"), ("udp", "D")])
def test_network_and_interface_scopes_do_not_mix(proto: object, history: object) -> None:
    """Verify network and interface scopes do not mix.

    Parameters:
        proto: Parameterized scenario value.
        history: Parameterized scenario value.
    """
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(18):
        send(module, conn(i, proto=proto, history=history, interface=f"eth{i // 9}"))
    module.db.set_evidence.assert_not_called()


def test_gateway_changes_and_delayed_flow_use_correct_scope() -> None:
    """Verify gateway changes and delayed flow use correct scope."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    module.live = True
    module.interfaces = ("eth0",)
    old = dict(gateway_mac="aa:aa:aa:aa:aa:aa", local_network="192.168.1.0/24", changed_at=900)
    new = dict(gateway_mac="bb:bb:bb:bb:bb:bb", local_network="192.168.1.0/24", changed_at=1010, history=[old])
    module.db.get_network_state.side_effect = [old, new]
    with patch("modules.network_discovery.horizontal_portscan.time.monotonic", side_effect=[0, 6, 7]):
        first = module.scope(ScanFlow.from_flow(conn(0)))
        second = module.scope(ScanFlow.from_flow(conn(15)))
        delayed = module.scope(ScanFlow.from_flow(conn(1)))
    assert first != second
    assert delayed == first


def test_subnet_broadcasts_excluded() -> None:
    """Verify subnet broadcasts excluded."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    module.live = True
    module.db.get_network_state.return_value = dict(local_network="192.168.1.0/24")
    for i in range(20):
        send(module, conn(i, daddr="192.168.1.255"))
    assert not module.detector.groups


def test_module_passes_event_flow_and_preserves_vertical_checks() -> None:
    """Verify module passes event flow and preserves vertical checks."""
    module = ModuleFactory().create_network_discovery_obj()
    import json
    flow = conn(0)
    module.get_msg = Mock(side_effect=[dict(data=json.dumps(dict(
        profileid="profile_192.168.1.2", twid="timewindow0", flow=flow))), None, None, None])
    module.horizontal_ps.check = Mock()
    module.vertical_ps.check = Mock()
    module.main()
    module.horizontal_ps.check.assert_called_once_with(ProfileID(ip=flow["saddr"]), TimeWindow(number=0), flow, "")
    module.vertical_ps.check.assert_called_once()


def test_p2p_exclusions_cover_all_probe_families_before_reassessment() -> None:
    """Verify p2p exclusions cover all probe families before reassessment."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(9):
        send(module, conn(i, history="F", state="SH"))
    for i in range(9, 18):
        send(module, conn(i))
    module.db.is_p2p_related_flow_batch.side_effect = lambda flows: [True] * len(flows)
    send(module, conn(18))
    module.db.set_evidence.assert_not_called()
    assert not next(iter(module.detector.groups.values())).targets


def test_capacity_messages_are_rate_limited() -> None:
    """Report dropped context once per minute while continuing flow processing."""
    module = ModuleFactory().create_network_discovery_obj()
    import json
    payload = dict(data=json.dumps(dict(profileid="profile_192.168.1.2", twid="timewindow0", flow=conn(0))))
    module.get_msg = Mock(side_effect=[payload, None, None, None] * 2)
    module.horizontal_ps.check = Mock()
    module.horizontal_ps.detector.capacity_evictions = 4
    module.vertical_ps.check = Mock()
    module.print = Mock()
    with patch("modules.network_discovery.network_discovery.time.monotonic", side_effect=[0, 1]):
        module.main()
        module.horizontal_ps.detector.capacity_evictions = 8
        module.main()
    warnings = [c for c in module.print.call_args_list if str(c.args[0]).startswith("Horizontal scan context")]
    assert len(warnings) == 1
    assert module.vertical_ps.check.call_count == 2
