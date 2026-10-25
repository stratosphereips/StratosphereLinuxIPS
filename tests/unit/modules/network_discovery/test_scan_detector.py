"""Probe classification, rolling periods and bounded resource regressions."""

import pytest

from modules.network_discovery.scan_detector import ScanFlow
from tests.module_factory import ModuleFactory
from tests.unit.modules.network_discovery.test_horizontal_portscans import conn, send


@pytest.mark.parametrize("change,kind", [
    ({"history": "S", "state": "S0"}, "syn"),
    ({"history": "Sr", "state": "REJ"}, "rejected"),
    ({"history": "ShAFf", "state": "SF"}, "connect"),
    ({"history": "ShADadFf", "state": "SF", "sbytes": 100, "dbytes": 20}, "success"),
    ({"history": "F", "state": "SH", "spkts": 4, "dur": 3}, "background"),
    ({"history": "Ar", "state": "RSTRH", "dpkts": 1}, "background"),
    ({"history": "F", "state": "SH"}, "flags"),
    ({"history": "", "state_hist": "S0", "state": "S0"}, "unknown"),
    ({"history": "", "state_hist": "", "state": "REJ"}, "unknown"),
    ({"history": "^S", "state": "S0"}, "background"),
    ({"proto": "udp", "history": "D"}, "udp"),
    ({"proto": "udp", "history": "Dd", "dpkts": 1}, "success"),
])
def test_flow_classification(change: object, kind: object) -> None:
    """Verify flow classification.

    Parameters:
        change: Parameterized scenario value.
        kind: Parameterized scenario value.
    """
    module = ModuleFactory().create_horizontal_portscan_obj()
    assert ScanFlow.from_flow(conn(0, **change)).kind == kind
    assert not module.detector.groups


@pytest.mark.parametrize("change", [
    {"saddr": "255.255.255.255"}, {"daddr": "224.0.0.1"},
    {"daddr": "::"}, {"daddr": "127.0.0.1"},
    {"proto": "icmp"}, {"proto": "icmp6"}, {"proto": "unknown_transport"},
    {"starttime": float("nan")}, {"dur": float("inf")}, {"dur": -1},
    {"dport": 65536}, {"sport": "bad"}, {"spkts": 0}, {"spkts": -1},
    {"uid": ""}, {"saddr": "bad"}, {"daddr": "2001:db8::1"},
])
def test_invalid_and_nonunicast_flows_are_ignored(change: object) -> None:
    """Verify invalid and nonunicast flows are ignored.

    Parameters:
        change: Parameterized scenario value.
    """
    module = ModuleFactory().create_horizontal_portscan_obj()
    if change.get("saddr") != "bad":
        send(module, conn(0, **change))
    assert ScanFlow.from_flow(conn(0, **change)) is None
    assert not module.detector.groups


def test_slow_scan_spans_slips_timewindows() -> None:
    """Verify slow scan spans slips timewindows."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(25):
        send(module, conn(i, starttime=1000 + i * 65), window=i)
    evidence = module.db.set_evidence.call_args.args[0]
    assert "within 1800 seconds" in evidence.description
    assert len(evidence.uid) == 20
    assert evidence.timewindow.number == 24


def test_targets_outside_both_periods_do_not_accumulate() -> None:
    """Verify targets outside both periods do not accumulate."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(50):
        send(module, conn(i, starttime=1000 + i * 2000))
    module.db.set_evidence.assert_not_called()


def test_late_failed_summary_does_not_undo_success() -> None:
    """Verify late failed summary does not undo success."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(20):
        send(module, conn(i, starttime=1100 + i, history="ShADadFf", state="SF", sbytes=5, dbytes=5))
    for i in range(20):
        send(module, conn(i, starttime=1000 + i))
    module.db.set_evidence.assert_not_called()


def test_scattered_unanswered_targets_have_lower_confidence() -> None:
    """Verify scattered unanswered targets have lower confidence."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(10):
        send(module, conn(i, daddr=f"10.{i}.0.1"))
    evidence = module.db.set_evidence.call_args.args[0]
    assert str(evidence.threat_level) == "low"
    assert evidence.confidence < 0.5
    module.db.mark_ip_as_port_scanner.assert_not_called()


def test_missing_packet_history_does_not_become_high_confidence() -> None:
    """Verify missing packet history does not become high confidence."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(10):
        send(module, conn(i, history="", state_hist="S0"))
    evidence = module.db.set_evidence.call_args.args[0]
    assert str(evidence.threat_level) == "low"
    assert "without packet history" in evidence.description


def test_many_successful_connections_reduce_failed_fanout_significance() -> None:
    """Verify many successful connections reduce failed fanout significance."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(20):
        send(module, conn(i, history="ShADadFf", state="SF", sbytes=5, dbytes=5))
    for i in range(20, 30):
        send(module, conn(i))
    module.db.set_evidence.assert_not_called()


def test_multi_service_outage_reduces_confidence() -> None:
    """Verify multi service outage reduces confidence."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    send(module, conn(0, dport=80))
    send(module, conn(1, dport=22))
    for i in range(10):
        send(module, conn(i, starttime=1002 + i))
    evidence = module.db.set_evidence.call_args.args[0]
    assert str(evidence.threat_level) == "low"
    assert "outage" in evidence.description


def test_scans_of_open_services_and_ipv6_addresses_detected() -> None:
    """Verify scans of open services and ipv6 addresses detected."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(10):
        send(module, conn(i, saddr="2001:db8:1::1", daddr=f"2001:db8:2::{i+1}", history="ShAFf", state="SF"))
    assert module.db.set_evidence.call_count == 1
    assert "short connections" in module.db.set_evidence.call_args.args[0].description


def test_quic_fanout_is_not_treated_as_syn_scan() -> None:
    """Verify quic fanout is not treated as syn scan."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(30):
        send(module, conn(i, daddr=f"10.{i}.0.1", proto="udp", history="D", sbytes=1200))
    module.db.set_evidence.assert_not_called()


def test_udp_scan_with_address_coverage_is_detected() -> None:
    """Verify udp scan with address coverage is detected."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(10):
        send(module, conn(i, proto="udp", history="D", sbytes=50))
    evidence = module.db.set_evidence.call_args.args[0]
    assert str(evidence.threat_level) == "medium"
    assert "UDP has no TCP handshake" in evidence.description


def test_cooldown_and_immediate_severity_escalation() -> None:
    """Verify cooldown and immediate severity escalation."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(10):
        send(module, conn(i, daddr=f"10.{i}.0.1"))
    assert module.db.set_evidence.call_count == 1
    for i in range(10, 20):
        send(module, conn(i, daddr=f"10.{i}.0.1", state="REJ", history="Sr"))
    assert module.db.set_evidence.call_count == 2
    assert str(module.db.set_evidence.call_args.args[0].threat_level) == "high"
    for i in range(20, 40):
        send(module, conn(i, daddr=f"10.{i}.0.1", state="REJ", history="Sr"))
    assert module.db.set_evidence.call_count == 2
    send(module, conn(40, starttime=1400, state="REJ", history="Sr"))
    assert module.db.set_evidence.call_count == 3


def test_memory_limits_and_idle_group_expiration() -> None:
    """Verify memory limits and idle group expiration."""
    module = ModuleFactory().create_horizontal_portscan_obj(horizontal_max_groups=2, horizontal_max_targets=25)
    for port in (443, 80, 22):
        for i in range(40):
            send(module, conn(i, dport=port))
    assert len(module.detector.groups) == 2
    assert all(len(g.targets) <= 25 for g in module.detector.groups.values())
    assert module.detector.capacity_evictions > 0
    send(module, conn(0, starttime=10000, dport=53, proto="udp", dpkts=1))
    assert len(module.detector.groups) == 1


def test_mixed_probe_kinds_do_not_delay_a_subsecond_syn_scan() -> None:
    """Verify mixed probe kinds do not delay a subsecond syn scan."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(6):
        send(module, conn(i, history="F", state="SH", starttime=1000 + i / 10000))
    for i in range(6, 16):
        send(module, conn(i, starttime=1000 + i / 10000))
    assert module.db.set_evidence.call_count == 1
    assert str(module.db.set_evidence.call_args.args[0].threat_level) == "high"


def test_stale_counter_is_recalculated_at_target_threshold() -> None:
    """Verify stale counter is recalculated at target threshold."""
    module = ModuleFactory().create_horizontal_portscan_obj(horizontal_evaluation_interval_seconds=60)
    for i in range(7):
        send(module, conn(i, starttime=1000 + i / 10000))
    for i in range(7, 17):
        send(module, conn(i, starttime=1060.1 + i / 10000))
    assert module.db.set_evidence.call_count == 1
    assert len(module.db.set_evidence.call_args.args[0].uid) == 10


def test_outage_downgrade_obeys_low_confidence_cooldown() -> None:
    """Verify outage downgrade obeys low confidence cooldown."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    send(module, conn(0, dport=22))
    send(module, conn(1, dport=80))
    for i in range(30):
        send(module, conn(i, starttime=1002 + i))
    assert module.db.set_evidence.call_count == 1


def test_cached_counts_stay_correct_after_success_and_p2p_removal() -> None:
    """Verify cached counts stay correct after success and p2p removal."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(9):
        send(module, conn(i))
    group = next(iter(module.detector.groups.values()))
    module.detector.forget(group, "10.0.0.1")
    send(module, conn(1, starttime=1010, state="SF", history="ShADadFf", sbytes=4, dbytes=4))
    assert group.counts[("fast", "tcp")] == 7
    for i in range(9, 12):
        send(module, conn(i, starttime=1010 + i / 10000))
    assert module.db.set_evidence.call_count == 1


@pytest.mark.parametrize("state", ["closed", "S_R", "......"])
def test_legacy_flow_state_is_only_a_low_confidence_fallback(state: str) -> None:
    """Use the profiler summary without claiming an observed TCP SYN.

    Parameters:
        state: Legacy input's connection-state representation.
    """
    module = ModuleFactory().create_horizontal_portscan_obj()
    from slips_files.core.structures.evidence import ProfileID, TimeWindow
    for i in range(10):
        flow = conn(i, history="", state=state, sbytes=40, dbytes=40)
        module.check(ProfileID(ip=flow["saddr"]), TimeWindow(number=0), flow, "Not Established")
    evidence = module.db.set_evidence.call_args.args[0]
    assert str(evidence.threat_level) == "low"
    assert "without packet history" in evidence.description


def test_connection_timeouts_do_not_erase_a_fast_syn_scan() -> None:
    """Measure probe spacing from SYN start times instead of timeout length."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(10):
        send(module, conn(i, dur=120))
    assert module.db.set_evidence.call_count == 1
    assert "within 60 seconds" in module.db.set_evidence.call_args.args[0].description


def test_late_long_connection_does_not_advance_the_scan_clock() -> None:
    """Keep a late summary's duration from expiring unrelated new probes."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(9):
        send(module, conn(i))
    send(module, conn(20, starttime=900, dur=10000, state="SF", history="ShADadFf", sbytes=10, dbytes=10))
    send(module, conn(9))
    assert module.db.set_evidence.call_count == 1


@pytest.mark.parametrize("kind,state,proto", [("", "REQ", "tcp"), ("", "INT", "udp")])
def test_legacy_total_packets_without_direction_counts(kind: str, state: str, proto: str) -> None:
    """Keep legacy scans visible while acknowledging missing packet direction.

    Parameters:
        kind: Empty packet history in the legacy record.
        state: Legacy connection state.
        proto: Transport protocol being tested.
    """
    module = ModuleFactory().create_horizontal_portscan_obj()
    from slips_files.core.structures.evidence import ProfileID, TimeWindow
    for i in range(10):
        flow = conn(i, history=kind, state=state, proto=proto, spkts=0, dpkts=0, pkts=1, type_="argus")
        module.check(ProfileID(ip=flow["saddr"]), TimeWindow(number=0), flow, "Not Established")
    assert str(module.db.set_evidence.call_args.args[0].threat_level) == "low"


def test_one_subnet_without_dense_address_coverage_is_not_strong_scan_evidence() -> None:
    """Several CDN destinations sharing a subnet do not prove a sweep."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    for i in range(10):
        send(module, conn(i, daddr=f"10.0.0.{1 + i * 20}"))
    assert str(module.db.set_evidence.call_args.args[0].threat_level) == "low"
