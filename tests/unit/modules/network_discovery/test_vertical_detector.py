"""Per-event vertical scans, confidence growth and fixed-memory continuation."""

from unittest.mock import patch
import pytest
from tests.module_factory import ModuleFactory
from tests.unit.modules.network_discovery.test_horizontal_portscans import conn, send


@pytest.mark.parametrize("proto,history,state,full", [("tcp", "S", "S0", True), ("udp", "D", "S0", True), ("tcp", "", "S0", False), ("tcp", "F", "SH", False)])
def test_distinct_ports_control_confidence(proto: str, history: str, state: str, full: bool) -> None:
    """Volume supports known probes; missing SYNs retain uncertainty.

    Parameters:
        proto: Transport being examined.
        history: Captured packet history.
        state: Connection outcome.
        full: Whether this pattern can be fully confirmed.
    """
    module = ModuleFactory().create_vertical_portscan_obj()
    for i in range(100):
        send(module, conn(i, daddr="198.51.100.1", dport=i+1, proto=proto, history=history, state=state, starttime=1000+i/10000))
    records = [c.args[0] for c in module.db.set_evidence.call_args_list]
    assert max(r.confidence for r in records) == (1.0 if full else 0.45 if not history else 0.65)
    group = next(iter(module.detector.groups.values()))
    assert (group.progress is not None) is full
    if full:
        assert not group.ports
    module.db.get_info_about_not_established_flows.assert_not_called()
    module.db.get_uids_for_vertical_portscan.assert_not_called()


def test_logarithmic_continuation_does_not_query_redis_totals() -> None:
    """Retain representative IDs and logarithmic reports through 12,000 ports."""
    module = ModuleFactory().create_vertical_portscan_obj()
    with patch("modules.network_discovery.vertical_portscan.time.monotonic", return_value=0):
        for i in range(12000):
            send(module, conn(i, daddr="198.51.100.1", dport=i+1, starttime=1000+i/10000))
    records = [c.args[0] for c in module.db.set_evidence.call_args_list]
    assert [r.confidence for r in records[:3]] == [0.85, 0.95, 1.0]
    assert len(records) == 5
    assert all("approximately" in r.description for r in records[-2:])
    assert all(len(r.uid) <= 20 for r in records)
    group = next(iter(module.detector.groups.values()))
    assert not group.ports and len(group.progress.samples) <= 20
    assert len(group.progress.counter.registers) == 1024
    assert module.detector.evictions == 0
    module.db.get_authenticated_p2p_connections.assert_called_once()
    module.db.get_info_about_not_established_flows.assert_not_called()


def test_vertical_retry_success_and_quiet_reset() -> None:
    """Remove successful ports and restart confirmation after a genuine pause."""
    module = ModuleFactory().create_vertical_portscan_obj()
    for i in range(100):
        send(module, conn(i, daddr="198.51.100.1", dport=1, starttime=1000+i/10000))
    module.db.set_evidence.assert_not_called()
    for i in range(1, 100):
        send(module, conn(i, daddr="198.51.100.1", dport=i+1, starttime=1001+i/10000))
    assert module.db.set_evidence.call_args.args[0].confidence == 1
    for i in range(10):
        send(module, conn(i, daddr="198.51.100.1", dport=i+1, starttime=1400+i/10000))
    assert module.db.set_evidence.call_args.args[0].confidence == 0.85


def test_authenticated_p2p_and_network_scopes_are_excluded_or_separated() -> None:
    """A known peer tuple is ignored and separate interfaces cannot add counts."""
    module = ModuleFactory().create_vertical_portscan_obj()
    module.db.get_authenticated_p2p_connections.return_value = [dict(local_ip="192.168.1.2", local_port=40000, remote_ip="198.51.100.1", remote_port=445)]
    send(module, conn(0, daddr="198.51.100.1", dport=445))
    assert not module.detector.groups
    for i in range(16):
        send(module, conn(i, daddr="198.51.100.1", dport=i+1, interface="a" if i < 8 else "b"))
    module.db.set_evidence.assert_not_called()
    assert len(module.detector.groups) == 2


def test_vertical_group_and_port_limits_remain_bounded() -> None:
    """Ambiguous inputs retain bounded context instead of claiming certainty."""
    module = ModuleFactory().create_vertical_portscan_obj(vertical_max_groups=2, vertical_max_ports=25)
    for dst in ("198.51.100.1", "198.51.100.2", "198.51.100.3"):
        for i in range(40):
            send(module, conn(i, daddr=dst, dport=i+1, history="", starttime=1000+i/10000))
    assert len(module.detector.groups) == 2
    assert all(len(g.ports) <= 25 for g in module.detector.groups.values())
    assert module.detector.evictions > 0


def test_horizontal_sweep_does_not_fill_vertical_scan_groups() -> None:
    """Single-port fanout rotates only a cheap first-contact cache."""
    module = ModuleFactory().create_vertical_portscan_obj()
    for i in range(12000):
        send(module, conn(i, daddr=f"198.18.{i//256}.{i%256}", dport=445, starttime=1000+i/10000))
    assert not module.detector.groups
    assert len(module.detector.singletons) <= 4 * module.settings.vertical_max_groups
    assert module.detector.evictions == 0
    module.db.set_evidence.assert_not_called()


def test_successful_retry_removes_a_failed_port() -> None:
    """An answered service removes its older outstanding failure."""
    module = ModuleFactory().create_vertical_portscan_obj()
    for i in range(9):
        send(module, conn(i, daddr="198.51.100.1", dport=i+1))
    send(module, conn(0, daddr="198.51.100.1", dport=1, history="ShADadFf", state="SF", sbytes=100, dbytes=100, starttime=1010))
    send(module, conn(9, daddr="198.51.100.1", dport=10, starttime=1011))
    module.db.set_evidence.assert_not_called()
    send(module, conn(10, daddr="198.51.100.1", dport=11, starttime=1012))
    module.db.set_evidence.assert_called_once()
