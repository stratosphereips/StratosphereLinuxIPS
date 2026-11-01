"""Module integration, evidence direction and network identity tests."""

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from modules.beaconing.detector import Observation
from modules.beaconing.model import PatternModel
from slips_files.core.structures.evidence import EvidenceType, ThreatLevel
from tests.module_factory import ModuleFactory


def payload(index: int) -> dict:
    """Create an original-direction established flow event.

    Parameters:
        index: Unique flow number.

    Returns:
        Slips flow publication crossing time windows.
    """
    return {"profileid": "profile_192.168.1.2", "twid": f"timewindow{1 + index // 10}", "flow": {"type_": "conn", "uid": f"uid-{index}", "starttime": 1700000000 + index * 60, "dur": 0.2, "saddr": "192.168.1.2", "daddr": "8.8.8.8", "dport": 443, "proto": "tcp", "state": "SF", "sbytes": 386, "dbytes": 115, "spkts": 5, "dpkts": 5}}


@pytest.mark.parametrize("history,accepted", [
    ("AdDTafF", False), ("^AdDTafF", False), ("ShA^Dd", False),
    ("ShADadFf", True), ("^ShADadFf", True), ("H^SADadFf", True),
])
def test_tcp_direction_does_not_invent_beacon_clients(history: str, accepted: bool) -> None:
    """Keep ongoing sessions out of endpoint learning without losing valid flips.

    Parameters:
        history: Zeek packet history in observation order.
        accepted: Whether the final source has supported client direction.
    """
    module = ModuleFactory().create_beaconing_obj()
    flow = {**payload(0)["flow"], "history": history}
    observation = Observation.from_flow(flow)
    assert (observation is not None) is accepted
    if observation:
        assert (observation.src, observation.dst, observation.port) == (
            flow["saddr"], flow["daddr"], flow["dport"]
        )
    assert module.detector.channels == {}


@pytest.mark.parametrize("malicious", [False, True])
def test_evidence_direction_and_provenance(malicious: bool) -> None:
    """Evidence direction and provenance.

    Parameters:
        malicious: Whether the mock model identifies a C2 pattern.
    """
    module = ModuleFactory().create_beaconing_obj()
    module.live = False
    if malicious:
        module.model = Mock(minimum_threshold=0.5, version="test", protocols=["tcp"])
        module.model.score.return_value = 0.999
    for i in range(32):
        module.handle_flow(payload(i))
        mirror = payload(i)
        mirror["profileid"] = "profile_8.8.8.8"
        module.handle_flow(mirror)
    assert module.db.set_evidence.call_count == 1
    evidence = module.db.set_evidence.call_args.args[0]
    assert evidence.profile.ip == "192.168.1.2"
    assert evidence.evidence_type == (EvidenceType.SUSPECTED_C2_CHANNEL if malicious else EvidenceType.PERIODIC_CONNECTION)
    assert evidence.threat_level == (ThreatLevel.LOW if malicious else ThreatLevel.INFO)
    assert "60.000s" in evidence.description
    assert 12 <= len(evidence.uid) <= 32
    assert evidence.timewindow.number == 2
    assert len(module.detector.channels) == 1


def test_network_change_packet_time_and_broadcast() -> None:
    """Network change packet time and broadcast.
    """
    module = ModuleFactory().create_beaconing_obj()
    flow = payload(0)["flow"]
    observation = Observation.from_flow(flow)
    first = module._scope(observation, flow)
    module.networks.clear()
    module.db.get_network_state.return_value = {"gateway_mac": "aa:bb:cc:00:00:02", "local_network": "192.168.1.0/24", "changed_at": 1700001000, "history": [{"gateway_mac": "aa:bb:cc:dd:ee:ff", "local_network": "192.168.1.0/24", "changed_at": 0}]}
    assert module._scope(observation, flow) == first
    later = Observation.from_flow({**flow, "starttime": 1700002000})
    assert module._scope(later, flow) != first
    broadcast = Observation.from_flow({**flow, "daddr": "192.168.1.255"})
    assert module._scope(broadcast, flow) is None


@pytest.mark.parametrize("code", [None, 5, 517])
@pytest.mark.parametrize("factory", ["create_beaconing_obj", "create_service_anomaly_obj"])
def test_checkpoint_busy_preserves_dirty_and_shutdown_closes(code: int | None, factory: str) -> None:
    """Checkpoint busy preserves dirty and shutdown closes.

    Parameters:
        code: SQLite busy code, absent on Python 3.10.
        factory: Detector constructor to check.
    """
    module = getattr(ModuleFactory(), factory)()
    import sqlite3
    error = sqlite3.OperationalError("database is locked")
    if code is not None:
        error.sqlite_errorcode = code
    module.store = Mock()
    store = module.store
    module.store.save.side_effect = error
    module._checkpoint(force=True)
    assert module.print.called
    module.shutdown_gracefully()
    store.close.assert_called_once()


def test_pre_main_and_subscribe(tmp_path: Path) -> None:
    """Pre main and subscribe.

    Parameters:
        tmp_path: Isolated test directory.
    """
    module = ModuleFactory().create_beaconing_obj(output_dir=str(tmp_path))
    module.subscribe_to_channels()
    module.db.subscribe.assert_called_once_with("new_flow")
    with patch("modules.beaconing.beaconing.utils.drop_root_privs_permanently"):
        module.pre_main()
    assert isinstance(module.model, PatternModel)
    module.shutdown_gracefully()


def test_continuing_reports_grow_logarithmically_and_allow_c2_upgrade() -> None:
    """Reduce repeated findings and classifications without delaying a checked C2 upgrade."""
    module = ModuleFactory().create_beaconing_obj()
    module.live = False
    module.model = Mock(minimum_threshold=0.5, version="test", protocols=["tcp"])
    module.model.score.return_value = 0.0
    for i in range(10032):
        module.handle_flow(payload(i))
    records = [call.args[0] for call in module.db.set_evidence.call_args_list]
    assert [record.detection_details["beaconing"]["connections"] for record in records] == [12, 108, 1004, 10028]
    assert len(records) == 4
    assert module.model.score.call_count < 320
    assert all(len(record.uid) <= 32 for record in records)
    assert records[-1].detection_details["beaconing"]["window_connections"] == 128
    assert "Continuing" in records[-1].description
    module.model.score.return_value = 0.999
    for i in range(10032, 10064):
        module.handle_flow(payload(i))
    upgrade = module.db.set_evidence.call_args.args[0]
    assert upgrade.evidence_type == EvidenceType.SUSPECTED_C2_CHANNEL
    assert not upgrade.detection_details["beaconing"]["continuation"]


def test_capacity_notice_requires_new_evictions() -> None:
    """A historical eviction count cannot repeat warnings on quiet checkpoints."""
    module = ModuleFactory().create_beaconing_obj()
    module.store = Mock()
    module.detector.evictions = 410
    with patch("modules.beaconing.beaconing.time.monotonic", return_value=100):
        module._checkpoint(force=True)
    assert module.print.call_count == 1
    with patch("modules.beaconing.beaconing.time.monotonic", return_value=200):
        module._checkpoint(force=True)
    assert module.print.call_count == 1
    module.detector.evictions += 1
    with patch("modules.beaconing.beaconing.time.monotonic", return_value=300):
        module._checkpoint(force=True)
    assert module.print.call_count == 2
    assert "1 mature windows discarded" in module.print.call_args.args[0]
