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


def test_checkpoint_busy_preserves_dirty_and_shutdown_closes() -> None:
    """Checkpoint busy preserves dirty and shutdown closes.
    """
    module = ModuleFactory().create_beaconing_obj()
    import sqlite3
    error = sqlite3.OperationalError("busy")
    error.sqlite_errorcode = sqlite3.SQLITE_BUSY
    module.store = Mock()
    module.store.save.side_effect = error
    module._checkpoint(force=True)
    assert module.print.called
    module.shutdown_gracefully()
    module.store.close.assert_called_once()


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
