# SPDX-FileCopyrightText: 2026 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import Mock, patch
from pathlib import Path

import pytest

from tests.module_factory import ModuleFactory

from modules.anomaly_detection_https.anomaly_detection_https import (
    AnomalyDetectionHTTPS,
)
from slips_files.core.structures.evidence import EvidenceType, ThreatLevel


def make_https_anomaly_conf():
    conf = Mock()
    conf.https_anomaly_training_hours.return_value = 1
    conf.https_anomaly_training_fit_method.return_value = "welford"
    conf.https_anomaly_training_alpha.return_value = 0.1
    conf.https_anomaly_hourly_zscore_thr.return_value = 3.0
    conf.https_anomaly_flow_zscore_thr.return_value = 3.0
    conf.https_anomaly_adapt_score_thr.return_value = 2.0
    conf.https_anomaly_baseline_alpha.return_value = 0.05
    conf.https_anomaly_drift_alpha.return_value = 0.02
    conf.https_anomaly_suspicious_alpha.return_value = 0.001
    conf.https_anomaly_min_baseline_points.return_value = 5
    conf.https_anomaly_max_small_flow_anomalies.return_value = 1
    conf.https_anomaly_ja3_min_variants_per_server.return_value = 2
    conf.https_anomaly_use_adwin_drift.return_value = False
    conf.https_anomaly_adwin_delta.return_value = 0.002
    conf.https_anomaly_adwin_clock.return_value = 32
    conf.https_anomaly_adwin_grace_period.return_value = 10
    conf.https_anomaly_adwin_min_window_length.return_value = 5
    conf.https_anomaly_empirical_threshold_quantile.return_value = 0.995
    conf.https_anomaly_log_verbosity.return_value = 0
    return conf


def test_https_anomaly_module_is_instantiable_and_subscribes_to_new_ssl(
    tmp_path,
):
    db = Mock()
    db.subscribe.return_value = "ssl_channel"
    conf = make_https_anomaly_conf()

    with (
        patch(
            "slips_files.common.abstracts.imodule.DBManager", return_value=db
        ),
        patch(
            "modules.anomaly_detection_https.anomaly_detection_https.ConfigParser",
            return_value=conf,
        ),
    ):
        module = AnomalyDetectionHTTPS(
            logger=Mock(),
            output_dir=str(tmp_path),
            redis_port=6379,
            termination_event=Mock(),
            slips_args=Mock(),
            conf=Mock(),
            ppid=12345,
            bloom_filters_manager=Mock(),
        )

    assert isinstance(module, AnomalyDetectionHTTPS)
    assert module.output_dir == str(tmp_path / "anomaly_detection_https")
    assert module.parent_output_dir == str(tmp_path)
    assert module.operational_log_path == str(
        tmp_path / "anomaly_detection_https" / "anomaly_detection_https.log"
    )

    module.subscribe_to_channels()

    db.subscribe.assert_called_once_with("new_ssl")
    assert module.channels == {"new_ssl": "ssl_channel"}


def test_https_operational_log_rotates_without_losing_events(tmp_path: Path) -> None:
    """Apply shared size rotation to the module's existing operational log.

    Parameters:
        tmp_path: Isolated module output directory.
    """
    _factory = ModuleFactory()
    module, _db = _create_https_anomaly_module(tmp_path)
    module.log_verbosity = 3
    module.operational_log.policy = {
        "enabled": True,
        "log_max_size_mb": 1,
        "archive_retention_days": 30,
        "log_backup_count": 2,
    }
    path = Path(module.operational_log_path)
    previous = "existing event\n" * 80000
    path.write_text(previous)
    module.log_event(1, "module_start", "new event")
    segments = list((path.parent / "rotated").glob(f"{path.name}.*"))
    assert len(segments) == 1
    assert segments[0].read_text() == previous
    assert "new event" in path.read_text()
    assert "existing event" not in path.read_text()



def _create_https_anomaly_module(tmp_path):
    conf = Mock()
    conf.https_anomaly_training_hours = Mock(return_value=24)
    conf.https_anomaly_hourly_zscore_thr = Mock(return_value=3.0)
    conf.https_anomaly_flow_zscore_thr = Mock(return_value=3.5)
    conf.https_anomaly_adapt_score_thr = Mock(return_value=2.0)
    conf.https_anomaly_baseline_alpha = Mock(return_value=0.1)
    conf.https_anomaly_drift_alpha = Mock(return_value=0.05)
    conf.https_anomaly_suspicious_alpha = Mock(return_value=0.005)
    conf.https_anomaly_min_baseline_points = Mock(return_value=6)
    conf.https_anomaly_max_small_flow_anomalies = Mock(return_value=1)
    conf.https_anomaly_ja3_min_variants_per_server = Mock(return_value=3)
    conf.https_anomaly_use_adwin_drift = Mock(return_value=False)
    conf.https_anomaly_adwin_delta = Mock(return_value=0.002)
    conf.https_anomaly_adwin_clock = Mock(return_value=32)
    conf.https_anomaly_adwin_grace_period = Mock(return_value=10)
    conf.https_anomaly_adwin_min_window_length = Mock(return_value=5)
    conf.https_anomaly_log_verbosity = Mock(return_value=0)

    db = Mock()
    db.subscribe.return_value = Mock()
    db.client_setname = Mock()
    db.set_evidence = Mock()
    db.close_sqlite = Mock()

    args = Mock()
    args.interface = None
    args.access_point = False

    with (
        patch(
            "slips_files.common.abstracts.imodule.DBManager",
            return_value=db,
        ),
        patch(
            "modules.anomaly_detection_https.anomaly_detection_https.ConfigParser",
            return_value=conf,
        ),
    ):
        module = AnomalyDetectionHTTPS(
            logger=Mock(),
            output_dir=str(tmp_path),
            redis_port=6379,
            termination_event=Mock(),
            slips_args=args,
            conf=conf,
            ppid=12345,
            bloom_filters_manager=Mock(),
        )
    module.print = Mock()
    return module, db


def test_emit_anomaly_evidence_uses_anomalous_flow_type(tmp_path):
    _factory = ModuleFactory()
    module, db = _create_https_anomaly_module(tmp_path)

    module.emit_anomaly_evidence(
        profileid="profile_192.168.1.20",
        twid_number=7,
        traffic_ts=1_700_000_000.0,
        uid="uid-1",
        confidence={"level": "high", "score": 0.8},
        reasons=[{"feature": "new_server", "value": "bad.example.com"}],
        kind="flow",
        server="bad.example.com",
        sni="bad.example.com",
        daddr="93.184.216.34",
    )

    evidence = db.set_evidence.call_args.args[0]
    assert evidence.evidence_type == EvidenceType.ANOMALOUS_FLOW
    assert evidence.description == (
        "Unusual HTTPS connection from 192.168.1.20 to bad.example.com. "
        "Server bad.example.com was not previously seen for this host."
    )
    assert evidence.profile.ip == "192.168.1.20"


@pytest.mark.parametrize("kind,reasons,expected", [
    ("hourly", [
        {"feature": "ssl_flows", "value": 734.0, "mean": 4.921244, "zscore": 3.904, "threshold": 3.0},
        {"feature": "unique_servers", "value": 67.0, "mean": 3.159633, "zscore": 3.917, "threshold": 3.0},
        {"feature": "new_servers", "value": 1.0, "mean": 0.000169, "zscore": 16.285, "threshold": 3.0},
        {"feature": "ja3_changes", "value": 390.0, "mean": 3.777653, "zscore": 47.722, "threshold": 3.0},
    ], "Unusual hourly HTTPS activity from 192.168.1.26. "
       "734 encrypted connections (usual: 4.9); 67 different servers (usual: 3.2); "
       "1 previously unseen server (usual: <1); "
       "390 new client encryption patterns across servers (usual: 3.8)."),
    ("flow", [{"feature": "bytes_to_known_server", "value": 1024, "mean": 8192, "zscore": 4}],
     "Unusual HTTPS connection from 192.168.1.26 to example.com. "
     "1 KiB transferred, counting sent and received data (usual: 8 KiB)."),
    ("flow", [{"feature": "new_ja3s", "value": "raw-fingerprint"}],
     "Unusual HTTPS connection from 192.168.1.26 to example.com. "
     "The server used a previously unseen encryption handshake pattern."),
    ("hourly", [{"feature": "known_server_avg_bytes", "value": 5242880, "mean": 2048}],
     "Unusual hourly HTTPS activity from 192.168.1.26. "
     "Average data per connection to familiar servers: 5 MiB (usual: 2 KiB)."),
    ("hourly", [], "Unusual hourly HTTPS activity from 192.168.1.26."),
])
def test_anomaly_evidence_explains_observations_and_retains_exact_details(
    tmp_path: Path, kind: str, reasons: list[dict], expected: str
) -> None:
    """Keep headlines short without losing reasons, precision, UIDs or scoring.

    Parameters:
        tmp_path: Isolated module output directory.
        kind: Hourly aggregate or individual flow.
        reasons: Original observations and statistical details.
        expected: Plain-language module description.
    """
    _factory = ModuleFactory()
    module, db = _create_https_anomaly_module(tmp_path)
    confidence = {"level": "high", "score": 0.998, "severity": 0.9}
    module.emit_anomaly_evidence(
        profileid="profile_192.168.1.26", twid_number=7,
        traffic_ts=1_700_000_000, uid="flow-1", confidence=confidence,
        reasons=reasons, kind=kind, server="example.com",
        extra={"uids": ["flow-1", "flow-2"]},
    )
    evidence = db.set_evidence.call_args.args[0]
    assert evidence.description == expected
    assert evidence.confidence == 0.998
    assert evidence.threat_level == ThreatLevel.MEDIUM
    assert set(evidence.uid) == ({"flow-1", "flow-2"} if kind == "hourly" else {"flow-1"})
    details = evidence.detection_details["https_anomaly"]
    assert details["reasons"] == reasons
    assert details["confidence"] == confidence
    if kind == "hourly":
        assert details["window_end"] - details["window_start"] == 3600
    assert all(token not in evidence.description for token in ("z-score", "threshold=", "confidence=", "raw-fingerprint"))


@pytest.mark.parametrize("value,byte_count,baseline,expected", [
    (0, False, True, "0"),
    (0.000169, False, True, "<1"),
    (4.921244, False, True, "4.9"),
    (12000, False, False, "12,000"),
    (1536, True, False, "1.5 KiB"),
    (0, True, True, "0 B"),
    (float("nan"), False, True, "unavailable"),
    (float("inf"), True, True, "unavailable"),
    (None, False, True, "unavailable"),
])
def test_measurement_copy_handles_units_rare_counts_and_invalid_values(
    tmp_path: Path, value: object, byte_count: bool, baseline: bool, expected: str
) -> None:
    """Avoid misleading zeros and non-finite statistics in alert copy.

    Parameters:
        tmp_path: Isolated module output directory.
        value: Observed value or reference level to format.
        byte_count: Whether the value is a byte volume.
        baseline: Whether this is a learned count level.
        expected: Readable quantity.
    """
    _factory = ModuleFactory()
    module, _db = _create_https_anomaly_module(tmp_path)
    assert module._display_measurement(value, byte_count=byte_count, baseline=baseline) == expected
