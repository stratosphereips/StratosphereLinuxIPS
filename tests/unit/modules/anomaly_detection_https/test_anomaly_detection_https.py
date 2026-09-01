# SPDX-FileCopyrightText: 2026 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import Mock, patch

from modules.anomaly_detection_https.anomaly_detection_https import (
    AnomalyDetectionHTTPS,
)
from slips_files.core.structures.evidence import EvidenceType


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
    assert evidence.description.startswith("HTTPS anomaly:")
    assert evidence.profile.ip == "192.168.1.20"
