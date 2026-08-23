import json
import sqlite3
from unittest.mock import Mock, patch

from modules.web_interface.history import (
    HistoryCollector,
    connect_history,
    initialize_history,
)
from tests.module_factory import ModuleFactory


def create_flow_database(path) -> None:
    """Create the minimal raw-flow schema used by collector tests."""
    path.parent.mkdir(parents=True)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE flows (uid TEXT, flow TEXT, label TEXT)")
        connection.execute(
            "CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, alert_time REAL, "
            "ip_alerted TEXT, timewindow TEXT, tw_start TEXT, tw_end TEXT, label TEXT)"
        )


def test_flow_index_is_restart_safe_and_deduplicates_uids(tmp_path) -> None:
    _module_factory = ModuleFactory()
    output_dir = tmp_path / "run"
    flows_path = output_dir / "databases" / "flows.sqlite"
    history_path = output_dir / "web_interface" / "history.sqlite"
    create_flow_database(flows_path)
    flow = {
        "starttime": 10,
        "saddr": "10.0.0.1",
        "daddr": "8.8.8.8",
        "proto": "udp",
        "appproto": "dns",
        "bytes": 100,
        "pkts": 2,
    }
    with sqlite3.connect(flows_path) as connection:
        connection.executemany(
            "INSERT INTO flows VALUES (?, ?, ?)",
            [
                ("duplicate", json.dumps(flow), "benign"),
                ("duplicate", json.dumps({**flow, "bytes": 200}), "malicious"),
            ],
        )
    collector = HistoryCollector(str(output_dir), history_path, Mock(), 999999)

    assert collector.index_new_flows() == 2
    restarted = HistoryCollector(str(output_dir), history_path, Mock(), 999999)
    assert restarted.index_new_flows() == 0
    with connect_history(history_path, read_only=True) as connection:
        rows = connection.execute("SELECT * FROM flow_index").fetchall()
        checkpoint = connection.execute(
            "SELECT value FROM metadata WHERE key = 'flow_last_rowid'"
        ).fetchone()["value"]

    assert len(rows) == 1
    assert rows[0]["bytes"] == 200
    assert checkpoint == "2"


def test_alerts_json_backfill_persists_expired_relationships(tmp_path) -> None:
    _module_factory = ModuleFactory()
    output_dir = tmp_path / "run"
    flows_path = output_dir / "databases" / "flows.sqlite"
    history_path = output_dir / "web_interface" / "history.sqlite"
    alerts_path = output_dir / "alerts" / "alerts.json"
    create_flow_database(flows_path)
    alerts_path.parent.mkdir()
    event = {
        "Status": "Event",
        "ID": "evidence-1",
        "Priority": "High",
        "StartTime": "2026-08-22T10:00:00+00:00",
        "Confidence": 0.9,
        "Description": "Historical event",
        "Source": [{"IP": "10.0.0.1"}],
        "Note": json.dumps({"timewindow": 7, "uids": ["flow-1"]}),
    }
    incident = {
        "Status": "Incident",
        "ID": "alert-1",
        "CreateTime": "2026-08-22T10:01:00+00:00",
        "StartTime": "2026-08-22T10:00:00+00:00",
        "Source": [{"IP": "10.0.0.1"}],
        "CorrelID": ["evidence-1"],
        "Note": json.dumps(
            {
                "timewindow": 7,
                "EndTime": "2026-08-22T11:00:00+00:00",
            }
        ),
    }
    alerts_path.write_text(
        json.dumps(event) + "\n" + json.dumps(incident) + "\n",
        encoding="utf-8",
    )
    redis_client = Mock()
    redis_client.scan_iter.return_value = []
    collector = HistoryCollector(str(output_dir), history_path, redis_client, 999999)

    assert collector.backfill_detections() == 2
    with sqlite3.connect(flows_path) as connection:
        evidence = connection.execute(
            "SELECT * FROM evidence WHERE evidence_id = 'evidence-1'"
        ).fetchone()
        relation = connection.execute(
            "SELECT * FROM alert_evidence WHERE alert_id = 'alert-1'"
        ).fetchone()
        flow = connection.execute(
            "SELECT * FROM evidence_flows WHERE evidence_id = 'evidence-1'"
        ).fetchone()

    assert evidence is not None
    assert relation == ("alert-1", "evidence-1")
    assert flow == ("evidence-1", "flow-1")
    assert collector.backfill_detections() == 0


def test_metric_rollup_waits_for_complete_minutes_and_is_idempotent(
    tmp_path,
) -> None:
    _module_factory = ModuleFactory()
    output_dir = tmp_path / "run"
    history_path = output_dir / "web_interface" / "history.sqlite"
    collector = HistoryCollector(str(output_dir), history_path, Mock(), 999999)
    now = 200000.0
    complete_cutoff = int((now - 24 * 60 * 60) // 60) * 60
    with connect_history(history_path) as connection:
        connection.executemany(
            "INSERT INTO runtime_metrics_1s VALUES (?, ?, ?, ?, ?)",
            [
                (complete_cutoff - 1, 10, 100, 2, 7),
                (complete_cutoff + 10, 20, 200, 3, 11),
            ],
        )

    with patch("modules.web_interface.history.time.time", return_value=now):
        assert collector.rollup_metrics() == 1
        assert collector.rollup_metrics() == 0

    with connect_history(history_path, read_only=True) as connection:
        raw = connection.execute("SELECT ts FROM runtime_metrics_1s").fetchall()
        rolled = connection.execute(
            "SELECT flow_total, samples FROM runtime_metrics_1m"
        ).fetchone()

    assert [row["ts"] for row in raw] == [complete_cutoff + 10]
    assert rolled["flow_total"] == 7
    assert rolled["samples"] == 1


def test_snapshot_hosts_persists_all_mac_addresses(tmp_path) -> None:
    _module_factory = ModuleFactory()
    output_dir = tmp_path / "run"
    history_path = output_dir / "web_interface" / "history.sqlite"
    redis_client = Mock()
    redis_client.zrange.return_value = ["profile_10.0.0.1"]
    identity_pipeline = Mock()
    identity_pipeline.execute.return_value = [
        {
            "MAC": "00:11:22:33:44:55",
            "host_name": "sensor",
        },
        "{}",
    ]
    mac_pipeline = Mock()
    mac_pipeline.execute.return_value = [
        json.dumps(["10.0.0.1", "fe80::1"])
    ]
    redis_client.pipeline.side_effect = [identity_pipeline, mac_pipeline]
    collector = HistoryCollector(str(output_dir), history_path, redis_client, 999999)

    assert collector.snapshot_hosts() == 1
    with connect_history(history_path, read_only=True) as connection:
        stored = json.loads(
            connection.execute(
                "SELECT data FROM host_snapshots WHERE ip = '10.0.0.1'"
            ).fetchone()["data"]
        )

    assert stored["all_ips"] == ["10.0.0.1", "fe80::1"]


def test_collect_once_snapshots_hosts_before_detection_backfill(tmp_path) -> None:
    """Publish host inventory before potentially expensive historical work."""
    _module_factory = ModuleFactory()
    output_dir = tmp_path / "run"
    history_path = output_dir / "web_interface" / "history.sqlite"
    collector = HistoryCollector(str(output_dir), history_path, Mock(), 999999)
    calls = []
    collector.snapshot_hosts = Mock(side_effect=lambda: calls.append("hosts"))
    collector.sample_storage = Mock()
    collector.index_new_flows = Mock()
    collector.sample_metrics = Mock()
    collector.tail_errors = Mock()
    collector.backfill_detections = Mock()
    collector.rollup_metrics = Mock()

    with patch("modules.web_interface.history.time.time", return_value=100):
        collector.collect_once()

    assert calls == ["hosts"]
    collector.backfill_detections.assert_not_called()


def test_initialize_history_migrates_legacy_metric_schema(tmp_path) -> None:
    """Test existing run history gains exact flow deltas without data loss."""
    _module_factory = ModuleFactory()
    history_path = tmp_path / "history.sqlite"
    with sqlite3.connect(history_path) as connection:
        connection.execute(
            "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute("INSERT INTO metadata VALUES ('schema_version', '1')")
        connection.execute(
            "CREATE TABLE runtime_metrics_1s ("
            "ts REAL PRIMARY KEY, cpu_percent REAL NOT NULL, "
            "memory_mb REAL NOT NULL, flows_per_second REAL NOT NULL)"
        )
        connection.execute("INSERT INTO runtime_metrics_1s VALUES (1, 2, 3, 4)")

    initialize_history(history_path)

    with connect_history(history_path, read_only=True) as connection:
        columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(runtime_metrics_1s)"
            ).fetchall()
        }
        row = connection.execute(
            "SELECT flow_delta FROM runtime_metrics_1s WHERE ts = 1"
        ).fetchone()
        version = connection.execute(
            "SELECT value FROM metadata WHERE key = 'schema_version'"
        ).fetchone()["value"]

    assert "flow_delta" in columns
    assert row["flow_delta"] == 0
    assert version == "2"


def test_metric_sample_preserves_exact_profiler_delta(tmp_path) -> None:
    """Test flow totals retain counter deltas independently of sample timing."""
    _module_factory = ModuleFactory()
    output_dir = tmp_path / "run"
    history_path = output_dir / "web_interface" / "history.sqlite"
    redis_client = Mock()
    redis_client.get.return_value = 107
    collector = HistoryCollector(str(output_dir), history_path, redis_client, 999999)
    collector._last_flow_count = 100
    collector._last_flow_check = 10.0
    collector._live_processes = Mock(return_value=[])

    with (
        patch("modules.web_interface.history.time.monotonic", return_value=12.0),
        patch("modules.web_interface.history.time.time", return_value=20.0),
    ):
        collector.sample_metrics()

    with connect_history(history_path, read_only=True) as connection:
        sample = connection.execute(
            "SELECT flows_per_second, flow_delta FROM runtime_metrics_1s"
        ).fetchone()

    assert sample["flows_per_second"] == 3.5
    assert sample["flow_delta"] == 7
