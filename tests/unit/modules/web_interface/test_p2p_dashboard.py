"""Check P2P dashboard persistence, connectivity and model values."""

import json
import sqlite3
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

from modules.web_interface.server import RunDataReader
from tests.module_factory import ModuleFactory


def test_p2p_activity_keeps_report_content_from_retained_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Expose the full bounded telemetry message for report inspection."""
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output" / "run"
    output_dir.mkdir(parents=True)
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.return_value = None
    reader.redis.hget.return_value = None
    reader.redis.hgetall.return_value = {}
    reader.redis.zrange.return_value = []
    record = {
        "direction": "received",
        "message_type": "report",
        "peer": "QmRemotePeer",
        "target": "8.8.8.8",
        "report_time": 100.0,
        "timestamp": 101.0,
        "message": {
            "key": "8.8.8.8",
            "evaluation": {"score": 0.7, "confidence": 0.8},
        },
    }
    reader.redis.lrange.return_value = [json.dumps(record)]

    result = reader.p2p()

    reader.redis.lrange.assert_called_once_with("p2p_message_history", 0, 999)
    assert result["activity"][0]["message"]["evaluation"] == {
        "score": 0.7,
        "confidence": 0.8,
    }


@pytest.mark.parametrize(
    "cached_trust,expected_trust", [(None, 0.305), ("0.61", 0.305)]
)
def test_p2p_uses_verified_peer_ip_and_persistent_trust_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cached_trust: str | None,
    expected_trust: float,
) -> None:
    """Ignore a loopback peer update and retain the authenticated endpoint.

    Parameters:
        tmp_path: Isolated trust database directory.
        monkeypatch: Changes to that isolated directory.
        cached_trust: Optional current model cache entry.
        expected_trust: Trust recomputed from reliable local inputs.
    """
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output" / "run"
    output_dir.mkdir(parents=True)
    trust_path = tmp_path / "permanent" / "p2p_trust_runtime" / "trustdb.db"
    trust_path.parent.mkdir(parents=True)
    with sqlite3.connect(trust_path) as connection:
        connection.executescript(
            "CREATE TABLE go_reliability (peerid TEXT, reliability REAL, update_time REAL);"
            "CREATE TABLE peer_ips (peerid TEXT, ipaddress TEXT, update_time REAL);"
            "CREATE TABLE peer_addresses (peerid TEXT, ipaddress TEXT, update_time REAL);"
            "CREATE TABLE slips_reputation (ipaddress TEXT, score REAL, confidence REAL, source TEXT);"
            "CREATE TABLE reports (reporter_peerid TEXT, reported_key TEXT, "
            "score REAL, confidence REAL, update_time REAL);"
            "INSERT INTO go_reliability VALUES ('QmLostPeer', 0.8, 300);"
            "INSERT INTO peer_ips VALUES ('QmLostPeer', '127.0.0.1', 300);"
            "INSERT INTO peer_addresses VALUES ('QmLostPeer', '192.168.1.249', 200);"
            "INSERT INTO slips_reputation VALUES ('192.168.1.249', 0, 0.05, 'local');"
        )
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.return_value = None
    reader.redis.hget.return_value = None
    reader.redis.hgetall.side_effect = lambda key: {
        "analysis": {"analysis_start": "0"},
        "peer_info": {
            "QmLostPeer": json.dumps(
                {"ip": "127.0.0.1", "timestamp": 300, "reliability": 0.8}
            )
        },
        "peer_trust": (
            {"192.168.1.249": cached_trust} if cached_trust else {}
        ),
    }.get(key, {})
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    peer = reader.p2p()["peers"][0]

    assert peer["ip"] == "192.168.1.249"
    assert peer["trust"] == pytest.approx(expected_trust)


def test_p2p_marks_recently_active_message_sender_online(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Show peers online for a short period after their latest message."""
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output" / "run"
    output_dir.mkdir(parents=True)
    now = time.time()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.return_value = None
    reader.redis.hget.return_value = None
    reader.redis.hgetall.side_effect = lambda key: {
        "analysis": {"analysis_start": str(now - 60)},
        "peer_info": {
            "QmSlowPeer": json.dumps(
                {
                    "ip": "192.0.2.40",
                    "connected": True,
                    "last_activity": now - 30,
                }
            )
        },
    }.get(key, {})
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    result = reader.p2p()

    assert result["counts"]["connected"] == 1
    assert result["peers"][0]["peer_id"] == "QmSlowPeer"
    assert result["peers"][0]["connected"] is True


def test_p2p_does_not_show_failed_connection_as_online(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep a recent failed dial offline until authenticated activity arrives."""
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output" / "run"
    output_dir.mkdir(parents=True)
    now = time.time()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.return_value = None
    reader.redis.hget.return_value = None
    reader.redis.hgetall.side_effect = lambda key: {
        "analysis": {"analysis_start": str(now - 60)},
        "peer_info": {
            "QmFailedPeer": json.dumps(
                {
                    "ip": "192.0.2.41",
                    "connected": False,
                    "last_activity": now - 1,
                }
            )
        },
    }.get(key, {})
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    result = reader.p2p()

    assert result["counts"]["connected"] == 0
    assert result["peers"][0]["connected"] is False


@pytest.mark.parametrize(
    "connected_peers,peer_state,expected",
    [
        (["QmPeer"], {"connected": True}, {"QmPeer"}),
        (["QmPeer"], {"connected": False}, set()),
        (["QmPeer"], {}, set()),
        ("invalid", {"connected": True}, set()),
    ],
)
def test_legacy_connected_p2p_peers_require_consistent_state(
    connected_peers: object,
    peer_state: dict,
    expected: set[str],
) -> None:
    """Use compatible connectivity only when both legacy records agree.

    Parameters:
        connected_peers: Decoded legacy connected-peer registry.
        peer_state: Legacy state stored for the peer.
        expected: Peer IDs considered connected.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.redis = Mock()
    reader.redis.get.return_value = connected_peers

    result = reader._legacy_connected_p2p_peers({"QmPeer": peer_state})

    assert result == expected


def test_p2p_uses_legacy_connectivity_without_connection_updates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Show active peers reported by the bundled legacy macOS Pigeon."""
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output" / "run"
    output_dir.mkdir(parents=True)
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.side_effect = lambda key: {
        "connected_peers": json.dumps(["QmLegacyPeer"]),
    }.get(key)
    reader.redis.smembers.return_value = set()
    reader.redis.hget.return_value = None
    reader.redis.hgetall.side_effect = lambda key: {
        "analysis": {"analysis_start": "2026-08-25T23:07:20"},
        "peer_info": {
            "QmLegacyPeer": json.dumps(
                {
                    "connected": True,
                    "ip": "192.0.2.20",
                    "reliability": 1.0,
                    "timestamp": time.time(),
                }
            )
        },
    }.get(key, {})
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    result = reader.p2p()

    assert result["counts"]["connected"] == 1
    assert result["peers"][0]["peer_id"] == "QmLegacyPeer"
    assert result["peers"][0]["connected"] is True
    assert result["peers"][0]["connections"] == []


def test_p2p_received_reports_survive_raw_report_compaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Show current-window message counts after raw trust rows are removed.

    Parameters:
        tmp_path: Isolated run and trust-database location.
        monkeypatch: Changes the process working directory for the test.
    """
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path / "output" / "run"
    reader.output_dir.mkdir(parents=True)
    reader.redis = Mock()
    reader.redis.get.return_value = "2"
    reader.redis.hget.return_value = None
    reader.redis.hgetall.side_effect = lambda key: {
        "p2p_message_counts_2": {
            "received:report": "7",
            "received:blame": "2",
        },
        "p2p_reports_by_peer_2": {"QmRemotePeer": "9"},
    }.get(key, {})
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    result = reader.p2p()

    assert result["counts"]["reports_received"] == 9
    assert result["peers"][0]["reports_received"] == 9


def test_p2p_trust_full_history_keeps_first_detection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep the first and latest reliability samples after history grows large.

    Parameters:
        tmp_path: Isolated trust database directory.
        monkeypatch: Runs the reader against the isolated directory.
    """
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output" / "run"
    output_dir.mkdir(parents=True)
    trust_path = tmp_path / "permanent" / "p2p_trust_runtime" / "trustdb.db"
    trust_path.parent.mkdir(parents=True)
    with sqlite3.connect(trust_path) as connection:
        connection.execute(
            "CREATE TABLE go_reliability "
            "(peerid TEXT, reliability REAL, update_time REAL)"
        )
        connection.execute(
            "CREATE TABLE peer_ips "
            "(peerid TEXT, ipaddress TEXT, update_time REAL)"
        )
        connection.execute(
            "CREATE TABLE reports "
            "(reporter_peerid TEXT, reported_key TEXT, score REAL, "
            "confidence REAL, update_time REAL)"
        )
        connection.execute(
            "INSERT INTO peer_ips VALUES ('QmPeer', '192.0.2.1', 50)"
        )
        connection.executemany(
            "INSERT INTO go_reliability VALUES (?, ?, ?)",
            (("QmPeer", 0.9, float(index)) for index in range(100, 2601)),
        )

    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.return_value = None
    reader.redis.hget.return_value = None
    reader.redis.hgetall.side_effect = lambda key: (
        {"analysis_start": "0"} if key == "analysis" else {}
    )
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    result = reader.p2p({"range": ["all"]})

    assert result["trust_history"][0]["timestamp"] == 100
    assert result["trust_history"][-1]["timestamp"] == 2600
    assert len(result["trust_history"]) <= 2002
    assert result["peers"][0]["first_seen"] == 50


def test_p2p_reliability_chart_uses_compact_range_control() -> None:
    """Wire the compact peer chart to the selected API history range."""
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    html_source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )
    css_source = Path("modules/web_interface/style.css").read_text(
        encoding="utf-8"
    )

    assert 'id="p2p-range"' in html_source
    assert 'id="p2p-trust-chart"' in html_source
    assert "function renderP2PReliabilityChart" in app_source
    assert "/api/p2p?range=${encodeURIComponent(range)}" in app_source
    assert 'byId("p2p-range").addEventListener("change"' in app_source
    assert (
        ".compact-line-chart { height: 130px; min-height: 130px; }"
        in css_source
    )
