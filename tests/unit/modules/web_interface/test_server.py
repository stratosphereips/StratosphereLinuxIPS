from collections import Counter
import json
import socket
import sqlite3
import threading
import time
from pathlib import Path
from urllib.request import urlopen
from unittest.mock import Mock

import pytest

from modules.web_interface.history import connect_history, initialize_history
from modules.web_interface.server import (
    RequestHandler,
    RunDataReader,
    RunMismatchError,
    SlipsHTTPServer,
)
from tests.module_factory import ModuleFactory


def test_idle_connection_does_not_block_page_requests() -> None:
    """Verify a speculative idle browser connection cannot stall the server."""
    _module_factory = ModuleFactory()
    server = SlipsHTTPServer(("127.0.0.1", 0), RequestHandler, Mock())
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    port = int(server.server_address[1])
    idle_connection = socket.create_connection(("127.0.0.1", port), timeout=1)

    try:
        with urlopen(f"http://127.0.0.1:{port}/", timeout=2) as response:
            assert response.status == 200
            assert b"Slips" in response.read()
    finally:
        idle_connection.close()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)


@pytest.mark.parametrize(
    "levels, expected",
    [
        (["info", "medium"], "medium"),
        (["high", "low", "critical"], "critical"),
        ([], "info"),
    ],
)
def test_highest_threat(levels: list[str], expected: str) -> None:
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)

    assert reader._highest_threat(levels) == expected


def test_flows_for_evidence_falls_back_to_evidence_uids(tmp_path) -> None:
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    reader.redis.hget.return_value = None
    reader._redis_evidence = Mock(
        return_value=[{"id": "evidence-1", "uid": ["flow-1"]}]
    )
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE flows (uid TEXT, flow TEXT, label TEXT, "
            "profileid TEXT, twid TEXT, aid TEXT)"
        )
        connection.execute(
            "CREATE TABLE altflows (uid TEXT, flow TEXT, label TEXT, "
            "profileid TEXT, twid TEXT, flow_type TEXT)"
        )
        connection.execute(
            "INSERT INTO flows VALUES (?, ?, ?, ?, ?, ?)",
            ("flow-1", json.dumps({"saddr": "10.0.0.1"}), "benign", "", "", ""),
        )

    result = reader.flows_for_evidence("evidence-1")

    assert result["total"] == 1
    assert result["items"][0]["uid"] == "flow-1"
    assert result["items"][0]["network_flow"]["table"] == "flows"
    assert result["items"][0]["protocol_flows"] == []
    assert result["network_flow_total"] == 1
    assert result["protocol_flow_total"] == 0


def test_flows_for_evidence_reads_durable_conn_and_altflows(tmp_path) -> None:
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE flows (uid TEXT, flow TEXT, label TEXT, "
            "profileid TEXT, twid TEXT, aid TEXT)"
        )
        connection.execute(
            "CREATE TABLE altflows (uid TEXT, flow TEXT, label TEXT, "
            "profileid TEXT, twid TEXT, flow_type TEXT)"
        )
        connection.execute("CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)")
        connection.execute(
            "INSERT INTO flows VALUES (?, ?, ?, ?, ?, ?)",
            ("flow-1", json.dumps({"saddr": "10.0.0.1"}), "benign", "", "", ""),
        )
        connection.execute(
            "INSERT INTO altflows VALUES (?, ?, ?, ?, ?, ?)",
            (
                "flow-1",
                json.dumps(
                    {
                        "query": "aaa.com",
                        "qtype_name": "A",
                        "rcode_name": "NXDOMAIN",
                        "answers": [],
                    }
                ),
                "benign",
                "",
                "",
                "dns",
            ),
        )
        connection.execute(
            "INSERT INTO evidence_flows VALUES (?, ?)",
            ("evidence-1", "flow-1"),
        )

    result = reader.flows_for_evidence("evidence-1")

    assert result["total"] == 1
    assert result["network_flow_total"] == 1
    assert result["protocol_flow_total"] == 1
    group = result["items"][0]
    assert group["network_flow"]["table"] == "flows"
    assert group["protocol_flows"][0]["table"] == "altflows"
    assert group["protocol_flows"][0]["flow"]["query"] == "aaa.com"
    assert group["protocol_flows"][0]["flow"]["rcode_name"] == "NXDOMAIN"


def test_api_routes_evidence_flow_ids() -> None:
    _module_factory = ModuleFactory()
    handler = RequestHandler.__new__(RequestHandler)
    handler.server = Mock()
    handler.server.reader.response_metadata.return_value = {}
    handler.server.reader.flows_for_evidence.return_value = {
        "items": [],
        "count": 0,
    }

    result = handler._api_response("/api/evidence/evidence-1/flows", {})

    assert result["count"] == 0
    handler.server.reader.flows_for_evidence.assert_called_once_with("evidence-1")

    handler.server.reader.evidence_for_host.return_value = {"items": [], "total": 2}
    host_result = handler._api_response("/api/hosts/10.0.0.1/evidence", {})

    assert host_result["total"] == 2
    handler.server.reader.evidence_for_host.assert_called_once_with("10.0.0.1", {})


@pytest.mark.parametrize(
    "evidence_type, expected",
    [
        ("ML_LINEAR_MALICIOUS_FLOW", "ml_linear_model"),
        ("UNSOLICITED_ARP", "arp"),
        ("SUSPICIOUS_USER_AGENT", "http_analyzer"),
        ("HORIZONTAL_PORT_SCAN", "network_discovery"),
        ("CONNECTION_WITHOUT_DNS", "flow_alerts"),
    ],
)
def test_module_for_evidence(evidence_type: str, expected: str) -> None:
    _module_factory = ModuleFactory()

    assert RunDataReader._module_for_evidence(evidence_type) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (["one", "two"], ["one", "two"]),
        ('["one", "two"]', ["one", "two"]),
        ("one", ["one"]),
        (None, []),
    ],
)
def test_id_list_normalizes_redis_alert_values(
    value: object, expected: list[str]
) -> None:
    _module_factory = ModuleFactory()

    assert RunDataReader._id_list(value) == expected


def test_web_returns_durable_connection_without_dns_and_linked_alert(
    tmp_path,
) -> None:
    """Return all durable records without interpreting detection configuration."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "history.sqlite"
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {}
    reader.redis.hget.return_value = None
    reader._ti_for_ip = Mock(return_value={})
    initialize_history(reader.history_path)
    now = time.time()
    with sqlite3.connect(reader.history_path) as connection:
        connection.execute(
            "INSERT INTO host_snapshots VALUES (?, ?, ?)",
            (
                "10.0.0.1",
                now,
                json.dumps(
                    {
                        "ip": "10.0.0.1",
                        "scope": "local",
                        "all_ips": ["10.0.0.1"],
                        "hostname": "workstation",
                    }
                ),
            ),
        )
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE alerts (alert_id TEXT, alert_time REAL, "
            "ip_alerted TEXT, timewindow TEXT, tw_start TEXT, "
            "tw_end TEXT, label TEXT)"
        )
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT, evidence_time REAL, "
            "profile_ip TEXT, timewindow TEXT, threat_level TEXT, "
            "evidence_type TEXT, description TEXT, confidence REAL, data TEXT)"
        )
        connection.execute("CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)")
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.execute(
            "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("alert-1", now - 1, "10.0.0.1", "timewindow1", "", "", "malicious"),
        )
        connection.execute(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "evidence-1",
                now - 2,
                "10.0.0.1",
                "timewindow1",
                "high",
                "CONNECTION_WITHOUT_DNS",
                "Durable evidence",
                1.0,
                "{}",
            ),
        )
        connection.execute(
            "INSERT INTO alert_evidence VALUES (?, ?)",
            ("alert-1", "evidence-1"),
        )

    host = reader.host("10.0.0.1")
    evidence_page = reader.evidence(
        {"range": ["all"], "search": ["CONNECTION_WITHOUT_DNS"]}
    )
    alert_page = reader.alerts(
        {"range": ["all"], "search": ["alert-1"], "limit": ["1"]}
    )

    assert host["live"] is False
    assert host["hostname"] == "workstation"
    assert host["evidence_count"] == 1
    assert host["alert_count"] == 1
    assert host["alerts"][0]["alert_id"] == "alert-1"
    assert host["alerts"][0]["evidence_count"] == 1
    assert evidence_page["full_total"] == 1
    assert evidence_page["total"] == 1
    assert evidence_page["items"][0]["evidence_type"] == "CONNECTION_WITHOUT_DNS"
    assert evidence_page["items"][0]["alert_ids"] == ["alert-1"]
    assert alert_page["full_total"] == 1
    assert alert_page["total"] == 1
    assert alert_page["items"][0]["evidence"][0]["id"] == "evidence-1"
    assert host["alerts"][0]["threat_level"] == "high"


@pytest.mark.parametrize("redis_output", [None, "output/different"])
def test_validate_run_identity_rejects_missing_or_stale_redis(
    redis_output: str | None,
) -> None:
    """Reject requests unless Redis identifies the exact configured run."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = Path("output/current")
    reader.redis_port = 32768
    reader.redis = Mock()
    reader.redis.hgetall.return_value = (
        {"output_dir": redis_output} if redis_output is not None else {}
    )

    with pytest.raises(RunMismatchError):
        reader.validate_run_identity()


def test_evidence_cursor_is_stable_when_newer_rows_arrive(tmp_path) -> None:
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute("CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)")
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    f"evidence-{number}",
                    float(number),
                    "10.0.0.1",
                    "tw",
                    "low",
                    "UNKNOWN_PORT",
                    "",
                    1.0,
                    "{}",
                )
                for number in range(1, 5)
            ],
        )

    first = reader.evidence({"range": ["all"], "limit": ["2"]})
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("newer", 10.0, "10.0.0.1", "tw", "high", "UNKNOWN_PORT", "", 1.0, "{}"),
        )
    second = reader.evidence(
        {
            "range": ["all"],
            "limit": ["2"],
            "cursor": [first["next_cursor"]],
        }
    )

    assert [item["id"] for item in first["items"]] == [
        "evidence-4",
        "evidence-3",
    ]
    assert [item["id"] for item in second["items"]] == [
        "evidence-2",
        "evidence-1",
    ]


def test_host_flows_match_all_ips_in_both_directions(tmp_path) -> None:
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "history.sqlite"
    reader._host_ips = Mock(return_value=["10.0.0.1", "fe80::1"])
    initialize_history(reader.history_path)
    raw_rows = [
        (
            "outbound",
            json.dumps(
                {
                    "saddr": "10.0.0.1",
                    "daddr": "8.8.8.8",
                    "sport": 1000,
                    "dport": 53,
                }
            ),
            "benign",
            "",
            "",
            "",
        ),
        (
            "inbound",
            json.dumps(
                {
                    "saddr": "1.1.1.1",
                    "daddr": "fe80::1",
                    "sport": 443,
                    "dport": 2000,
                }
            ),
            "malicious",
            "",
            "",
            "",
        ),
    ]
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE flows (uid TEXT, flow TEXT, label TEXT, "
            "profileid TEXT, twid TEXT, aid TEXT)"
        )
        connection.executemany("INSERT INTO flows VALUES (?, ?, ?, ?, ?, ?)", raw_rows)
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO flow_index VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "outbound",
                    1,
                    20.0,
                    "10.0.0.1",
                    "8.8.8.8",
                    "udp",
                    "dns",
                    100,
                    2,
                    "benign",
                ),
                (
                    "inbound",
                    2,
                    10.0,
                    "1.1.1.1",
                    "fe80::1",
                    "tcp",
                    "ssl",
                    200,
                    3,
                    "malicious",
                ),
            ],
        )

    result = reader.flows_for_host("10.0.0.1", {"range": ["all"]})

    assert result["total"] == 2
    assert [item["direction"] for item in result["items"]] == [
        "outbound",
        "inbound",
    ]
    assert [item["peer"] for item in result["items"]] == [
        "8.8.8.8",
        "1.1.1.1",
    ]


def test_metrics_response_never_exceeds_requested_points(tmp_path) -> None:
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.history_path = tmp_path / "history.sqlite"
    initialize_history(reader.history_path)
    now = time.time()
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO runtime_metrics_1s VALUES (?, ?, ?, ?, ?)",
            [
                (now - number, number % 100, 100 + number, number % 10, number % 7)
                for number in range(2000)
            ],
        )

    result = reader.metrics({"range": ["1h"], "max_points": ["100"]})

    assert result["page_size"] <= 100
    assert result["max_points"] == 100


def test_durable_module_counts_survive_redis_window_expiry(tmp_path) -> None:
    """Test module health uses durable evidence after Redis cleanup."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    database_path = tmp_path / "flows.sqlite"
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("CREATE TABLE evidence (evidence_type TEXT)")
        connection.executemany(
            "INSERT INTO evidence VALUES (?)",
            [
                ("ML_LINEAR_MALICIOUS_FLOW",),
                ("ML_LINEAR_MALICIOUS_FLOW",),
                ("ARP_SCAN",),
            ],
        )
        counts = reader._durable_evidence_counts(connection)

    assert counts["ml_linear_model"] == 2
    assert counts["arp"] == 1


def test_module_rows_exclude_internal_threads(mocker) -> None:
    """Verify PID bookkeeping threads are not presented as Slips modules."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {
        "flow_alerts": "123",
        "dns_without_connection_timeout_checker_thread": "124",
    }
    reader.redis.smembers.return_value = set()
    process = Mock()
    process.is_running.return_value = True
    process.status.return_value = "sleeping"
    process.memory_info.return_value = Mock(rss=1024 * 1024)
    process.cpu_percent.return_value = 0
    mocker.patch(
        "modules.web_interface.server.psutil.virtual_memory",
        return_value=Mock(total=100 * 1024 * 1024),
    )
    reader._processes = {123: process}

    rows = reader._module_rows(Counter(), {}, analysis_complete=False)

    assert rows[0]["memory_percent"] == 1.0
    assert [row["name"] for row in rows] == ["flow_alerts"]


def test_live_evidence_range_uses_newest_capture_timestamp(tmp_path) -> None:
    """Test offline evidence ranges follow capture time instead of wall time."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute("CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)")
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                ("old", 100.0, "10.0.0.1", "tw", "low", "OLD", "", 1.0, "{}"),
                (
                    "current",
                    7300.0,
                    "10.0.0.1",
                    "tw",
                    "high",
                    "CURRENT",
                    "",
                    1.0,
                    "{}",
                ),
            ],
        )

    result = reader.evidence({"range": ["live"]})

    assert result["total"] == 1
    assert result["full_total"] == 2
    assert result["items"][0]["id"] == "current"


def test_host_load_reports_directional_flows_and_bytes(tmp_path) -> None:
    """Test host totals separate inbound, outbound, and internal traffic."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.history_path = tmp_path / "history.sqlite"
    reader._host_ips = Mock(return_value=["10.0.0.1"])
    initialize_history(reader.history_path)
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO flow_index VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                ("in", 1, 1.0, "8.8.8.8", "10.0.0.1", "tcp", "", 100, 2, ""),
                ("out", 2, 2.0, "10.0.0.1", "1.1.1.1", "udp", "", 200, 3, ""),
                ("self", 3, 3.0, "10.0.0.1", "10.0.0.1", "tcp", "", 50, 1, ""),
            ],
        )

    load = reader._host_load("10.0.0.1")

    assert load["flows"] == 3
    assert load["inbound_flows"] == 1
    assert load["outbound_flows"] == 1
    assert load["inbound_bytes"] == 100
    assert load["outbound_bytes"] == 200


def test_evidence_sorting_is_server_side_and_stable(tmp_path) -> None:
    """Test evidence sort parameters order the complete result before paging."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute("CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)")
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                ("z", 1.0, "192.0.2.20", "tw", "low", "B", "", 1.0, "{}"),
                ("a", 2.0, "192.0.2.10", "tw", "high", "A", "", 1.0, "{}"),
            ],
        )

    result = reader.evidence({"range": ["all"], "sort": ["host"], "order": ["asc"]})

    assert [item["id"] for item in result["items"]] == ["a", "z"]
    assert result["sort"] == "host"
    assert result["order"] == "asc"


def test_host_evidence_includes_associated_ips_and_sorts_before_paging(
    tmp_path,
) -> None:
    """Test a host evidence page covers all addresses with server-side sorting."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    reader._host_ips = Mock(return_value=["10.0.0.1", "2001:db8::1"])
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute("CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)")
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                ("low", 3.0, "10.0.0.1", "tw", "low", "DNS", "first", 0.2, "{}"),
                ("high", 2.0, "2001:db8::1", "tw", "high", "SCAN", "second", 0.9, "{}"),
                (
                    "other",
                    4.0,
                    "203.0.113.4",
                    "tw",
                    "high",
                    "OTHER",
                    "excluded",
                    1.0,
                    "{}",
                ),
            ],
        )

    result = reader.evidence_for_host(
        "10.0.0.1",
        {"range": ["all"], "sort": ["confidence"], "order": ["desc"]},
    )

    assert result["total"] == 2
    assert [item["id"] for item in result["items"]] == ["high", "low"]
    reader._host_ips.assert_called_once_with("10.0.0.1")

def test_host_evidence_searches_all_durable_evidence_fields(tmp_path) -> None:
    """Test host evidence search includes raw fields and linked identifiers."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    reader._host_ips = Mock(return_value=["10.0.0.1"])
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute("CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)")
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.execute(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "evidence-id", 1.0, "10.0.0.1", "tw", "low", "DNS", "",
                0.2, '{"attacker": "raw-field-token"}',
            ),
        )
        connection.execute(
            "INSERT INTO evidence_flows VALUES (?, ?)",
            ("evidence-id", "flow-identifier-token"),
        )
        connection.execute(
            "INSERT INTO alert_evidence VALUES (?, ?)",
            ("alert-identifier-token", "evidence-id"),
        )

    for search in (
        "raw-field-token",
        "flow-identifier-token",
        "alert-identifier-token",
    ):
        result = reader.evidence_for_host(
            "10.0.0.1", {"range": ["all"], "search": [search]}
        )

        assert [item["id"] for item in result["items"]] == ["evidence-id"]


def test_ip_context_prefers_rdns_and_reports_ti_feeds() -> None:
    """Test cached IP context returns rDNS, DNS fallback, and TI feed names."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader._ti_for_ip = Mock(
        return_value={
            "reverse_dns": "rdns.example.test",
            "threatintelligence": {"source": ["feed-a", "feed-b"]},
        }
    )

    context = reader._ip_context_for_ip(
        "192.0.2.1", {"domains": ["domain.example.test"]}
    )

    assert context == {
        "dns_name": "rdns.example.test",
        "dns_name_source": "rDNS",
        "ti_feeds": ["feed-a", "feed-b"],
    }

    reader._ti_for_ip.return_value = {}
    fallback = reader._ip_context_for_ip(
        "192.0.2.1", {"domains": ["domain.example.test"]}
    )

    assert fallback["dns_name"] == "domain.example.test"
    assert fallback["dns_name_source"] == "DNS"
    assert fallback["ti_feeds"] == []

def test_run_metadata_reads_info_file(tmp_path) -> None:
    """Test the overview metadata parser preserves technical run facts."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    (metadata_dir / "info.txt").write_text(
        "Slips version: 1.2.3\nBranch: develop\nCommand: ./slips.py -w\n",
        encoding="utf-8",
    )

    metadata = reader._run_metadata()

    assert metadata == {
        "Slips version": "1.2.3",
        "Branch": "develop",
        "Command": "./slips.py -w",
    }


def test_evidence_aggregation_groups_host_and_type(tmp_path) -> None:
    """Test repeated evidence becomes one bounded host/type aggregate."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute("CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)")
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                ("one", 1.0, "10.0.0.1", "tw", "low", "SCAN", "", 1.0, "{}"),
                ("two", 2.0, "10.0.0.1", "tw", "high", "SCAN", "", 1.0, "{}"),
                ("three", 3.0, "10.0.0.1", "tw", "low", "DNS", "", 1.0, "{}"),
            ],
        )
        connection.executemany(
            "INSERT INTO evidence_flows VALUES (?, ?)",
            [("one", "flow-1"), ("two", "flow-2")],
        )

    result = reader.evidence(
        {
            "range": ["all"],
            "group": ["host_type"],
            "sort": ["evidence"],
            "order": ["desc"],
        }
    )

    assert result["total"] == 2
    assert result["full_total"] == 3
    assert result["items"][0]["evidence_type"] == "SCAN"
    assert result["items"][0]["evidence_count"] == 2
    assert result["items"][0]["flow_count"] == 2
    assert result["items"][0]["threat_level"] == "high"


def test_alert_aggregation_groups_each_host(tmp_path) -> None:
    """Test repeated alerts become one aggregate per affected host."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            "CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, alert_time REAL, "
            "ip_alerted TEXT, timewindow TEXT, tw_start TEXT, tw_end TEXT, "
            "label TEXT)"
        )
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute("CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)")
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                ("a1", 1.0, "10.0.0.1", "tw", "", "", "malicious"),
                ("a2", 2.0, "10.0.0.1", "tw", "", "", "malicious"),
                ("a3", 3.0, "10.0.0.2", "tw", "", "", "malicious"),
            ],
        )
        connection.execute(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("e1", 1.0, "10.0.0.1", "tw", "high", "SCAN", "", 1.0, "{}"),
        )
        connection.executemany(
            "INSERT INTO alert_evidence VALUES (?, ?)",
            [("a1", "e1"), ("a2", "e1")],
        )

    result = reader.alerts(
        {
            "range": ["all"],
            "group": ["host"],
            "sort": ["alerts"],
            "order": ["desc"],
        }
    )
    compact_result = reader.alerts(
        {
            "range": ["all"],
            "search": ["a1"],
            "details": ["false"],
        }
    )

    assert result["total"] == 2
    assert result["full_total"] == 3
    assert result["items"][0]["ip_alerted"] == "10.0.0.1"
    assert result["items"][0]["alert_count"] == 2
    assert result["items"][0]["evidence_count"] == 2
    assert result["items"][0]["threat_level"] == "high"
    assert compact_result["items"][0]["evidence_count"] == 1
    assert compact_result["items"][0]["threat_level"] == "high"
    assert "evidence" not in compact_result["items"][0]


def test_hosts_filter_by_maximum_threat_level(tmp_path) -> None:
    """Test Host Inventory applies the threat filter before pagination."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "history.sqlite"
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {}
    reader._host_load = Mock(
        return_value={"flows": 0, "bytes": 0, "packets": 0, "last_seen": 0}
    )
    reader._profile_evidence_count = Mock(return_value=0)
    reader._profile_alert_count = Mock(return_value=0)
    initialize_history(reader.history_path)
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("CREATE TABLE evidence (profile_ip TEXT)")
        connection.execute("CREATE TABLE alerts (ip_alerted TEXT)")
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO host_snapshots VALUES (?, ?, ?)",
            [
                (
                    "10.0.0.1",
                    1.0,
                    json.dumps(
                        {
                            "ip": "10.0.0.1",
                            "scope": "local",
                            "max_threat_level": "high",
                        }
                    ),
                ),
                (
                    "10.0.0.2",
                    2.0,
                    json.dumps(
                        {
                            "ip": "10.0.0.2",
                            "scope": "local",
                            "max_threat_level": "info",
                        }
                    ),
                ),
            ],
        )

    result = reader.hosts({"range": ["all"], "threat": ["high"]})

    assert result["total"] == 1
    assert result["full_total"] == 2
    assert result["items"][0]["ip"] == "10.0.0.1"


def test_hosts_live_range_uses_indexed_flow_clock(tmp_path) -> None:
    """Test capture-relative traffic is not compared with wall-clock snapshots."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "history.sqlite"
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {}
    reader._host_load = Mock(
        return_value={"flows": 1, "bytes": 100, "packets": 2, "last_seen": 4000}
    )
    reader._profile_evidence_count = Mock(return_value=0)
    reader._profile_alert_count = Mock(return_value=0)
    initialize_history(reader.history_path)
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("CREATE TABLE evidence (profile_ip TEXT)")
        connection.execute("CREATE TABLE alerts (ip_alerted TEXT)")
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO host_snapshots VALUES (?, ?, ?)",
            [
                (
                    "10.0.0.1",
                    2_000_000_000.0,
                    json.dumps({"ip": "10.0.0.1", "scope": "local"}),
                ),
                (
                    "10.0.0.2",
                    2_000_000_001.0,
                    json.dumps({"ip": "10.0.0.2", "scope": "local"}),
                ),
            ],
        )
        connection.executemany(
            "INSERT INTO flow_index VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "recent",
                    1,
                    4000.0,
                    "10.0.0.1",
                    "8.8.8.8",
                    "udp",
                    "dns",
                    100,
                    2,
                    "benign",
                ),
                (
                    "old",
                    2,
                    100.0,
                    "10.0.0.2",
                    "1.1.1.1",
                    "tcp",
                    "ssl",
                    200,
                    3,
                    "benign",
                ),
            ],
        )

    result = reader.hosts({"range": ["live"]})
    full_run = reader.hosts({"range": ["all"]})

    assert result["total"] == 1
    assert result["full_total"] == 2
    assert result["items"][0]["ip"] == "10.0.0.1"
    assert full_run["total"] == 2


def test_p2p_reports_enabled_listener_and_healthy_empty_network(
    tmp_path, monkeypatch
) -> None:
    """Expose a listening P2P module even before any peers are discovered."""
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output" / "run"
    log_dir = output_dir / "p2p_trust"
    log_dir.mkdir(parents=True)
    log_dir.joinpath("p2p.log").write_text(
        "[*] Your Multiaddress Is:  "
        "/ip4/10.0.0.1/tcp/32768/p2p/QmLocalPeer\n",
        encoding="utf-8",
    )
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.return_value = None
    reader.redis.hget.side_effect = lambda key, field: (
        "123" if (key, field) == ("PIDs", "p2p_trust") else None
    )
    reader.redis.hgetall.side_effect = lambda key: (
        {"analysis_start": "2026-08-25T23:07:20"}
        if key == "analysis"
        else {}
    )
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    result = reader.p2p()

    assert result["enabled"] is True
    assert result["local_peer_id"] == "QmLocalPeer"
    assert result["counts"]["connected"] == 0
    assert result["peers"] == []
