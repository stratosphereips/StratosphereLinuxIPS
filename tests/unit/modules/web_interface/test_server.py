from collections import Counter
import argparse
import json
import socket
import sqlite3
import threading
import time
from pathlib import Path
from urllib.request import urlopen
from unittest.mock import Mock, patch

import pytest
import psutil

from modules.web_interface.history import connect_history, initialize_history
from modules.web_interface.server import (
    RequestHandler,
    RunDataReader,
    RunMismatchError,
    SlipsHTTPServer,
    ipv4_address,
)
from tests.module_factory import ModuleFactory


def test_idle_connection_does_not_block_page_requests() -> None:
    """Verify a speculative idle browser connection cannot stall the server."""
    _module_factory = ModuleFactory()
    server = SlipsHTTPServer(("127.0.0.1", 0), RequestHandler, Mock())
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    port = int(server.server_address[1])
    idle_connection = socket.create_connection(("127.0.0.1", port), timeout=5)

    try:
        with urlopen(f"http://127.0.0.1:{port}/", timeout=10) as response:
            assert response.status == 200
            page = response.read()
            assert b"Slips" in page
            assert b'class="brand-logo"' in page
            assert b'src="/favicon.svg?v=3"' in page
            assert b'<p class="brand-name">SLIPS</p>' in page
        with urlopen(
            f"http://127.0.0.1:{port}/favicon.svg", timeout=10
        ) as response:
            assert response.status == 200
            assert response.headers["Content-Type"] == "image/svg+xml"
            favicon = response.read()
            assert b"<svg" in favicon
            assert b'xmlns="http://www.w3.org/2000/svg"' in favicon
        with urlopen(
            f"http://127.0.0.1:{port}/slips-logo.png", timeout=10
        ) as response:
            assert response.status == 200
            assert response.headers["Content-Type"] == "image/png"
            assert response.read().startswith(b"\x89PNG\r\n\x1a\n")
    finally:
        idle_connection.close()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=10)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("127.0.0.1", "127.0.0.1"),
        ("192.0.2.25", "192.0.2.25"),
    ],
)
def test_server_accepts_only_normalized_ipv4_bind_addresses(
    value: str, expected: str
) -> None:
    """Validate exact IPv4 server bind addresses.

    Parameters:
        value: Address supplied to the server.
        expected: Normalized address.
    """
    _module_factory = ModuleFactory()

    assert ipv4_address(value) == expected


@pytest.mark.parametrize("value", ["::1", "localhost", "0.0.0.0", "0.0.0.0/0"])
def test_server_rejects_non_ipv4_bind_addresses(value: str) -> None:
    """Reject hostnames, IPv6, and network ranges as listen addresses.

    Parameters:
        value: Invalid bind value supplied to the server.
    """
    _module_factory = ModuleFactory()

    with pytest.raises(argparse.ArgumentTypeError):
        ipv4_address(value)


def test_header_marks_failed_web_connection_as_disconnected() -> None:
    """Keep the persistent run indicator honest when API polling fails."""
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    connection_renderer = app_source.split(
        "function renderConnectionState(connected)", 1
    )[1].split("function toast", 1)[0]
    api_error_handler = app_source.split("async function api", 1)[1].split(
        "function renderTable", 1
    )[0]

    assert 'dot.className = "state-dot error"' in connection_renderer
    assert 'label.textContent = "Web disconnected"' in connection_renderer
    assert "renderConnectionState(false);" in api_error_handler
    assert "renderConnectionState(true);" in api_error_handler


@pytest.mark.parametrize("tab", ["alerts", "evidence", "hosts"])
def test_primary_tables_render_real_slips_score_column(tab: str) -> None:
    """Keep the real Slips score visible in all three requested tables.

    Parameters:
        tab: Web-interface table whose score header and cell are verified.
    """
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    index_source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )

    if tab == "alerts":
        section = app_source.split("async function loadAlerts()", 1)[1].split(
            "async function loadEvidence()", 1
        )[0]
        assert '["Peak Slips score", "score"]' in section
        assert '["Slips score", "score"]' in section
        assert "(row) => slipsScore(row)" in section
    elif tab == "evidence":
        section = app_source.split("async function loadEvidence()", 1)[
            1
        ].split("async function loadFirewall()", 1)[0]
        assert '["Peak Slips score", "score"]' in section
        assert '["Slips score", "score"]' in section
        assert "(row) => slipsScore(row)" in section
    else:
        section = app_source.split("async function loadHosts()", 1)[1].split(
            "function contextName", 1
        )[0]
        style_source = Path("modules/web_interface/style.css").read_text(
            encoding="utf-8"
        )
        summary_renderer = app_source.split("function setSummaryCards", 1)[
            1
        ].split("function renderOverview", 1)[0]
        assert 'data-sort="score">Current Slips score</th>' in index_source
        assert (
            'data-sort="peak_score">Past peak Slips score</th>' in index_source
        )
        assert "(row) => pastPeakSlipsScore(row)" in section
        assert (
            'id="host-score-chart" class="line-chart" viewBox="0 0 1200 180"'
            in index_source
        )
        assert (
            ".score-history-figure .line-chart { height: 180px" in style_source
        )
        assert "height * renderedWidth / renderedHeight" in app_source
        assert "async function loadLegacyScoreHistory(params)" in app_source
        assert "compatibility_limited: total > records.length" in app_source
        assert 'params.set("profile", state.host.ip)' in app_source
        assert (
            "row.src_ip === state.host.ip || row.dst_ip === state.host.ip"
            in app_source
        )
        assert (
            "host.exact_aggregates = staleAliases.length === 0" in app_source
        )
        assert "(row) => slipsScore(row)" in section
        assert "openHost(row.ip, row)" in section
        host_workspace = app_source.split("async function openHost", 1)[
            1
        ].split("async function refreshHostWorkspace", 1)[0]
        assert 'range: "all", search: ip' in host_workspace
        assert ".find((row) => row.ip === ip)" in host_workspace
        assert "value instanceof Node" in summary_renderer
        assert "valueElement.append(value)" in summary_renderer
        assert "loadHostScoreHistory()" in app_source


@pytest.mark.parametrize(
    "renderer, expected",
    [
        ("const text =", "element.textContent = displayValue(value)"),
        ("const cell =", "td.textContent = displayValue(value)"),
        (
            "function setSummaryCards",
            "valueElement.textContent = displayValue(value)",
        ),
    ],
)
def test_shared_renderers_humanize_unix_timestamps(
    renderer: str, expected: str
) -> None:
    """Keep raw Unix epochs out of tables, cards, and detail fields.

    Parameters:
        renderer: Start of the shared renderer being checked.
        expected: Human-time conversion required inside that renderer.
    """
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    section = app_source.split(renderer, 1)[1].split("\n}", 1)[0]

    assert expected in section


@pytest.mark.parametrize(
    "expected",
    [
        "JSON.stringify(displayData(record), null, 2)",
        "JSON.stringify(displayData(host.ti), null, 2)",
        "JSON.stringify(displayData(value))",
        "String(displayValue(value))",
    ],
)
def test_nested_detail_fields_humanize_unix_timestamps(expected: str) -> None:
    """Keep raw Unix epochs out of nested and protocol detail fields.

    Parameters:
        expected: Required use of the recursive human-time formatter.
    """
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )

    assert expected in app_source


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


def test_configuration_explains_captured_run_snapshot(tmp_path) -> None:
    """Render every captured setting as explained data and redact secrets."""
    _module_factory = ModuleFactory()
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    (metadata / "run.yaml").write_text(
        "parameters:\n  time_window_width: 3600\n"
        "web_interface:\n  enabled: true\n  api_key: keep-private\n",
        encoding="utf-8",
    )
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path

    result = reader.configuration()

    assert result["source"] == "run.yaml"
    assert result["total"] == 3
    parameters = result["sections"][0]
    assert (
        "evidence is accumulated" in parameters["settings"][0]["explanation"]
    )
    web_settings = result["sections"][1]["settings"]
    assert web_settings[1]["value"] == "Configured — hidden"
    assert web_settings[1]["sensitive"] is True


def test_whitelists_returns_parsed_runtime_rules(tmp_path) -> None:
    """Show the active parsed rule rather than dumping whitelist text."""
    _module_factory = ModuleFactory()
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    (metadata / "run.yaml").write_text(
        "whitelists:\n  enable_local_whitelist: true\n"
        "  enable_online_whitelist: false\n",
        encoding="utf-8",
    )
    (metadata / "run.conf").write_text(
        "ip,147.32.80.37,both,alerts\n", encoding="utf-8"
    )
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.redis = Mock()
    reader.redis.hgetall.side_effect = lambda key: {
        "whitelist_IPs": {
            "147.32.80.37": json.dumps(
                {"from": "both", "what_to_ignore": "alerts"}
            )
        }
    }.get(key, {})
    reader.cache = Mock()
    reader.cache.zcard.return_value = 0

    result = reader.whitelists()

    assert result["total"] == 1
    assert result["rules"][0]["value"] == "147.32.80.37"
    assert result["rules"][0]["effect"] == (
        "Suppresses evidence and alerts when this value appears on the source or destination side."
    )


def test_whitelisted_evidence_reports_matching_victim_rule() -> None:
    """Explain why Slips retained evidence but did not add it to the score."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.redis = Mock()
    pipeline = reader.redis.pipeline.return_value
    pipeline.execute.return_value = [True]
    reader._runtime_whitelist_rules = Mock(
        return_value=[
            {
                "type": "IP address",
                "value": "147.32.80.37",
                "direction": "both",
                "ignore": "alerts",
                "effect": "Suppresses evidence and alerts.",
            }
        ]
    )
    items = [
        {
            "id": "evidence-1",
            "attacker": {
                "value": "91.231.89.211",
                "ioc_type": "IP",
                "direction": "SRC",
            },
            "victim": {
                "value": "147.32.80.37",
                "ioc_type": "IP",
                "direction": "DST",
            },
        }
    ]

    reader._annotate_whitelisted_evidence(items)

    assert items[0]["whitelisted"] is True
    assert items[0]["whitelist_matches"] == [
        {
            "entity": "victim",
            "type": "IP address",
            "value": "147.32.80.37",
            "rule": "147.32.80.37",
            "direction": "both",
            "ignore": "alerts",
            "effect": "Suppresses evidence and alerts.",
        }
    ]


def test_configuration_and_whitelist_tabs_are_wired() -> None:
    """Keep both run-inspection tabs and evidence exclusion UI reachable."""
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    index_source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )
    server_source = Path("modules/web_interface/server.py").read_text(
        encoding="utf-8"
    )

    assert 'data-tab="configuration"' in index_source
    assert 'data-tab="whitelists"' in index_source
    assert 'id="configuration-sections"' in index_source
    assert 'id="whitelists-table"' in index_source
    assert "function whitelistHandling" not in app_source
    assert "const whitelistHandling" in app_source
    assert 'path == "/api/configuration"' in server_source
    assert 'path == "/api/whitelists"' in server_source


def test_overview_prioritizes_operational_data() -> None:
    """Keep supporting metadata and logs out of the operational overview."""
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    index_source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )
    overview = index_source.split('<section id="overview"', 1)[1].split(
        '<section id="logs"', 1
    )[0]

    assert (
        'rel="icon" href="/favicon.svg?v=2" type="image/svg+xml" sizes="any"'
        in index_source
    )
    favicon_source = Path("modules/web_interface/favicon.svg").read_text(
        encoding="utf-8"
    )
    assert "<rect" not in favicon_source
    assert 'viewBox="0 0 128 128"' in favicon_source
    assert 'stroke-width="7.5"' in favicon_source
    assert 'data-tab="logs"' in index_source
    assert 'data-tab="metadata"' in index_source
    assert 'id="logs-table"' in index_source
    assert 'id="run-metadata"' in index_source
    assert "Data sources" not in overview
    assert "Run metadata" not in overview
    assert "Recent log events" not in overview
    assert '["Uptime", formatDuration(data.run.uptime_seconds)]' in app_source
    assert '["FW active", compact(firewall.current)]' in app_source
    assert '["FW added", compact(firewall.added)]' in app_source
    assert '["FW discarded", compact(firewall.discarded)]' in app_source
    assert 'sort: "cpu_percent", order: "desc"' in app_source
    assert "document.title = `Slips ${compact" in app_source


@pytest.mark.parametrize(
    "analysis, now, expected",
    [
        ({"analysis_start": "100"}, 160.0, 60.0),
        (
            {"analysis_start": "100", "analysis_end": "130"},
            160.0,
            30.0,
        ),
        ({}, 160.0, None),
        ({"analysis_start": "200"}, 160.0, 0.0),
    ],
)
def test_run_uptime_seconds(
    analysis: dict, now: float, expected: float | None
) -> None:
    """Calculate live uptime and freeze completed run duration."""
    _module_factory = ModuleFactory()

    assert RunDataReader._run_uptime_seconds(analysis, now) == expected


def test_firewall_overview_counts_rule_transitions() -> None:
    """Expose active, added, and discarded enforcement totals."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.redis = Mock()
    reader.redis.zrange.return_value = [("10.0.0.1", 100.0)]
    reader.redis.hgetall.return_value = {
        "10.0.0.1": "{}",
        "10.0.0.2": "{}",
    }
    history = [
        {"action": "blocked", "ip": "10.0.0.1"},
        {"action": "blocked", "ip": "10.0.0.2"},
        {"action": "unblocked", "ip": "10.0.0.3"},
        {"action": "unblock failed", "ip": "10.0.0.4"},
    ]
    reader._firewall_history = Mock(return_value=history)
    reader._firewall_attack_estimate = Mock(
        return_value={"packets": 8, "flows": 3, "evidence": 1}
    )

    result = reader._firewall_overview()

    assert result == {
        "current": 2,
        "added": 2,
        "discarded": 1,
        "impact": {"packets": 8, "flows": 3, "evidence": 1},
    }
    reader._firewall_attack_estimate.assert_called_once_with(
        history, {"10.0.0.1": 100.0}
    )


def test_metadata_and_logs_endpoints_are_bounded(tmp_path: Path) -> None:
    """Read supporting run facts without loading the full overview."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.history_path = tmp_path / "history.sqlite"
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    (metadata_dir / "info.txt").write_text(
        "Slips version: 1.2.3\nBranch: local-web-page\n",
        encoding="utf-8",
    )
    initialize_history(reader.history_path)
    with connect_history(reader.history_path) as history:
        history.execute(
            "INSERT INTO error_events(event_time, module, message, line) "
            "VALUES (?, ?, ?, ?)",
            (100.0, "Profiler", "failed once", "raw line"),
        )

    metadata = reader.metadata()
    logs = reader.logs()

    assert metadata["items"]["Slips version"] == "1.2.3"
    assert metadata["items"]["Branch"] == "local-web-page"
    assert logs["total"] == 1
    assert logs["items"][0]["module"] == "Profiler"
    assert logs["items"][0]["message"] == "failed once"
    assert logs["items"][0]["line"] == "raw line"


def test_log_rows_open_the_colored_raw_console() -> None:
    """Keep each log row clickable with its exact source line visible."""
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    index_source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )
    style_source = Path("modules/web_interface/style.css").read_text(
        encoding="utf-8"
    )

    assert "function openLog(record)" in app_source
    assert 'openDrawer("RUNTIME LOG", record.module || "Slips")' in app_source
    assert "record.line || record.message" in app_source
    assert "], openLog);" in app_source
    assert "function appendHighlightedLogText" in app_source
    assert "<th>Time</th><th>Level</th><th>Module</th>" in index_source
    assert ".log-console-titlebar" in style_source
    assert ".log-console-level.critical" in style_source
    assert ".log-token-reference" in style_source


@pytest.mark.parametrize(
    "mode, expected_score, expected_threshold",
    [
        ("ratl", 1.6, 5.0),
        ("atl", 5.0, 15.0),
    ],
)
def test_score_fields_use_real_slips_detector_value(
    mode: str, expected_score: float, expected_threshold: float
) -> None:
    """Select the same ATL or RATL value that Slips compares to its threshold."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.score_mode = mode
    reader.alert_threshold = expected_threshold

    result = reader._score_fields(5.0, 1.6, "test capture")

    assert result["alert_score"] == expected_score
    assert result["alert_threshold"] == expected_threshold
    assert result["alert_score_mode"] == mode.upper()


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
            (
                "flow-1",
                json.dumps({"saddr": "10.0.0.1"}),
                "benign",
                "",
                "",
                "",
            ),
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
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "INSERT INTO flows VALUES (?, ?, ?, ?, ?, ?)",
            (
                "flow-1",
                json.dumps({"saddr": "10.0.0.1"}),
                "benign",
                "",
                "",
                "",
            ),
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
    handler.server.reader.flows_for_evidence.assert_called_once_with(
        "evidence-1"
    )

    handler.server.reader.evidence_for_host.return_value = {
        "items": [],
        "total": 2,
    }
    host_result = handler._api_response("/api/hosts/10.0.0.1/evidence", {})

    assert host_result["total"] == 2
    handler.server.reader.evidence_for_host.assert_called_once_with(
        "10.0.0.1", {}
    )

    handler.server.reader.score_history.return_value = {
        "timeline": [],
        "threshold": 5.0,
    }
    score_result = handler._api_response(
        "/api/hosts/10.0.0.1/score-history", {"range": ["all"]}
    )

    assert score_result["threshold"] == 5.0
    handler.server.reader.score_history.assert_called_once_with(
        "10.0.0.1", {"range": ["all"]}
    )


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
    timewindow_pipeline = Mock()
    timewindow_pipeline.execute.return_value = [[]]
    score_pipeline = Mock()
    score_pipeline.execute.return_value = [1.26]
    reader.redis.pipeline.side_effect = [timewindow_pipeline, score_pipeline]
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
            "evidence_type TEXT, source_module TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.execute(
            "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "alert-1",
                now - 1,
                "10.0.0.1",
                "timewindow1",
                "",
                "",
                "malicious",
            ),
        )
        connection.execute(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "evidence-1",
                now - 2,
                "10.0.0.1",
                "timewindow1",
                "high",
                "CONNECTION_WITHOUT_DNS",
                "conn_analyzer",
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
    grouped_evidence_page = reader.evidence(
        {"range": ["all"], "group": ["host_type"]}
    )
    alert_page = reader.alerts(
        {"range": ["all"], "search": ["alert-1"], "limit": ["1"]}
    )

    assert host["live"] is False
    assert host["hostname"] == "workstation"
    assert host["evidence_count"] == 1
    assert host["alert_count"] == 1
    assert host["alert_score"] == pytest.approx(0.4032)
    assert host["alert_threshold"] == 5.0
    assert host["alerts"][0]["alert_id"] == "alert-1"
    assert host["alerts"][0]["evidence_count"] == 1
    assert evidence_page["full_total"] == 1
    assert evidence_page["total"] == 1
    assert (
        evidence_page["items"][0]["evidence_type"] == "CONNECTION_WITHOUT_DNS"
    )
    assert evidence_page["items"][0]["alert_ids"] == ["alert-1"]
    assert evidence_page["items"][0]["module"] == "conn_analyzer"
    assert grouped_evidence_page["items"][0]["module"] == "conn_analyzer"
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


def test_firewall_marks_overdue_and_returns_transition_history(
    tmp_path: Path,
) -> None:
    """Expose stale enforcement and deduplicated block/unblock events."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.redis = Mock()
    reader.redis.zrange.return_value = [("101.36.97.74", 1787757891.0)]
    reader.redis.hgetall.return_value = {
        "101.36.97.74": json.dumps(
            {
                "unblock_at": "2026-08-26T18:38:10+02:00",
                "remaining_timewindows": 0,
            }
        )
    }
    reader._profile_evidence_count = Mock(return_value=27)
    reader._profile_alert_count = Mock(return_value=1)
    log_dir = tmp_path / "blocking"
    log_dir.mkdir()
    (log_dir / "blocking.log").write_text(
        "2026/08/26 17:24:51.100000 - Blocked all traffic from: 101.36.97.74\n"
        "2026/08/26 17:24:51.200000 - Blocked all traffic to: 101.36.97.74\n"
        "2026/08/26 18:38:11.000000 - IP 101.36.97.74 is unblocked in timewindow3.\n",
        encoding="utf-8",
    )

    with patch(
        "modules.web_interface.server.time.time", return_value=1787781085.0
    ):
        payload = reader.firewall({})

    assert payload["items"][0]["status"] == "overdue"
    assert payload["items"][0]["remaining_seconds"] == 0
    assert payload["history_total"] == 2
    assert payload["history_next_cursor"] is None
    assert [event["action"] for event in payload["history"]] == [
        "unblocked",
        "blocked",
    ]
    assert payload["history"][1]["details"] == "traffic from + to"


def test_firewall_estimates_attempts_inside_block_intervals(
    tmp_path: Path,
) -> None:
    """Count source packets, flows, and evidence only while rules were active."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.history_path = tmp_path / "web_interface" / "history.sqlite"
    reader.sqlite_path = tmp_path / "databases" / "flows.sqlite"
    reader.redis = Mock()
    initialize_history(reader.history_path)
    reader.sqlite_path.parent.mkdir()
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO flow_index "
            "(uid, flow_rowid, event_time, src_ip, dst_ip, proto, app_proto, "
            "bytes, packets, source_packets, label) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "before",
                    1,
                    90,
                    "10.0.0.8",
                    "10.0.0.1",
                    "tcp",
                    "",
                    0,
                    5,
                    5,
                    "",
                ),
                (
                    "blocked-1",
                    2,
                    110,
                    "10.0.0.8",
                    "10.0.0.1",
                    "tcp",
                    "",
                    0,
                    7,
                    7,
                    "",
                ),
                (
                    "reverse",
                    3,
                    120,
                    "10.0.0.1",
                    "10.0.0.8",
                    "tcp",
                    "",
                    0,
                    9,
                    9,
                    "",
                ),
                (
                    "blocked-2",
                    4,
                    140,
                    "10.0.0.8",
                    "10.0.0.1",
                    "tcp",
                    "",
                    0,
                    3,
                    3,
                    "",
                ),
                (
                    "unblocked",
                    5,
                    170,
                    "10.0.0.8",
                    "10.0.0.1",
                    "tcp",
                    "",
                    0,
                    8,
                    8,
                    "",
                ),
                (
                    "reblocked",
                    6,
                    220,
                    "10.0.0.8",
                    "10.0.0.1",
                    "tcp",
                    "",
                    0,
                    4,
                    4,
                    "",
                ),
            ],
        )
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?)",
            [
                ("before", 95, "10.0.0.8"),
                ("blocked", 130, "10.0.0.8"),
                ("unblocked", 180, "10.0.0.8"),
                ("reblocked", 225, "10.0.0.8"),
            ],
        )
    history = [
        {"timestamp": 100, "ip": "10.0.0.8", "action": "blocked"},
        {"timestamp": 150, "ip": "10.0.0.8", "action": "unblocked"},
        {"timestamp": 200, "ip": "10.0.0.8", "action": "blocked"},
    ]

    with patch("modules.web_interface.server.time.time", return_value=250):
        result = reader._firewall_attack_estimate(history, {"10.0.0.8": 200})

    assert result["packets"] == 14
    assert result["flows"] == 3
    assert result["evidence"] == 2
    assert result["blocked_intervals"] == 2
    assert result["by_ip"]["10.0.0.8"] == {
        "packets": 14,
        "flows": 3,
        "evidence": 2,
    }


def test_firewall_includes_schedule_missing_from_blocked_set(
    tmp_path: Path,
) -> None:
    """Keep legacy scheduled rules visible even without a blocked timestamp."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.redis = Mock()
    reader.redis.zrange.return_value = []
    reader.redis.hgetall.return_value = {
        "147.32.80.6": json.dumps(
            {
                "unblock_at": None,
                "remaining_timewindows": None,
                "recovered": True,
                "recovery_status": "legacy metadata",
                "origin_run": "unknown",
                "rule_comment": "Slips rule",
            }
        )
    }
    reader._profile_evidence_count = Mock(return_value=10)
    reader._profile_alert_count = Mock(return_value=1)

    with patch(
        "modules.web_interface.server.time.time", return_value=1787781085.0
    ):
        payload = reader.firewall({})

    assert payload["total"] == 1
    assert payload["items"][0]["ip"] == "147.32.80.6"
    assert payload["items"][0]["blocked_at"] is None
    assert payload["items"][0]["status"] == "stale"
    assert payload["items"][0]["recovered"] is True
    assert payload["items"][0]["recovery_status"] == "legacy metadata"
    assert payload["items"][0]["rule_comment"] == "Slips rule"


def test_firewall_tab_renders_transition_history() -> None:
    """Keep the durable firewall history visible in the browser tab."""
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    index_source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )

    assert 'id="firewall-history-table"' in index_source
    assert 'id="firewall-history-pager"' in index_source
    assert 'id="overview-firewall-impact"' in index_source
    assert 'id="firewall-impact-summary"' in index_source
    assert "<th>Rule origin</th>" in index_source
    assert "row.stopped_packets" in app_source
    assert "row.stopped_flows" in app_source
    assert "row.evidence_while_blocked" in app_source
    assert "row.recovery_status" in app_source
    assert 'renderTable("firewall-history-table", history' in app_source


def test_arp_poisoning_parser_tracks_extensions_and_releases(
    tmp_path: Path,
) -> None:
    """Build host state from durable poison, extension, and release events."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    log_dir = tmp_path / "arp_poisoner"
    log_dir.mkdir()
    (log_dir / "arp_poisoning.log").write_text(
        "2026/08/28 10:00:00.000000+0200 - Poisoned 10.0.0.8 at aa:bb:cc:dd:ee:08.\n"
        "2026/08/28 10:00:01.000000+0200 - Current TW: 7. Registered a request to stop poisoning 10.0.0.8 at the end of: timewindow8. IP will be poisoned for 1 more timewindows. Timestamp to stop poisoning: 2026-08-28T12:00:00+02:00) \n"
        "2026/08/28 10:10:00.000000+0200 - Current TW: 7. Registered a request to stop poisoning 10.0.0.8 at the end of: timewindow9. IP will be poisoned for 2 more timewindows. Timestamp to stop poisoning: 2026-08-28T13:00:00+02:00) \n"
        "2026/08/28 10:20:00.000000+0200 - Poisoned 10.0.0.9 at aa:bb:cc:dd:ee:09.\n"
        "2026/08/28 10:20:01.000000+0200 - Current TW: 8. Registered a request to stop poisoning 10.0.0.9 at the end of: timewindow9. IP will be poisoned for 1 more timewindows. Timestamp to stop poisoning: 2026-08-28T11:00:00+02:00) \n"
        "2026/08/28 11:00:01.000000+0200 - Done poisoning 10.0.0.9. The poisoning lasted 1 timewindows. (1.0hrs - From 2026/08/28 10:20:00.000000+0200 to 2026/08/28 11:00:01.000000+0200).\n",
        encoding="utf-8",
    )

    now = reader._event_timestamp("2026-08-28T13:00:01+02:00")
    with patch("modules.web_interface.server.time.time", return_value=now):
        result = reader._arp_poisoning_events()

    hosts = {item["ip"]: item for item in result["hosts"]}
    assert hosts["10.0.0.8"]["status"] == "release due"
    assert hosts["10.0.0.8"]["release_tw"] == "timewindow9"
    assert hosts["10.0.0.8"]["extra_timewindows"] == 2
    assert hosts["10.0.0.8"]["remaining_seconds"] == 0
    assert hosts["10.0.0.9"]["status"] == "released"
    assert hosts["10.0.0.9"]["released_at"] == pytest.approx(
        reader._event_timestamp("2026/08/28 11:00:01.000000+0200")
    )
    actions = [item["action"] for item in result["events"]]
    assert actions.count("poisoned") == 2
    assert actions.count("scheduled") == 2
    assert actions.count("extended") == 1
    assert actions.count("released") == 1


def test_arp_evidence_uses_only_durable_arp_detections(
    tmp_path: Path,
) -> None:
    """Return ARP evidence with durable flow and alert relationships."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "arp-1",
                    20,
                    "10.0.0.8",
                    "7",
                    "high",
                    "MITM_ARP_ATTACK",
                    "ARP packets claim different MACs",
                    0.9,
                    "{}",
                ),
                (
                    "dns-1",
                    30,
                    "10.0.0.9",
                    "7",
                    "low",
                    "DGA_NXDOMAINS",
                    "Not ARP",
                    1.0,
                    "{}",
                ),
            ],
        )
        connection.executemany(
            "INSERT INTO evidence_flows VALUES (?, ?)",
            [("arp-1", "flow-1"), ("arp-1", "flow-2")],
        )
        connection.execute(
            "INSERT INTO alert_evidence VALUES (?, ?)",
            ("alert-1", "arp-1"),
        )

    result = reader._arp_evidence()

    assert result["total"] == 1
    assert result["counts"] == {"MITM_ARP_ATTACK": 1}
    assert [item["evidence_type"] for item in result["items"]] == [
        "MITM_ARP_ATTACK"
    ]
    assert result["items"][0]["flow_count"] == 2
    assert result["items"][0]["alert_count"] == 1


def test_arp_poisoning_summarizes_current_module_state(tmp_path: Path) -> None:
    """Summarize active, overdue, and released ARP isolation records."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.redis = Mock()
    reader.redis.hget.return_value = None
    reader._processes = {}
    log_dir = tmp_path / "arp_poisoner"
    log_dir.mkdir()
    (log_dir / "arp_poisoning.log").touch()
    reader._arp_poisoning_events = Mock(
        return_value={
            "hosts": [
                {"ip": "10.0.0.8", "status": "poisoned"},
                {"ip": "10.0.0.9", "status": "release due"},
                {"ip": "10.0.0.10", "status": "released"},
            ],
            "events": [
                {"ip": "10.0.0.8", "action": "poisoned"},
                {"ip": "10.0.0.10", "action": "released"},
            ],
        }
    )
    reader._arp_evidence = Mock(
        return_value={
            "items": [{"evidence_type": "ARP_SCAN"}],
            "total": 4,
            "counts": {"ARP_SCAN": 4},
        }
    )

    result = reader.arp_poisoning()

    assert result["module"] == {
        "enabled": True,
        "state": "stopped",
        "pid": None,
    }
    assert result["counts"] == {
        "active": 2,
        "released": 1,
        "hosts": 3,
        "transitions": 2,
        "evidence": 4,
    }
    assert result["evidence_counts"] == {"ARP_SCAN": 4}


def test_arp_poisoning_tab_is_wired_and_every_column_is_sortable() -> None:
    """Keep all ARP state, history, and evidence columns sortable."""
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    index_source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )
    server_source = Path("modules/web_interface/server.py").read_text(
        encoding="utf-8"
    )
    section = index_source.split('<section id="arp-poisoning"', 1)[1].split(
        '<section id="p2p"', 1
    )[0]

    assert 'data-tab="arp-poisoning"' in index_source
    assert 'id="arp-poisoning-hosts-table"' in section
    assert 'id="arp-poisoning-events-table"' in section
    assert 'id="arp-poisoning-evidence-table"' in section
    assert section.count("<th ") == section.count('data-sort="')
    assert 'api("arpPoisoning", "/api/arp-poisoning")' in app_source
    assert "bindLocalTableSort(id, renderArpPoisoning)" in app_source
    assert 'path == "/api/arp-poisoning"' in server_source


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
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
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
            (
                "newer",
                10.0,
                "10.0.0.1",
                "tw",
                "high",
                "UNKNOWN_PORT",
                "",
                1.0,
                "{}",
            ),
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


def test_host_flows_exclude_mac_alias_addresses(tmp_path) -> None:
    """Only the selected profile IP may contribute host-workspace flows."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "history.sqlite"
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
        connection.executemany(
            "INSERT INTO flows VALUES (?, ?, ?, ?, ?, ?)", raw_rows
        )
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO flow_index "
            "(uid, flow_rowid, event_time, src_ip, dst_ip, proto, "
            "app_proto, bytes, packets, label) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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

    assert result["total"] == 1
    assert [item["direction"] for item in result["items"]] == ["outbound"]
    assert [item["peer"] for item in result["items"]] == ["8.8.8.8"]
    assert result["host_ips"] == ["10.0.0.1"]


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
                (
                    now - number,
                    number % 100,
                    100 + number,
                    number % 10,
                    number % 7,
                )
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
        "web_interface_history": "125",
        "web_interface_detection_backfill": "126",
    }
    reader.redis.smembers.return_value = set()
    process = Mock()
    process.is_running.return_value = True
    process.status.return_value = "sleeping"
    process.memory_info.return_value = Mock(rss=1024 * 1024)
    process.cpu_percent.return_value = 0
    process_constructor = mocker.patch(
        "modules.web_interface.server.psutil.Process",
        side_effect=psutil.NoSuchProcess(123),
    )
    mocker.patch(
        "modules.web_interface.server.psutil.virtual_memory",
        return_value=Mock(total=100 * 1024 * 1024),
    )
    reader._processes = {123: process}

    rows = reader._module_rows(Counter(), {}, analysis_complete=False)

    assert rows[0]["memory_percent"] == 1.0
    assert [row["name"] for row in rows] == ["flow_alerts"]
    process_constructor.assert_not_called()


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
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
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
            "INSERT INTO flow_index "
            "(uid, flow_rowid, event_time, src_ip, dst_ip, proto, "
            "app_proto, bytes, packets, label) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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


def test_host_score_history_reports_peaks_resets_and_missing_coverage(
    tmp_path,
) -> None:
    """Return bounded real score samples and distinguish unscored evidence."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.score_mode = "ratl"
    reader.alert_threshold = 5.0
    reader._live_host = Mock(return_value={"live": False})
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "accumulated_threat_level REAL, accumulated_ratl REAL)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?)",
            [
                ("unscored", 100.0, "10.0.0.1", "timewindow1", None, None),
                ("rise", 110.0, "10.0.0.1", "timewindow1", 3.0, 1.0),
                ("cross", 120.0, "10.0.0.1", "timewindow1", 18.0, 6.0),
                ("alert-reset", 130.0, "10.0.0.1", "timewindow1", 1.5, 0.5),
                ("tw-reset", 200.0, "10.0.0.1", "timewindow2", 0.6, 0.2),
            ],
        )

    result = reader.score_history(
        "10.0.0.1", {"range": ["all"], "max_points": ["100"]}
    )

    assert result["evidence_total"] == 5
    assert result["scored_evidence"] == 4
    assert result["coverage"] == pytest.approx(0.8)
    assert result["peak_score"] == 6.0
    assert result["threshold"] == 5.0
    assert result["reset_count"] == 2
    assert [point["reset_reason"] for point in result["timeline"]] == [
        "",
        "",
        "score reset after an alert",
        "time window changed",
    ]

    custom = reader.score_history(
        "10.0.0.1",
        {
            "range": ["custom"],
            "from": ["115"],
            "to": ["135"],
            "max_points": ["100"],
        },
    )

    assert custom["range"] == "custom"
    assert custom["evidence_total"] == 2
    assert [point["ts"] for point in custom["timeline"]] == [120.0, 130.0]


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
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
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

    result = reader.evidence(
        {"range": ["all"], "sort": ["host"], "order": ["asc"]}
    )

    assert [item["id"] for item in result["items"]] == ["a", "z"]
    assert result["sort"] == "host"
    assert result["order"] == "asc"


def test_host_evidence_excludes_mac_alias_profiles(
    tmp_path,
) -> None:
    """Test a host evidence page covers only the selected profile IP."""
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
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "low",
                    3.0,
                    "10.0.0.1",
                    "tw",
                    "low",
                    "DNS",
                    "first",
                    0.2,
                    "{}",
                ),
                (
                    "high",
                    2.0,
                    "2001:db8::1",
                    "tw",
                    "high",
                    "SCAN",
                    "second",
                    0.9,
                    "{}",
                ),
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

    assert result["total"] == 1
    assert [item["id"] for item in result["items"]] == ["low"]


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
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.execute(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "evidence-id",
                1.0,
                "10.0.0.1",
                "tw",
                "low",
                "DNS",
                "",
                0.2,
                '{"attacker": "raw-field-token"}',
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
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
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
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
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


def test_hosts_show_and_sort_real_past_peak_score(tmp_path) -> None:
    """Return full-run persisted score peaks and sort the complete inventory."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "history.sqlite"
    reader.score_mode = "ratl"
    reader.alert_threshold = 5.0
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {}
    reader._host_load = Mock(
        return_value={"flows": 0, "bytes": 0, "packets": 0, "last_seen": 0}
    )
    reader._profile_evidence_count = Mock(return_value=0)
    reader._profile_alert_count = Mock(return_value=0)
    initialize_history(reader.history_path)
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (profile_ip TEXT, "
            "accumulated_threat_level REAL, accumulated_ratl REAL)"
        )
        connection.execute("CREATE TABLE alerts (ip_alerted TEXT)")
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?)",
            [
                ("10.0.0.1", 3.0, 1.0),
                ("10.0.0.1", 18.0, 6.0),
                ("10.0.0.2", 9.0, 3.0),
            ],
        )
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO host_snapshots VALUES (?, ?, ?)",
            [
                (
                    "10.0.0.1",
                    1.0,
                    json.dumps({"ip": "10.0.0.1", "scope": "local"}),
                ),
                (
                    "10.0.0.2",
                    2.0,
                    json.dumps({"ip": "10.0.0.2", "scope": "local"}),
                ),
            ],
        )

    result = reader.hosts(
        {"range": ["all"], "sort": ["peak_score"], "order": ["desc"]}
    )

    assert [item["ip"] for item in result["items"]] == [
        "10.0.0.1",
        "10.0.0.2",
    ]
    assert [item["peak_alert_score"] for item in result["items"]] == [
        6.0,
        3.0,
    ]
    assert result["sort"] == "peak_score"
    assert result["order"] == "desc"


def test_hosts_live_range_uses_indexed_flow_clock(tmp_path) -> None:
    """Test capture-relative traffic is not compared with wall-clock snapshots."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "history.sqlite"
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {}
    reader._host_load = Mock(
        return_value={
            "flows": 1,
            "bytes": 100,
            "packets": 2,
            "last_seen": 4000,
        }
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
            "INSERT INTO flow_index "
            "(uid, flow_rowid, event_time, src_ip, dst_ip, proto, "
            "app_proto, bytes, packets, label) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        {"analysis_start": "2026-08-25T23:07:20"} if key == "analysis" else {}
    )
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    result = reader.p2p()

    assert result["enabled"] is True
    assert result["local_peer_id"] == "QmLocalPeer"
    assert result["counts"]["connected"] == 0
    assert result["peers"] == []


def test_p2p_uses_redis_identity_and_live_peer_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Prefer Redis identity and expose live peer updates without log data."""
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output" / "run"
    output_dir.mkdir(parents=True)
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.side_effect = lambda key: {
        "connected_peers": json.dumps(["QmRemotePeer"]),
        "multiAddress": ("/ip4/10.0.0.1/tcp/32768/p2p/QmRedisLocalPeer"),
    }.get(key)
    reader.redis.hget.side_effect = lambda key, field: (
        "123" if (key, field) == ("PIDs", "p2p_trust") else None
    )
    reader.redis.hgetall.side_effect = lambda key: {
        "analysis": {"analysis_start": "2026-08-25T23:07:20"},
        "peer_info": {
            "QmRemotePeer": json.dumps(
                {
                    "ip": "192.0.2.10",
                    "reliability": 0.75,
                    "timestamp": 1649445643,
                }
            )
        },
    }.get(key, {})
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    result = reader.p2p()

    assert result["listener"] == (
        "/ip4/10.0.0.1/tcp/32768/p2p/QmRedisLocalPeer"
    )
    assert result["local_peer_id"] == "QmRedisLocalPeer"
    assert result["counts"]["connected"] == 1
    assert result["peers"] == [
        {
            "peer_id": "QmRemotePeer",
            "ip": "192.0.2.10",
            "connected": True,
            "trust": None,
            "reliability": 0.75,
            "last_seen": 1649445643.0,
            "reports_received": 0,
        }
    ]


def test_p2p_report_counter_is_not_limited_to_latest_500(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Count every report from this run while limiting returned report rows."""
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
        connection.executemany(
            "INSERT INTO reports VALUES (?, ?, ?, ?, ?)",
            [
                (
                    "QmRemotePeer",
                    f"192.0.2.{index}",
                    0.5,
                    0.8,
                    1000 + index,
                )
                for index in range(501)
            ]
            + [
                (
                    "QmOldPeer",
                    f"198.51.100.{index}",
                    0.5,
                    0.8,
                    index,
                )
                for index in range(20)
            ],
        )

    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.return_value = None
    reader.redis.hget.return_value = None
    reader.redis.hgetall.side_effect = lambda key: (
        {"analysis_start": "1000"} if key == "analysis" else {}
    )
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    result = reader.p2p()

    assert len(result["reports"]) == 200
    assert result["counts"]["reports_received"] == 501


def test_host_workspace_live_range_uses_run_wide_flow_clock(tmp_path) -> None:
    """Exclude an inactive host from Live using the newest run-wide flow."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.history_path = tmp_path / "history.sqlite"
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader._host_ips = Mock(return_value=["10.0.0.1"])
    reader._live_host = Mock(return_value={})
    reader.score_mode = "ratl"
    reader.alert_threshold = 5.0
    initialize_history(reader.history_path)
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO flow_index "
            "(uid, flow_rowid, event_time, src_ip, dst_ip, proto, "
            "app_proto, bytes, packets, label) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "inactive-host-flow",
                    1,
                    100.0,
                    "10.0.0.1",
                    "8.8.8.8",
                    "udp",
                    "dns",
                    100,
                    2,
                    "benign",
                ),
                (
                    "run-clock-flow",
                    2,
                    4000.0,
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
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE flows (uid TEXT, flow TEXT, label TEXT)"
        )
        connection.execute(
            "INSERT INTO flows VALUES (?, ?, ?)",
            ("inactive-host-flow", "{}", "benign"),
        )
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT, evidence_time REAL, "
            "profile_ip TEXT, timewindow TEXT, accumulated_ratl REAL)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?)",
            [
                ("inactive-evidence", 100, "10.0.0.1", "timewindow1", 1.0),
                ("run-clock-evidence", 4000, "10.0.0.2", "timewindow1", 2.0),
            ],
        )

    live_flows = reader.flows_for_host("10.0.0.1", {"range": ["live"]})
    full_flows = reader.flows_for_host("10.0.0.1", {"range": ["all"]})
    live_summary = reader.traffic_summary("10.0.0.1", {"range": ["live"]})
    live_score = reader.score_history("10.0.0.1", {"range": ["live"]})

    assert live_flows["total"] == 0
    assert live_flows["items"] == []
    assert full_flows["total"] == 1
    assert live_summary["timeline"] == []
    assert live_score["timeline"] == []
    assert live_score["evidence_total"] == 0


def test_host_workspace_range_is_used_for_evidence_and_reset() -> None:
    """Send the selected host range to evidence and reset its cursor."""
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    evidence_loader = app_source.split("async function loadHostEvidence()", 1)[
        1
    ].split("async function loadHostFlows()", 1)[0]
    host_binding = app_source.split('bindRange("host", "hostFlows"', 1)[
        1
    ].split("bindTableSort", 1)[0]

    assert "const params = hostRangeParams();" in evidence_loader
    assert 'range: "all"' not in evidence_loader
    assert 'resetPage("host-evidence");' in host_binding


def test_p2p_trust_history_honors_selected_range(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Filter plotted history while preserving each peer's latest reliability."""
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
        connection.executemany(
            "INSERT INTO go_reliability VALUES (?, ?, ?)",
            [("QmOldPeer", 0.25, 100), ("QmRecentPeer", 0.75, 4000)],
        )
        connection.executemany(
            "INSERT INTO peer_ips VALUES (?, ?, ?)",
            [
                ("QmOldPeer", "192.0.2.1", 100),
                ("QmRecentPeer", "192.0.2.2", 4000),
            ],
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

    result = reader.p2p({"range": ["live"]})

    assert result["trust_range"] == "live"
    assert [row["peer_id"] for row in result["trust_history"]] == [
        "QmRecentPeer"
    ]
    assert {peer["peer_id"] for peer in result["peers"]} == {
        "QmOldPeer",
        "QmRecentPeer",
    }


def test_p2p_api_forwards_selected_history_range() -> None:
    """Forward the P2P history selector through the HTTP API route."""
    _module_factory = ModuleFactory()
    handler = RequestHandler.__new__(RequestHandler)
    handler.server = Mock()
    handler.server.reader.response_metadata.return_value = {}
    handler.server.reader.p2p.return_value = {"trust_history": []}
    query = {"range": ["1h"]}

    result = handler._api_response("/api/p2p", query)

    assert result["trust_history"] == []
    handler.server.reader.p2p.assert_called_once_with(query)


def test_p2p_trust_chart_uses_compact_range_control() -> None:
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
    assert "function renderP2PTrustChart" in app_source
    assert "/api/p2p?range=${encodeURIComponent(range)}" in app_source
    assert 'byId("p2p-range").addEventListener("change"' in app_source
    assert (
        ".compact-line-chart { height: 130px; min-height: 130px; }"
        in css_source
    )


def test_alerts_default_to_grouped_by_host() -> None:
    """Default the Alerts tab to its host-grouped API and table layout."""
    _module_factory = ModuleFactory()
    html_source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )

    assert (
        '<option value="grouped" selected>Group by host</option>'
        in html_source
    )
    assert 'params.set("group", "host")' in app_source
    assert "Grouped by host. Select a host" in html_source
