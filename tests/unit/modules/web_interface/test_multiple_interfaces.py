"""Exercise simultaneous capture networks and independent connection boundaries."""

import json
import sqlite3
from pathlib import Path

import pytest

from modules.web_interface.history import connect_history
from modules.web_interface.server import RunDataReader
from slips_files.core.database.sqlite_db.host_profiles import HostProfileStore
from tests.module_factory import ModuleFactory
from tests.unit.modules.web_interface.test_server import _network_scope_reader

NOW = 2_000_000_000.0
HOST = "192.168.1.22"


def multiple_reader(tmp_path: Path, legacy: bool = False, shared: bool = False) -> tuple[RunDataReader, dict]:
    """Create two captures with retained findings for a reused host address.

    Parameters:
        tmp_path: Isolated SQLite databases.
        legacy: Omit the AP interface metadata, as in older runs.
        shared: Attach both interfaces to the same identified LAN.

    Returns:
        Reader and mutable network states for reconnection tests.
    """
    reader = _network_scope_reader(tmp_path)
    states = {
        "eth0": {"interface": "eth0", "connected": True, "changed_at": NOW - 600,
                 "gateway_mac": "aa:bb:cc:dd:ee:01", "local_network": "192.168.1.0/24"},
        "wlan_ap0": {"interface": "wlan_ap0", "connected": True, "changed_at": NOW - 200,
                     "gateway_mac": "aa:bb:cc:dd:ee:01" if shared else "aa:bb:cc:dd:ee:02",
                     "local_network": "192.168.1.0/24"},
    }
    analysis = {"input_type": "interface", "output_dir": str(reader.output_dir)}
    if not legacy:
        analysis["interface"] = ",".join(states)
    reader.redis.hgetall.side_effect = lambda key: analysis if key == "analysis" else {n: json.dumps(s) for n, s in states.items()} if key == "network_states" else {}
    reader.redis.hget.side_effect = lambda key, field: json.dumps(states.get(field, {})) if key == "network_states" else analysis.get(field) if key == "analysis" else "123" if (key, field) == ("PIDs", "main") else None
    with sqlite3.connect(reader.sqlite_path) as connection, connect_history(reader.history_path) as history:
        for table in ("flows", "evidence", "alerts", "evidence_flows", "alert_evidence"):
            connection.execute(f"DELETE FROM {table}")
        history.execute("DELETE FROM flow_index")
        for identifier, iface, stamp in [
            ("eth-earlier", "eth0", NOW-400), ("eth-new", "eth0", NOW-50),
            ("ap-earlier", "wlan_ap0", NOW-400), ("ap-new", "wlan_ap0", NOW-50),
            ("guest", "wlan_ap0", NOW-50), ("unknown", "default", NOW-50),
        ]:
            identity = HostProfileStore.network_id_for_state(states[iface], "") if iface in states else ""
            if identifier == "guest":
                identity = "gateway:aa:bb:cc:dd:ee:03"
            data = json.dumps({"interface": iface, "detection_provenance": {"network_id": identity}})
            connection.execute("INSERT INTO evidence VALUES (?,?,?,'tw','high','SCAN','arp','finding',1,?,2,0)", (identifier, stamp, HOST, data))
            connection.execute("INSERT INTO alerts VALUES (?,?,?,'malicious',5)", (identifier, HOST, stamp))
            connection.execute("INSERT INTO alert_evidence VALUES (?,?)", (identifier, identifier))
            if identifier not in {"guest", "unknown"}:
                flow = json.dumps({"saddr": HOST, "daddr": "8.8.8.8", "starttime": stamp, "interface": iface, "proto": "tcp"})
                connection.execute("INSERT INTO flows VALUES (?,?,'benign')", (identifier, flow))
                connection.execute("INSERT INTO evidence_flows VALUES (?,?)", (identifier, identifier))
                history.execute("INSERT INTO flow_index VALUES (?,1,?,?,'8.8.8.8','tcp','',100,2,1,'benign')", (identifier, stamp, HOST))
    return reader, states


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("shared", [False, True])
@pytest.mark.parametrize("group", ["", "host", "type", "host_type"])
@pytest.mark.parametrize("network,expected", [("current", 4), ("connection", 3)])
def test_multiple_networks_keep_independent_boundaries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, legacy: bool, shared: bool, group: str, network: str, expected: int) -> None:
    """Include both networks without applying the AP cutoff to Ethernet.

    Parameters:
        tmp_path: Isolated databases.
        monkeypatch: Fix the live clock.
        legacy: Read old AP metadata.
        shared: Use two interfaces on one LAN.
        group: Evidence grouping mode.
        network: History or current-session scope.
        expected: Number of visible detections.
    """
    _factory = ModuleFactory()
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: NOW)
    reader, _ = multiple_reader(tmp_path, legacy, shared)
    query = {"range": ["all"], "network": [network], "limit": ["100"]}
    payload = reader.evidence({**query, **({"group": [group]} if group else {})})
    assert payload.get("matching_total", payload["total"]) == expected
    assert reader.alerts(query)["total"] == expected
    host = reader.host(HOST, query)
    assert host["evidence_count"] == host["alert_count"] == expected
    assert reader.flows_for_host(HOST, query)["total"] == expected
    assert getattr(reader, "_active_network_scope", None) is None


@pytest.mark.parametrize("selection,expected", [
    ({"interface": ["eth0"]}, {"eth-earlier", "eth-new"}),
    ({"interface": ["wlan_ap0"]}, {"ap-new"}),
    ({"network_id": ["gateway:aa:bb:cc:dd:ee:02"]}, {"ap-new"}),
    ({"interface": ["absent"]}, set()),
    ({"network_id": ["unknown-network"]}, set()),
])
def test_network_and_interface_selections_do_not_leak(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, selection: dict, expected: set[str]) -> None:
    """Keep selections separate even when addresses overlap.

    Parameters:
        tmp_path: Isolated databases.
        monkeypatch: Fix the live clock.
        selection: Selected interface or network.
        expected: Visible evidence IDs.
    """
    _factory = ModuleFactory()
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: NOW)
    reader, _ = multiple_reader(tmp_path, legacy=True)
    query = {"range": ["connection"], **selection}
    assert {item["id"] for item in reader.evidence(query)["items"]} == expected
    assert {item["uid"] for item in reader.flows_for_host(HOST, query)["items"]} == expected


def test_one_interface_reconnects_without_resetting_the_other(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Invalidate the AP session while retaining Ethernet's earlier session.

    Parameters:
        tmp_path: Isolated databases.
        monkeypatch: Fix the live clock.
    """
    _factory = ModuleFactory()
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: NOW)
    reader, states = multiple_reader(tmp_path)
    query = {"range": ["connection"]}
    assert reader.evidence(query)["total"] == 3
    states["wlan_ap0"]["connected"] = False
    assert reader.evidence(query)["total"] == 2
    states["wlan_ap0"].update(connected=True, changed_at=NOW-10)
    assert reader.evidence(query)["total"] == 2
    assert reader._current_network_start() == NOW-600


def test_interface_filter_can_include_other_network_visits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """All retained networks keeps an interface's historical records.

    Parameters:
        tmp_path: Isolated databases.
        monkeypatch: Fix the live clock.
    """
    _factory = ModuleFactory()
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: NOW)
    reader, _ = multiple_reader(tmp_path)
    query = {"range": ["all"], "interface": ["wlan_ap0"]}
    assert {item["id"] for item in reader.evidence(query)["items"]} == {"ap-earlier", "ap-new", "guest"}


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_browser_combined_networks_and_independent_selectors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, theme: str) -> None:
    """Use real scoped queries while switching header selectors in Chrome.

    Parameters:
        tmp_path: Isolated capture data.
        monkeypatch: Fix backend capture time.
        theme: Browser color theme.
    """
    _factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    from urllib.parse import parse_qs, unquote, urlparse
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: NOW)
    reader, states = multiple_reader(tmp_path, legacy=True)
    assets = Path("modules/web_interface")
    networks = [{**s, "name": "Uplink" if n == "eth0" else "Test AP",
                 "network_id": HostProfileStore.network_id_for_state(s, ""),
                 "connection_start": s["changed_at"],
                 "host_addresses": {"ipv4": ["192.168.1.170" if n == "eth0" else "192.168.12.1"], "ipv6": []}}
                for n, s in states.items()]
    aggregate = {"interface": "eth0,wlan_ap0", "connected": True, "networks": networks,
                 "host_addresses": {"ipv4": ["192.168.1.170", "192.168.12.1"], "ipv6": []}}
    identity = {"input_type": "interface", "interface": "eth0,wlan_ap0", "network_filter_supported": True,
                "network_scope_version": 3, "current_networks": networks, "current_network": aggregate,
                "current_network_start": NOW-600, "review_actions": True}
    errors = []
    queries = []

    def respond(route: object) -> None:
        """Serve browser assets and real multi-interface data queries.

        Parameters:
            route: Playwright route to fulfill.
        """
        parsed = urlparse(route.request.url)
        query = parse_qs(parsed.query)
        path = parsed.path
        if path in {"/", "/app.js", "/style.css"}:
            route.fulfill(path=str(assets / ("index.html" if path == "/" else path[1:])))
        elif path == "/api/identity":
            route.fulfill(json=identity)
        elif path == "/api/overview":
            route.fulfill(json={"run": {"state": "running", "input_type": "interface", "interface": "eth0,wlan_ap0", "output_dir": "output/test-ap"},
                                "network_states": networks, "host_addresses": aggregate["host_addresses"],
                                "counts": {"hosts": 1, "evidence": 4}, "modules": [], "system": {}})
        elif path == "/api/evidence":
            queries.append(query)
            route.fulfill(json=reader.evidence(query))
        elif path == "/api/hosts":
            route.fulfill(json=reader.hosts(query))
        elif path == "/api/alerts":
            route.fulfill(json=reader.alerts(query))
        elif path.startswith("/api/hosts/"):
            route.fulfill(json=reader.host(unquote(path.split("/")[3]), query))
        elif path == "/api/host-names":
            route.fulfill(json={"names": {}})
        elif path == "/api/archives":
            route.fulfill(json={"items": []})
        else:
            route.fulfill(json={"items": [], "total": 0})

    with playwright.sync_playwright() as engine:
        browser = engine.chromium.launch(channel="chrome", headless=True)
        try:
            page = browser.new_page(viewport={"width": 1600, "height": 1000})
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.route("**/*", respond)
            page.goto("http://slips.test/")
            page.wait_for_function("state.networkScopeVersion === 3 && state.overview !== null")
            page.evaluate("""theme => { setTheme(theme); clearTimeout(state.timer); clearTimeout(state.statusTimer); }""", theme)
            assert page.locator("#network-selection").input_value() == "current"
            assert page.locator("#network-selection option:checked").inner_text() == "All active networks"
            assert page.locator("#network-states .network-state").count() == 2
            assert "Uplink" in page.locator("#run-meta").inner_text()
            assert "Test AP" in page.locator("#run-meta").inner_text()
            assert "192.168.12.1" in page.locator("#run-addresses").inner_text()
            page.locator('.tab[data-tab="evidence"]').click()
            page.wait_for_function("byId('evidence-count').textContent === '3 records'")
            page.evaluate("""() => { byId('evidence-threat').value='low_or_more'; byId('evidence-view').value='grouped'; }""")
            page.locator("#evidence-filter-button").click()
            page.locator("#interface-selection").select_option("eth0")
            page.wait_for_function("byId('evidence-count').textContent === '2 records'")
            assert page.locator("#evidence-threat").input_value() == "low_or_more"
            assert page.locator("#evidence-view").input_value() == "grouped"
            assert queries[-1]["interface"] == ["eth0"]
            assert queries[-1]["range"] == ["connection"]
            assert "from" not in queries[-1]
            page.locator("#interface-selection").select_option("wlan_ap0")
            page.wait_for_function("byId('evidence-count').textContent === '1 records'")
            page.locator("#interface-selection").select_option("")
            page.locator("#network-selection").select_option(networks[1]["network_id"])
            page.wait_for_function("byId('evidence-count').textContent === '1 records'")
            assert queries[-1]["network_id"] == [networks[1]["network_id"]]
            page.locator("#network-selection").select_option("current")
            page.wait_for_function("byId('evidence-count').textContent === '3 records'")
            assert not errors, errors
        finally:
            browser.close()


def test_disconnected_interface_keeps_retained_history(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An interface's retained history survives its disconnection.

    Parameters:
        tmp_path: Isolated databases.
        monkeypatch: Fix the capture clock.
    """
    _factory = ModuleFactory()
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: NOW)
    reader, states = multiple_reader(tmp_path)
    states["wlan_ap0"]["connected"] = False
    query = {"range": ["all"], "interface": ["wlan_ap0"]}
    assert reader.evidence(query)["total"] == 3
    assert reader.flows_for_host(HOST, query)["total"] == 2


@pytest.mark.parametrize("iface,identity,timestamp,expected", [
    ("eth0", "", NOW-400, True), ("wlan_ap0", "", NOW-400, False),
    ("wlan_ap0", "", NOW-50, True), ("", "", NOW-50, False),
    ("", "gateway:aa:bb:cc:dd:ee:02", NOW-50, True),
    ("eth0", "gateway:aa:bb:cc:dd:ee:02", NOW-50, False),
])
def test_p2p_messages_keep_interface_session_context(tmp_path: Path, iface: str, identity: str, timestamp: float, expected: bool) -> None:
    """Do not infer a P2P message's network from an unrelated active session.

    Parameters:
        tmp_path: Isolated databases.
        iface: Recorded capture interface.
        identity: Explicit network identity.
        timestamp: Event timestamp.
        expected: Whether the scoped event is visible.
    """
    _factory = ModuleFactory()
    reader, _ = multiple_reader(tmp_path)
    scoped = reader._for_network_scope({"network": ["connection"]})
    events = [{"timestamp": timestamp, "interface": iface, "network_id": identity}]
    assert bool(scoped._scoped_p2p_events(events)) is expected


@pytest.mark.parametrize("protocol", [False, True])
@pytest.mark.parametrize("extra_link", [None, "ap-new", "missing-flow"])
def test_legacy_evidence_uses_unambiguous_linked_interface(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra_link: str | None, protocol: bool) -> None:
    """Recover legacy interface labels only when every linked flow agrees.

    Parameters:
        tmp_path: Isolated databases.
        monkeypatch: Fix the capture clock.
        extra_link: Conflicting or unavailable flow, or no extra link.
        protocol: Resolve an ARP/protocol record instead of a connection record.
    """
    _factory = ModuleFactory()
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: NOW)
    reader, _ = multiple_reader(tmp_path)
    with sqlite3.connect(reader.sqlite_path) as connection:
        if protocol:
            connection.execute("INSERT INTO altflows SELECT uid,flow FROM flows WHERE uid='eth-new'")
            connection.execute("DELETE FROM flows WHERE uid='eth-new'")
        connection.execute("UPDATE evidence SET data='{}' WHERE evidence_id='eth-new'")
        if extra_link:
            connection.execute("INSERT INTO evidence_flows VALUES ('eth-new',?)", (extra_link,))
    query = {"network": ["connection"], "range": ["all"], "interface": ["eth0"]}
    ids = {item["id"] for item in reader.evidence(query)["items"]}
    assert ("eth-new" in ids) is (extra_link is None)
    assert "eth-earlier" in ids


@pytest.mark.parametrize("query,visible", [
    ({"range": ["all"], "network": ["current"]}, True),
    ({"range": ["connection"]}, False),
    ({"range": ["all"], "network": ["current"], "interface": ["eth0"]}, False),
])
def test_network_history_retains_a_previous_capture_interface(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, query: dict, visible: bool) -> None:
    """Keep tagged network history when its old interface is no longer active.

    Parameters:
        tmp_path: Isolated databases.
        monkeypatch: Fix the capture clock.
        query: Network history, connection or explicit interface filter.
        visible: Whether the prior-interface observation belongs in this view.
    """
    _factory = ModuleFactory()
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: NOW)
    reader, _ = multiple_reader(tmp_path)
    with sqlite3.connect(reader.sqlite_path) as connection:
        payload = {"interface": "old_capture_nic", "detection_provenance": {"network_id": "gateway:aa:bb:cc:dd:ee:01"}}
        connection.execute("UPDATE evidence SET data=? WHERE evidence_id='eth-new'", (json.dumps(payload),))
    ids = {item["id"] for item in reader.evidence(query)["items"]}
    assert ("eth-new" in ids) is visible


def test_connection_scope_exposes_its_lower_bound_to_sqlite(tmp_path: Path) -> None:
    """Keep historical evidence out of a connection query before membership checks.

    Parameters:
        tmp_path: Two interfaces with separate reconnection times.
    """
    _factory = ModuleFactory()
    reader, _ = multiple_reader(tmp_path)
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("CREATE INDEX evidence_time_lookup ON evidence(evidence_time)")
    scoped = reader._for_network_scope({"network":["connection"]})
    with scoped._connect_sqlite() as connection:
        plan = [str(row[3]) for row in connection.execute("EXPLAIN QUERY PLAN SELECT COUNT(*) FROM evidence")]
        assert any("SEARCH e USING INDEX evidence_time_lookup" in step for step in plan)
        assert connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 3
