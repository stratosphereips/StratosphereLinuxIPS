"""Optional Chrome checks for the real web interface, with isolated API data."""

import json
import sqlite3
from pathlib import Path
from typing import Any
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse
from unittest.mock import Mock

import pytest

from modules.web_interface.server import RunDataReader
from slips_files.core.database.sqlite_db.host_profiles import HostProfileStore
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("legacy", [False, True])
def test_large_grouped_record_loads_bounded_flows_in_chrome(tmp_path: Path, legacy: bool) -> None:
    """Opening a grouped device record renders one page and keeps protocol tabs usable.

    Parameters:
        tmp_path: Isolated flows database; no running Slips data is touched.
        legacy: Exercise a web server that still returns an unpaged flow list.
    """
    _module_factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {}
    reader.host_profiles_path = tmp_path / "hosts.sqlite"
    store = HostProfileStore(reader.host_profiles_path, "run", lambda _: {
        "gateway_mac": "aa:bb:cc:dd:ee:01", "local_network": "192.168.1.0/24",
    }, ["en0"])
    store.observe_flow(SimpleNamespace(interface="en0", starttime="100", type_="dhcp",
        saddr="192.168.1.20", daddr="192.168.1.1", host_name="laptop", smac="02:00:00:00:00:20"))
    reader._live_host = Mock(side_effect=lambda ip: {"ip": ip, "live": True})
    reader._attach_current_host_scores = Mock()
    reader._host_ips = Mock(return_value=["192.168.1.20"])
    reader._host_load = Mock(return_value={})
    reader._ti_for_ip = Mock(return_value={})
    reader.alerts = Mock(return_value={"items": [], "total": 0})
    reader._profile_evidence_count = Mock(return_value=0)
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "CREATE TABLE flows(uid TEXT PRIMARY KEY, flow TEXT);"
            "CREATE TABLE altflows(uid TEXT, flow TEXT, flow_type TEXT);"
            "CREATE INDEX alt_uid ON altflows(uid);"
            "CREATE TABLE evidence_flows(evidence_id TEXT, uid TEXT, PRIMARY KEY(evidence_id,uid));"
        )
        for index in range(1051):
            uid = f"flow-{index:04}"
            connection.execute("INSERT INTO evidence_flows VALUES ('e', ?)", (uid,))
            connection.execute("INSERT INTO flows VALUES (?, ?)", (uid, json.dumps({
                "saddr": "192.168.1.20", "daddr": "8.8.8.8", "sport": 12345,
                "dport": 53, "proto": "udp", "starttime": 100, "bytes": 42,
            })))
            for protocol in range(8):
                connection.execute("INSERT INTO altflows VALUES (?, ?, 'dns')", (uid, json.dumps({
                    "query": f"query-{protocol}.example", "rcode_name": "NOERROR",
                    "answers": ["TXT " + "x" * 500], "uid": uid,
                })))
    record = {"id": "e", "profile_ip": "192.168.1.20", "evidence_type": "HIGH_ENTROPY_DNS_ANSWER",
              "description": "A DNS TXT answer with high entropy", "timestamp": 100,
              "threat_level": "low", "confidence": .8, "module": "flow_alerts", "flow_count": 1051}
    requests: list[dict[str, list[str]]] = []
    errors: list[str] = []
    whitelist_requests: list[dict[str, Any]] = []
    assets = Path("modules/web_interface")

    def route_request(route: Any) -> None:
        """Serve shipped assets and read-only flow pages inside the browser.

        Parameters:
            route: Playwright request route intercepted before network access.
        """
        url = urlparse(route.request.url)
        if url.path == "/api/host-annotation":
            payload = route.request.post_data_json
            route.fulfill(json=reader.save_host_annotation(**payload))
        elif url.path == "/api/whitelists" and route.request.method == "POST":
            payload = route.request.post_data_json
            whitelist_requests.append(payload)
            route.fulfill(json=payload)
        elif url.path == "/api/evidence/e/flows":
            query = parse_qs(url.query)
            requests.append(query)
            payload = reader.flows_for_evidence("e", {"limit": ["100"]} if legacy else query)
            if legacy:
                payload.pop("next_cursor", None)
            route.fulfill(json=payload)
        elif url.path == "/api/host-names":
            route.fulfill(json={"names": {}})
        elif url.path == "/api/whitelists":
            route.fulfill(json={"rules": [], "counts": {}, "evidence_types": []})
        elif url.path.startswith("/api/"):
            route.fulfill(status=503, json={"error": "Isolated browser fixture"})
        elif url.path in {"/", "/app.js", "/style.css"}:
            name = "index.html" if url.path == "/" else url.path[1:]
            route.fulfill(path=str(assets / name))
        else:
            route.fulfill(status=404, body="")

    with playwright.sync_playwright() as engine:
        try:
            browser = engine.chromium.launch(channel="chrome", headless=True)
        except playwright.Error as error:
            pytest.skip(f"Chrome is not available: {error}")
        page = browser.new_page(viewport={"width": 1600, "height": 1000})
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.route("**/*", route_request)
        page.goto("http://slips.test/")
        page.wait_for_function("typeof openEvidence === 'function'")
        elapsed = page.evaluate("""async record => {
            state.activeTab = 'evidence'; state.deviceView = true;
            document.querySelectorAll('.panel').forEach(panel => panel.classList.toggle('active', panel.id === 'evidence'));
            state.evidenceWorkspace.group = { id: 'mac:02:00:00:00:00:20', device_ips: ['192.168.1.20', 'fe80::20'] };
            state.evidenceWorkspace.records = [record];
            const start = performance.now(); await openEvidence(record);
            return performance.now() - start;
        }""", record)
        assert elapsed < 3000
        assert requests == [{"limit": ["20"]}]
        assert page.locator(".evidence-detail-flow-list .flow-group").count() == 20
        assert page.locator(".evidence-detail-flow-list .protocol-card").count() == 20
        assert page.locator(".evidence-detail-flow-list .json-details pre").count() == 0
        assert page.locator(".evidence-flow-status").inner_text() == "20 of 1.1k linked flows loaded"
        first = page.locator(".flow-group").first
        first.get_by_role("tab", name="Related DNS · 8", exact=True).click()
        assert "query-7.example" in first.inner_text()
        assert first.locator(".protocol-card").count() == 2
        first.get_by_role("tab", name="conn · flow", exact=True).click()
        first.locator("[role=tabpanel]:not([hidden]) summary").click()
        page.wait_for_function("document.querySelector('.flow-group .json-details pre') !== null")
        assert '"dport": 53' in first.locator(".json-details pre").inner_text()
        page.get_by_role("button", name="Load more triggering flows", exact=True).click()
        page.wait_for_function("document.querySelectorAll('.evidence-detail-flow-list .flow-group').length === 40")
        if legacy:
            assert len(requests) == 1
        else:
            assert requests[1]["cursor"] == ["flow-0019"]
        page.evaluate("closeEvidenceDetail()")
        assert page.locator("#evidence-detail-content .flow-group").count() == 0
        page.evaluate("record => openEvidence(record)", record)
        assert page.locator(".evidence-detail-flow-list .flow-group").count() == 20
        assert errors == []
        page.evaluate("""host => {
            closeEvidenceDetail(); state.activeTab = 'hosts'; state.host = host;
            document.querySelectorAll('.panel').forEach(panel => panel.classList.toggle('active', panel.id === 'hosts'));
            byId('hosts-list-view').hidden = true; byId('host-detail-view').hidden = false;
            renderHostCards(host);
        }""", reader.host("192.168.1.20"))
        page.get_by_role("button", name="Mark or name this host", exact=True).click()
        form = page.locator("#host-annotation-entry .host-annotation-form")
        form.get_by_label("Review mark", exact=True).select_option("to_analyze")
        form.get_by_label("Labels (comma separated)", exact=True).fill("dns, lab")
        form.get_by_label("Note", exact=True).fill("Inspect tomorrow")
        form.get_by_role("button", name="Save host review", exact=True).click()
        page.wait_for_function("state.host.user_status === 'to_analyze'")
        reopened = reader.host("192.168.1.20")
        assert reopened["user_labels"] == ["dns", "lab"]
        assert reopened["user_note"] == "Inspect tomorrow"
        page.evaluate("host => {state.host=host; renderHostCards(host)}", reopened)
        assert "To analyze" in page.locator("#host-identity").inner_text()
        assert "dns, lab" in page.locator("#host-identity").inner_text()
        assert "02:00:00:00:00:20" in page.locator("#host-identity").inner_text()
        page.locator("#host-whitelist-action").click()
        assert page.locator("#drawer .whitelist-form input[list]").input_value() == "192.168.1.20"
        page.locator("#drawer .whitelist-form").get_by_role("button", name="Add rule", exact=True).click()
        page.wait_for_function("document.querySelector('#drawer .whitelist-feedback').textContent.includes('configured whitelist file')")
        assert whitelist_requests == [{"action": "add", "rule_type": "ip", "value": "192.168.1.20",
                                       "direction": "both", "ignore": "alerts", "evidence_type": ""}]
        print(f"Chrome grouped device record: {elapsed:.1f} ms; 20/1051 flows initially; protocol tabs, JSON, more, close/reopen passed")
        print("Chrome host editor: persisted review mark, labels, note, MAC and contextual whitelist passed")
        browser.close()
