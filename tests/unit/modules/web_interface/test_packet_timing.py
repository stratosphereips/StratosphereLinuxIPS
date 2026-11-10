"""Browser checks for packet gaps and the recorded timing decision."""

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest

from tests.module_factory import ModuleFactory
from tests.unit.modules.beaconing.test_packet_timing import summary


@pytest.mark.parametrize("theme,width", [("light", 360), ("dark", 360), ("light", 800), ("dark", 800)])
def test_packet_gaps_and_saved_decision_render_in_real_investigation(
    theme: str, width: int,
) -> None:
    """Show intervals, explain the actual detector result and keep narrow panes usable.

    Parameters:
        theme: Browser color theme.
        width: Available flow investigation width.
    """
    factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    module = factory.create_beaconing_obj(packet_timing={"enabled": True})
    base = 1_794_160_000
    flow = summary(
        starttime=base + 304, times=[base + i * 30 for i in range(11)] + [base + 304],
        lengths=[124] + [28] * 10 + [52], is_orig=False, service=["ssl"],
    )
    finding = module.packet_detector.process(flow, "network")
    assert finding is not None
    record = {
        "id": "packet-gap-test", "evidence_type": finding["evidence_type"],
        "module": "beaconing", "profile_ip": finding["source"],
        "description": finding["description"], "timestamp": finding["timestamp"],
        "threat_level": finding["threat"], "confidence": finding["confidence"],
        "detection_details": {"packet_timing": finding["details"]},
    }
    group = {
        "uid": flow["record_id"],
        "network_flow": {"uid": flow["uid"], "flow": {
            "saddr": flow["saddr"], "daddr": flow["daddr"], "sport": flow["sport"],
            "dport": flow["dport"], "proto": "tcp", "starttime": base, "dur": 304,
        }},
        "protocol_flows": [{"uid": flow["record_id"], "flow_type": "packet_timing", "flow": flow}],
    }
    assets = Path("modules/web_interface")
    errors: list[str] = []

    def respond(route: Any) -> None:
        """Serve real assets and the isolated linked packet summary.

        Parameters:
            route: Browser request to fulfill.
        """
        path = urlparse(route.request.url).path
        if path in {"/", "/app.js", "/style.css"}:
            route.fulfill(path=str(assets / ("index.html" if path == "/" else path[1:])))
        elif path == "/api/evidence/packet-gap-test/flows":
            route.fulfill(json={"items": [group], "linked_uid_count": 1, "next_cursor": None})
        else:
            route.fulfill(status=503, json={"error": "Isolated fixture"})

    with playwright.sync_playwright() as engine:
        browser = engine.chromium.launch(channel="chrome", headless=True)
        try:
            page = browser.new_page(viewport={"width": 1500, "height": 1300})
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.route("**/*", respond)
            page.goto("http://slips.test/")
            page.wait_for_function("typeof openEvidence === 'function'")
            page.evaluate("""async ({record,group,theme,width}) => {
                clearTimeout(state.timer);clearTimeout(state.statusTimer);clearInterval(state.titleTimer);
                setTheme(theme);state.activeTab='overview';state.whitelists={evidence_types:[]};
                window.packetFixture=group;window.originalPacketJSON=JSON.stringify(group);
                await openEvidence(record,[record]);
                const flowPane=document.querySelector('.evidence-detail-flows');
                flowPane.style.width=width+'px';
            }""", {"record": record, "group": group, "theme": theme, "width": width})
            pane = page.locator(".evidence-detail-flows")
            card = pane.locator(".protocol-packet_timing")
            assert pane.get_by_role("tab", name="Related Packet timing · 1", exact=True).get_attribute("aria-selected") == "true"
            assert card.locator("h4").inner_text() == "Packet timing"
            assert "Responder → originator" in card.inner_text()
            assert "12 selected packets · 11 gaps" in card.inner_text()
            assert "Packet times (seconds)" not in card.inner_text()
            rows = card.locator(".packet-gap-table tbody tr")
            assert rows.count() == 12
            assert rows.nth(0).locator("td").nth(1).inner_text() == "—"
            assert rows.nth(1).locator("td").nth(1).inner_text() == "30 s"
            assert rows.last.locator("td").nth(1).inner_text() == "4 s"
            assert rows.nth(0).locator("td").last.inner_text() == "124 B"
            assert rows.last.locator("td").last.inner_text() == "52 B"
            assert "2026" in rows.first.locator("time").get_attribute("title")
            assert "2026" not in card.locator(".packet-gap-table").inner_text()
            assert card.locator(".protocol-context").inner_text().startswith("Connection UID: Cpacket")
            decision = pane.locator(".packet-timing-decision")
            assert "30 s" in decision.inner_text()
            assert "90.9%" in decision.inner_text()
            assert "Decision based on 12 selected packets over 304 s" in decision.inner_text()
            assert not decision.locator("details").evaluate("node => node.open")
            decision.get_by_text("More detection details", exact=True).click()
            assert "83.3%" in decision.inner_text()
            assert "28 B" in decision.inner_text()
            assert page.evaluate("JSON.stringify(packetFixture) === originalPacketJSON")
            assert pane.evaluate("node => node.scrollWidth <= node.clientWidth")
            artifact = Path("output/packet-timing-web-validation")
            artifact.mkdir(parents=True, exist_ok=True)
            decision.get_by_text("More detection details", exact=True).click()
            pane.screenshot(path=str(artifact / f"{theme}-{width}.png"))
            page.evaluate("""() => {
                window.packetEdgeCases = [
                    {times:[1000,1000.25,1000.75],lengths:[1,2,3]},
                    {times:'1000,1000.25,1000.75',lengths:'1,2,3'},
                    {times:[1,null,3]}, {times:[3,2,4]}, {times:[1,'bad',3]},
                    {times:[1,false,3]}, {times:[1,-2,3]}, {times:[1,Infinity,3]},
                    {times:Array(257).fill(1)}, {times:[]}, {times:[0]},
                ].map(sample => {
                    const card=protocolFlowCard({flow_type:'packet_timing',flow:sample});
                    return {text:card.textContent,rows:card.querySelectorAll('tbody tr').length};
                });
            }""")
            edge = page.evaluate("packetEdgeCases")
            assert "250 ms" in edge[0]["text"] and "500 ms" in edge[0]["text"]
            assert edge[0]["text"] == edge[1]["text"]
            assert all(item["rows"] == 0 and "gaps cannot be calculated" in item["text"] for item in edge[2:-1])
            assert edge[-1]["rows"] == 1 and "0 gaps" in edge[-1]["text"]
            assert page.evaluate("packetTimingEvidencePanel({evidence_type:'PERIODIC_PACKETS'}) === null")
            assert page.evaluate("""() => {
                const strong=packetTimingEvidencePanel({evidence_type:'SUSPICIOUS_PACKET_HEARTBEAT',
                    detection_details:{packet_timing:{period:300.503,count:12,span:3305.533,support:1,jitter:.001,uniform_size_fraction:1,sent:8}}});
                const grouped=packetTimingEvidencePanel({evidence_type:'PERIODIC_PACKETS',
                    detection_details:{packet_timing:{period:30,mode:'burst-to-burst'}}});
                return strong.textContent.includes('expected TLS port')
                    && strong.textContent.includes('300.503 s')
                    && grouped.textContent.includes('Between packet groups')
                    && packetGapText(0.0000001)==='<0.001 ms';
            }""")
            assert not errors, errors
        finally:
            browser.close()


@pytest.mark.parametrize("mode", ["missing", "connection", "tls"])
@pytest.mark.parametrize("theme,width", [("light", 360), ("dark", 800)])
def test_long_connection_keeps_packet_samples_in_collapsed_context(
    mode: str, theme: str, width: int,
) -> None:
    """Keep ACK samples from replacing the actual Long Connection details.

    Parameters:
        mode: Missing connection, retained connection or TLS protocol context.
        theme: Color scheme used by the investigation.
        width: Available flow pane width.
    """
    _factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    flow = summary(kind="ack", times=[1000 + i * 20.48 for i in range(12)], lengths=[0] * 12)
    protocols = [{"uid": f"Cpacket:packet:{index}", "flow_type": "packet_timing",
                  "flow": {**flow, "record_id": f"Cpacket:packet:{index}", "is_orig": index == 0}}
                 for index in range(2)]
    if mode == "tls":
        protocols.append({"uid": "Cpacket", "flow_type": "ssl", "flow": {"type_": "ssl", "server_name": "example.test"}})
    group = {"uid": "Cpacket", "network_flow": None if mode == "missing" else {
        "uid": "Cpacket", "flow": {"saddr": "10.0.0.1", "daddr": "8.8.8.8", "proto": "tcp", "dur": 3300}},
        "protocol_flows": protocols}
    record = {"id": "long-connection", "uid": ["Cpacket"], "evidence_type": "LONG_CONNECTION",
              "module": "conn_analyzer", "description": "Connection took 55 mins", "threat_level": "low"}
    assets = Path("modules/web_interface")
    script = (assets / "app.js").read_text().split("let viewPreferencesTimer = null;", 1)[0]
    errors: list[str] = []

    def respond(route: Any) -> None:
        """Serve the actual UI and retain the unmodified linked flow group.

        Parameters:
            route: Isolated browser request.
        """
        path = urlparse(route.request.url).path
        if path in {"/", "/style.css", "/slips-logo.png"}:
            route.fulfill(path=str(assets / ("index.html" if path == "/" else path[1:])))
        elif path == "/app.js":
            route.fulfill(body=script, content_type="text/javascript")
        elif path == "/api/evidence/long-connection/flows":
            route.fulfill(json={"items": [group], "linked_uid_count": 1})
        else:
            route.fulfill(json={})

    with playwright.sync_playwright() as engine:
        browser = engine.chromium.launch(channel="chrome", headless=True)
        try:
            page = browser.new_page(viewport={"width": 1500, "height": 1300})
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.route("**/*", respond)
            page.goto("http://slips.test/")
            page.evaluate("""async ({record,theme,width}) => {
                setTheme(theme);state.activeTab='overview';state.whitelists={evidence_types:[]};
                await openEvidence(record,[record]);
                document.querySelector('.evidence-detail-flows').style.width=width+'px';
            }""", {"record": record, "theme": theme, "width": width})
            pane = page.locator(".evidence-detail-flows")
            context = pane.locator(".packet-timing-context")
            assert not context.evaluate("element => element.open")
            assert pane.locator(".protocol-packet_timing").count() == 0
            assert pane.get_by_role("tab", name="Related Packet timing", exact=False).count() == 0
            assert pane.locator(".packet-timing-decision").count() == 0
            if mode == "missing":
                assert "full connection record is unavailable" in pane.inner_text()
                assert pane.get_by_role("tab").count() == 0
                assert pane.locator(".flow-related-count").count() == 0
            else:
                tab = pane.get_by_role("tab", name="Related SSL · 1" if mode == "tls" else "conn · flow", exact=True)
                assert tab.get_attribute("aria-selected") == "true"
                if mode == "tls":
                    assert pane.locator(".flow-related-count").inner_text() == "1 related protocol record"
                else:
                    assert pane.locator(".flow-related-count").count() == 0
            context.locator(":scope > summary").click()
            card = context.locator(".protocol-packet_timing")
            playwright.expect(card).to_be_visible()
            assert "Long Connection uses the connection duration" in context.inner_text()
            assert "20.48 s" in card.inner_text()
            assert "Originator → responder" in card.inner_text()
            context.get_by_role("combobox", name="Packet timing context sample").select_option("1")
            assert context.locator(".protocol-packet_timing").count() == 1
            assert "Responder → originator" in card.inner_text()
            assert "0 B" in card.inner_text()
            assert context.get_by_role("combobox").bounding_box()["width"] <= context.bounding_box()["width"]
            context.locator(":scope > summary").click()
            playwright.expect(card).to_be_hidden()
            primary = page.evaluate("""group => {
                const mixed={...group,protocol_flows:[{flow_type:'ssl',flow:{server_name:'example.test'}},
                    ...group.protocol_flows.filter(item => item.flow_type==='packet_timing')]};
                const card=flowCard(mixed,1,1,null,{evidence_type:'PERIODIC_PACKETS'});
                return {tab:card.querySelector('[role=tab][aria-selected=true]').textContent,
                    context:card.querySelectorAll('.packet-timing-context').length};
            }""", group)
            assert primary == {"tab": "Related Packet timing · 2", "context": 0}
            assert not errors, errors
        finally:
            browser.close()
