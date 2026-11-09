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
