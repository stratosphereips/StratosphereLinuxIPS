"""Exercise the P2P-only interface and reversible review controls in Chrome."""

import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest

from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("entity", ["alert", "evidence"])
def test_p2p_review_can_be_saved_reopened_and_withdrawn(entity: str) -> None:
    """Keep analyst feedback editable through the existing detail drawer.

    Parameters:
        entity: Durable detection category being reviewed.
    """
    _factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    changes: list[dict[str, Any]] = []
    saved: dict[str, Any] = {
        "status": "active" if entity == "alert" else "unreviewed",
        "verdict": "",
        "note": "",
    }
    assets = Path("modules/web_interface")

    def serve(route: Any) -> None:
        """Serve the real assets and retain isolated analyst feedback.

        Parameters:
            route: Browser request intercepted before network access.
        """
        path = urlparse(route.request.url).path
        if path in {"/", "/app.js", "/style.css"}:
            route.fulfill(
                path=str(assets / ("index.html" if path == "/" else path[1:]))
            )
        elif path == f"/api/{entity}-review":
            if route.request.method == "POST":
                payload = route.request.post_data_json
                changes.append(payload)
                saved.update(payload)
                route.fulfill(json={"p2p_feedback": "applied"})
            else:
                route.fulfill(json=saved)
        elif path.endswith("/flows"):
            route.fulfill(json={"items": []})
        else:
            route.fulfill(
                status=503, json={"error": "Isolated browser fixture"}
            )

    with playwright.sync_playwright() as engine:
        try:
            browser = engine.chromium.launch(channel="chrome", headless=True)
        except playwright.Error as error:
            pytest.skip(f"Chrome is unavailable: {error}")
        page = browser.new_page()
        errors: list[str] = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.route("**/*", serve)
        page.goto("http://slips.test/", wait_until="domcontentloaded")
        opener = (
            "() => openAlert({alert_id:'case',ip_alerted:'192.0.2.1',evidence:[]})"
            if entity == "alert"
            else "() => openEvidence({id:'case',evidence_type:'ARP_SCAN',profile_ip:'192.0.2.1'})"
        )
        page.evaluate(opener)
        editor = page.locator(".p2p-review-editor")
        button = editor.get_by_role("button", name="Save review")
        button.wait_for()
        page.wait_for_function(
            "() => !document.querySelector('.p2p-review-editor button').disabled"
        )
        editor.get_by_label("Detection verdict").select_option(
            "false_positive"
        )
        editor.get_by_label("Private review note").fill(
            "Verified against captured traffic"
        )
        button.click()
        page.wait_for_function(
            "() => document.querySelector('.p2p-review-editor [role=status]').textContent === 'Review saved.'"
        )
        assert changes[-1]["status"] == (
            "resolved" if entity == "alert" else "false_positive"
        )
        if entity == "alert":
            assert changes[-1]["verdict"] == "false_positive"
        page.evaluate(opener)
        page.wait_for_function(
            "() => !document.querySelector('.p2p-review-editor button').disabled"
        )
        assert (
            editor.get_by_label("Detection verdict").input_value()
            == "false_positive"
        )
        assert (
            editor.get_by_label("Private review note").input_value()
            == "Verified against captured traffic"
        )
        editor.get_by_label("Detection verdict").select_option("")
        editor.get_by_role("button", name="Save review").click()
        page.wait_for_function(
            "() => document.querySelector('.p2p-review-editor [role=status]').textContent === 'Review saved.'"
        )
        assert changes[-1]["status"] == (
            "active" if entity == "alert" else "unreviewed"
        )
        assert errors == []
        browser.close()


def test_p2p_table_separates_reliability_trust_and_report_accuracy() -> None:
    """Render three distinct model values with the actual P2P table."""
    _factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    assets = Path("modules/web_interface")
    data = {
        "enabled": True,
        "local_peer_id": "local",
        "listener": "/ip4/127.0.0.1/tcp/6668",
        "counts": {"connected": 1, "known": 1},
        "peers": [
            {
                "peer_id": "peer",
                "ip": "192.0.2.1",
                "connected": True,
                "trust": 0.35,
                "reliability": 1.0,
                "reports_received": 2,
                "confirmed_reports": 1,
                "false_reports": 0,
                "report_accuracy": [
                    {
                        "evidence_type": "ARP_SCAN",
                        "rule_version": "v1",
                        "adjustment": 0.05,
                    }
                ],
            }
        ],
        "trust_history": [
            {"peer_id": "peer", "reliability": 1.0, "timestamp": time.time()}
        ],
    }

    def serve(route: Any) -> None:
        """Supply one peer and the real P2P interface assets.

        Parameters:
            route: Intercepted browser request.
        """
        path = urlparse(route.request.url).path
        if path in {"/", "/app.js", "/style.css"}:
            route.fulfill(
                path=str(assets / ("index.html" if path == "/" else path[1:]))
            )
        elif path == "/api/p2p":
            route.fulfill(json=data)
        else:
            route.fulfill(
                status=503, json={"error": "Isolated browser fixture"}
            )

    with playwright.sync_playwright() as engine:
        try:
            browser = engine.chromium.launch(channel="chrome", headless=True)
        except playwright.Error as error:
            pytest.skip(f"Chrome is unavailable: {error}")
        page = browser.new_page()
        errors: list[str] = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.route("**/*", serve)
        page.goto("http://slips.test/", wait_until="domcontentloaded")
        page.locator('[data-tab="p2p"]').click()
        page.wait_for_function(
            "() => document.querySelector('#p2p-peers-table tbody').textContent.includes('0.350')"
        )
        values = page.locator("#p2p-peers-table tbody").inner_text()
        assert "1.000" in values and "1 TP · 0 FP" in values
        assert page.get_by_role(
            "heading", name="Peer reliability history"
        ).is_visible()
        assert errors == []
        browser.close()
