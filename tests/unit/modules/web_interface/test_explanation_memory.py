"""Browser checks for restoring explanations without another model request."""

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest

from tests.module_factory import ModuleFactory


def test_explanation_returns_after_navigation_and_reload() -> None:
    """Restore a saved answer while keeping first-time generation on click."""
    _factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    assets = Path("modules/web_interface")
    script = (
        (assets / "app.js").read_text().split("let viewPreferencesTimer = null;", 1)[0]
    )
    requests: list[bool] = []
    saved_text = "Slips observed UDP traffic on one unknown destination port."

    def respond(route: Any) -> None:
        """Serve the UI and a cache that remembers one generated answer.

        Parameters:
            route: Intercepted browser request.
        """
        path = urlparse(route.request.url).path
        if path in {"/", "/style.css"}:
            route.fulfill(
                path=str(assets / ("index.html" if path == "/" else "style.css"))
            )
        elif path == "/app.js":
            route.fulfill(body=script, content_type="text/javascript")
        elif path == "/api/explanations/status":
            route.fulfill(json={"ready": True, "explain_evidence": True})
        elif path == "/api/explanations":
            cache_only = route.request.post_data_json.get("cache_only") is True
            requests.append(cache_only)
            if cache_only and not saved:
                route.fulfill(json={"status": "expired", "id": "a" * 64})
            else:
                saved.append(saved_text)
                route.fulfill(
                    json={"status": "ready", "id": "a" * 64, "text": saved_text}
                )
        else:
            route.fulfill(status=404)

    saved: list[str] = []
    with playwright.sync_playwright() as engine:
        browser = engine.chromium.launch(channel="chrome", headless=True)
        try:
            page = browser.new_page()
            page.route("**/*", respond)
            page.goto("http://slips.test/")
            create_card = """() => {
              document.querySelector('.ai-explanation')?.remove();
              document.body.append(explanationCard('evidence', () => ({id:'one'})));
            }"""
            page.evaluate(create_card)
            page.wait_for_function(
                "() => document.querySelector('.ai-explanation')?.textContent.includes('Generated only when requested')"
            )
            page.locator(".ai-explanation button").click()
            page.wait_for_function(
                "() => document.querySelector('.ai-explanation')?.textContent.includes('Slips observed UDP traffic')"
            )
            assert requests.count(False) == 1
            requests_before_navigation = len(requests)
            page.evaluate(create_card)
            assert saved_text in page.locator(".ai-explanation").inner_text()
            assert requests.count(False) == 1
            assert len(requests) == requests_before_navigation
            page.reload()
            page.evaluate(create_card)
            page.wait_for_function(
                "() => document.querySelector('.ai-explanation')?.textContent.includes('Slips observed UDP traffic')"
            )
            assert requests.count(False) == 1
            assert requests[-1] is True
        finally:
            browser.close()
