"""T Cell dashboard checks for current state and decision context."""

import json
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest

from modules.web_interface.server import RunDataReader
from tests.module_factory import ModuleFactory


def test_t_cell_status_exposes_waits_and_bounded_decision_details(
    tmp_path: Path,
) -> None:
    """Return enough saved context to explain cells and transitions.

    Parameters:
        tmp_path: Isolated run directory.
    """
    _factory = ModuleFactory()
    store = tmp_path / "t_cell" / "data"
    store.mkdir(parents=True)
    with sqlite3.connect(store / "t_cell.sqlite") as db:
        db.executescript(
            "CREATE TABLE cells (profile_ip TEXT,regex_type TEXT,antigen_value TEXT,"
            "state INTEGER,state_name TEXT,last_transition_at REAL,updated_at REAL,"
            "matched_regex TEXT,matched_value TEXT,last_co_stimulation REAL,"
            "last_effector_score REAL,last_memory_score REAL,anergic_until REAL,"
            "last_evidence_id TEXT,context_json TEXT);"
            "CREATE TABLE transitions (id INTEGER PRIMARY KEY,profile_ip TEXT,"
            "regex_type TEXT,antigen_value TEXT,from_state INTEGER,to_state INTEGER,"
            "reason TEXT,created_at REAL,evidence_id TEXT,scores_json TEXT,"
            "matched_regex TEXT,matched_value TEXT);"
            "CREATE TABLE observations (evidence_signal TEXT);"
        )
        db.executemany(
            "INSERT INTO cells VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    "192.0.2.1",
                    "dns_domain",
                    "example.test",
                    3,
                    "3 - activated",
                    10,
                    20,
                    "^example",
                    "example.test",
                    0.77,
                    0.8,
                    0.3,
                    None,
                    "evidence-1",
                    json.dumps(
                        {"waiting_for": "context", "wait_deadline": 30}
                    ),
                ),
                (
                    "192.0.2.2",
                    "dns_domain",
                    "other.test",
                    2,
                    "2 - anergic",
                    10,
                    40,
                    None,
                    None,
                    None,
                    None,
                    None,
                    50,
                    "evidence-2",
                    "{}",
                ),
            ],
        )
        db.execute(
            "INSERT INTO transitions VALUES (1,'192.0.2.1','dns_domain',"
            "'example.test',1,3,'co_stimulation_threshold_met',10,"
            "'evidence-1',?,'^example','example.test')",
            (
                json.dumps(
                    {
                        "value": 0.77,
                        "threshold": 0.65,
                        "confidence": 0.9,
                        "related_pamp_count": 4,
                        "profile_danger_score": 0.8,
                    }
                ),
            ),
        )
        db.executemany(
            "INSERT INTO observations VALUES (?)", [("PAMP",), ("DAMP",)]
        )
    reader = object.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader._run_config = lambda: (
        {"t_cell": {"store_dir": "output/t_cell/data"}},
        None,
    )

    result = reader.t_cell_status()

    assert result["waiting"] == [
        {"state": 3, "waiting_for": "context", "count": 1}
    ]
    assert {
        item["evidence_signal"]: item["count"] for item in result["signals"]
    } == {
        "PAMP": 1,
        "DAMP": 1,
    }
    assert result["cells"][0]["state"] == 3
    assert result["cells"][0]["matched_regex"] == "^example"
    assert result["cells"][0]["wait_deadline"] == 30
    assert result["transitions"][0]["value"] == 0.77
    assert result["transitions"][0]["threshold"] == 0.65
    assert result["transitions"][0]["matched_regex"] == "^example"
    assert result["transitions"][0]["related_pamp_count"] == 4


def test_t_cell_page_explains_live_state_and_saved_scores() -> None:
    """Show plain-language decisions and expandable cell context in Chrome."""
    _factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    assets = Path("modules/web_interface")
    script = (
        (assets / "app.js")
        .read_text()
        .split("let viewPreferencesTimer = null;", 1)[0]
    )
    payload = {
        "available": True,
        "store_bytes": 2048,
        "states": [{"state": 1, "count": 2}, {"state": 3, "count": 1}],
        "waiting": [
            {"state": 1, "waiting_for": "co_stimulation", "count": 2},
            {"state": 3, "waiting_for": "context", "count": 1},
        ],
        "signals": [
            {"evidence_signal": "PAMP", "count": 7},
            {"evidence_signal": "DAMP", "count": 2},
        ],
        "cells": [
            {
                "profile_ip": "192.0.2.1",
                "regex_type": "dns_domain",
                "antigen_value": "example.test",
                "state": 3,
                "state_name": "3 - activated",
                "updated_at": 1700000000,
                "matched_regex": "^example",
                "last_co_stimulation": 0.77,
                "waiting_for": "context",
                "wait_deadline": 1700003600,
            },
            {
                "profile_ip": "192.0.2.2",
                "regex_type": "dns_domain",
                "antigen_value": "other.test",
                "state": 2,
                "state_name": "2 - anergic",
                "updated_at": 1700000001,
                "anergic_until": 1700007200,
            },
        ],
        "transitions": [
            {
                "id": 1,
                "profile_ip": "192.0.2.1",
                "antigen_value": "example.test",
                "from_state": 1,
                "to_state": 3,
                "reason": "co_stimulation_threshold_met",
                "created_at": 1700000000,
                "value": 0.77,
                "threshold": 0.65,
                "matched_regex": "^example",
                "confidence": 0.9,
                "related_pamp_count": 4,
                "profile_danger_score": 0.8,
                "evidence_id": "evidence-1",
            },
            {
                "id": 2,
                "profile_ip": "192.0.2.1",
                "antigen_value": "example.test",
                "from_state": 3,
                "to_state": 4,
                "reason": "context_effector",
                "created_at": 1699999999,
                "effector_score": 0.74,
                "effector_threshold": 0.7,
                "recent_related_count": 4,
                "effector_min_related_count": 4,
                "novelty_score": 1,
                "recent_pressure": 0.54,
                "previous_pressure": 0.1,
                "evidence_id": "evidence-2",
            },
        ],
    }

    def respond(route: Any) -> None:
        """Serve UI assets and one T Cell status response.

        Parameters:
            route: Intercepted browser request.
        """
        path = urlparse(route.request.url).path
        if path in {"/", "/style.css"}:
            route.fulfill(
                path=str(
                    assets / ("index.html" if path == "/" else "style.css")
                )
            )
        elif path == "/app.js":
            route.fulfill(body=script, content_type="text/javascript")
        elif path == "/api/immune/t-cell":
            route.fulfill(json=payload)
        else:
            route.fulfill(status=404)

    with playwright.sync_playwright() as engine:
        browser = engine.chromium.launch(channel="chrome", headless=True)
        try:
            page = browser.new_page()
            page.route("**/*", respond)
            page.goto("http://slips.test/")
            page.evaluate(
                "() => { document.querySelector('#overview').classList.remove('active'); document.querySelector('#t-cell').classList.add('active'); }"
            )
            page.evaluate("() => loadTCell()")
            assert (
                "7 PAMP and 2 DAMP" in page.locator("#t-cell-now").inner_text()
            )
            assert (
                "Latest change for 192.0.2.1"
                in page.locator("#t-cell-now").inner_text()
            )
            assert (
                "Co-stimulation: 0.770 / threshold 0.650"
                in page.locator("#t-cell-now").inner_text()
            )
            assert (
                "2 cells are waiting for co-stimulation"
                in page.locator("#t-cell-now").inner_text()
            )
            assert page.locator("#t-cell-now time").count() == 1
            assert (
                "[object HTMLTimeElement]"
                not in page.locator("#t-cell-now").inner_text()
            )
            assert "Mature" in page.locator(".t-cell-state-guide").inner_text()
            assert (
                "Activated · 1" in page.locator("#t-cell-reasons").inner_text()
            )
            page.locator(".t-cell-help summary").click()
            assert (
                "The evidence that started recognition cannot also activate"
                in page.locator(".t-cell-help").inner_text()
            )
            page.locator("#t-cell-cells details summary").first.click()
            assert (
                "Matched regex" in page.locator("#t-cell-cells").inner_text()
            )
            assert "0.770" in page.locator("#t-cell-cells").inner_text()
            assert page.locator("#t-cell-cells details time").count() == 2
            assert (
                "Wait deadline" in page.locator("#t-cell-cells").inner_text()
            )
            assert (
                "[object HTMLTimeElement]"
                not in page.locator("#t-cell-cells").inner_text()
            )
            page.locator("#t-cell-cells details summary").nth(1).click()
            assert (
                "Anergy expiry" in page.locator("#t-cell-cells").inner_text()
            )
            page.locator("#t-cell-transitions details summary").first.click()
            assert (
                "threshold 0.650"
                in page.locator("#t-cell-transitions").inner_text()
            )
            assert (
                "Recent related PAMP observations: 4"
                in page.locator("#t-cell-transitions").inner_text()
            )
            assert (
                "evidence-1"
                in page.locator("#t-cell-transitions").inner_text()
            )
            page.locator("#t-cell-transitions details summary").nth(1).click()
            assert (
                "Recent related PAMP observations: 4 / required 4"
                in page.locator("#t-cell-transitions").inner_text()
            )
            assert (
                "Effector score: 0.740 / threshold 0.700"
                in page.locator("#t-cell-transitions").inner_text()
            )
        finally:
            browser.close()
