"""Verify web verdicts reach persistent P2P learning and remain reversible."""

import json
import sqlite3
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from modules.p2p_trust.trust.report_validation import ReportValidator
from modules.supported_module_names import Modules
from modules.web_interface.server import RunDataReader
from tests.module_factory import ModuleFactory


def reviewed_run(directory: Path) -> RunDataReader:
    """Create a run containing linked local and authenticated peer evidence.

    Parameters:
        directory: Isolated test directory.

    Returns:
        Real web reader using durable SQLite records.
    """
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = directory / "flows.sqlite"
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "CREATE TABLE alerts(alert_id TEXT PRIMARY KEY);"
            "CREATE TABLE evidence(evidence_id TEXT PRIMARY KEY,data TEXT);"
            "CREATE TABLE alert_evidence(alert_id TEXT,evidence_id TEXT);"
            "CREATE TABLE evidence_flows(evidence_id TEXT,uid TEXT);"
            "CREATE TABLE flows(uid TEXT); CREATE TABLE altflows(uid TEXT);"
            "INSERT INTO alerts VALUES ('local-alert'),('peer-alert');"
            "INSERT INTO alert_evidence VALUES ('local-alert','local'),('peer-alert','remote');"
        )
        now = time.time()
        provenance = {
            "evidence_type": "ARP_SCAN",
            "module": Modules.ARP.value,
            "rule_version": "rule-v1",
            "family": "network_discovery",
            "method": "HEURISTIC",
            "observed_at": now,
            "network_id": "gateway:home",
        }
        for identifier in ("local", "remote"):
            raw = {
                "id": identifier,
                "timestamp": now,
                "attacker": {"value": "192.168.1.185"},
                "evidence_type": "ARP_SCAN",
                "threat_level": "low",
                "confidence": 0.8,
                "source_module": Modules.ARP.value,
                "detection_provenance": provenance,
            }
            if identifier == "remote":
                raw.update(
                    {
                        "evidence_type": "P2P_REPORT",
                        "detection_provenance": {},
                        "peer_report": {
                            "peer_id": "peer-A",
                            "score": 0.2,
                            "confidence": 0.8,
                            "message_type": "blame",
                            "network_id": "gateway:home",
                            "provenance": [provenance],
                        },
                    }
                )
            connection.execute(
                "INSERT INTO evidence VALUES (?,?)",
                (identifier, json.dumps(raw)),
            )
    return reader


@pytest.mark.parametrize(
    "verdict,expected",
    [
        ("true_positive", 1),
        ("false_positive", -1),
        ("expected_behavior", -1),
        ("inconclusive", 0),
        ("in_review", 0),
    ],
)
def test_web_reviews_update_peer_accuracy(
    tmp_path: Path, verdict: str, expected: int
) -> None:
    factory = ModuleFactory()
    reader = reviewed_run(tmp_path)
    result = reader.save_review(
        "evidence",
        {
            "id": "remote",
            "action": "review",
            "status": verdict,
            "note": "Checked the traffic",
        },
    )
    assert result["p2p_feedback"] == "applied"
    validator = ReportValidator(reader._report_validation_path())
    adjustment = validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")
    assert adjustment["confirmed"] - adjustment["false_positive"] == expected
    reader.save_review(
        "evidence",
        {
            "id": "remote",
            "action": "review",
            "status": "unreviewed",
            "note": "Reopened",
        },
    )
    assert (
        validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")[
            "adjustment"
        ]
        == 0
    )
    assert factory is not None


def test_web_alert_and_evidence_conflicts_suspend_and_restore_learning(
    tmp_path: Path,
) -> None:
    factory = ModuleFactory()
    reader = reviewed_run(tmp_path)
    reader.save_review(
        "evidence",
        {"id": "remote", "action": "review", "status": "true_positive"},
    )
    reader.save_review(
        "alert",
        {
            "id": "peer-alert",
            "action": "review",
            "status": "resolved",
            "verdict": "false_positive",
            "note": "False alarm",
        },
    )
    validator = ReportValidator(reader._report_validation_path())
    assert (
        validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")[
            "adjustment"
        ]
        == 0
    )
    reader.save_review(
        "alert",
        {
            "id": "peer-alert",
            "action": "review",
            "status": "active",
            "verdict": "",
            "note": "Reopened",
        },
    )
    assert (
        validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")[
            "confirmed"
        ]
        == 1
    )
    assert factory is not None


def test_shared_evidence_is_not_withdrawn_when_deleting_an_alert(
    tmp_path: Path,
) -> None:
    factory = ModuleFactory()
    reader = reviewed_run(tmp_path)
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "INSERT INTO alert_evidence VALUES ('local-alert','remote')"
        )
    reader.save_review(
        "evidence",
        {"id": "remote", "action": "review", "status": "true_positive"},
    )
    result = reader.save_review(
        "alert",
        {
            "id": "peer-alert",
            "action": "delete",
            "depth": "evidence",
            "note": "Duplicate alert",
        },
    )
    validator = ReportValidator(reader._report_validation_path())
    assert result["shared_preserved"] == 1
    assert (
        validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")[
            "confirmed"
        ]
        == 1
    )
    reader.save_review(
        "evidence",
        {
            "id": "remote",
            "action": "delete",
            "depth": "evidence",
            "note": "Remove evidence",
        },
    )
    assert (
        validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")[
            "adjustment"
        ]
        == 0
    )
    assert factory is not None


def test_review_commit_survives_unavailable_validation_database(
    tmp_path: Path,
) -> None:
    factory = ModuleFactory()
    reader = reviewed_run(tmp_path)
    with patch(
        "modules.web_interface.server.ReportValidator",
        side_effect=sqlite3.OperationalError("locked"),
    ):
        result = reader.save_review(
            "evidence",
            {"id": "remote", "action": "review", "status": "false_positive"},
        )
    assert result["p2p_feedback"] == "pending"
    with sqlite3.connect(reader.sqlite_path) as connection:
        assert (
            connection.execute(
                "SELECT status FROM evidence_reviews WHERE evidence_id='remote'"
            ).fetchone()[0]
            == "false_positive"
        )
    validator = ReportValidator(reader._report_validation_path())
    assert validator.drain_reviews(reader.sqlite_path) == 1
    assert (
        validator.report_adjustment("peer-A", "ARP_SCAN", "rule-v1")[
            "false_positive"
        ]
        == 1
    )
    assert factory is not None


@pytest.mark.parametrize(
    "authenticated,origin,content_type,body,expected",
    [
        (False, "same", "application/json", b'{"id":"case"}', 401),
        (
            True,
            "https://other.example",
            "application/json",
            b'{"id":"case"}',
            403,
        ),
        (True, "", "application/json", b'{"id":"case"}', 403),
        (True, "same", "text/plain", b'{"id":"case"}', 400),
        (True, "same", "application/json", b"[]", 400),
        (
            True,
            "same",
            "application/json",
            b'{"id":"case","action":"review"}',
            200,
        ),
    ],
)
def test_review_http_requires_session_origin_and_json(
    authenticated: bool,
    origin: str,
    content_type: str,
    body: bytes,
    expected: int,
) -> None:
    """Protect analyst feedback from unauthenticated or cross-origin writes.

    Parameters:
        authenticated: Whether the request has a valid session.
        origin: Request origin or the bound server's exact origin.
        content_type: Request media type.
        body: JSON object or deliberately invalid payload.
        expected: Expected HTTP status.
    """
    factory = ModuleFactory()
    from http.client import HTTPConnection
    from threading import Thread
    from unittest.mock import Mock
    from modules.web_interface.server import RequestHandler, SlipsHTTPServer
    from slips_files.common.slips_utils import utils

    reader = Mock()
    reader.save_review.return_value = {"id": "case", "p2p_feedback": "applied"}
    server = SlipsHTTPServer(("127.0.0.1", 0), RequestHandler, reader)
    thread = Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.01},
        daemon=True,
    )
    utils.start_thread(thread, factory.logger)
    port = server.server_address[1]
    client = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        with (
            patch.object(
                RequestHandler, "_require_password", return_value=True
            ),
            patch.object(
                RequestHandler, "_session_ok", return_value=authenticated
            ),
        ):
            client.request(
                "POST",
                "/api/evidence-review",
                body=body,
                headers={
                    "Origin": (
                        f"http://127.0.0.1:{port}"
                        if origin == "same"
                        else origin
                    ),
                    "Content-Type": content_type,
                },
            )
            response = client.getresponse()
            assert response.status == expected
            response.read()
        assert reader.save_review.call_count == (1 if expected == 200 else 0)
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize(
    "entity,identifier", [("alert", "peer-alert"), ("evidence", "remote")]
)
def test_review_reader_preserves_verdict_and_note(
    tmp_path: Path, entity: str, identifier: str
) -> None:
    """Keep reopened verdicts and notes without creating state on reads.

    Parameters:
        tmp_path: Isolated run database directory.
        entity: Alert or evidence review endpoint.
        identifier: Existing durable record identifier.
    """
    factory = ModuleFactory()
    reader = reviewed_run(tmp_path)
    original = reader.sqlite_path.read_bytes()
    initial = reader.review(entity, identifier)
    assert initial["note"] == ""
    assert reader.sqlite_path.read_bytes() == original
    reader.save_review(
        entity,
        {
            "id": identifier,
            "action": "review",
            "status": "resolved" if entity == "alert" else "false_positive",
            "verdict": "false_positive",
            "note": "Checked against captured traffic",
        },
    )
    saved = reader.review(entity, identifier)
    assert saved["note"] == "Checked against captured traffic"
    assert (
        saved["verdict"] if entity == "alert" else saved["status"]
    ) == "false_positive"
    assert factory is not None
