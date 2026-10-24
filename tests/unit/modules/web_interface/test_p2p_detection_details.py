"""Exercise typed peer packets, indexed storage, and readable web records."""

import json
import sqlite3
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from modules.p2p_trust.trust.report_validation import (
    provenance_for_evidence,
    validate_provenance,
)
from modules.web_interface.server import RunDataReader
from slips_files.core.database.sqlite_db.database import SQLiteDB
from slips_files.core.database.sqlite_db.detection_history import (
    migrate_peer_report_types,
)
from slips_files.core.structures.evidence import dict_to_evidence
from tests.module_factory import ModuleFactory


def detection_details(kind: str = "UNKNOWN_PORT") -> dict:
    """Build one valid detection description shared by packet and web checks.

    Parameters:
        kind: Canonical original detection type.

    Returns:
        Wire metadata produced from a local evidence record.
    """
    return provenance_for_evidence(
        {
            "id": "original-evidence",
            "evidence_type": kind,
            "source_module": "conn_analyzer",
            "threat_level": "low",
            "observed_at": time.time() - 1,
            "description": "Connection to unknown TCP port 8123",
            "proto": "tcp",
            "src_port": 45000,
            "dst_port": 8123,
            "review_note": "private analyst note",
            "packet": "not transmitted",
        },
        "test-version",
    )


def test_packet_details_are_bounded_validated_and_exclude_private_fields() -> (
    None
):
    """Keep useful reported facts without copying analyst notes or raw packets."""
    _factory = ModuleFactory()
    details = validate_provenance([detection_details()])[0]
    assert details["description"] == "Connection to unknown TCP port 8123"
    assert (details["proto"], details["src_port"], details["dst_port"]) == (
        "tcp",
        45000,
        8123,
    )
    assert "review_note" not in details and "packet" not in details
    raw = detection_details()
    raw["description"] = "x" * 3000
    with pytest.raises(ValueError):
        validate_provenance([raw])


@pytest.mark.parametrize(
    "field,value",
    [
        ("description", "bad\x00text"),
        ("description", 1),
        ("proto", "script"),
        ("dst_port", 0),
        ("src_port", 65536),
        ("dst_port", True),
    ],
)
def test_packet_details_reject_invalid_values(
    field: str, value: object
) -> None:
    """Reject malformed added fields while continuing to accept old packets.

    Parameters:
        field: Added detail field to corrupt.
        value: Invalid wire value.
    """
    _factory = ModuleFactory()
    details = detection_details()
    details[field] = value
    with pytest.raises(ValueError):
        validate_provenance([details])


def test_each_reported_detection_gets_a_separate_peer_evidence() -> None:
    """Keep every type independently visible when one packet reports several."""
    director = ModuleFactory().create_go_director_obj()
    director.trustdb.get_ip_of_peer.return_value = (time.time(), "192.0.2.2")
    director.db.get_tw_of_ts.return_value = ["timewindow1"]
    director.process_evaluation_score_confidence(
        "peer-A",
        time.time(),
        "ip",
        "192.0.2.10",
        {
            "score": 0.6,
            "confidence": 0.8,
            "provenance": [
                detection_details(),
                detection_details("LONG_CONNECTION"),
            ],
        },
    )
    records = [
        call.args[0] for call in director.db.set_evidence.call_args_list
    ]
    assert len(records) == 2
    assert [
        record.peer_report["provenance"][0]["evidence_type"]
        for record in records
    ] == ["UNKNOWN_PORT", "LONG_CONNECTION"]
    assert all(str(record.evidence_type) == "P2P_REPORT" for record in records)
    assert all("Reported via P2P" in record.description for record in records)
    director.trustdb.insert_new_go_report.assert_called_once()


def test_report_storage_groups_by_detection_but_preserves_peer_envelope(
    tmp_path: Path,
) -> None:
    """Serve searchable report types without treating peer evidence as local.

    Parameters:
        tmp_path: Isolated detection database directory.
    """
    director = ModuleFactory().create_go_director_obj()
    director.trustdb.get_ip_of_peer.return_value = (time.time(), "192.0.2.2")
    director.db.get_tw_of_ts.return_value = ["timewindow1"]
    director.set_evidence_p2p_report(
        "192.0.2.10",
        "peer-A",
        0.6,
        0.8,
        time.time(),
        "profile_192.0.2.10",
        [detection_details()],
    )
    evidence = director.db.set_evidence.call_args.args[0]
    database = SQLiteDB(ModuleFactory().logger, str(tmp_path), 12345)
    database.add_evidence(evidence)
    database.conn.row_factory = sqlite3.Row
    row = database.conn.execute("SELECT * FROM evidence").fetchone()
    assert row["evidence_type"] == "UNKNOWN_PORT"
    raw = json.loads(row["data"])
    assert str(dict_to_evidence(raw).evidence_type) == "P2P_REPORT"
    reader = RunDataReader.__new__(RunDataReader)
    record = reader._durable_evidence_row(database.conn, row)
    assert record["evidence_type"] == "UNKNOWN_PORT"
    assert record["record_type"] == "P2P_REPORT" and record["origin"] == "p2p"
    assert record["reporting_peers"] == ["peer-A"]
    assert record["reported_detections"][0]["dst_port"] == 8123
    plan = database.conn.execute(
        "EXPLAIN QUERY PLAN SELECT evidence_id FROM evidence WHERE evidence_type='UNKNOWN_PORT'"
    ).fetchall()
    assert any("INDEX" in str(tuple(item)) for item in plan)
    client = Mock()
    client.hgetall.return_value = {}
    client.hget.return_value = None
    client.get.return_value = None
    client.smembers.return_value = set()
    client.zrange.return_value = []
    with patch(
        "modules.web_interface.server.try_connect_with_and_without_password",
        return_value=client,
    ):
        reader = RunDataReader(
            6379, str(tmp_path), str(tmp_path / "hosts.sqlite")
        )
    groups = reader.evidence(
        {
            "group": ["host_type"],
            "type": ["UNKNOWN_PORT"],
            "range": ["all"],
            "compact": ["1"],
        }
    )
    assert len(groups["items"]) == 1
    assert groups["items"][0]["evidence_type"] == "UNKNOWN_PORT"
    assert groups["items"][0]["module"] == "p2p_trust"
    page = reader.evidence(
        {"profile": ["192.0.2.10"], "type": ["UNKNOWN_PORT"], "range": ["all"]}
    )
    assert page["total"] == 1 and page["items"][0]["origin"] == "p2p"


def test_saved_report_type_migration_is_once_only_and_preserves_json(
    tmp_path: Path,
) -> None:
    """Upgrade old typed envelopes without changing evidence IDs or local types.

    Parameters:
        tmp_path: Isolated detection database directory.
    """
    factory = ModuleFactory()
    database = SQLiteDB(factory.logger, str(tmp_path), 12345)
    database.conn.execute(
        "DELETE FROM history_state WHERE key='peer_report_display_types_v1'"
    )
    raw = json.dumps(
        {
            "evidence_type": "P2P_REPORT",
            "peer_report": {
                "peer_id": "peer-A",
                "provenance": [detection_details()],
            },
        }
    )
    database.conn.executemany(
        "INSERT INTO evidence(evidence_id,evidence_type,data) VALUES (?,'P2P_REPORT',?)",
        [(f"peer-{index}", raw) for index in range(600)],
    )
    database.conn.execute(
        "INSERT INTO evidence(evidence_id,evidence_type,data) VALUES ('legacy','P2P_REPORT','{}')"
    )
    assert migrate_peer_report_types(database.conn) == 600
    assert migrate_peer_report_types(database.conn) == 0
    assert (
        database.conn.execute(
            "SELECT count(*) FROM evidence WHERE evidence_type='UNKNOWN_PORT'"
        ).fetchone()[0]
        == 600
    )
    assert (
        database.conn.execute(
            "SELECT data FROM evidence WHERE evidence_id='peer-0'"
        ).fetchone()[0]
        == raw
    )
    assert (
        database.conn.execute(
            "SELECT evidence_type FROM evidence WHERE evidence_id='legacy'"
        ).fetchone()[0]
        == "P2P_REPORT"
    )
