# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import sqlite3
from datetime import datetime
from types import SimpleNamespace
import os
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from slips_files.core.database.sqlite_db.database import SQLiteDB
from tests.module_factory import ModuleFactory
from slips_files.core.flows.zeek import (
    Conn,
    HTTP,
)


@pytest.fixture
def db(tmp_path):
    logger = MagicMock()
    return SQLiteDB(logger, str(tmp_path), 12345)


def test_sqlite_lockfile_is_world_writable(tmp_path):
    """The lock file must be openable by both root and non-root Slips
    processes/modules regardless of which one created it, so it's created
    world read/write (it's only ever used as an flock() mutex, never holds
    sensitive data).
    """
    logger = MagicMock()
    locks_dir = tmp_path / "locks"
    locks_dir.mkdir()

    with patch(
        "slips_files.common.sqlite_flock.SLIPS_LOCKS_DIR", str(locks_dir)
    ):
        db = SQLiteDB(logger, str(tmp_path), 12345)

    assert locks_dir.exists()
    assert db.lockfile_path.endswith("sqlite_db.lock")
    assert oct(os.stat(db.lockfile_path).st_mode & 0o777) == "0o666"


def test_get_flow_uses_parameterized_query(db):
    flow = Conn(
        starttime="1.0",
        uid='uid" OR 1=1 --',
        saddr="192.168.1.10",
        daddr="8.8.8.8",
        dur=1,
        proto="tcp",
        appproto="http",
        sport="12345",
        dport="80",
        spkts=1,
        dpkts=1,
        sbytes=10,
        dbytes=10,
        state="EST",
        history="ShADadf",
        interface="eth0",
    )

    db.add_flow(flow, "profile-a", "tw-1")

    result = db.get_flow(flow.uid)

    assert json.loads(result[flow.uid])["uid"] == flow.uid


def test_flow_retention_preserves_evidence_and_expires_old_raw_rows(
    db,
) -> None:
    """Keep linked flows longer while retaining all detection records."""
    _module_factory = ModuleFactory()
    timestamps = {
        "recent": 150000.0,
        "ordinary": 50000.0,
        "linked": 50000.0,
        "excluded": 50000.0,
        "ancient-linked": 500.0,
    }
    for uid, timestamp in timestamps.items():
        flow = Conn(
            starttime=str(timestamp),
            uid=uid,
            saddr="192.0.2.10",
            daddr="198.51.100.10",
            dur=1,
            proto="tcp",
            appproto="http",
            sport="50000",
            dport="80",
            spkts=1,
            dpkts=1,
            sbytes=10,
            dbytes=10,
            state="EST",
            history="ShADadf",
            interface="eth0",
        )
        db.add_flow(flow, "profile-a", "tw-1")
    for evidence_id, uid, whitelisted in (
        ("e-linked", "linked", 0),
        ("e-excluded", "excluded", 1),
        ("e-ancient", "ancient-linked", 0),
    ):
        db.execute(
            "INSERT INTO evidence (evidence_id, whitelisted) VALUES (?, ?)",
            (evidence_id, whitelisted),
        )
        db.execute(
            "INSERT INTO evidence_flows (evidence_id, uid) VALUES (?, ?)",
            (evidence_id, uid),
        )

    deleted = db.maintain_flow_retention(
        ordinary_cutoff=100000.0,
        linked_cutoff=1000.0,
        batch_size=10,
    )

    assert set(deleted) == {"ordinary", "excluded", "ancient-linked"}
    assert set(row[0] for row in db.select("flows", columns="uid")) == {
        "recent",
        "linked",
    }
    assert (
        db.select(
            "flows",
            columns="retention_class",
            condition="uid = ?",
            params=("linked",),
            limit=1,
        )[0]
        == 1
    )
    assert db.get_count("evidence") == 3
    assert db.get_count("evidence_flows") == 3


def test_flow_retention_applies_to_protocol_flows(db) -> None:
    """Keep protocol details for evidence while expiring ordinary records."""
    _module_factory = ModuleFactory()
    for uid in ("linked-http", "ordinary-http"):
        db.add_altflow(
            HTTP(
                starttime="50000",
                uid=uid,
                saddr="192.0.2.10",
                daddr="198.51.100.10",
                method="GET",
                host="example.test",
                uri="/",
                version=1,
                user_agent="pytest",
                request_body_len=0,
                response_body_len=0,
                status_code="200",
                status_msg="OK",
                resp_mime_types="text/html",
                resp_fuids="",
                interface="eth0",
            ),
            "profile-a",
            "tw-1",
        )
    db.execute(
        "INSERT INTO evidence (evidence_id, whitelisted) VALUES (?, 0)",
        ("e-http",),
    )
    db.execute(
        "INSERT INTO evidence_flows (evidence_id, uid) VALUES (?, ?)",
        ("e-http", "linked-http"),
    )

    assert db.maintain_flow_retention(100000.0, 1000.0) == []
    assert set(row[0] for row in db.select("altflows", columns="uid")) == {
        "linked-http"
    }


def test_size_retention_prunes_oldest_row_across_flow_tables(db) -> None:
    """Choose the oldest flow across both tables before pruning newer data."""
    _module_factory = ModuleFactory()
    for uid, starttime in (("old-connection", "100"),):
        db.add_flow(
            Conn(
                starttime=starttime,
                uid=uid,
                saddr="192.0.2.10",
                daddr="198.51.100.10",
                dur=1,
                proto="tcp",
                appproto="http",
                sport="50000",
                dport="80",
                spkts=1,
                dpkts=1,
                sbytes=10,
                dbytes=10,
                state="EST",
                history="ShADadf",
                interface="eth0",
            ),
            "profile-a",
            "tw-1",
        )
    db.add_altflow(
        HTTP(
            starttime="200",
            uid="newer-http",
            saddr="192.0.2.10",
            daddr="198.51.100.10",
            method="GET",
            host="example.test",
            uri="/",
            version=1,
            user_agent="pytest",
            request_body_len=0,
            response_body_len=0,
            status_code="200",
            status_msg="OK",
            resp_mime_types="text/html",
            resp_fuids="",
            interface="eth0",
        ),
        "profile-a",
        "tw-1",
    )

    deleted = db._prune_for_size(
        db.conn.cursor(), 1, linked_only=False, linked_size_cutoff=1000.0
    )

    assert deleted == {"flows": ["old-connection"], "altflows": []}
    assert db.get_count("flows") == 0
    assert db.get_count("altflows") == 1


def test_size_retention_protects_recent_evidence_flows(db) -> None:
    """Keep flows cited by new evidence even when the flow itself is old."""
    _module_factory = ModuleFactory()
    for uid, event_time, evidence_time in (
        ("old-linked", 50, 50),
        ("recent-linked", 150, 150),
        ("old-flow-new-evidence", 50, 150),
    ):
        db.execute(
            "INSERT INTO flows (uid, flow, event_time) VALUES (?, ?, ?)",
            (uid, "{}", event_time),
        )
        db.execute(
            "INSERT INTO evidence (evidence_id, evidence_time, whitelisted) "
            "VALUES (?, ?, 0)",
            (uid, evidence_time),
        )
        db.execute(
            "INSERT INTO evidence_flows (evidence_id, uid) VALUES (?, ?)",
            (uid, uid),
        )

    deleted = db.maintain_flow_retention(
        ordinary_cutoff=100,
        linked_cutoff=0,
        batch_size=10,
        max_size_bytes=1,
    )

    assert deleted == ["old-linked"]
    assert db.get_flow("recent-linked")["recent-linked"] == "{}"
    assert (
        db.get_flow("old-flow-new-evidence")["old-flow-new-evidence"] == "{}"
    )
    assert db.maintain_flow_retention(100, 0, max_size_bytes=1) == []
    assert db.get_count("flows") == 2


@pytest.mark.parametrize(
    "max_size_bytes,linked_cutoff,batch_size", [(1, 0, 1), (0, 100, 10)]
)
def test_retention_prioritizes_latest_evidence_for_shared_flow(
    db, max_size_bytes: int, linked_cutoff: int, batch_size: int
) -> None:
    """Keep a flow with newer evidence before a newer flow with old evidence.

    Parameters:
        db: Isolated SQLite database fixture.
        max_size_bytes: Size target for this retention pass.
        linked_cutoff: Age cutoff for linked records.
        batch_size: Maximum number of linked records to prune in a pass.
    """
    _module_factory = ModuleFactory()
    for uid, flow_time in (("old-flow", 10), ("newer-flow", 40)):
        db.execute(
            "INSERT INTO flows (uid, flow, event_time) VALUES (?, ?, ?)",
            (uid, "{}", flow_time),
        )
    for evidence_id, uid, evidence_time in (
        ("old-evidence", "old-flow", 30),
        ("latest-evidence", "old-flow", 150),
        ("other-evidence", "newer-flow", 80),
    ):
        db.execute(
            "INSERT INTO evidence (evidence_id, evidence_time, whitelisted) "
            "VALUES (?, ?, 0)",
            (evidence_id, evidence_time),
        )
        db.execute(
            "INSERT INTO evidence_flows (evidence_id, uid) VALUES (?, ?)",
            (evidence_id, uid),
        )

    deleted = db.maintain_flow_retention(
        ordinary_cutoff=1000,
        linked_cutoff=linked_cutoff,
        batch_size=batch_size,
        max_size_bytes=max_size_bytes,
    )

    assert deleted == ["newer-flow"]
    assert db.get_flow("old-flow")["old-flow"] == "{}"


def test_retention_backfills_legacy_flow_timestamps(db) -> None:
    """Bound migration work and retain evidence links from older runs."""
    _module_factory = ModuleFactory()
    flow = Conn(
        starttime="50000",
        uid="legacy-linked",
        saddr="192.0.2.10",
        daddr="198.51.100.10",
        dur=1,
        proto="tcp",
        appproto="http",
        sport="50000",
        dport="80",
        spkts=1,
        dpkts=1,
        sbytes=10,
        dbytes=10,
        state="EST",
        history="ShADadf",
        interface="eth0",
    )
    db.add_flow(flow, "profile-a", "tw-1")
    db.execute("UPDATE flows SET event_time = NULL WHERE uid = ?", (flow.uid,))
    db.execute(
        "INSERT INTO evidence (evidence_id, whitelisted) VALUES (?, 0)",
        ("e-legacy",),
    )
    db.execute(
        "INSERT INTO evidence_flows (evidence_id, uid) VALUES (?, ?)",
        ("e-legacy", flow.uid),
    )

    assert db.maintain_flow_retention(100000.0, 1000.0) == []
    row = db.select(
        "flows",
        columns="event_time, retention_class",
        condition="uid = ?",
        params=(flow.uid,),
        limit=1,
    )
    assert row == (50000.0, 1)


def test_retention_removes_only_deleted_uids_from_web_index(db) -> None:
    """Keep historical host traffic totals aligned with retained raw flows."""
    _module_factory = ModuleFactory()
    history_path = os.path.join(
        db.output_dir, "web_interface", "history.sqlite"
    )
    os.makedirs(os.path.dirname(history_path))
    with sqlite3.connect(history_path) as history:
        history.execute("CREATE TABLE flow_index (uid TEXT PRIMARY KEY)")
        history.executemany(
            "INSERT INTO flow_index(uid) VALUES (?)",
            [("expired",), ("kept",)],
        )

    assert db.remove_flow_index_uids(["expired"]) == 1
    with sqlite3.connect(history_path) as history:
        assert history.execute("SELECT uid FROM flow_index").fetchall() == [
            ("kept",)
        ]


def test_retention_schema_migrates_existing_run_without_vacuum(
    tmp_path,
) -> None:
    """Upgrade an old flows DB without copying its potentially large file."""
    _module_factory = ModuleFactory()
    database_dir = tmp_path / "databases"
    database_dir.mkdir()
    path = database_dir / "flows.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE flows (uid TEXT PRIMARY KEY, flow TEXT, label TEXT, "
            "profileid TEXT, twid TEXT, aid TEXT)"
        )
        connection.execute(
            "CREATE TABLE altflows (uid TEXT PRIMARY KEY, flow TEXT, "
            "label TEXT, profileid TEXT, twid TEXT, flow_type TEXT)"
        )
        connection.execute(
            "CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, "
            "alert_time REAL, ip_alerted TEXT)"
        )
    migrated = SQLiteDB(MagicMock(), str(tmp_path), 12345)

    assert {"event_time", "retention_class"}.issubset(
        migrated.get_columns("flows")
    )
    assert {"event_time", "retention_class"}.issubset(
        migrated.get_columns("altflows")
    )
    assert migrated.conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 0
    migrated.close()


def test_new_run_enables_incremental_vacuum(db) -> None:
    """Return freed pages gradually without blocking active profiling."""
    _module_factory = ModuleFactory()
    assert db.conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2


def test_set_flow_label_and_altflow_lookup_handle_quoted_values(db):
    uid = 'uid" OR 1=1 --'
    altflow = HTTP(
        starttime="1.0",
        uid=uid,
        saddr="192.168.1.10",
        daddr="8.8.8.8",
        method="GET",
        host='example"host.test',
        uri="/index.html",
        version=1,
        user_agent="pytest",
        request_body_len=0,
        response_body_len=0,
        status_code="200",
        status_msg="OK",
        resp_mime_types="text/html",
        resp_fuids="",
        interface="eth0",
    )

    db.add_altflow(altflow, "profile-a", "tw-1")
    db.set_flow_label([uid], 'malicious"label')

    fetched_altflow = db.get_altflow_from_uid(uid)
    stored_label = db.select(
        "altflows",
        columns="label",
        condition="uid = ?",
        params=(uid,),
        limit=1,
    )

    assert fetched_altflow["uid"] == uid
    assert stored_label[0] == 'malicious"label'


def test_get_flows_count_handles_quoted_filters(db):
    first_flow = Conn(
        starttime="1.0",
        uid="flow-1",
        saddr="192.168.1.10",
        daddr="8.8.8.8",
        dur=1,
        proto="tcp",
        appproto="http",
        sport="12345",
        dport="80",
        spkts=1,
        dpkts=1,
        sbytes=10,
        dbytes=10,
        state="EST",
        history="ShADadf",
        interface="eth0",
    )
    second_flow = Conn(
        starttime="2.0",
        uid="flow-2",
        saddr="192.168.1.11",
        daddr="1.1.1.1",
        dur=1,
        proto="tcp",
        appproto="http",
        sport="12346",
        dport="443",
        spkts=1,
        dpkts=1,
        sbytes=10,
        dbytes=10,
        state="EST",
        history="ShADadf",
        interface="eth0",
    )

    db.add_flow(first_flow, 'profile"quoted', 'tw"quoted')
    db.add_flow(second_flow, 'profile"quoted', "tw-other")

    assert db.get_flows_count(profileid='profile"quoted') == 2
    assert (
        db.get_flows_count(profileid='profile"quoted', twid='tw"quoted') == 1
    )


def test_get_columns_rejects_unknown_tables(db):
    with pytest.raises(ValueError, match="Invalid SQLiteDB table name"):
        db.get_columns("flows; DROP TABLE flows;")


def test_detection_transaction_rolls_back_the_whole_group(db) -> None:
    _module_factory = ModuleFactory()
    db.execute("CREATE TABLE transaction_test (value TEXT)")

    with pytest.raises(sqlite3.Error):
        db._execute_detection_transaction(
            [
                ("INSERT INTO transaction_test VALUES (?)", ("kept-out",)),
                ("INSERT INTO missing_table VALUES (?)", ("failure",)),
            ]
        )

    assert db.select("transaction_test") == []


def test_evidence_and_alert_relationships_are_persisted(db) -> None:
    _module_factory = ModuleFactory()
    profile = SimpleNamespace(ip="10.0.0.1")
    evidence = SimpleNamespace(
        id="evidence-1",
        timestamp=datetime.now(),
        profile=profile,
        timewindow="timewindow1",
        threat_level="high",
        evidence_type="UNKNOWN_PORT",
        source_module="flow_alerts",
        description="Test evidence",
        confidence=0.9,
        uid=["flow-1", "flow-2"],
    )
    alert_timewindow = SimpleNamespace(
        start_time="1",
        end_time="2",
    )
    alert_timewindow.__str__ = lambda self: "timewindow1"
    alert = SimpleNamespace(
        id="alert-1",
        profile=profile,
        timewindow=alert_timewindow,
        correl_id=["evidence-1"],
    )

    with patch(
        "slips_files.core.database.sqlite_db.database.utils.to_dict",
        return_value={"id": "evidence-1"},
    ):
        db.add_evidence(evidence)
    db.add_alert(alert)

    assert db.select("evidence")[0][0] == "evidence-1"
    assert (
        db.execute(
            "SELECT source_module FROM evidence WHERE evidence_id = ?",
            ("evidence-1",),
        ).fetchone()[0]
        == "flow_alerts"
    )
    assert set(db.select("evidence_flows")) == {
        ("evidence-1", "flow-1"),
        ("evidence-1", "flow-2"),
    }
    assert db.select("alert_evidence") == [("alert-1", "evidence-1")]


def test_whitelist_decision_is_persisted_with_evidence(db) -> None:
    """Retain Evidence Handler's exclusion decision after Redis expires."""
    _module_factory = ModuleFactory()
    profile = SimpleNamespace(ip="10.0.0.1")
    evidence = SimpleNamespace(
        id="evidence-whitelisted",
        timestamp=datetime.now(),
        profile=profile,
        timewindow="timewindow1",
        threat_level="low",
        evidence_type="UNKNOWN_PORT",
        description="Whitelisted destination",
        confidence=1.0,
        uid=[],
    )
    with patch(
        "slips_files.core.database.sqlite_db.database.utils.to_dict",
        return_value={"id": evidence.id},
    ):
        db.add_evidence(evidence)

    db.mark_evidence_whitelisted(evidence.id)

    columns = db.get_columns("evidence")
    record = dict(zip(columns, db.select("evidence")[0]))
    assert record["whitelisted"] == 1


def test_get_whitelisted_evidence_ids_in_tw_scopes_by_ip_and_twid(
    db,
) -> None:
    """Resolve whitelisted evidence for one profile+timewindow in one query."""
    profile = SimpleNamespace(ip="10.0.0.1")
    other_profile = SimpleNamespace(ip="10.0.0.2")

    def make_evidence(evidence_id, profile, timewindow):
        return SimpleNamespace(
            id=evidence_id,
            timestamp=datetime.now(),
            profile=profile,
            timewindow=timewindow,
            threat_level="low",
            evidence_type="UNKNOWN_PORT",
            description="d",
            confidence=1.0,
            uid=[],
        )

    with patch(
        "slips_files.core.database.sqlite_db.database.utils.to_dict",
        side_effect=lambda ev: {"id": ev.id},
    ):
        db.add_evidence(make_evidence("ev1", profile, "timewindow1"))
        db.add_evidence(make_evidence("ev2", profile, "timewindow1"))
        # same evidence id space, different timewindow -> must not leak in
        db.add_evidence(make_evidence("ev3", profile, "timewindow2"))
        # same timewindow, different ip -> must not leak in
        db.add_evidence(make_evidence("ev4", other_profile, "timewindow1"))

    db.mark_evidence_whitelisted("ev1")
    db.mark_evidence_whitelisted("ev3")
    db.mark_evidence_whitelisted("ev4")

    assert db.get_whitelisted_evidence_ids_in_tw(
        "10.0.0.1", "timewindow1"
    ) == {"ev1"}
    assert db.get_whitelisted_evidence_ids_in_tw(
        "10.0.0.1", "timewindow2"
    ) == {"ev3"}
    assert db.get_whitelisted_evidence_ids_in_tw(
        "10.0.0.2", "timewindow1"
    ) == {"ev4"}
    assert (
        db.get_whitelisted_evidence_ids_in_tw("10.0.0.3", "timewindow1")
        == set()
    )
