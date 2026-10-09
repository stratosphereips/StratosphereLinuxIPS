# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import sqlite3
import time
import pytest
from contextlib import nullcontext
from unittest.mock import (
    patch,
    call,
    MagicMock,
    Mock,
)
from tests.module_factory import ModuleFactory
import datetime
from modules.p2p_trust.trust.trustdb import TrustDB


def normalize_sql(sql):
    return " ".join(sql.strip().split())


@pytest.mark.parametrize(
    "existing_tables",
    [
        # Testcase 1: All tables exist
        (
            [
                "opinion_cache",
                "slips_reputation",
                "go_reliability",
                "peer_ips",
                "peer_addresses",
                "reports",
                "report_aggregates",
                "report_compaction_state",
            ]
        ),
        # Testcase 2: Some tables missing
        (["slips_reputation", "peer_ips"]),
        # Testcase 3: No tables exist
        ([]),
    ],
)
def test_delete_tables(existing_tables):
    trust_db = ModuleFactory().create_trust_db_obj()
    trust_db.execute = Mock()
    trust_db.execute.side_effect = lambda query: (
        None if query.startswith("DROP TABLE") else ["table"]
    )
    trust_db.conn.fetchall = Mock()
    trust_db.conn.fetchall.return_value = existing_tables

    expected_calls = [
        call("DROP TABLE IF EXISTS opinion_cache;"),
        call("DROP TABLE IF EXISTS slips_reputation;"),
        call("DROP TABLE IF EXISTS go_reliability;"),
        call("DROP TABLE IF EXISTS peer_ips;"),
        call("DROP TABLE IF EXISTS peer_addresses;"),
        call("DROP TABLE IF EXISTS reports;"),
        call("DROP TABLE IF EXISTS report_aggregates;"),
        call("DROP TABLE IF EXISTS report_compaction_state;"),
    ]

    trust_db.delete_tables()
    assert trust_db.execute.call_args_list == expected_calls


@pytest.mark.parametrize(
    "key_type, reported_key, fetchone_result, expected_result",
    [
        # Testcase 1: Cache hit
        (
            "ip",
            "192.168.1.1",
            (0.8, 0.9, 0.7, 1678886400),
            (0.8, 0.9, 0.7, 1678886400),
        ),
        # Testcase 2: Cache miss
        (
            "peerid",
            "some_peer_id",
            None,
            (None, None, None, None),
        ),
    ],
)
def test_get_cached_network_opinion(
    key_type,
    reported_key,
    fetchone_result,
    expected_result,
):
    trust_db = ModuleFactory().create_trust_db_obj()
    trust_db.fetchone = Mock()
    trust_db.fetchone.return_value = fetchone_result
    result = trust_db.get_cached_network_opinion(key_type, reported_key)
    assert result == expected_result


@pytest.mark.parametrize(
    "key_type, reported_key, score, confidence, "
    "network_score, expected_query, expected_params",
    [  # Test Case 1: Update IP reputation in cache
        (
            "ip",
            "192.168.1.1",
            0.8,
            0.9,
            0.7,
            "REPLACE INTO opinion_cache (key_type, reported_key, score, "
            "confidence, network_score, "
            "update_time)VALUES (?, ?, ?, ?, ?, strftime('%s','now'));",
            ("ip", "192.168.1.1", 0.8, 0.9, 0.7),
        ),
        # Test Case 2: Update Peer ID reputation in cache
        (
            "peerid",
            "some_peer_id",
            0.5,
            0.6,
            0.4,
            "REPLACE INTO opinion_cache (key_type, reported_key, score, "
            "confidence, network_score, "
            "update_time)VALUES (?, ?, ?, ?, ?, strftime('%s','now'));",
            ("peerid", "some_peer_id", 0.5, 0.6, 0.4),
        ),
    ],
)
def test_update_cached_network_opinion(
    key_type,
    reported_key,
    score,
    confidence,
    network_score,
    expected_query,
    expected_params,
):
    trust_db = ModuleFactory().create_trust_db_obj()
    trust_db.execute = Mock()
    trust_db.update_cached_network_opinion(
        key_type, reported_key, score, confidence, network_score
    )
    trust_db.execute.assert_called_once_with(expected_query, expected_params)


@pytest.mark.parametrize(
    "peerid, ip, timestamp, expected_params",
    [  # Testcase 1: Using provided timestamp
        (
            "peer_123",
            "192.168.1.20",
            1678887000,
            ("192.168.1.20", "peer_123", 1678887000),
        ),
        # Testcase 2: Using current time as timestamp
        (
            "another_peer",
            "10.0.0.5",
            datetime.datetime(2024, 7, 24, 20, 26, 35),
            (
                "10.0.0.5",
                "another_peer",
                datetime.datetime(2024, 7, 24, 20, 26, 35),
            ),
        ),
    ],
)
def test_insert_go_ip_pairing(peerid, ip, timestamp, expected_params):
    trust_db = ModuleFactory().create_trust_db_obj()
    trust_db.insert = Mock()
    trust_db.insert_go_ip_pairing(peerid, ip, timestamp)
    trust_db.insert.assert_called_once_with(
        "peer_ips", (ip, peerid, timestamp), "ipaddress, peerid, update_time"
    )


def test_insert_go_peer_address_stores_authenticated_endpoint() -> None:
    """Persist the remote IP and P2P port observed on an authenticated link."""
    module_factory = ModuleFactory()
    trust_db = module_factory.create_trust_db_obj()
    trust_db.execute = Mock()

    trust_db.insert_go_peer_address("peer-1", "192.0.2.4", 6669, 1234)

    trust_db.execute.assert_called_once_with(
        "INSERT INTO peer_addresses "
        "(peerid, ipaddress, port, update_time) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(peerid) DO UPDATE SET "
        "ipaddress = excluded.ipaddress, port = excluded.port, "
        "update_time = excluded.update_time "
        "WHERE excluded.update_time >= peer_addresses.update_time",
        ("peer-1", "192.0.2.4", 6669, 1234),
    )


@pytest.mark.parametrize(
    "method,columns,table,condition",
    [
        (
            "get_recent_peer_addresses",
            "peerid, ipaddress, port, update_time",
            "peer_addresses",
            "newer.peerid = peer_addresses.peerid",
        ),
        (
            "get_recent_peer_ips",
            "peerid, ipaddress, update_time",
            "peer_ips",
            "newer.peerid = peer_ips.peerid",
        ),
    ],
)
def test_recent_peer_mapping_queries_select_latest_per_peer(
    method: str, columns: str, table: str, condition: str
) -> None:
    """Fetch bounded latest addresses so old mappings cannot override them."""
    module_factory = ModuleFactory()
    trust_db = module_factory.create_trust_db_obj()
    trust_db.select = Mock(return_value=[("peer-1", "192.0.2.4", 1)])

    assert getattr(trust_db, method)(25) == [("peer-1", "192.0.2.4", 1)]
    trust_db.select.assert_called_once()
    assert trust_db.select.call_args.kwargs["columns"] == columns
    assert trust_db.select.call_args.args[0] == table
    assert condition in trust_db.select.call_args.kwargs["condition"]
    assert trust_db.select.call_args.kwargs["limit"] == 25


@pytest.mark.parametrize(
    "ip, score, confidence, timestamp, expected_timestamp",
    [
        # Testcase 1: Using provided timestamp
        ("192.168.1.10", 0.85, 0.95, 1678886400, 1678886400),
        # Testcase 2: Using current time as timestamp
        ("10.0.0.1", 0.6, 0.7, None, 1234),
    ],
)
def test_insert_slips_score(
    ip, score, confidence, timestamp, expected_timestamp
):
    trust_db = ModuleFactory().create_trust_db_obj()
    trust_db.execute = Mock()
    trust_db.insert_slips_score(ip, score, confidence, timestamp)
    actual_call = trust_db.execute.call_args
    actual_sql = normalize_sql(actual_call[0][0])
    expected_sql = normalize_sql(
        "INSERT INTO slips_reputation (ipaddress, score, confidence, "
        "update_time) VALUES (?, ?, ?, ?) ON CONFLICT(ipaddress) DO "
        "UPDATE SET score = excluded.score, confidence = excluded.confidence, "
        "update_time = excluded.update_time WHERE excluded.update_time >= "
        "slips_reputation.update_time"
    )
    assert actual_sql == expected_sql


def test_reputation_history_migration_keeps_latest_value(tmp_path):
    db_path = tmp_path / "trust.db"
    connection = sqlite3.connect(db_path)
    connection.execute(
        "CREATE TABLE slips_reputation (id INTEGER PRIMARY KEY NOT NULL, "
        "ipaddress TEXT NOT NULL, score REAL NOT NULL, confidence REAL NOT NULL, "
        "update_time REAL NOT NULL)"
    )
    connection.executemany(
        "INSERT INTO slips_reputation "
        "(ipaddress, score, confidence, update_time) VALUES (?, ?, ?, ?)",
        [
            ("203.0.113.1", 0.2, 0.3, 1),
            ("203.0.113.1", 0.8, 0.9, 3),
            ("203.0.113.1", 0.5, 0.6, 2),
            ("203.0.113.2", 0.4, 0.5, 4),
        ],
    )
    connection.commit()
    connection.close()

    with (
        patch(
            "slips_files.common.abstracts.isqlite.ISQLite._init_flock",
            autospec=True,
            side_effect=lambda instance, *_: setattr(
                instance,
                "sqlite_flock",
                Mock(acquire=Mock(return_value=nullcontext())),
            ),
        ),
    ):
        trust_db = TrustDB(Mock(), str(db_path), 1)

    assert trust_db.select(
        "slips_reputation",
        columns="score, confidence, update_time",
        condition="ipaddress = ?",
        params=("203.0.113.1",),
    ) == [(0.8, 0.9, 3)]
    assert trust_db.get_count("slips_reputation") == 2
    trust_db.insert_slips_score("203.0.113.1", 0.1, 0.2, 2)
    assert trust_db.get_reporter_reputation("203.0.113.1") == (0.8, 0.9)
    trust_db.insert_slips_score("203.0.113.1", 0.7, 0.8, 5)
    assert trust_db.get_reporter_reputation("203.0.113.1") == (0.7, 0.8)


@pytest.mark.parametrize(
    "older_time,newer_time",
    [(1, 2), (2, 2)],
)
def test_peer_address_migration_keeps_latest_endpoint(
    tmp_path, older_time: int, newer_time: int
) -> None:
    """Migrate duplicate legacy peers before authenticated endpoint upserts."""
    module_factory = ModuleFactory()
    db_path = tmp_path / "trust.db"
    connection = sqlite3.connect(db_path)
    connection.execute(
        "CREATE TABLE peer_addresses (id INTEGER PRIMARY KEY NOT NULL, "
        "peerid TEXT NOT NULL, ipaddress TEXT NOT NULL, "
        "port INTEGER NOT NULL, update_time REAL NOT NULL)"
    )
    connection.executemany(
        "INSERT INTO peer_addresses "
        "(peerid, ipaddress, port, update_time) VALUES (?, ?, ?, ?)",
        [
            ("peer-1", "192.0.2.1", 6668, older_time),
            ("peer-1", "192.0.2.2", 6669, newer_time),
            ("peer-2", "192.0.2.3", 6668, 3),
        ],
    )
    connection.commit()
    connection.close()

    with patch(
        "slips_files.common.abstracts.isqlite.ISQLite._init_flock",
        autospec=True,
        side_effect=lambda instance, *_: setattr(
            instance,
            "sqlite_flock",
            Mock(acquire=Mock(return_value=nullcontext())),
        ),
    ):
        trust_db = TrustDB(module_factory.logger, str(db_path), 1)

    assert trust_db.select(
        "peer_addresses",
        columns="ipaddress, port, update_time",
        condition="peerid = ?",
        params=("peer-1",),
    ) == [("192.0.2.2", 6669, newer_time)]
    assert trust_db.get_count("peer_addresses") == 2
    trust_db.insert_go_peer_address("peer-1", "192.0.2.1", 6668, 1)
    assert trust_db.select(
        "peer_addresses",
        columns="ipaddress, port, update_time",
        condition="peerid = ?",
        params=("peer-1",),
    ) == [("192.0.2.2", 6669, newer_time)]
    trust_db.insert_go_peer_address("peer-1", "192.0.2.4", 6670, 4)
    assert trust_db.select(
        "peer_addresses",
        columns="ipaddress, port, update_time",
        condition="peerid = ?",
        params=("peer-1",),
    ) == [("192.0.2.4", 6670, 4)]
    assert trust_db.get_count("peer_addresses") == 2
    assert trust_db.conn.execute("PRAGMA integrity_check").fetchone() == (
        "ok",
    )


@pytest.mark.parametrize(
    "peerid, reliability, timestamp, expected_timestamp",
    [
        # Testcase 1: Using provided timestamp
        ("peer_123", 0.92, 1678887000, 1678887000),
        # Testcase 2: Using current time as timestamp
        ("another_peer", 0.55, None, datetime.datetime.now()),
    ],
)
def test_insert_go_reliability(
    peerid, reliability, timestamp, expected_timestamp
):
    trust_db = ModuleFactory().create_trust_db_obj()
    with patch.object(
        datetime, "datetime", wraps=datetime.datetime
    ) as mock_datetime:
        mock_datetime.now.return_value = expected_timestamp
        trust_db.insert = Mock()
        trust_db.insert_go_reliability(peerid, reliability, timestamp)
        trust_db.insert.assert_called_once_with(
            "go_reliability",
            (peerid, reliability, expected_timestamp),
            "peerid, reliability, update_time",
        )


@pytest.mark.parametrize(
    "peerid, fetchone_result, expected_result",
    [
        # Testcase 1: IP found for peerid
        (
            "peer_123",
            (1678887000, "192.168.1.20"),
            (1678887000, "192.168.1.20"),
        ),
        # Testcase 2: No IP found for peerid
        ("unknown_peer", None, (False, False)),
    ],
)
def test_get_ip_of_peer(peerid, fetchone_result, expected_result):
    trust_db = ModuleFactory().create_trust_db_obj()
    trust_db.select = Mock()
    trust_db.select.return_value = fetchone_result
    result = trust_db.get_ip_of_peer(peerid)
    assert result == expected_result


def test_create_tables():
    trust_db = ModuleFactory().create_trust_db_obj()
    trust_db.create_table = Mock()
    trust_db._ensure_unique_peer_addresses = Mock()

    trust_db.create_tables()

    expected_calls = [
        (
            "slips_reputation",
            "id INTEGER PRIMARY KEY NOT NULL, ipaddress TEXT NOT NULL, score REAL NOT NULL, confidence REAL NOT NULL, update_time REAL NOT NULL",
        ),
        (
            "go_reliability",
            "id INTEGER PRIMARY KEY NOT NULL, peerid TEXT NOT NULL, reliability REAL NOT NULL, update_time REAL NOT NULL",
        ),
        (
            "peer_ips",
            "id INTEGER PRIMARY KEY NOT NULL, ipaddress TEXT NOT NULL, peerid TEXT NOT NULL, update_time REAL NOT NULL",
        ),
        (
            "peer_addresses",
            "id INTEGER PRIMARY KEY NOT NULL, peerid TEXT NOT NULL UNIQUE, ipaddress TEXT NOT NULL, port INTEGER NOT NULL, update_time REAL NOT NULL",
        ),
        (
            "reports",
            "id INTEGER PRIMARY KEY NOT NULL, reporter_peerid TEXT NOT NULL, key_type TEXT NOT NULL, reported_key TEXT NOT NULL, score REAL NOT NULL, confidence REAL NOT NULL, update_time REAL NOT NULL",
        ),
        (
            "opinion_cache",
            "key_type TEXT NOT NULL, reported_key TEXT NOT NULL PRIMARY KEY, score REAL NOT NULL, confidence REAL NOT NULL, network_score REAL NOT NULL, update_time DATE NOT NULL",
        ),
        (
            "report_aggregates",
            "key_type TEXT NOT NULL, reported_key TEXT NOT NULL, reporter_peerid TEXT NOT NULL, reporter_ip TEXT NOT NULL, report_count INTEGER NOT NULL, score_sum REAL NOT NULL, confidence_sum REAL NOT NULL, PRIMARY KEY (key_type, reported_key, reporter_peerid, reporter_ip)",
        ),
        (
            "report_compaction_state",
            "id INTEGER PRIMARY KEY CHECK (id = 1), last_report_id INTEGER NOT NULL, database_vacuumed INTEGER NOT NULL DEFAULT 0",
        ),
    ]

    for table, schema in expected_calls:
        trust_db.create_table.assert_any_call(table, schema)

    assert trust_db.create_table.call_count == len(expected_calls)


def test_create_tables_adds_indexes_for_opinion_lookups():
    trust_db = ModuleFactory().create_trust_db_obj()
    trust_db.create_table = Mock()
    trust_db.execute = Mock()
    trust_db._ensure_unique_peer_addresses = Mock()

    trust_db.create_tables()

    executed_sql = [call.args[0] for call in trust_db.execute.call_args_list]
    expected_indexes = (
        "CREATE INDEX IF NOT EXISTS reports_key_type_idx "
        "ON reports(reported_key, key_type)",
        "CREATE INDEX IF NOT EXISTS peer_ips_peer_time_idx "
        "ON peer_ips(peerid, update_time DESC)",
        "CREATE INDEX IF NOT EXISTS peer_addresses_peer_time_idx "
        "ON peer_addresses(peerid, update_time DESC)",
        "CREATE INDEX IF NOT EXISTS go_reliability_peer_idx "
        "ON go_reliability(peerid)",
        "CREATE UNIQUE INDEX IF NOT EXISTS slips_reputation_ip_idx "
        "ON slips_reputation(ipaddress)",
        "CREATE INDEX IF NOT EXISTS report_aggregates_key_idx "
        "ON report_aggregates(reported_key, key_type)",
    )

    for index in expected_indexes:
        assert index in executed_sql


def test_compact_reports_preserves_opinions_and_unmapped_raw_reports(
    tmp_path,
):
    trust_db = ModuleFactory().create_trust_db_obj()
    trust_db.conn = sqlite3.connect(tmp_path / "trust.db")
    trust_db.create_tables()
    trust_db.insert_go_ip_pairing("peer_1", "203.0.113.10", 1)
    trust_db.insert_go_reliability("peer_1", 0.8, 1)
    trust_db.insert_slips_score("203.0.113.10", 0.6, 0.9, 1)
    trust_db.insert_new_go_report(
        "peer_1", "ip", "8.8.8.8", 0.4, 0.8, 2
    )
    trust_db.insert_new_go_report(
        "peer_1", "ip", "8.8.8.8", 0.8, 0.2, 3
    )
    trust_db.insert_new_go_report(
        "peer_without_mapping", "ip", "8.8.8.8", 0.9, 0.9, 3
    )

    assert trust_db.compact_reports(batch_size=2) is False
    assert trust_db.compact_reports(batch_size=2) is False
    assert trust_db.compact_reports(batch_size=2) is True

    aggregates = trust_db.select(
        "report_aggregates",
        columns=(
            "reporter_peerid, reporter_ip, report_count, score_sum, "
            "confidence_sum"
        ),
        condition="reported_key = ?",
        params=("8.8.8.8",),
    )
    remaining_reports = trust_db.get_reports_for_ip("8.8.8.8")
    opinion = trust_db.get_opinion_on_ip("8.8.8.8")

    assert aggregates[0][:3] == ("peer_1", "203.0.113.10", 2)
    assert aggregates[0][3:] == pytest.approx((1.2, 1.0))
    assert len(remaining_reports) == 1
    assert remaining_reports[0][0] == "peer_without_mapping"
    assert len(opinion) == 1
    assert opinion[0][0:2] == pytest.approx((1.2, 1.0))
    assert opinion[0][-1] == 2


def test_new_lookup_ignores_compacted_history_and_keeps_fresh_replies(
    tmp_path,
) -> None:
    """Only newly received reports contribute to the current lookup."""
    trust_db = ModuleFactory().create_trust_db_obj()
    trust_db.conn = sqlite3.connect(tmp_path / "fresh-reports.db")
    trust_db.create_tables()
    now = time.time()
    trust_db.insert_go_ip_pairing("old-peer", "192.0.2.10", now - 100)
    trust_db.insert_go_ip_pairing("new-peer", "192.0.2.20", now - 100)
    for peer_id, peer_ip in (
        ("old-peer", "192.0.2.10"),
        ("new-peer", "192.0.2.20"),
    ):
        trust_db.insert_go_reliability(peer_id, 0.8, now - 100)
        trust_db.insert_slips_score(peer_ip, 0.6, 0.9, now - 100)
    trust_db.insert_new_go_report(
        "old-peer", "ip", "8.8.8.8", 0.9, 0.9, now - 90
    )
    trust_db.compact_reports()
    after_id = trust_db.get_latest_report_id()
    trust_db.insert_new_go_report(
        "new-peer", "ip", "8.8.8.8", 0.2, 0.8, now
    )

    assert trust_db.get_latest_report_id() > after_id
    assert trust_db.get_reporter_peerids_for_ip("8.8.8.8", after_id) == {
        "new-peer"
    }
    assert len(trust_db.get_reports_for_ip("8.8.8.8", after_id)) == 1
    opinion = trust_db.get_opinion_on_ip("8.8.8.8", after_id)
    assert len(opinion) == 1
    assert opinion[0][0] == pytest.approx(0.2)
    trust_db.compact_reports()
    assert len(trust_db.get_reports_for_ip("8.8.8.8", after_id)) == 1


@pytest.mark.parametrize(
    "reporter_peerid, key_type, reported_key, score, confidence, "
    "timestamp, expected_query, expected_params",
    [
        (
            "peer_123",
            "ip",
            "192.168.1.1",
            0.8,
            0.9,
            1678887000,
            "INSERT INTO reports (reporter_peerid, key_type, reported_key, "
            "score, confidence, update_time) VALUES (?, ?, ?, ?, ?, ?)",
            ("peer_123", "ip", "192.168.1.1", 0.8, 0.9, 1678887000),
        ),
        (
            "another_peer",
            "peerid",
            "target_peer",
            0.6,
            0.7,
            None,
            "INSERT INTO reports (reporter_peerid, key_type, reported_key, "
            "score, confidence, update_time) VALUES (?, ?, ?, ?, ?, ?)",
            ("another_peer", "peerid", "target_peer", 0.6, 0.7, 1678887000.0),
        ),
    ],
)
def test_insert_new_go_report(
    reporter_peerid,
    key_type,
    reported_key,
    score,
    confidence,
    timestamp,
    expected_query,
    expected_params,
):
    trust_db = ModuleFactory().create_trust_db_obj()
    trust_db.execute = Mock()

    if timestamp is None:
        with patch("time.time", return_value=1678887000.0):
            trust_db.insert_new_go_report(
                reporter_peerid,
                key_type,
                reported_key,
                score,
                confidence,
                timestamp,
            )
    else:
        trust_db.insert_new_go_report(
            reporter_peerid,
            key_type,
            reported_key,
            score,
            confidence,
            timestamp,
        )

    trust_db.execute.assert_called_once()
    query, params = trust_db.execute.call_args.args
    assert query.startswith("INSERT INTO reports (id, reporter_peerid")
    assert params == expected_params


@pytest.mark.parametrize(
    "ipaddress, expected_reports",
    [
        ("192.168.1.1", []),
        (
            "192.168.1.1",
            [
                (
                    "reporter_1",
                    1678886400,
                    0.5,
                    0.8,
                    "192.168.1.1",
                )
            ],
        ),
        (
            "192.168.1.1",
            [
                (
                    "reporter_1",
                    1678886400,
                    0.5,
                    0.8,
                    "192.168.1.1",
                ),
                (
                    "reporter_2",
                    1678886500,
                    0.3,
                    0.6,
                    "192.168.1.1",
                ),
            ],
        ),
    ],
)
def test_get_reports_for_ip(ipaddress, expected_reports):
    trust_db = ModuleFactory().create_trust_db_obj()
    trust_db.select = Mock(return_value=expected_reports)

    result = trust_db.get_reports_for_ip(ipaddress)

    trust_db.select.assert_called_once_with(
        table_name="reports",
        columns="reporter_peerid, update_time, score, confidence, reported_key",
        condition="reported_key = ? AND key_type = ?",
        params=(ipaddress, "ip"),
    )

    assert result == expected_reports


@pytest.mark.parametrize(
    "reporter_peerid, expected_reliability",
    [
        ("reporter_1", 0.7),
        ("unknown_reporter", None),
    ],
)
def test_get_reporter_reliability(reporter_peerid, expected_reliability):
    trust_db = ModuleFactory().create_trust_db_obj()
    trust_db.select = Mock()

    if expected_reliability is not None:
        trust_db.select.return_value = (expected_reliability,)
    else:
        trust_db.select.return_value = []

    reliability = trust_db.get_reporter_reliability(reporter_peerid)
    assert reliability == expected_reliability


@pytest.mark.parametrize(
    "reporter_ipaddress, expected_score, expected_confidence",
    [
        ("192.168.1.2", 0.6, 0.9),
        ("unknown_ip", None, None),
    ],
)
def test_get_reporter_reputation(
    reporter_ipaddress, expected_score, expected_confidence
):
    trust_db = ModuleFactory().create_trust_db_obj()

    with patch.object(trust_db, "select") as mock_select:
        if expected_score is not None:
            mock_select.return_value = (expected_score, expected_confidence)
        else:
            mock_select.return_value = None

        score, confidence = trust_db.get_reporter_reputation(
            reporter_ipaddress
        )
        assert score == expected_score
        assert confidence == expected_confidence


@pytest.mark.parametrize(
    "reporter_peerid, report_timestamp, fetchone_result, expected_ip",
    [
        # Testcase 1: IP found for reporter at report time
        ("reporter_1", 1678886450, (1678886400, "192.168.1.2"), "192.168.1.2"),
        # Testcase 2: No IP found for reporter at report time
        ("reporter_2", 1678886550, None, None),
    ],
)
def test_get_reporter_ip(
    reporter_peerid, report_timestamp, fetchone_result, expected_ip
):
    trust_db = ModuleFactory().create_trust_db_obj()
    trust_db.fetchone = Mock()
    trust_db.fetchone.return_value = fetchone_result
    ip = trust_db.get_reporter_ip(reporter_peerid, report_timestamp)
    assert ip == expected_ip


@pytest.mark.parametrize(
    "ipaddress, reports, expected_result",
    [
        # Testcase 1: No reports for the IP
        ("192.168.1.1", [], []),
        # Testcase 2: One report with valid reporter data, but
        # reporter_ipaddress == ipaddress:
        (
            "192.168.1.1",
            # peerid, ts, score, conf, reported_ip
            [("reporter_1", 1678886400, 0.5, 0.8, "192.168.1.1")],
            [],
        ),
        # Testcase 3: Multiple reports with valid reporter data
        (
            "192.168.1.7",
            [
                # these 2 ips shouldnt be the same as the reports ips
                ("reporter_1", 1678886400, 0.5, 0.8, "192.168.1.3"),
                ("reporter_2", 1678886500, 0.3, 0.6, "192.168.1.4"),
            ],
            [
                (0.5, 0.8, 0.7, 0.6, 0.9, "192.168.1.1", 1),
                (0.3, 0.6, 0.8, 0.4, 0.7, "192.168.1.2", 1),
            ],
        ),
    ],
)
def test_get_opinion_on_ip(ipaddress, reports, expected_result):
    trust_db = ModuleFactory().create_trust_db_obj()

    trust_db.select = MagicMock(return_value=[])
    trust_db.get_reports_for_ip = MagicMock(return_value=reports)
    trust_db.get_reporter_ip = MagicMock(
        side_effect=["192.168.1.1", "192.168.1.2"]
    )
    trust_db.get_reporter_reliability = MagicMock(side_effect=[0.7, 0.8, 0.7])
    trust_db.get_reporter_reputation = MagicMock(
        side_effect=[(0.6, 0.9), (0.4, 0.7), (0.6, 0.9)]
    )

    result = trust_db.get_opinion_on_ip(ipaddress)
    assert result == expected_result
