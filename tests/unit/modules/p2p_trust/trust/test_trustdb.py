# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
from unittest.mock import (
    patch,
    call,
    MagicMock,
    Mock,
)
from tests.module_factory import ModuleFactory
import datetime


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
                "reports",
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
        call("DROP TABLE IF EXISTS reports;"),
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
        "INSERT OR REPLACE INTO slips_reputation (ipaddress, score, "
        "confidence, update_time) VALUES (?, ?, ?, ?)"
    )
    assert actual_sql == expected_sql


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
            "reports",
            "id INTEGER PRIMARY KEY NOT NULL, reporter_peerid TEXT NOT NULL, key_type TEXT NOT NULL, reported_key TEXT NOT NULL, score REAL NOT NULL, confidence REAL NOT NULL, update_time REAL NOT NULL",
        ),
        (
            "opinion_cache",
            "key_type TEXT NOT NULL, reported_key TEXT NOT NULL PRIMARY KEY, score REAL NOT NULL, confidence REAL NOT NULL, network_score REAL NOT NULL, update_time DATE NOT NULL",
        ),
    ]

    for table, schema in expected_calls:
        trust_db.create_table.assert_any_call(table, schema)

    assert trust_db.create_table.call_count == len(expected_calls)


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
    trust_db.insert = Mock()

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

    trust_db.insert.assert_called_once_with(
        "reports",
        expected_params,
        "reporter_peerid, key_type, reported_key, score, confidence, update_time",
    )


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
                (0.5, 0.8, 0.7, 0.6, 0.9, "192.168.1.1"),
                (0.3, 0.6, 0.8, 0.4, 0.7, "192.168.1.2"),
            ],
        ),
    ],
)
def test_get_opinion_on_ip(ipaddress, reports, expected_result):
    trust_db = ModuleFactory().create_trust_db_obj()

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
