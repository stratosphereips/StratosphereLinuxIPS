from collections import Counter
import argparse
from http import HTTPStatus
from http.cookies import SimpleCookie
from io import BytesIO
import json
import re
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.request import Request, urlopen
from unittest.mock import Mock, patch

import pytest
import yaml
import psutil
from pytest_mock import MockerFixture

from modules.web_interface.history import connect_history, initialize_history
from modules.supported_module_names import Modules
from modules.web_interface.server import (
    RequestHandler,
    RunDataReader,
    RunMismatchError,
    SlipsHTTPServer,
    ipv4_address,
)
from slips_files.common.web_auth import SESSION_COOKIE_NAME, issue_token
from slips_files.common import web_auth
from slips_files.common.slips_utils import utils
from slips_files.common.mac import classify_mac
from slips_files.common.sqlite_flock import SQLiteFlock
from slips_files.core.database.sqlite_db.host_profiles import HostProfileStore
from tests.module_factory import ModuleFactory
from slips_files.core.database.sqlite_db.database import SQLiteDB
from slips_files.core.database.sqlite_db.detection_history import (
    DetectionHistory,
)


@pytest.mark.parametrize("main_pid", [12345, "12345", None])
def test_review_writer_lock_matches_capture_namespace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, main_pid: int | str | None
) -> None:
    """Serialize live reviews with capture while allowing completed runs.

    Parameters:
        tmp_path: Isolated lock storage.
        monkeypatch: Scope file locks to the test.
        main_pid: Redis owner of the active run, if any.
    """
    _factory = ModuleFactory()
    monkeypatch.setattr("slips_files.common.sqlite_flock.SLIPS_LOCKS_DIR", str(tmp_path))
    reader = object.__new__(RunDataReader)
    reader.redis = Mock()
    reader.redis.hget.return_value = main_pid
    probe = SQLiteFlock("sqlite_db", 12345)
    with reader._writer_lock():
        with probe.try_acquire() as acquired:
            assert acquired is (main_pid is None)
    with probe.try_acquire() as acquired:
        assert acquired is True


@pytest.mark.parametrize("group", ["type", "host", "host_type"])
@pytest.mark.parametrize("device", [False, True])
@pytest.mark.parametrize("hide_excluded", [False, True])
@pytest.mark.parametrize("threat", ["", "low_or_more", "info"])
def test_hourly_detection_pages_match_direct_queries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    group: str,
    device: bool,
    hide_excluded: bool,
    threat: str,
) -> None:
    """Keep summaries equivalent to raw queries, including nullable legacy fields.

    Parameters:
        tmp_path: Isolated run database.
        monkeypatch: Fix the live clock.
        group: Requested evidence grouping.
        device: Combine verified address aliases.
        hide_excluded: Omit excluded evidence.
        threat: Exact or minimum severity filter.
    """
    factory = ModuleFactory()
    db = SQLiteDB(factory.logger, str(tmp_path), 12345)
    monkeypatch.setattr(
        "modules.web_interface.server.time.time", lambda: 20000.0
    )
    records = [
        ("edge-first", 1200, "192.0.2.1", "SCAN", "low", 0.2, 0),
        ("inside", 3700, "fe80::1", "SCAN", "medium", 0.8, 0),
        ("excluded", 3800, "192.0.2.1", "SCAN", "critical", 5, 1),
        ("dns", 7400, "192.0.2.2", "DNS", "low", 1, 0),
        ("nullable", 7500, None, None, None, None, 0),
        ("edge-last", 18100, "192.0.2.1", "SCAN", "high", 4, 0),
        ("outside", 19100, "192.0.2.1", "SCAN", "critical", 9, 0),
    ]
    for record in records:
        db.execute(
            "INSERT INTO evidence(evidence_id,evidence_time,profile_ip,evidence_type,threat_level,"
            "accumulated_ratl,whitelisted) VALUES (?,?,?,?,?,?,?)",
            record,
        )
        db.execute(
            "INSERT INTO alert_evidence VALUES ('alert',?)", (record[0],)
        )
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.sqlite_path = Path(db.get_db_path())
    reader.history_path = tmp_path / "history.sqlite"
    reader.host_profiles_path = tmp_path / "hosts.sqlite"
    initialize_history(reader.history_path)
    reader.redis = Mock()
    reader.redis.hget.return_value = "interface"
    reader.redis.hgetall.side_effect = lambda key: (
        {"input_type": "interface"} if key == "analysis" else {}
    )
    reader._device_key_map = Mock(
        return_value={"192.0.2.1": "device-1", "fe80::1": "device-1"}
    )
    query = {
        "range": ["custom"],
        "from": ["1000"],
        "to": ["19000"],
        "group": [group],
        "compact": ["1"],
        "device": ["1" if device else "0"],
        "hide_excluded": ["1" if hide_excluded else "0"],
        "threat": [threat],
    }
    expected = reader.evidence(query)
    maintenance = DetectionHistory(db.conn, str(tmp_path))
    for _ in range(100):
        if not maintenance.summary_step(2):
            break
    result = reader.evidence(query)
    assert result == expected
    db.close()


@pytest.mark.parametrize("extra_segments", [0, 12])
def test_archive_context_resolves_other_segments_and_active_evidence(
    tmp_path: Path,
    extra_segments: int,
) -> None:
    """Keep an archived alert's links readable across rotated segments.

    Parameters:
        tmp_path: Isolated run directory.
        extra_segments: Unrelated files exceeding SQLite's attachment limit.
    """
    factory = ModuleFactory()
    db = SQLiteDB(factory.logger, str(tmp_path), 12345)
    db.execute(
        "INSERT INTO evidence(evidence_id,evidence_time) VALUES ('old',1),('recent',1000)"
    )
    db.execute("INSERT INTO alerts(alert_id,alert_time) VALUES ('alert',2)")
    db.execute(
        "INSERT INTO alert_evidence VALUES ('alert','old'),('alert','recent')"
    )
    maintenance = DetectionHistory(db.conn, str(tmp_path))
    for _ in range(5):
        maintenance.archive_step("evidence", 100, 10, 1700000000)
    for _ in range(5):
        maintenance.archive_step("alerts", 100, 10, 1703000000)
    for index in range(extra_segments):
        archive = maintenance._open_archive(
            f"detections-2023-12-{index+10:04d}.sqlite"
        )
        archive.close()
    db.execute("INSERT INTO altflows(uid,flow) VALUES ('retained-uid','{}')")
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.sqlite_path = Path(db.get_db_path())
    reader.host_profiles_path = tmp_path / "hosts.sqlite"
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {}
    files = reader.archives()["items"]
    assert len(files) == 2
    assert {(item["start_time"], item["end_time"]) for item in files} == {(1.0, 1.0), (2.0, 2.0)}
    assert all("1970-01-01" in item["label"] for item in files)
    archived = reader.with_archive(files[0]["id"], context=True)
    with archived._connect_sqlite() as connection:
        items = archived._alert_evidence(connection, {"alert_id": "alert"})
    assert {item["id"] for item in items} == {"old", "recent"}
    assert reader.sqlite_path == Path(db.get_db_path())
    with pytest.raises(KeyError):
        reader.with_archive("../flows.sqlite")
    with pytest.raises(ValueError, match="read-only"):
        archived.save_review("alert", {"id": "alert", "action": "review"})
    assert (
        len(archived.flow_details("retained-uid", {})["protocol_flows"]) == 1
    )
    db.close()


@pytest.mark.parametrize("proto", ["icmp", "icmp6"])
def test_saved_icmp_evidence_is_corrected_without_rewriting_history(tmp_path: Path, proto: str) -> None:
    """Correct both Redis and SQLite evidence while preserving the saved record.

    Parameters:
        tmp_path: Isolated detection database.
        proto: Legacy protocol name.
    """
    factory = ModuleFactory()
    db = SQLiteDB(factory.logger, str(tmp_path), 12345)
    description = f"A connection from a private IP (10.0.2.2) on port 0/{proto} outside of the used local network 192.168.0.0/16"
    saved = {"id": "legacy-icmp", "evidence_type": "DIFFERENT_LOCALNET", "proto": proto,
             "src_port": 11, "dst_port": 0, "description": description}
    db.execute("INSERT INTO evidence(evidence_id,evidence_time,description,data) VALUES (?,?,?,?)",
               ("legacy-icmp", 100, description, json.dumps(saved)))
    db.conn.row_factory = sqlite3.Row
    reader = object.__new__(RunDataReader)
    row = db.conn.execute("SELECT * FROM evidence").fetchone()
    durable = reader._durable_evidence_row(db.conn, row)
    reader.redis = Mock()
    reader.redis.scan_iter.side_effect = [[], ["profile_10.0.2.2_timewindow1_evidence"]]
    reader.redis.hgetall.return_value = {"legacy-icmp": json.dumps(saved)}
    compatibility = reader._redis_evidence()[0]
    for result in (durable, compatibility):
        assert "on port" not in result["description"]
        assert "using ICMP" in result["description"]
        assert result["icmp_type"] == 11 and result["icmp_code"] == 0
        assert result["src_port"] is None and result["dst_port"] is None
    assert db.conn.execute("SELECT description FROM evidence").fetchone()[0] == description
    assert saved["src_port"] == 11
    db.close()


@pytest.mark.parametrize("device", [False, True])
@pytest.mark.parametrize(
    "range_name,network,hide_excluded,recent,expected_peak,expected_threat,expected_count",
    [
        ("live", False, True, False, None, "", 0),
        ("live", False, True, True, 0.1, "low", 1),
        ("all", False, True, False, 0.49, "medium", 1),
        ("all", True, True, False, None, "", 0),
        ("24h", False, False, False, 8.0, "critical", 2),
    ],
)
def test_host_inventory_findings_match_opened_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, device: bool,
    range_name: str, network: bool, hide_excluded: bool, recent: bool,
    expected_peak: float | None, expected_threat: str, expected_count: int,
) -> None:
    """A displayed peak and threat must have evidence in the same selected scope.

    Parameters:
        tmp_path: Isolated run databases.
        monkeypatch: Fix the active capture clock.
        device: Whether the inventory and details combine MAC-matched IPs.
        range_name: Selected inventory time range.
        network: Restrict findings to the current connection.
        hide_excluded: Omit whitelist-excluded findings.
        recent: Include a recent low-severity finding.
        expected_peak: Highest visible score, or no scored evidence.
        expected_threat: Highest visible severity, or no evidence.
        expected_count: Number of matching evidence records.
    """
    _module_factory = ModuleFactory()
    now = 2_000_000_000.0
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: now)
    reader = _network_scope_reader(tmp_path)
    ip = "192.168.1.249"
    alias = "fe80::249"
    with connect_history(reader.history_path) as connection:
        for address in (ip, alias):
            connection.execute("INSERT INTO host_snapshots VALUES (?, ?, ?)", (address, now,
                json.dumps({"ip": address, "scope": "local", "mac": "d8:3a:dd:bb:1d:6c"})))
            connection.execute("INSERT INTO flow_index(uid, flow_rowid, event_time, src_ip, dst_ip, bytes, packets) "
                "VALUES (?,1,?,?, '8.8.8.8',1,1)", (address, now-10, address))
    rows = [("old-medium", now-7200, ip, "medium", .49, 0),
            ("excluded-critical", now-20, ip, "critical", 8.0, 1)]
    if recent:
        rows.append(("recent-low", now-60, alias if device else ip, "low", .1, 0))
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executemany("INSERT INTO evidence(evidence_id,evidence_time,profile_ip,threat_level,accumulated_ratl,whitelisted) "
            "VALUES (?,?,?,?,?,?)", rows)
    query = {"range": [range_name], "hide_excluded": ["1" if hide_excluded else "0"],
             **({"network": ["current"]} if network else {}), **({"device": ["1"]} if device else {})}
    inventory = reader.hosts(query)
    row = next(item for item in inventory["items"] if ip in item.get("device_ips", [item["ip"]]))
    assert row["peak_alert_score"] == expected_peak
    assert row["max_threat_level"] == expected_threat
    assert row["evidence_count"] == expected_count
    detail = reader.host(ip, query)
    evidence = reader.evidence_for_host(ip, query)
    assert detail["evidence_count"] == evidence["total"] == expected_count
    assert detail["alert_count"] == 0
    assert detail["peak_alert_score"] == expected_peak
    assert detail["max_threat_level"] == expected_threat
    if expected_count:
        assert max(item["alert_score"] for item in evidence["items"]) == expected_peak


@pytest.mark.parametrize("device", [False, True])
def test_host_inventory_uses_activity_clock_for_offline_findings(
    tmp_path: Path, device: bool,
) -> None:
    """Offline inventory findings use the same capture clock as their activity API.

    Parameters:
        tmp_path: Isolated run databases.
        device: Whether MAC-matched addresses are combined.
    """
    _module_factory = ModuleFactory()
    reader = _network_scope_reader(tmp_path)
    previous_hget = reader.redis.hget.side_effect
    reader.redis.hget.side_effect = lambda key, field: (
        "pcap" if (key, field) == ("analysis", "input_type") else previous_hget(key, field)
    )
    ip = "192.168.1.20"
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("DELETE FROM evidence")
        connection.execute("DELETE FROM alerts")
        connection.execute("INSERT INTO evidence(evidence_id,evidence_time,profile_ip,threat_level,accumulated_ratl) "
            "VALUES ('offline',1999992800,?,'medium',0.49)", (ip,))
        connection.execute("INSERT INTO alerts VALUES ('offline-alert',?,1999992800,'malicious',5)", (ip,))
    query = {"range": ["live"], "hide_excluded": ["1"], "device": ["1" if device else "0"]}
    row = next(item for item in reader.hosts(query)["items"] if ip in item.get("device_ips", [item["ip"]]))
    detail = reader.host(ip, query)
    assert row["evidence_count"] == detail["evidence_count"] == reader.evidence_for_host(ip, query)["total"] == 1
    assert row["alert_count"] == detail["alert_count"] == 1
    assert row["peak_alert_score"] == detail["peak_alert_score"] == 0.49
    assert row["max_threat_level"] == detail["max_threat_level"] == "medium"


@pytest.mark.parametrize("device", [False, True])
@pytest.mark.parametrize("mac,kind", [("A2:D7:7B:FA:6A:55", "locally_administered"),
    ("d8:58:d7:0:67:11", "universally_administered")])
def test_mac_classification_in_inventory_and_details(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, device: bool, mac: str, kind: str) -> None:
    """Derive the same classification for old snapshots, devices and host details.

    Parameters:
        tmp_path: Isolated run data.
        monkeypatch: Set the clock to the fixture's capture time.
        device: Whether inventory combines addresses by device.
        mac: Retained MAC notation, including operating-system shorthand.
        kind: Classification expected from its IEEE bits.
    """
    _module_factory = ModuleFactory()
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: 2_000_000_000.0)
    reader = _network_scope_reader(tmp_path)
    ip = "192.168.1.20"
    with connect_history(reader.history_path) as connection:
        connection.execute("UPDATE host_snapshots SET data=? WHERE ip=?",
            (json.dumps({"ip": ip, "mac": mac, "scope": "local"}), ip))
    query = {"range": ["all"], "search": [kind.replace("_", " ")], **({"device": ["1"]} if device else {})}
    page = reader.hosts(query)
    assert page["items"]
    assert all(item["mac_address_type"] == kind for item in page["items"])
    item = next(item for item in page["items"] if item["ip"] == ip)
    assert item["mac_address_type"] == classify_mac(mac)
    detail = reader.host(ip)
    assert detail["mac_address_type"] == kind
    assert detail["mac"] == mac


@pytest.mark.parametrize("device", [False, True])
def test_host_names_inventory_and_details_reject_ambiguous_mdns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, device: bool
) -> None:
    """All host name surfaces retain the manual iPad name without naming the router.

    Parameters:
        tmp_path: Isolated run databases.
        monkeypatch: Fixes the current connection clock.
        device: Whether the inventory groups device addresses.
    """
    _module_factory = ModuleFactory()
    now = 2_000_000_000.0
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: now)
    reader = _network_scope_reader(tmp_path)
    reader.redis.pipeline.return_value.execute.return_value = [None] * 6
    network = {
        "gateway_mac": "aa:bb:cc:dd:ee:01",
        "local_network": "192.168.1.0/24",
    }
    store = HostProfileStore(
        reader.host_profiles_path, "current", lambda _: network, ["en0"]
    )
    with connect_history(reader.history_path) as connection:
        for ip in ("192.168.1.1", "192.168.1.112"):
            connection.execute(
                "INSERT INTO host_snapshots VALUES (?, ?, ?)",
                (ip, now, json.dumps({"ip": ip, "scope": "local"})),
            )
            store.observe_flow(
                SimpleNamespace(
                    type_="conn",
                    interface="en0",
                    starttime=now - 60,
                    saddr=ip,
                    daddr="8.8.8.8",
                )
            )
    with sqlite3.connect(reader.host_profiles_path) as connection:
        for ip in ("192.168.1.1", "192.168.1.112"):
            connection.execute(
                "INSERT INTO facts VALUES (?,?,'mdns_name','storm.local',100,100,1)",
                ("gateway:aa:bb:cc:dd:ee:01", ip),
            )
    HostProfileStore.set_host_annotation(
        reader.host_profiles_path,
        "192.168.1.112",
        "gateway:aa:bb:cc:dd:ee:01",
        "iPad-Storm",
        "Tablet",
    )
    with sqlite3.connect(reader.host_profiles_path) as connection:
        connection.execute(
            "INSERT INTO hosts VALUES ('run:past-network','192.168.1.112','Unknown network',?,?)",
            (now, now + 1),
        )
    names = reader.host_names(
        {"ip": ["192.168.1.1", "192.168.1.112"], "network": ["current"]}
    )["names"]
    assert names["192.168.1.1"]["name"] == ""
    assert names["192.168.1.112"] == {
        "name": "iPad-Storm",
        "source": "User name",
    }
    query = {
        "network": ["current"],
        "range": ["all"],
        "device": ["1" if device else "0"],
    }
    rows = {row["ip"]: row for row in reader.hosts(query)["items"]}
    assert rows["192.168.1.1"]["user_name"] == ""
    assert rows["192.168.1.112"]["user_name"] == "iPad-Storm"
    assert reader.host("192.168.1.1", query)["user_name"] == ""
    assert reader.host("192.168.1.112", query)["user_name"] == "iPad-Storm"


def _network_scope_reader(tmp_path: Path) -> RunDataReader:
    """Build independent run data with fresh cache timestamps and older network activity.

    Parameters:
        tmp_path: Isolated databases.

    Returns:
        Reader connected only to test data and a mocked current network.
    """
    now = 2_000_000_000.0
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = Path("output/network-test")
    reader.history_path = tmp_path / "history.sqlite"
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.host_profiles_path = tmp_path / "hosts.sqlite"
    reader.score_mode = "ratl"
    reader.alert_threshold = 5.0
    reader.redis = Mock()
    state = {
        "interface": "en0",
        "connected": True,
        "changed_at": now - 600,
        "gateway_mac": "aa:bb:cc:dd:ee:01",
        "local_network": "192.168.1.0/24",
    }
    reader.redis.hgetall.side_effect = lambda key: (
        {"input_type": "interface", "interface": "en0"}
        if key == "analysis"
        else {"en0": json.dumps(state)} if key == "network_states" else {}
    )
    reader.redis.hget.side_effect = lambda key, field: (
        json.dumps(state)
        if key == "network_states"
        else (
            "interface"
            if (key, field) == ("analysis", "input_type")
            else "123" if (key, field) == ("PIDs", "main") else None
        )
    )
    reader._attach_current_host_scores = Mock()
    reader._ip_context_for_ip = Mock(return_value={})
    reader._ti_for_ip = Mock(return_value={})
    initialize_history(reader.history_path)
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "CREATE TABLE flows(uid TEXT PRIMARY KEY, flow TEXT, label TEXT);"
            "CREATE TABLE altflows(uid TEXT PRIMARY KEY, flow TEXT);"
            "CREATE TABLE alerts(alert_id TEXT PRIMARY KEY, ip_alerted TEXT, alert_time REAL, label TEXT, accumulated_ratl REAL);"
            "CREATE TABLE evidence(evidence_id TEXT PRIMARY KEY, evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, source_module TEXT, description TEXT, confidence REAL, "
            "data TEXT, accumulated_ratl REAL, whitelisted INTEGER DEFAULT 0);"
            "CREATE TABLE evidence_flows(evidence_id TEXT, uid TEXT);"
            "CREATE TABLE alert_evidence(alert_id TEXT, evidence_id TEXT);"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, 'timewindow1','low','ARP_SCAN','arp','scan',0.8,'{}',1,0)",
            [
                ("old", now - 1200, "192.168.12.1"),
                ("new", now - 100, "192.168.1.22"),
            ],
        )
        connection.execute(
            "INSERT INTO alerts VALUES ('new-alert','192.168.1.22',?,'malicious',5)",
            (now - 100,),
        )
        connection.execute(
            "INSERT INTO alert_evidence VALUES ('new-alert','new')"
        )
    addresses = [
        "192.168.12.1",
        "192.168.55.1",
        "192.168.1.20",
        "fe80::20",
        "192.168.1.21",
        "192.168.13.1",
        "192.168.1.22",
        "192.168.1.25",
    ]
    flows = [
        ("old-unknown", now - 1200, "192.168.12.1", "8.8.8.8", 100),
        ("old-internal", now - 1200, "192.168.1.20", "fe80::20", 100),
        ("current-v4", now - 60, "192.168.1.20", "8.8.8.8", 20),
        ("current-v6", now - 90, "fe80::20", "8.8.8.8", 40),
        ("current-outside", now - 50, "192.168.13.1", "8.8.8.8", 30),
    ]
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO host_snapshots VALUES (?, ?, ?)",
            [
                (
                    ip,
                    now,
                    json.dumps(
                        {
                            "ip": ip,
                            "scope": "local",
                            "mac": (
                                "02:00:00:00:00:20"
                                if ip
                                in {"192.168.12.1", "192.168.1.20", "fe80::20"}
                                else ""
                            ),
                        }
                    ),
                )
                for ip in addresses
            ],
        )
        connection.executemany(
            "INSERT INTO flow_index(uid,flow_rowid,event_time,src_ip,dst_ip,proto,bytes,packets) "
            "VALUES (?,1,?,?,?,'udp',?,1)",
            flows,
        )
    store = HostProfileStore(
        reader.host_profiles_path,
        "output/network-test:123",
        lambda _: state,
        ["en0"],
    )
    HostProfileStore.set_network_name(
        reader.host_profiles_path, "gateway:aa:bb:cc:dd:ee:01", "Home-Wifi6"
    )
    store.observe_flow(
        SimpleNamespace(
            interface="en0",
            starttime=now - 1200,
            type_="arp",
            saddr="192.168.1.25",
            daddr="192.168.1.1",
        )
    )
    store.observe_hostname("metadata-refresh", "profile_192.168.1.25")
    store.observe_hostname("metadata-only", "profile_192.168.55.1")
    store.observe_flow(
        SimpleNamespace(
            interface="en0",
            starttime=now - 120,
            type_="arp",
            saddr="192.168.1.21",
            daddr="192.168.1.1",
        )
    )
    return reader


@pytest.mark.parametrize("device", [False, True])
@pytest.mark.parametrize("range_name", ["all", "live", "7d", "custom"])
def test_current_network_hosts_ignore_refreshed_historical_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    device: bool,
    range_name: str,
) -> None:
    """Fresh Redis snapshots and metadata enrichment cannot revive a past-network host.

    Parameters:
        tmp_path: Isolated run databases.
        monkeypatch: Fixes the live capture clock.
        device: Whether verified MAC grouping is enabled.
        range_name: A time filter that overlaps older network activity.
    """
    _module_factory = ModuleFactory()
    monkeypatch.setattr(
        "modules.web_interface.server.time.time", lambda: 2_000_000_000.0
    )
    reader = _network_scope_reader(tmp_path)
    query = {
        "network": ["current"],
        "range": [range_name],
        "device": ["1" if device else "0"],
        "limit": ["2"],
        "from": ["1999998200"],
        "to": ["2000000000"],
    }
    rows = []
    while True:
        page = reader.hosts(query)
        rows.extend(page["items"])
        if not page["next_cursor"]:
            break
        query["cursor"] = [page["next_cursor"]]
    ips = {ip for row in rows for ip in row.get("device_ips", [row["ip"]])}
    assert ips == {
        "192.168.1.20",
        "fe80::20",
        "192.168.1.21",
        "192.168.13.1",
        "192.168.1.22",
    }
    assert page["total"] == (4 if device else 5)
    if device:
        combined = next(row for row in rows if row["ip"] == "192.168.1.20")
        assert combined["load"]["flows"] == 2
        assert combined["load"]["bytes"] == 60
    all_networks = reader.hosts({"range": ["all"]})
    assert "192.168.12.1" in {row["ip"] for row in all_networks["items"]}
    assert (
        reader.live_counts(
            {"network": ["current"], "device": ["1" if device else "0"]}
        )["hosts"]
        == page["total"]
    )


@pytest.mark.parametrize("sort", ["flows", "bytes"])
@pytest.mark.parametrize("device", [False, True])
def test_current_network_traffic_sort_uses_displayed_totals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sort: str, device: bool
) -> None:
    """Sort current observations without allowing older traffic to affect paging.

    Parameters:
        tmp_path: Isolated run databases.
        monkeypatch: Fixes the live capture clock.
        sort: Traffic column being sorted.
        device: Whether MAC grouping is selected.
    """
    _module_factory = ModuleFactory()
    monkeypatch.setattr(
        "modules.web_interface.server.time.time", lambda: 2_000_000_000.0
    )
    reader = _network_scope_reader(tmp_path)
    page = reader.hosts(
        {
            "network": ["current"],
            "range": ["all"],
            "sort": [sort],
            "device": ["1" if device else "0"],
            "order": ["desc"],
            "limit": ["2"],
        }
    )

    assert [row["ip"] for row in page["items"]] == (
        ["192.168.1.20", "192.168.13.1"]
        if device
        else ["fe80::20", "192.168.13.1"]
    )
    assert [row["load"][sort] for row in page["items"]] == (
        [2, 1]
        if sort == "flows" and device
        else [1, 1] if sort == "flows" else [60, 30] if device else [40, 30]
    )


@pytest.mark.parametrize("device", [False, True])
def test_current_network_alerts_only_excludes_resolved_alerts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, device: bool
) -> None:
    """Keep the alerts-only filter consistent with the displayed open-alert count.

    Parameters:
        tmp_path: Isolated run databases.
        monkeypatch: Fixes the live capture clock.
        device: Whether MAC grouping is selected.
    """
    _module_factory = ModuleFactory()
    monkeypatch.setattr(
        "modules.web_interface.server.time.time", lambda: 2_000_000_000.0
    )
    reader = _network_scope_reader(tmp_path)
    query = {
        "network": ["current"],
        "range": ["all"],
        "alerts_only": ["1"],
        "device": ["1" if device else "0"],
    }
    assert [row["ip"] for row in reader.hosts(query)["items"]] == [
        "192.168.1.22"
    ]
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "CREATE TABLE alert_reviews(alert_id TEXT PRIMARY KEY, status TEXT);"
            "INSERT INTO alert_reviews VALUES ('new-alert', 'resolved');"
        )
    assert reader.hosts(query)["items"] == []


def test_host_traffic_and_score_endpoints_share_current_network_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cards, flow pages, peer/protocol plots and scores exclude pre-connection records.

    Parameters:
        tmp_path: Isolated run databases.
        monkeypatch: Fixes the live capture clock.
    """
    _module_factory = ModuleFactory()
    monkeypatch.setattr(
        "modules.web_interface.server.time.time", lambda: 2_000_000_000.0
    )
    reader = _network_scope_reader(tmp_path)
    query = {"network": ["current"], "range": ["all"]}
    load = reader._host_load("192.168.1.20", query)
    assert (load["flows"], load["bytes"]) == (1, 20)
    page_load = reader._host_page_loads(["192.168.1.20"], 1_999_999_400)
    assert page_load["192.168.1.20"]["flows"] == 1
    assert [
        row["uid"]
        for row in reader.flows_for_host("192.168.1.20", query)["items"]
    ] == ["current-v4"]
    summary = reader.traffic_summary("192.168.1.20", query)
    assert sum(row["outbound_bytes"] for row in summary["timeline"]) == 20
    assert summary["peers"] == [{"name": "8.8.8.8", "value": 1}]
    assert reader._host_ips("192.168.1.20", {**query, "device": ["1"]}) == [
        "192.168.1.20",
        "fe80::20",
    ]
    stale = reader.host("192.168.12.1", query)
    assert (
        stale["load"]["flows"]
        == stale["alert_count"]
        == stale["evidence_count"]
        == 0
    )
    assert stale["seen_on_current_network"] is False
    assert stale["capture_network"]["name"] == "Home-Wifi6"
    assert reader.flows_for_host("192.168.12.1", query)["total"] == 0
    reader._live_host = Mock(
        return_value={
            "live": True,
            "ip": "192.168.12.1",
            "accumulated_ratl": 8,
        }
    )
    assert reader.score_history("192.168.12.1", query)["timeline"] == []


@pytest.mark.parametrize("device", [False, True])
def test_current_network_does_not_fall_back_when_disconnected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, device: bool
) -> None:
    """An unavailable connection yields empty current-network lists and plots.

    Parameters:
        tmp_path: Isolated run databases.
        monkeypatch: Fixes the live capture clock.
        device: Whether device grouping is selected.
    """
    _module_factory = ModuleFactory()
    monkeypatch.setattr(
        "modules.web_interface.server.time.time", lambda: 2_000_000_000.0
    )
    reader = _network_scope_reader(tmp_path)
    reader._current_network_start = Mock(return_value=None)
    query = {
        "network": ["current"],
        "range": ["all"],
        "device": ["1" if device else "0"],
    }
    assert reader.hosts(query)["total"] == 0
    assert reader.live_counts(query)["hosts"] == 0
    assert reader.flows_for_host("192.168.1.20", query)["total"] == 0
    assert reader.traffic_summary("192.168.1.20", query)["timeline"] == []
    assert reader.score_history("192.168.1.20", query)["timeline"] == []


@pytest.mark.parametrize("device", [False, True])
@pytest.mark.parametrize(
    "threat, expected",
    [("low_or_more", {"10.0.0.3"}), ("info_or_more", {"10.0.0.2", "10.0.0.3"}),
     ("info", {"10.0.0.2"}), ("high", {"10.0.0.3"}),
     ("", {"10.0.0.1", "10.0.0.2", "10.0.0.3"})],
)
def test_host_threat_filters_use_scoped_findings(
    tmp_path: Path, device: bool, threat: str, expected: set[str],
) -> None:
    """Old high threat metadata cannot turn a host without current findings into Low+."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "history.sqlite"
    reader.host_profiles_path = tmp_path / "hosts.sqlite"
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {}
    reader._attach_current_host_scores = Mock()
    reader._current_profile_threats = Mock(return_value={"10.0.0.1": "critical"})
    reader._scoped_start = Mock(return_value=100.0)
    reader._host_load = Mock(return_value={})
    reader._ip_context_for_ip = Mock(return_value={})
    initialize_history(reader.history_path)
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "CREATE TABLE evidence(profile_ip TEXT, evidence_time REAL, threat_level TEXT);"
            "CREATE TABLE alerts(ip_alerted TEXT, alert_time REAL);"
            "INSERT INTO evidence VALUES ('10.0.0.1', 10, 'critical'),"
            "('10.0.0.2', 110, 'info'), ('10.0.0.3', 110, 'high');"
        )
    with connect_history(reader.history_path) as connection:
        connection.executemany("INSERT INTO host_snapshots VALUES (?, 120, ?)", [
            (ip, json.dumps({"ip": ip, "scope": "local", "max_threat_level": "critical"}))
            for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3")
        ])
    with connect_history(reader.history_path) as connection:
        connection.execute("INSERT INTO flow_index (uid, flow_rowid, event_time, src_ip, dst_ip, bytes, packets) "
                           "VALUES ('current-no-findings',1,110,'10.0.0.1','8.8.8.8',10,1)")
    page = reader.hosts({"range": ["all"], "network": ["current"],
                         "threat": [threat], "device": ["1" if device else "0"]})
    assert {row["ip"] for row in page["items"]} == expected
    for row in page["items"]:
        assert row["has_findings"] == (row["ip"] != "10.0.0.1")
        assert row["max_threat_level"] == {"10.0.0.1": "", "10.0.0.2": "info", "10.0.0.3": "high"}[row["ip"]]


def test_evidence_flow_pages_preserve_all_uids_and_protocols(tmp_path: Path) -> None:
    """An evidence with over 1,000 flows stays bounded and can be fully traversed."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "CREATE TABLE flows(uid TEXT PRIMARY KEY, flow TEXT);"
            "CREATE TABLE altflows(uid TEXT PRIMARY KEY, flow TEXT, flow_type TEXT);"
            "CREATE TABLE evidence_flows(evidence_id TEXT, uid TEXT, PRIMARY KEY(evidence_id,uid));"
        )
        for index in range(1051):
            uid = f"flow-{index:04}"
            connection.execute("INSERT INTO evidence_flows VALUES ('e', ?)", (uid,))
            if index % 3:
                connection.execute("INSERT INTO flows VALUES (?, '{}')", (uid,))
            if index % 3 != 1:
                connection.execute("INSERT INTO altflows VALUES (?, ?, 'dns')",
                                   (uid, json.dumps({"query": uid + ".example"})))
    query: dict[str, list[str]] = {}
    seen = []
    while True:
        page = reader.flows_for_evidence("e", query)
        assert page["linked_uid_count"] == 1051
        assert page["page_size"] <= 20
        seen.extend(item["uid"] for item in page["items"])
        for item in page["items"]:
            if item["protocol_flows"]:
                assert item["protocol_flows"][0]["flow"]["query"] == item["uid"] + ".example"
        if not page["next_cursor"]:
            break
        query["cursor"] = [page["next_cursor"]]
    assert seen == [f"flow-{index:04}" for index in range(1051)]
    reader.redis.hget.assert_not_called()


def test_durable_evidence_without_flow_ids_does_not_scan_redis(tmp_path: Path) -> None:
    """A retained record with no UIDs returns immediately instead of scanning all evidence."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    reader._redis_evidence = Mock(side_effect=AssertionError("full Redis scan"))
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "CREATE TABLE evidence(evidence_id TEXT PRIMARY KEY, data TEXT);"
            "CREATE TABLE evidence_flows(evidence_id TEXT, uid TEXT);"
            "INSERT INTO evidence VALUES ('notice', '{\"uid\":[]}');"
            "INSERT INTO evidence_flows VALUES ('notice', ''), ('notice', ' ');"
        )
    assert reader.flows_for_evidence("notice")["linked_uid_count"] == 0
    reader.redis.hget.assert_not_called()


def test_live_host_preserves_saved_identity(tmp_path: Path) -> None:
    """A Redis profile containing counters must not clear its last-known identity."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {"threat_level": "info"}
    reader.redis.hget.return_value = None
    reader._snapshot = Mock(return_value={"mac": "02:00:00:00:00:01", "mac_vendor": "Vendor", "hostname": "laptop"})
    host = reader._live_host("192.168.1.163")
    assert (host["mac"], host["mac_vendor"], host["hostname"]) == ("02:00:00:00:00:01", "Vendor", "laptop")


@pytest.mark.parametrize("device", [False, True])
def test_host_review_saved_then_filtered_and_searched(tmp_path: Path, device: bool) -> None:
    """Host marks, labels and notes survive a fresh reader and filter before pagination."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.host_profiles_path = tmp_path / "hosts.sqlite"
    state = {"local_network": "192.168.1.0/24", "gateway_mac": "aa:bb:cc:dd:ee:01"}
    store = HostProfileStore(reader.host_profiles_path, "run", lambda _: state, ["en0"])
    for ip in ("192.168.1.20", "192.168.1.21"):
        store.observe_flow(SimpleNamespace(interface="en0", starttime="100", type_="dhcp", saddr=ip,
            daddr="192.168.1.1", smac="02:00:00:00:00:20", host_name="laptop"))
    saved = reader.save_host_annotation("192.168.1.20", "gateway:aa:bb:cc:dd:ee:01", "Laptop", "Investigate tomorrow",
                                        "to_analyze", [" lab ", "dns", "lab"])
    assert saved["labels"] == ["lab", "dns"]
    # An older client editing only name/note does not discard the review mark.
    reader.save_host_annotation("192.168.1.20", "gateway:aa:bb:cc:dd:ee:01", "Laptop", "Investigate tomorrow")
    fresh = RunDataReader.__new__(RunDataReader)
    fresh.host_profiles_path = reader.host_profiles_path
    fresh.sqlite_path = tmp_path / "flows.sqlite"
    fresh.history_path = tmp_path / "history.sqlite"
    fresh.redis = Mock()
    fresh.redis.hgetall.return_value = {}
    fresh._attach_current_host_scores = Mock()
    fresh._host_load = Mock(return_value={})
    fresh._profile_evidence_count = Mock(return_value=0)
    fresh._profile_alert_count = Mock(return_value=0)
    fresh._ip_context_for_ip = Mock(return_value={})
    initialize_history(fresh.history_path)
    with sqlite3.connect(fresh.sqlite_path) as connection:
        connection.executescript("CREATE TABLE evidence(profile_ip TEXT); CREATE TABLE alerts(ip_alerted TEXT);")
    with connect_history(fresh.history_path) as connection:
        connection.executemany("INSERT INTO host_snapshots VALUES (?, 100, ?)", [
            (ip, json.dumps({"ip": ip, "scope": "local", "mac": "02:00:00:00:00:20"}))
            for ip in ("192.168.1.20", "192.168.1.21")])
    for search in ("dns", "Investigate tomorrow", "Laptop"):
        page = fresh.hosts({"range": ["all"], "search": [search], "review": ["to_analyze"],
                            "device": ["1" if device else "0"], "sort": ["review"], "limit": ["1"]})
        assert page["total"] == (1 if device else 2)
        assert page["items"][0]["user_status"] == "to_analyze"
        assert page["items"][0]["user_labels"] == ["lab", "dns"]
        assert page["items"][0]["user_note"] == "Investigate tomorrow"


def test_host_detail_reads_own_mac_from_monitored_interface(tmp_path: Path) -> None:
    """Current local identity is available even when Redis and saved facts lack a MAC."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.host_profiles_path = tmp_path / "hosts.sqlite"
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {"input_type": "interface", "interface": "en0"}
    reader._live_host = Mock(return_value={"ip": "192.168.1.163", "live": True})
    reader._attach_current_host_scores = Mock()
    reader._host_ips = Mock(return_value=["192.168.1.163"])
    reader._host_load = Mock(return_value={})
    reader._ti_for_ip = Mock(return_value={})
    reader.alerts = Mock(return_value={"items": [], "total": 0})
    reader._host_finding_stats = Mock(return_value={
        "192.168.1.163": {"evidence": 0, "peak": None, "threat_rank": -1},
    })
    with patch("modules.web_interface.server.psutil.net_if_addrs", return_value={"en0": [
        SimpleNamespace(family=socket.AF_INET, address="192.168.1.163"),
        SimpleNamespace(family=psutil.AF_LINK, address="02:00:00:00:00:20"),
    ]}):
        host = reader.host("192.168.1.163")
    assert host["mac"] == "02:00:00:00:00:20"
    assert host["mac_source"] == "Monitored interface en0"


def test_observed_legacy_host_can_be_marked_without_prior_permanent_profile(tmp_path: Path) -> None:
    """An inventory host with no old identity store still has a persistent review editor."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.host_profiles_path = tmp_path / "hosts.sqlite"
    reader.output_dir = Path("fixture-run")
    reader.redis = Mock()
    reader._live_host = Mock(return_value={"observed_at": 100, "ip": "192.168.1.20"})
    fallback = reader._host_annotation_profile("192.168.1.20")
    assert fallback["network_id"] == "run:fixture-run"
    reader.save_host_annotation("192.168.1.20", fallback["network_id"], "Printer", "Check tomorrow",
                                "to_analyze", ["office"])
    assert HostProfileStore.read(reader.host_profiles_path, "192.168.1.20")[0]["user_note"] == "Check tomorrow"
    assert HostProfileStore.triage_for_ips(reader.host_profiles_path, ["192.168.1.20"])["192.168.1.20"] == {
        "status": "to_analyze", "labels": ["office"]}
    reader._live_host.return_value = {"ip": "192.168.1.21"}
    with pytest.raises(ValueError, match="unavailable"):
        reader.save_host_annotation("192.168.1.21", fallback["network_id"], "Invented", "", "", [])


@pytest.mark.parametrize("helper_name", ["create_set_evidence_helper", "create_conn_analyzer_set_evidence_helper"])
def test_different_localnet_evidence_profiles_the_connection_source(helper_name: str) -> None:
    """Keep source and receiving-host findings in their respective profiles.

    Parameters:
        helper_name: Analyzer evidence helper factory.
    """
    factory = ModuleFactory()
    helper = getattr(factory, helper_name)()
    helper.db.get_local_network.return_value = "192.168.1.0/24"
    flow = SimpleNamespace(saddr="192.168.1.163", daddr="172.17.0.1", sport=54321,
                           dport=6668, proto="tcp", uid="docker-flow", starttime=100, interface="en0")
    helper.different_localnet_usage("timewindow1", flow, "dstip")
    findings = {call.args[0].profile.ip: call.args[0]
                for call in helper.db.set_evidence.call_args_list}
    assert len(findings) == 2
    evidence = findings[flow.saddr]
    assert str(evidence.threat_level) == "high"
    assert str(findings[flow.daddr].threat_level) == "info"
    assert evidence.profile.ip == flow.saddr
    assert evidence.interface == flow.interface
    assert evidence.proto == flow.proto
    assert evidence.attacker.value == flow.saddr
    assert evidence.attacker.direction.name == "SRC"
    assert evidence.victim.value == flow.daddr
    assert evidence.victim.direction.name == "DST"


def test_reviewed_flow_export_preserves_detector_label(tmp_path: Path) -> None:
    """Flow export combines linked verdicts without changing detector labels."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "CREATE TABLE flows(uid TEXT PRIMARY KEY, flow TEXT, label TEXT, "
            "profileid TEXT, twid TEXT, aid TEXT, event_time REAL, "
            "retention_class TEXT);"
            "CREATE TABLE altflows(uid TEXT PRIMARY KEY, flow TEXT, label TEXT, "
            "profileid TEXT, twid TEXT, event_time REAL, retention_class TEXT);"
            "CREATE TABLE alerts(alert_id TEXT PRIMARY KEY);"
            "CREATE TABLE alert_reviews(alert_id TEXT PRIMARY KEY, "
            "status TEXT NOT NULL, note TEXT NOT NULL, updated_at REAL NOT NULL);"
            "CREATE TABLE evidence(evidence_id TEXT PRIMARY KEY);"
            "CREATE TABLE evidence_flows(evidence_id TEXT, uid TEXT);"
            "CREATE TABLE alert_evidence(alert_id TEXT, evidence_id TEXT);"
            "INSERT INTO alerts VALUES ('a-false');"
            "INSERT INTO evidence VALUES ('e-false'), ('e-true');"
            "INSERT INTO alert_evidence VALUES ('a-false', 'e-false');"
            "INSERT INTO evidence_flows VALUES "
            "('e-false','u-benign'), ('e-true','u-malicious'), "
            "('e-false','u-conflict'), ('e-true','u-conflict'), "
            "('e-false','u-alt');"
            "INSERT INTO flows VALUES "
            "('u-benign','{}','malicious','p','tw','a',1,'normal'),"
            "('u-malicious','{}','malicious','p','tw','a',1,'normal'),"
            "('u-conflict','{}','malicious','p','tw','a',1,'normal'),"
            "('u-unreviewed','{}','benign','p','tw','a',1,'normal');"
            "INSERT INTO altflows VALUES "
            "('u-alt','{}','malicious','p','tw',1,'normal');"
        )
    reader.save_review("alert", {
        "id": "a-false", "action": "review", "status": "resolved",
        "verdict": "false_positive", "note": "Checked this alert",
    })
    reader.save_review("evidence", {
        "id": "e-true", "action": "review", "status": "true_positive",
        "note": "Confirmed this evidence",
    })
    rows = {row["uid"]: row for row in reader.iter_reviewed_flows()}
    assert {uid: row["human_review"] for uid, row in rows.items()} == {
        "u-benign": "benign", "u-malicious": "malicious",
        "u-conflict": "conflict", "u-unreviewed": "", "u-alt": "benign",
    }
    assert rows["u-benign"]["label"] == "malicious"
    assert rows["u-alt"]["aid"] is None


def test_reviewed_flow_download_streams_tsv() -> None:
    """The authenticated export route sends both detector and analyst columns."""
    _module_factory = ModuleFactory()
    reader = Mock()
    reader.iter_reviewed_flows.return_value = iter([{
        "uid": "u-1", "flow": "{}", "label": "malicious",
        "profileid": "p", "twid": "tw", "aid": "a",
        "event_time": 1, "retention_class": "normal",
        "human_review": "benign",
    }])
    server = SlipsHTTPServer(("127.0.0.1", 0), RequestHandler, reader)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        with patch.object(RequestHandler, "_require_password", return_value=False):
            with urlopen(
                f"http://127.0.0.1:{server.server_address[1]}"
                "/api/flows/export", timeout=10
            ) as response:
                body = response.read().decode("utf-8")
                assert response.status == 200
                assert "attachment" in response.headers["Content-Disposition"]
        assert "label\tprofileid" in body
        assert "retention_class\thuman_review" in body
        assert "u-1\t{}\tmalicious" in body
        assert body.rstrip().endswith("normal\tbenign")
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=10)


def test_alert_review_persists_and_requires_resolution_note(tmp_path: Path) -> None:
    """Resolved alerts remain durable and are excluded from open queries."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("CREATE TABLE alerts(alert_id TEXT PRIMARY KEY)")
        connection.execute("INSERT INTO alerts VALUES ('alert-1')")
    with pytest.raises(ValueError, match="note"):
        reader.save_review("alert", {
            "id": "alert-1", "action": "review", "status": "resolved", "note": ""
        })
    reader.save_review("alert", {
        "id": "alert-1", "action": "review", "status": "resolved",
        "note": "Checked the connection against the router log."
    })
    with sqlite3.connect(reader.sqlite_path) as connection:
        open_clause = reader._review_clause(connection, "alert", "open", "alerts")
        resolved_clause = reader._review_clause(
            connection, "alert", "resolved", "alerts"
        )
        assert connection.execute(
            f"SELECT COUNT(*) FROM alerts WHERE {open_clause}"
        ).fetchone()[0] == 0
        assert connection.execute(
            f"SELECT COUNT(*) FROM alerts WHERE {resolved_clause}"
        ).fetchone()[0] == 1
    reader.save_review("alert", {
        "id": "alert-1", "action": "review", "status": "active", "note": "Reopened"
    })
    with sqlite3.connect(reader.sqlite_path) as connection:
        assert connection.execute(
            "SELECT status, note FROM alert_reviews WHERE alert_id = 'alert-1'"
        ).fetchone() == ("active", "Reopened")


@pytest.mark.parametrize(
    ("review", "expected"),
    [("open", 1), ("active", 1), ("resolved", 1), ("all", 2)],
)
def test_grouped_alerts_filter_review_state(
    tmp_path: Path, review: str, expected: int
) -> None:
    """Host aggregation excludes resolved alerts unless explicitly selected."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    reader.redis.hget.return_value = "pcap"
    reader.score_mode = "ratl"
    reader._ip_context_for_ip = Mock(return_value={})
    reader._annotate_detection_networks = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "CREATE TABLE alerts(alert_id TEXT PRIMARY KEY, ip_alerted TEXT, "
            "alert_time REAL, label TEXT, accumulated_ratl REAL);"
            "CREATE TABLE evidence(evidence_id TEXT, threat_level TEXT);"
            "CREATE TABLE alert_evidence(alert_id TEXT, evidence_id TEXT);"
            "INSERT INTO alerts VALUES "
            "('open','192.0.2.5',10,'malicious',5),"
            "('closed','192.0.2.5',11,'malicious',6);"
            "INSERT INTO evidence VALUES ('e1','high'),('e2','critical');"
            "INSERT INTO alert_evidence VALUES ('open','e1'),('closed','e2');"
        )
    reader.save_review("alert", {
        "id": "closed", "action": "review", "status": "resolved",
        "note": "Reviewed and closed"
    })
    result = reader._grouped_alerts_fast({"range": ["all"], "review": [review]})
    assert result["items"][0]["alert_count"] == expected
    assert result["matching_total"] == expected
    assert result["open_total"] == 1


@pytest.mark.parametrize(
    ("depth", "expected_evidence", "expected_flows"),
    [
        ("alert", {"shared", "unique"}, {"shared-uid", "unique-uid"}),
        ("evidence", {"shared"}, {"shared-uid", "unique-uid"}),
        ("flows", {"shared"}, {"shared-uid"}),
    ],
)
def test_alert_cleanup_preserves_shared_records(
    tmp_path: Path, depth: str, expected_evidence: set[str],
    expected_flows: set[str],
) -> None:
    """Only unshared evidence and flow rows are removed at each depth."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "web_history.sqlite"
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "CREATE TABLE alerts(alert_id TEXT PRIMARY KEY);"
            "CREATE TABLE evidence(evidence_id TEXT PRIMARY KEY);"
            "CREATE TABLE alert_evidence(alert_id TEXT, evidence_id TEXT);"
            "CREATE TABLE evidence_flows(evidence_id TEXT, uid TEXT);"
            "CREATE TABLE flows(uid TEXT PRIMARY KEY);"
            "CREATE TABLE altflows(uid TEXT PRIMARY KEY);"
            "INSERT INTO alerts VALUES ('first'), ('second');"
            "INSERT INTO evidence VALUES ('shared'), ('unique');"
            "INSERT INTO alert_evidence VALUES "
            "('first','shared'), ('first','unique'), ('second','shared');"
            "INSERT INTO evidence_flows VALUES "
            "('shared','shared-uid'), ('unique','shared-uid'), "
            "('unique','unique-uid');"
            "INSERT INTO flows VALUES ('shared-uid'), ('unique-uid');"
        )
    with sqlite3.connect(reader.history_path) as connection:
        connection.executescript(
            "CREATE TABLE flow_index(uid TEXT PRIMARY KEY);"
            "INSERT INTO flow_index VALUES ('shared-uid'), ('unique-uid');"
        )
    result = reader.save_review("alert", {
        "id": "first", "action": "delete", "depth": depth,
        "note": "Duplicate alert after investigation"
    })
    with sqlite3.connect(reader.sqlite_path) as connection:
        assert set(connection.execute(
            "SELECT alert_id FROM alerts"
        ).fetchall()) == {("second",)}
        assert {row[0] for row in connection.execute(
            "SELECT evidence_id FROM evidence"
        )} == expected_evidence
        assert {row[0] for row in connection.execute(
            "SELECT uid FROM flows"
        )} == expected_flows
        assert connection.execute(
            "SELECT COUNT(*) FROM review_deletions"
        ).fetchone()[0] == 1
    with sqlite3.connect(reader.history_path) as connection:
        assert {row[0] for row in connection.execute(
            "SELECT uid FROM flow_index"
        )} == expected_flows
    assert result["shared_preserved"] == (0 if depth == "alert" else 1)


def _authenticated_request(url: str) -> Request:
    """A request carrying a valid session cookie, for gated pages."""
    return Request(
        url, headers={"Cookie": f"{SESSION_COOKIE_NAME}={issue_token()}"}
    )


@pytest.mark.parametrize("case,expected", [
    ("scoped", True), ("legacy", True), ("both", True),
    ("invalid-scoped", False), ("none", False),
])
def test_web_server_uses_its_own_session_cookie(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str, expected: bool,
) -> None:
    """Authenticate this server despite unrelated localhost session cookies.

    Parameters:
        tmp_path: Private credential file.
        monkeypatch: Isolate the web signing credentials.
        case: Cookies supplied by the browser.
        expected: Whether the request is authenticated.
    """
    _factory = ModuleFactory()
    auth = tmp_path / "web-auth.json"
    auth.write_text(json.dumps({"hash": "ab" * 32}))
    monkeypatch.setattr(web_auth, "get_web_auth_path", lambda: str(auth))
    monkeypatch.setattr(web_auth, "ensure_web_password_matches_redis_password", Mock())
    name = web_auth.session_cookie_name()
    token = issue_token()
    values = {name: token}
    if case == "legacy":
        values = {SESSION_COOKIE_NAME: token}
    elif case == "both":
        values[SESSION_COOKIE_NAME] = "other-computer-session"
    elif case == "invalid-scoped":
        values = {name: "invalid", SESSION_COOKIE_NAME: token}
    elif case == "none":
        values = {}
    handler = RequestHandler.__new__(RequestHandler)
    handler.headers = {"Cookie": "; ".join(f"{key}={value}" for key, value in values.items())}
    assert handler._session_ok() is expected


def test_web_login_issues_a_scoped_persistent_cookie(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Publish an installation-specific cookie with the existing protections.

    Parameters:
        tmp_path: Private credential file.
        monkeypatch: Isolate credentials and submitted password verification.
    """
    _factory = ModuleFactory()
    auth = tmp_path / "web-auth.json"
    auth.write_text(json.dumps({"hash": "ab" * 32}))
    monkeypatch.setattr(web_auth, "get_web_auth_path", lambda: str(auth))
    monkeypatch.setattr(web_auth, "ensure_web_password_matches_redis_password", Mock())
    monkeypatch.setattr("modules.web_interface.server.ensure_web_password_matches_redis_password", Mock())
    monkeypatch.setattr("modules.web_interface.server.is_locked_out", Mock(return_value=False))
    verifier = Mock(return_value=True)
    monkeypatch.setattr("modules.web_interface.server.verify_web_password", verifier)
    body = b"password=test-password"
    handler = RequestHandler.__new__(RequestHandler)
    handler.path = "/login"
    handler.client_address = ("127.0.0.1", 12345)
    handler.headers = {"Content-Length": str(len(body))}
    handler.rfile = BytesIO(body)
    handler._send_html = Mock()
    handler.do_POST()
    verifier.assert_called_once_with("test-password")
    headers = handler._send_html.call_args.kwargs["headers"]
    cookie = SimpleCookie(headers["Set-Cookie"])
    assert list(cookie) == [web_auth.session_cookie_name()]
    morsel = cookie[web_auth.session_cookie_name()]
    assert morsel["httponly"] and morsel["samesite"] == "Strict"
    assert morsel["path"] == "/"
    assert int(morsel["max-age"]) == web_auth.SESSION_TTL_SECONDS
    assert web_auth.validate_session_cookies({morsel.key: morsel.value})


def test_every_static_web_table_header_has_a_sort_key() -> None:
    """Prevent a new visible table column from silently losing sorting."""
    _module_factory = ModuleFactory()
    source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )
    tables = re.findall(r"<table\b[^>]*>.*?</table>", source, re.S)
    assert len(tables) >= 13
    for table in tables:
        table_id = re.search(r'id="([^"]+)"', table)
        for header in re.findall(r"<th\b([^>]*)>", table):
            assert 'data-sort="' in header, table_id.group(1) if table_id else table


def test_logs_sort_all_retained_rows_before_bounding_page(tmp_path: Path) -> None:
    """A non-time sort includes older logs outside the newest 100."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.history_path = tmp_path / "history.sqlite"
    initialize_history(reader.history_path)
    with connect_history(reader.history_path) as history:
        history.executemany(
            "INSERT INTO error_events(event_time, module, message, line) "
            "VALUES (?, ?, ?, ?)",
            [(float(index), "zzz", "newer", "newer") for index in range(101)]
            + [(0.0, "aaa", "oldest", "oldest")],
        )

    result = reader.logs({"sort": ["module"], "order": ["asc"], "scope": ["history"]})

    assert result["total"] == 102
    assert len(result["items"]) == 100
    assert result["items"][0]["module"] == "aaa"


@pytest.mark.parametrize("scope,start,end,metadata_start,expected", [
    ("current", "100", "", "", [140, 120, 100]),
    ("current", "100", "130", "", [120, 100]),
    ("current", "130", "", "", [140]),
    ("current", "", "", "100", [140, 120, 100]),
    ("current", "", "", "", []),
    ("current", "nan", "", "", []),
    ("history", "100", "130", "", [140, 120, 100, 90]),
])
def test_logs_scope_uses_run_wall_clock(
    tmp_path: Path, scope: str, start: str, end: str,
    metadata_start: str, expected: list[int],
) -> None:
    """Keep older errors out of this run while retaining explicit history.

    Parameters:
        tmp_path: Isolated output directory.
        scope: Current run or all retained runs.
        start: Redis wall-clock process start.
        end: Optional completed-run end.
        metadata_start: Fallback start from info.txt.
        expected: Event timestamps visible in descending order.
    """
    _factory = ModuleFactory()
    reader = object.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.history_path = tmp_path / "history.sqlite"
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {"analysis_start": start, "analysis_end": end,
                                       "input_type": "pcap", "file_start": "1"}
    if metadata_start:
        (tmp_path / "metadata").mkdir()
        (tmp_path / "metadata" / "info.txt").write_text(f"Slips start date: {metadata_start}\n")
    initialize_history(reader.history_path)
    with connect_history(reader.history_path) as history:
        history.executemany("INSERT INTO error_events(event_time,module,message,line) VALUES (?,'Profiler','error','raw')",
                            [(stamp,) for stamp in (90, 100, 120, 140)])
    result = reader.logs({"scope": [scope]})
    assert [item["event_time"] for item in result["items"]] == expected
    assert result["total"] == len(expected)
    assert result["scope"] == scope
    if scope == "current" and expected:
        with connect_history(reader.history_path) as history:
            where, parameters, _, _ = reader._log_scope()
            plan = history.execute("EXPLAIN QUERY PLAN SELECT * FROM error_events" + where, parameters).fetchall()
        assert any("error_time_idx" in str(tuple(row)) for row in plan)
    with pytest.raises(ValueError, match="Unknown log history scope"):
        reader.logs({"scope": ["invalid"]})


@pytest.mark.parametrize(
    ("sort_key", "order", "expected"),
    [
        ("bytes", "asc", ["flow-small", "flow-middle"]),
        ("ports", "asc", ["flow-small", "flow-middle"]),
        ("duration", "desc", ["flow-large", "flow-middle"]),
    ],
)
def test_host_flows_sort_before_cursor_paging(
    tmp_path: Path, sort_key: str, order: str, expected: list[str]
) -> None:
    """Sort all matching flows, including fields kept in raw records."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.history_path = tmp_path / "history.sqlite"
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    reader.redis.hget.return_value = "pcap"
    reader._host_ips = Mock(return_value=["10.0.0.1"])
    initialize_history(reader.history_path)
    records = [
        ("flow-large", 1.0, 30, 3000, 3.0),
        ("flow-middle", 2.0, 10, 2000, 2.0),
        ("flow-small", 3.0, 5, 1000, 1.0),
    ]
    with connect_history(reader.history_path) as history:
        history.executemany(
            "INSERT INTO flow_index(uid, flow_rowid, event_time, src_ip, "
            "dst_ip, proto, app_proto, bytes, packets, label) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (uid, index, timestamp, "10.0.0.1", "10.0.0.2", "tcp", "", size, 1, "")
                for index, (uid, timestamp, size, _, _) in enumerate(records, 1)
            ],
        )
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("CREATE TABLE flows(uid TEXT, flow TEXT, label TEXT)")
        connection.executemany(
            "INSERT INTO flows VALUES (?, ?, ?)",
            [
                (uid, json.dumps({"sport": port, "dport": 443, "dur": duration}), "")
                for uid, _, _, port, duration in records
            ],
        )

    first = reader.flows_for_host(
        "10.0.0.1",
        {"range": ["all"], "sort": [sort_key], "order": [order], "limit": ["2"]},
    )

    assert [item["uid"] for item in first["items"]] == expected
    assert first["next_cursor"] is not None
    second = reader.flows_for_host(
        "10.0.0.1",
        {
            "range": ["all"], "sort": [sort_key], "order": [order],
            "limit": ["2"], "cursor": [first["next_cursor"]],
        },
    )
    assert len(second["items"]) == 1


def test_host_flows_filter_by_linked_evidence_threat(tmp_path: Path) -> None:
    """Filter the full host range by linked threat, retaining unlinked flows."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.history_path = tmp_path / "history.sqlite"
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    reader.redis.hget.return_value = "pcap"
    reader._host_ips = Mock(return_value=["10.0.0.1"])
    initialize_history(reader.history_path)
    with connect_history(reader.history_path) as history:
        history.executemany(
            "INSERT INTO flow_index(uid, flow_rowid, event_time, src_ip, "
            "dst_ip, proto, app_proto, bytes, packets, label) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(uid, index, float(index), "10.0.0.1", "10.0.0.2", "tcp", "", 1, 1, "")
             for index, uid in enumerate(["high", "info", "unlinked"], 1)],
        )
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "CREATE TABLE flows(uid TEXT, flow TEXT, label TEXT);"
            "CREATE TABLE evidence(evidence_id TEXT, threat_level TEXT);"
            "CREATE TABLE evidence_flows(evidence_id TEXT, uid TEXT);"
            "INSERT INTO evidence VALUES ('e-high', 'high'), ('e-info', 'info');"
            "INSERT INTO evidence_flows VALUES ('e-high', 'high'), "
            "('e-info', 'info');"
        )
        connection.executemany(
            "INSERT INTO flows VALUES (?, '{}', '')",
            [(uid,) for uid in ["high", "info", "unlinked"]],
        )

    all_flows = reader.flows_for_host("10.0.0.1", {"range": ["all"]})
    high = reader.flows_for_host(
        "10.0.0.1", {"range": ["all"], "threat": ["high_or_more"]}
    )
    linked = reader.flows_for_host(
        "10.0.0.1", {"range": ["all"], "threat": ["info_or_more"]}
    )
    ordered = reader.flows_for_host(
        "10.0.0.1", {"range": ["all"], "sort": ["threat"], "order": ["desc"]}
    )

    assert all_flows["total"] == 3
    assert {item["uid"]: item["linked_threat_level"] for item in all_flows["items"]} == {
        "high": "high", "info": "info", "unlinked": None
    }
    assert [item["uid"] for item in high["items"]] == ["high"]
    assert {item["uid"] for item in linked["items"]} == {"high", "info"}
    assert [item["uid"] for item in ordered["items"]] == [
        "high", "info", "unlinked"
    ]


def test_current_network_profile_precedes_newer_run_fallback() -> None:
    """Restore host annotations when an earlier run missed its router."""
    _module_factory = ModuleFactory()
    reader = object.__new__(RunDataReader)
    reader.output_dir = "output/test-run"
    reader.redis = Mock()
    reader.redis.hget.return_value = "100"
    reader.redis.hgetall.return_value = {
        "en0": json.dumps(
            {
                "connected": True,
                "local_network": "192.168.1.0/24",
                "gateway_mac": "d8:58:d7:1:ff:e1",
            }
        )
    }
    profiles = [
        {"network_id": "run:output/test-run:99", "user_name": ""},
        {
            "network_id": "gateway:d8:58:d7:1:ff:e1",
            "user_name": "homeassistant",
        },
    ]

    ordered = reader._current_network_profile_first("192.168.1.185", profiles)

    assert ordered[0]["user_name"] == "homeassistant"
    assert profiles[0]["user_name"] == ""


def test_idle_connection_does_not_block_page_requests() -> None:
    """Verify a speculative idle browser connection cannot stall the server."""
    _module_factory = ModuleFactory()
    server = SlipsHTTPServer(("127.0.0.1", 0), RequestHandler, Mock())
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    port = int(server.server_address[1])
    idle_connection = socket.create_connection(("127.0.0.1", port), timeout=5)

    try:
        with patch.object(RequestHandler, "_require_password", return_value=False):
            with urlopen(f"http://127.0.0.1:{port}/", timeout=10) as response:
                assert response.status == 200
                page = response.read()
                assert b"Slips" in page
                assert b'class="brand-logo"' in page
                assert b'src="/slips-logo.png?v=4"' in page
                assert b'<p class="brand-name">SLIPS</p>' in page
            with urlopen(
                f"http://127.0.0.1:{port}/slips-logo.png?v=4", timeout=10
            ) as response:
                assert response.status == 200
                assert response.headers["Content-Type"] == "image/png"
                assert response.read().startswith(b"\x89PNG\r\n\x1a\n")
    finally:
        idle_connection.close()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=10)


@pytest.mark.parametrize("failure_point", ["headers", "body"])
@pytest.mark.parametrize(
    "disconnect_error", [BrokenPipeError, ConnectionResetError]
)
def test_json_response_ignores_client_disconnect(
    failure_point: str, disconnect_error: type[ConnectionError]
) -> None:
    """Stop sending JSON when the requesting client disconnects.

    Parameters:
        failure_point: Response operation interrupted by the client.
        disconnect_error: Socket exception raised for the disconnection.
    """
    _module_factory = ModuleFactory()
    handler = RequestHandler.__new__(RequestHandler)
    handler.send_response = Mock()
    handler.send_header = Mock()
    handler.end_headers = Mock()
    handler.wfile = Mock()
    if failure_point == "headers":
        handler.end_headers.side_effect = disconnect_error
    else:
        handler.wfile.write.side_effect = disconnect_error

    handler._send_json({"status": "ready"})

    handler.send_response.assert_called_once_with(200)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("127.0.0.1", "127.0.0.1"),
        ("192.0.2.25", "192.0.2.25"),
    ],
)
def test_server_accepts_only_normalized_ipv4_bind_addresses(
    value: str, expected: str
) -> None:
    """Validate exact IPv4 server bind addresses.

    Parameters:
        value: Address supplied to the server.
        expected: Normalized address.
    """
    _module_factory = ModuleFactory()

    assert ipv4_address(value) == expected


@pytest.mark.parametrize("value", ["::1", "localhost", "0.0.0.0", "0.0.0.0/0"])
def test_server_rejects_non_ipv4_bind_addresses(value: str) -> None:
    """Reject hostnames, IPv6, and network ranges as listen addresses.

    Parameters:
        value: Invalid bind value supplied to the server.
    """
    _module_factory = ModuleFactory()

    with pytest.raises(argparse.ArgumentTypeError):
        ipv4_address(value)


def test_header_tracks_backend_heartbeat_and_freezes_uptime() -> None:
    """Keep retained pages honest after the Slips backend disconnects."""
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    style_source = Path("modules/web_interface/style.css").read_text(
        encoding="utf-8"
    )
    connection_renderer = app_source.split(
        "function renderConnectionState(", 1
    )[1].split("function toast", 1)[0]
    api_handler = app_source.split("async function api", 1)[1].split(
        "function renderTable", 1
    )[0]

    assert 'dot.className = "state-dot error"' in connection_renderer
    assert (
        'label.textContent = "Disconnected from backend"'
        in connection_renderer
    )
    assert 'const prefix = disconnected ? "Last uptime" : "Uptime"' in (
        connection_renderer
    )
    assert 'element.classList.toggle("error", disconnected)' in (
        connection_renderer
    )
    assert "state.runUptimeRunning && state.connected" in connection_renderer
    assert "payload.backend_status?.connected === true" in api_handler
    assert 'label.textContent = "Viewing saved results"' in connection_renderer
    assert "payload.run_identity?.saved_view === true" in api_handler
    assert "renderConnectionState(false);" in api_handler
    assert 'api("backendStatus", "/api/identity", false)' in app_source
    assert "scheduleBackendStatusPoll();" in app_source
    assert ".run-state small.error { color: var(--danger); }" in style_source


@pytest.mark.parametrize("tab", ["alerts", "evidence", "hosts"])
def test_primary_tables_render_real_slips_score_column(tab: str) -> None:
    """Keep the real Slips score visible in the primary detection views.

    Parameters:
        tab: Web-interface view whose score display is verified.
    """
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    index_source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )

    if tab == "alerts":
        section = app_source.split(
            "function renderAlertDetailPane(record)", 1
        )[1].split("async function selectAlertDetailPane", 1)[0]
        assert '"Score / threshold", slipsScore(record)' in section
        assert '"Network", networkContext(record)' in section
        assert 'id="alerts-detail-pane"' in index_source
    elif tab == "evidence":
        section = app_source.split("function renderEvidenceTable(payload)", 1)[
            1
        ].split("function evidenceClock(timestamp)", 1)[0]
        assert '["Score", "score"]' in section
        assert "(row) => slipsScore(row)" in section
        assert 'id="evidence-right"' in index_source
        assert (
            '["Network", group.profile_ip ? networkContext(group)'
            in app_source
        )
    else:
        section = app_source.split("async function loadHosts()", 1)[1].split(
            "function contextName", 1
        )[0]
        style_source = Path("modules/web_interface/style.css").read_text(
            encoding="utf-8"
        )
        summary_renderer = app_source.split("function setSummaryCards", 1)[
            1
        ].split("function renderOverview", 1)[0]
        assert 'data-host-column="score"' in index_source
        assert 'data-sort="score"' in index_source
        assert (
            'data-sort="peak_score">Threat · Peak score</th>' in index_source
        )
        assert "(row) => hostPeakScoreCell(row)" in section
        assert (
            'id="host-score-chart" class="line-chart" viewBox="0 0 1200 180"'
            in index_source
        )
        assert (
            ".score-history-figure .line-chart { height: 180px" in style_source
        )
        assert "height * renderedWidth / renderedHeight" in app_source
        assert "async function loadLegacyScoreHistory(params)" in app_source
        assert "compatibility_limited: total > records.length" in app_source
        assert 'params.set("profile", ip)' in app_source
        assert "if (!payload || state.host?.ip !== ip) return;" in app_source
        assert (
            "host.exact_aggregates = state.deviceView || staleAliases.length === 0"
            in app_source
        )
        assert "(row) => slipsScore(row)" in section
        assert "openHost(row.ip, row)" in section
        host_workspace = app_source.split("async function openHost", 1)[
            1
        ].split("async function refreshHostWorkspace", 1)[0]
        assert 'range: "all", search: ip' in host_workspace
        assert ".find((row) => row.ip === ip)" in host_workspace
        assert "value instanceof Node" in summary_renderer
        assert "valueElement.append(value)" in summary_renderer
        assert "loadHostScoreHistory()" in app_source


@pytest.mark.parametrize(
    "renderer, expected",
    [
        ("const text =", "element.textContent = displayValue(value)"),
        ("const cell =", "td.textContent = displayValue(value)"),
        (
            "function setSummaryCards",
            "valueElement.textContent = displayValue(value)",
        ),
    ],
)
def test_shared_renderers_humanize_unix_timestamps(
    renderer: str, expected: str
) -> None:
    """Keep raw Unix epochs out of tables, cards, and detail fields.

    Parameters:
        renderer: Start of the shared renderer being checked.
        expected: Human-time conversion required inside that renderer.
    """
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    section = app_source.split(renderer, 1)[1].split("\n}", 1)[0]

    assert expected in section


@pytest.mark.parametrize(
    "expected",
    [
        "JSON.stringify(displayData(record), null, 2)",
        "JSON.stringify(displayData(host.ti), null, 2)",
        "JSON.stringify(displayData(value))",
        "String(displayValue(value))",
    ],
)
def test_nested_detail_fields_humanize_unix_timestamps(expected: str) -> None:
    """Keep raw Unix epochs out of nested and protocol detail fields.

    Parameters:
        expected: Required use of the recursive human-time formatter.
    """
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )

    assert expected in app_source


@pytest.mark.parametrize(
    "levels, expected",
    [
        (["info", "medium"], "medium"),
        (["high", "low", "critical"], "critical"),
        ([], "info"),
    ],
)
def test_highest_threat(levels: list[str], expected: str) -> None:
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)

    assert reader._highest_threat(levels) == expected


def test_configuration_explains_captured_run_snapshot(tmp_path) -> None:
    """Render every captured setting as explained data and redact secrets."""
    _module_factory = ModuleFactory()
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    (metadata / "run.yaml").write_text(
        "parameters:\n  time_window_width: 3600\n"
        "detection:\n  evidence_detection_threshold: 0.43\n"
        "alert_summary:\n  llm_max_tokens: 1024\n"
        "web_interface:\n  enabled: true\n  api_key: keep-private\n",
        encoding="utf-8",
    )
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path

    result = reader.configuration()

    assert result["source"] == "run.yaml"
    assert result["total"] == 5
    parameters = result["sections"][0]
    assert (
        "evidence is accumulated" in parameters["settings"][0]["explanation"]
    )
    assert parameters["settings"][0]["changed"] is False
    detection = result["sections"][1]
    assert detection["settings"][0]["changed"] is True
    assert detection["settings"][0]["default"] == 0.25
    assert result["changed_total"] >= 1
    assert result["secret_total"] == 1
    assert result["sections"][2]["settings"][0]["value"] == 1024
    assert result["sections"][2]["settings"][0]["sensitive"] is False
    web_settings = result["sections"][3]["settings"]
    assert web_settings[1]["value"] == "Configured — hidden"
    assert web_settings[1]["sensitive"] is True
    assert web_settings[1]["default"] is None
    assert "keep-private" not in result["redacted_yaml"]
    assert "Configured — hidden" in result["redacted_yaml"]


def test_whitelists_returns_parsed_runtime_rules(tmp_path) -> None:
    """Show the active parsed rule rather than dumping whitelist text."""
    _module_factory = ModuleFactory()
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    (metadata / "run.yaml").write_text(
        "whitelists:\n  enable_local_whitelist: true\n"
        "  enable_online_whitelist: false\n",
        encoding="utf-8",
    )
    (metadata / "run.conf").write_text(
        "ip,147.32.80.37,both,alerts\n", encoding="utf-8"
    )
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.redis = Mock()
    reader.redis.hgetall.side_effect = lambda key: {
        "whitelist_IPs": {
            "147.32.80.37": json.dumps(
                {"from": "both", "what_to_ignore": "alerts"}
            )
        }
    }.get(key, {})
    reader.cache = Mock()
    reader.cache.zcard.return_value = 0

    result = reader.whitelists()

    assert result["total"] == 1
    assert result["rules"][0]["value"] == "147.32.80.37"
    assert result["rules"][0]["effect"] == (
        "Suppresses evidence and alerts when this value appears on the source or destination side."
    )


@pytest.mark.parametrize(
    "value, expected",
    [
        ("192.0.2.4", "192.0.2.4"),
        ("192.0.2.4:443", "192.0.2.4:443"),
        ("[2001:db8::1]:443", "[2001:db8::1]:443"),
        ("2001:db8::1", "2001:db8::1"),
        ("*:443", "*:443"),
    ],
)
def test_normalize_web_whitelist_ip(value: str, expected: str) -> None:
    """Accept the exact IP and port forms supported by Slips.

    Parameters:
        value: Browser input.
        expected: Stored rule value.
    """
    _module_factory = ModuleFactory()
    assert RunDataReader._normalize_whitelist_ip(value) == expected


@pytest.mark.parametrize(
    "value",
    ["*:0", "*:65536", "192.0.2.4:abc", "192.0.2.0/24", "bad,src,flows"],
)
def test_reject_invalid_web_whitelist_ip(value: str) -> None:
    """Reject invalid rules before they can be written to the file.

    Parameters:
        value: Invalid browser input.
    """
    _module_factory = ModuleFactory()
    with pytest.raises(ValueError):
        RunDataReader._normalize_whitelist_ip(value)


def test_web_whitelist_rule_persists_and_can_be_removed(tmp_path) -> None:
    """Save a live IP:port rule in the configured file and reload it."""
    factory = ModuleFactory()
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    configured = tmp_path / "whitelist.conf"
    configured.write_text("ip,192.0.2.1,both,alerts\n", encoding="utf-8")
    (metadata / "run.yaml").write_text(
        "whitelists:\n  enable_local_whitelist: true\n"
        f"  local_whitelist_path: {configured}\n",
        encoding="utf-8",
    )
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.redis = Mock()
    reader.redis.hexists.return_value = False
    reader.response_metadata = Mock(
        return_value={"backend_status": {"connected": True}}
    )

    saved = reader.save_whitelist_rule("add", "192.0.2.4:443", "dst", "alerts")

    assert saved["value"] == "192.0.2.4:443"
    managed = configured
    assert "ip,192.0.2.4:443,dst,alerts" in managed.read_text(encoding="utf-8")
    assert (tmp_path / "whitelist.conf.bak").read_text(encoding="utf-8") == (
        managed.read_text(encoding="utf-8")
    )
    assert "ip,192.0.2.1,both,alerts" in configured.read_text(
        encoding="utf-8"
    )
    assert not (tmp_path / "whitelist.conf.web.conf").exists()
    reader.redis.hset.assert_called_once()
    whitelist = factory.create_whitelist_obj()
    whitelist.parser.local_whitelist_path = str(configured)
    whitelist.parser.parse()
    assert whitelist.parser.whitelisted_ips["192.0.2.4:443"] == {
        "from": "dst",
        "what_to_ignore": "alerts",
    }

    reader.save_whitelist_rule("remove", "192.0.2.4:443", "dst", "alerts")
    assert "192.0.2.4:443" not in managed.read_text(encoding="utf-8")
    reader.redis.hdel.assert_called_once_with("whitelist_IPs", "192.0.2.4:443")


@pytest.mark.parametrize("value", ["192.0.2.10", "2001:db8::1"])
def test_web_blocking_whitelist_uses_configured_file(tmp_path: Path, value: str) -> None:
    """Save and remove the same enforcement-only CSV used by action modules.

    Parameters:
        tmp_path: Isolated run and whitelist directory.
        value: Individual IPv4 or IPv6 host address.
    """
    factory = ModuleFactory()
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    path = tmp_path / "whitelist.conf"
    path.write_text("")
    (metadata / "run.yaml").write_text(
        "whitelists:\n  enable_local_whitelist: true\n"
        f"  local_whitelist_path: {path}\n"
    )
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.redis = Mock()
    reader.redis.hexists.return_value = False
    reader.response_metadata = Mock(return_value={"backend_status": {"connected": True}})

    reader.save_whitelist_rule("add", value, "both", "blocking")

    assert f"ip,{value},both,blocking\n" in path.read_text()
    policy = factory.create_blocking_whitelist_obj(str(path))
    assert policy.is_exempt(value)
    reader.redis.hset.assert_called_once_with(
        "whitelist_IPs", value,
        json.dumps({"from": "both", "what_to_ignore": "blocking"}),
    )
    effect = reader._whitelist_effect("both", "blocking")
    assert "keeps flows, evidence and alerts" in effect
    assert "ARP poisoning" in effect
    reader.save_whitelist_rule("remove", value, "both", "blocking")
    assert f"ip,{value},both,blocking" not in path.read_text()
    policy._next_check = 0
    assert not policy.is_exempt(value)


@pytest.mark.parametrize(
    "value,direction,evidence_type,rule_type",
    [
        ("192.0.2.10:443", "both", None, "ip"),
        ("*:443", "both", None, "ip"),
        ("192.0.2.10", "src", None, "ip"),
        ("192.0.2.10", "dst", None, "ip"),
        ("192.0.2.10", "both", "ARP_SCAN", "ip"),
        ("/example", "both", None, "uri"),
    ],
)
def test_web_rejects_ambiguous_blocking_whitelist(
    value: str, direction: str, evidence_type: str | None, rule_type: str
) -> None:
    """Reject selectors that cannot describe whole-IP enforcement.

    Parameters:
        value: Unsupported address or URI selector.
        direction: Unsupported direction for an IP-wide exemption.
        evidence_type: Optional alert-type scope.
        rule_type: IP or URI rule category.
    """
    _factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    with pytest.raises(ValueError):
        reader.save_whitelist_rule(
            "add", value, direction, "blocking", evidence_type, rule_type
        )


def test_web_whitelist_refuses_missing_configured_file(tmp_path: Path) -> None:
    """Never replace a vanished personal file with a partial web rule file.

    Parameters:
        tmp_path: Isolated configured whitelist directory.
    """
    _module_factory = ModuleFactory()
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    configured = tmp_path / "personal-whitelist.conf"
    (metadata / "run.yaml").write_text(
        "whitelists:\n  enable_local_whitelist: true\n"
        f"  local_whitelist_path: {configured}\n",
        encoding="utf-8",
    )
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.redis = Mock()
    reader.redis.hexists.return_value = False
    reader.response_metadata = Mock(
        return_value={"backend_status": {"connected": True}}
    )

    with pytest.raises(FileNotFoundError, match="will not start"):
        reader.save_whitelist_rule(
            "add", "192.0.2.4", "src", "alerts", "ARP_SCAN"
        )
    assert not configured.exists()
    reader.redis.hset.assert_not_called()


def test_web_whitelist_restores_backup_before_adding_rule(
    tmp_path: Path,
) -> None:
    """Preserve manual entries when adding a rule after the file vanishes.

    Parameters:
        tmp_path: Isolated configured whitelist directory.
    """
    _module_factory = ModuleFactory()
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    configured = tmp_path / "personal-whitelist.conf"
    backup = tmp_path / "personal-whitelist.conf.bak"
    backup.write_text("domain,example.com,both,alerts\n", encoding="utf-8")
    (metadata / "run.yaml").write_text(
        "whitelists:\n  enable_local_whitelist: true\n"
        f"  local_whitelist_path: {configured}\n",
        encoding="utf-8",
    )
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.redis = Mock()
    reader.redis.hexists.return_value = False
    reader.response_metadata = Mock(
        return_value={"backend_status": {"connected": True}}
    )

    reader.save_whitelist_rule(
        "add", "192.0.2.4", "src", "alerts", "ARP_SCAN"
    )

    content = configured.read_text(encoding="utf-8")
    assert "domain,example.com,both,alerts" in content
    assert "ip,192.0.2.4,src,alerts,ARP_SCAN" in content
    assert backup.read_text(encoding="utf-8") == content
    reader.redis.hset.assert_called_once()


def test_web_uri_whitelist_persists_and_can_be_removed(tmp_path) -> None:
    """Keep the AirPlay request text in the configured whitelist file.

    Parameters:
        tmp_path: Isolated configured whitelist directory.
    """
    factory = ModuleFactory()
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    configured = tmp_path / "whitelist.conf"
    configured.write_text("", encoding="utf-8")
    (metadata / "run.yaml").write_text(
        "whitelists:\n  enable_local_whitelist: true\n"
        f"  local_whitelist_path: {configured}\n",
        encoding="utf-8",
    )
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.redis = Mock()
    reader.redis.hexists.return_value = False
    reader.response_metadata = Mock(
        return_value={"backend_status": {"connected": True}}
    )
    uri = "/info?txtAirPlay&txtRAOP RTSP/1."

    saved = reader.save_whitelist_rule("add", uri, "both", "flows", None, "uri")

    assert saved["rule_type"] == "uri"
    assert f"uri,{uri},both,flows" in configured.read_text(encoding="utf-8")
    whitelist = factory.create_whitelist_obj()
    whitelist.parser.local_whitelist_path = str(configured)
    whitelist.parser.parse()
    assert whitelist.parser.whitelisted_uris[uri] == {
        "from": "both",
        "what_to_ignore": "flows",
    }
    reader.redis.hset.assert_called_once()
    assert reader.redis.hset.call_args.args[0] == "whitelist_uris"

    reader.save_whitelist_rule("remove", uri, "both", "flows", None, "uri")
    assert uri not in configured.read_text(encoding="utf-8")
    reader.redis.hdel.assert_called_once_with("whitelist_uris", uri)


def test_web_whitelist_can_scope_ip_to_alert_type(tmp_path) -> None:
    """Persist a source IP rule for one detector without hiding flows.

    Parameters:
        tmp_path: Isolated configured whitelist directory.
    """
    factory = ModuleFactory()
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    configured = tmp_path / "whitelist.conf"
    configured.write_text("", encoding="utf-8")
    (metadata / "run.yaml").write_text(
        "whitelists:\n  enable_local_whitelist: true\n"
        f"  local_whitelist_path: {configured}\n",
        encoding="utf-8",
    )
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.redis = Mock()
    reader.redis.hexists.return_value = False
    reader.response_metadata = Mock(
        return_value={"backend_status": {"connected": True}}
    )

    saved = reader.save_whitelist_rule(
        "add", "192.0.2.4", "src", "alerts", "ARP_SCAN"
    )

    assert saved["evidence_type"] == "ARP_SCAN"
    managed = configured
    assert "ip,192.0.2.4,src,alerts,ARP_SCAN" in managed.read_text(
        encoding="utf-8"
    )
    whitelist = factory.create_whitelist_obj()
    whitelist.parser.local_whitelist_path = str(configured)
    whitelist.parser.parse()
    assert (
        whitelist.parser.whitelisted_ips["192.0.2.4|ARP_SCAN"]["evidence_type"]
        == "ARP_SCAN"
    )

    reader.save_whitelist_rule(
        "remove", "192.0.2.4", "src", "alerts", "ARP_SCAN"
    )
    assert "ip,192.0.2.4,src,alerts,ARP_SCAN" not in managed.read_text(
        encoding="utf-8"
    )
    reader.redis.hdel.assert_called_once_with(
        "whitelist_IPs", "192.0.2.4|ARP_SCAN"
    )


def test_web_whitelist_migrates_existing_sidecar(tmp_path: Path) -> None:
    """Move old web rules into the configured file on the next save."""
    _module_factory = ModuleFactory()
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    configured = tmp_path / "whitelist.conf"
    configured.write_text("ip,192.0.2.1,both,alerts\n", encoding="utf-8")
    legacy = tmp_path / "whitelist.conf.web.conf"
    legacy.write_text("ip,192.0.2.5,src,alerts,ARP_SCAN\n", encoding="utf-8")
    (metadata / "run.yaml").write_text(
        "whitelists:\n  enable_local_whitelist: true\n"
        f"  local_whitelist_path: {configured}\n",
        encoding="utf-8",
    )
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.redis = Mock()
    reader.redis.hexists.return_value = False
    reader.response_metadata = Mock(
        return_value={"backend_status": {"connected": True}}
    )

    reader.save_whitelist_rule("add", "192.0.2.6", "src", "alerts")

    content = configured.read_text(encoding="utf-8")
    assert "ip,192.0.2.5,src,alerts,ARP_SCAN" in content
    assert "ip,192.0.2.6,src,alerts" in content
    assert not legacy.exists()


@pytest.mark.parametrize(
    "ignored, evidence_type",
    [("flows", "ARP_SCAN"), ("alerts", "NOT_A_DETECTION")],
)
def test_web_whitelist_rejects_invalid_alert_scope(
    ignored: str, evidence_type: str
) -> None:
    """Reject scoped flow rules and unknown detector names.

    Parameters:
        ignored: Requested suppression class.
        evidence_type: Requested detection name.
    """
    _factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)

    with pytest.raises(ValueError):
        reader.save_whitelist_rule(
            "add", "192.0.2.4", "src", ignored, evidence_type
        )


@pytest.mark.parametrize("dst_port", [None, 902])
def test_local_web_request_can_add_whitelist_rule(dst_port: int | None) -> None:
    """Route legacy and destination-port requests to the whitelist writer.

    Parameters:
        dst_port: Optional new condition in the JSON request.
    """
    _module_factory = ModuleFactory()
    reader = Mock()
    reader.save_whitelist_rule.return_value = {
        "action": "add",
        "value": "192.0.2.4:443",
        "direction": "dst",
        "ignore": "alerts",
    }
    server = SlipsHTTPServer(("127.0.0.1", 0), RequestHandler, reader)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    utils.start_thread(worker, Mock())
    request = Request(
        f"http://127.0.0.1:{server.server_address[1]}/api/whitelists",
        data=json.dumps(
            {
                "action": "add",
                "value": "192.0.2.4:443",
                "direction": "dst",
                "ignore": "alerts",
                **({"dst_port": dst_port} if dst_port is not None else {}),
            }
        ).encode(),
        headers={
            "Content-Type": "application/json",
            "Cookie": f"{SESSION_COOKIE_NAME}={issue_token()}",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:
            assert response.status == 200
            assert json.load(response)["value"] == "192.0.2.4:443"
        reader.save_whitelist_rule.assert_called_once_with(
            "add", "192.0.2.4:443", "dst", "alerts",
            **({"dst_port": dst_port} if dst_port is not None else {}),
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


@pytest.mark.parametrize("requires_password", [True, False])
def test_remote_whitelist_write_requires_web_login(
    requires_password: bool,
) -> None:
    """Permit authenticated remote writes and reject unprotected ones.

    Parameters:
        requires_password: Whether web login protects this listener.
    """
    _module_factory = ModuleFactory()
    body = json.dumps(
        {
            "action": "add",
            "value": "192.0.2.4:443",
            "direction": "dst",
            "ignore": "alerts",
        }
    ).encode()
    reader = Mock()
    reader.save_whitelist_rule.return_value = {"value": "192.0.2.4:443"}
    handler = RequestHandler.__new__(RequestHandler)
    handler.path = "/api/whitelists"
    handler.client_address = ("192.168.1.20", 54321)
    handler.headers = {
        "Host": "192.168.1.10:55000",
        "Origin": "http://192.168.1.10:55000",
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    }
    handler.rfile = BytesIO(body)
    handler.server = SimpleNamespace(reader=reader)
    handler._send_json = Mock()
    handler._require_password = Mock(return_value=requires_password)
    handler._session_ok = Mock(return_value=True)

    handler.do_POST()

    if requires_password:
        reader.save_whitelist_rule.assert_called_once_with(
            "add", "192.0.2.4:443", "dst", "alerts"
        )
        handler._send_json.assert_called_once_with(
            reader.save_whitelist_rule.return_value
        )
    else:
        reader.save_whitelist_rule.assert_not_called()
        handler._send_json.assert_called_once_with(
            {"error": "Remote whitelist changes require web login"},
            HTTPStatus.FORBIDDEN,
        )


def test_whitelisted_evidence_explains_ip_port_rule() -> None:
    """Report an exact IP:port rule that excluded later evidence."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    record = {
        "dst_port": 443,
        "victim": {
            "value": "2001:db8::1",
            "ioc_type": "IP",
            "direction": "DST",
        },
    }
    rules = [
        {
            "type": "IP address",
            "value": "[2001:db8::1]:443",
            "direction": "dst",
            "ignore": "alerts",
            "effect": "Suppressed",
        }
    ]

    matches = reader._whitelist_matches_for_record(record, rules)

    assert len(matches) == 1
    assert matches[0]["rule"] == "[2001:db8::1]:443"


def test_whitelisted_evidence_reports_matching_victim_rule() -> None:
    """Explain why Slips retained evidence but did not add it to the score."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader._runtime_whitelist_rules = Mock(
        return_value=[
            {
                "type": "IP address",
                "value": "147.32.80.37",
                "direction": "both",
                "ignore": "alerts",
                "effect": "Suppresses evidence and alerts.",
            }
        ]
    )
    items = [
        {
            "id": "evidence-1",
            # persisted by Evidence Handler in SQLite's evidence.whitelisted
            "whitelisted": 1,
            "attacker": {
                "value": "91.231.89.211",
                "ioc_type": "IP",
                "direction": "SRC",
            },
            "victim": {
                "value": "147.32.80.37",
                "ioc_type": "IP",
                "direction": "DST",
            },
        }
    ]

    reader._annotate_whitelisted_evidence(items)

    assert items[0]["whitelisted"] is True
    assert items[0]["whitelist_matches"] == [
        {
            "entity": "victim",
            "type": "IP address",
            "value": "147.32.80.37",
            "rule": "147.32.80.37",
            "direction": "both",
            "ignore": "alerts",
            "effect": "Suppresses evidence and alerts.",
        }
    ]


def test_configuration_and_whitelist_tabs_are_wired() -> None:
    """Keep both run-inspection tabs and evidence exclusion UI reachable."""
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    index_source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )
    server_source = Path("modules/web_interface/server.py").read_text(
        encoding="utf-8"
    )

    assert 'data-tab="configuration"' in index_source
    assert 'data-tab="whitelists"' in index_source
    assert 'id="configuration-sections"' in index_source
    assert 'id="whitelists-table"' in index_source
    assert "function whitelistHandling" not in app_source
    assert "const whitelistHandling" in app_source
    assert 'path == "/api/configuration"' in server_source
    assert 'path == "/api/whitelists"' in server_source


def test_overview_prioritizes_operational_data() -> None:
    """Keep supporting metadata and logs out of the operational overview."""
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    server_source = Path("modules/web_interface/server.py").read_text(
        encoding="utf-8"
    )
    index_source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )
    overview = index_source.split('<section id="overview"', 1)[1].split(
        '<section id="logs"', 1
    )[0]
    metadata = index_source.split('<section id="metadata"', 1)[1].split(
        '<section id="alerts"', 1
    )[0]

    assert (
        'rel="icon" href="/slips-logo.png?v=4" type="image/png" sizes="512x512"'
        in index_source
    )
    assert 'data-tab="logs"' in index_source
    assert 'data-tab="metadata"' in index_source
    assert 'id="logs-table"' in index_source
    assert 'id="run-metadata"' in index_source
    assert 'id="metadata-device"' in metadata
    assert 'id="modules-table"' in metadata
    assert 'id="modules-table"' not in overview
    assert 'api("metadataOverview", `/api/overview${state.networkOnly' in app_source
    assert "Data sources" not in overview
    assert "Run metadata" not in overview
    assert "Recent log events" not in overview
    assert 'id="overview-status"' in overview
    assert 'id="overview-system"' in overview
    assert 'id="summary-cards"' in overview
    assert 'id="overview-details" hidden' in overview
    assert "function renderOverviewStatus(data)" in app_source
    assert "function renderOverviewSystem(data)" in app_source
    assert '["Firewall blocks", firewall.current' in app_source
    assert 'sort: "cpu_percent", order: "desc"' in app_source
    assert 'id="load-module-evidence" disabled' in index_source
    assert '`/api/overview/evidence-counts${scope}`' in app_source
    assert "async function loadOverviewEvidenceCounts" in app_source
    assert "document.title = `Slips ${compact" in app_source
    assert 'api("liveTitleCounts", `/api/live-counts${params.size' in app_source
    assert 'path == "/api/live-counts"' in server_source
    assert "updatePageTitle({ alerts: data.counts.alerts" not in app_source
    assert "updatePageTitle({ [name]: payload.full_total" not in app_source


@pytest.mark.parametrize(
    "input_type, offset",
    [("interface", 0), ("file", -5 * 24 * 60 * 60)],
)
def test_live_title_counts_match_alert_and_host_ranges(
    tmp_path: Path, input_type: str, offset: int
) -> None:
    """Count only alerts and hosts in the live window for each input clock.

    Parameters:
        tmp_path: Isolated run databases.
        input_type: Live capture or saved-file input.
        offset: Age of the newest saved-file events.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "history.sqlite"
    reader.redis = Mock()
    reader.redis.hget.return_value = input_type
    newest = time.time() + offset
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("CREATE TABLE alerts (alert_time REAL)")
        connection.executemany(
            "INSERT INTO alerts VALUES (?)",
            [(newest - 60,), (newest - 7200,)],
        )
    with sqlite3.connect(reader.history_path) as connection:
        connection.execute(
            "CREATE TABLE host_snapshots (ip TEXT, observed_at REAL)"
        )
        connection.execute(
            "CREATE TABLE flow_index (event_time REAL, src_ip TEXT, dst_ip TEXT)"
        )
        connection.executemany(
            "INSERT INTO host_snapshots VALUES (?, ?)",
            [
                ("192.0.2.1", newest - 5000),
                ("192.0.2.2", newest - 7200),
                ("192.0.2.3", newest - 300),
            ],
        )
        connection.executemany(
            "INSERT INTO flow_index VALUES (?, ?, ?)",
            [
                (newest - 120, "192.0.2.1", "192.0.2.10"),
                (newest - 7200, "192.0.2.2", "192.0.2.10"),
            ],
        )

    assert reader.live_counts() == {"alerts": 1, "hosts": 2}


def test_live_title_poll_continues_when_tab_is_hidden() -> None:
    """The title's timer must fetch counts while the browser tab is hidden."""
    _module_factory = ModuleFactory()
    if not shutil.which("node"):
        pytest.skip("Node.js is required for the browser title timer test")
    script = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('modules/web_interface/app.js', 'utf8');
const definition = source.match(/function startLiveTitlePolling\(\) \{[\s\S]*?\n\}/);
assert.ok(definition);
let requests = 0;
let tick;
let finish;
const context = {
  document: { hidden: true }, state: { titleTimer: null },
  window: {
    clearTimeout() {},
    setTimeout(callback, interval) {
      assert.equal(interval, 30000);
      tick = callback;
      return 1;
    },
  },
  loadLiveTitleCounts() {
    requests += 1;
    return new Promise(resolve => { finish = resolve; });
  },
};
(async () => {
  vm.createContext(context);
  vm.runInContext(definition[0], context);
  context.startLiveTitlePolling();
  assert.equal(requests, 1);
  assert.equal(tick, undefined, 'a pending request must not schedule another');
  finish();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(typeof tick, 'function');
  tick();
  assert.equal(requests, 2, 'hidden title counts still refresh at a slower rate');
  finish();
})().catch(error => { console.error(error); process.exitCode = 1; });
"""
    result = subprocess.run(
        ["node", "-e", script],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("mode", ["individual", "grouped", "type", "host"])
def test_evidence_middle_list_survives_selection_and_refresh(mode: str) -> None:
    """Keep actual browser record lists populated during navigation and refresh.

    Parameters:
        mode: Ungrouped records or a supported evidence grouping.
    """
    _factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    assets = Path("modules/web_interface")
    script = (assets / "app.js").read_text().split(
        "let viewPreferencesTimer = null;", 1
    )[0]
    records = [
        {"id": f"record-{index}", "profile_ip": "192.0.2.1",
         "evidence_type": "UNKNOWN_PORT", "module": "conn_analyzer",
         "timestamp": 1793000000 + index, "threat_level": "medium",
         "confidence": 0.8, "flow_count": 1, "alert_ids": [],
         "description": f"Unknown port connection {index}",
         "alert_score": index / 10, "alert_threshold": 1.2}
        for index in range(1, 4)
    ]
    errors = []
    queries = []

    def respond(route: object) -> None:
        """Serve real UI assets and bounded evidence without a Slips backend.

        Parameters:
            route: Intercepted browser HTTP request.
        """
        from urllib.parse import parse_qs, urlparse

        url = urlparse(route.request.url)
        query = parse_qs(url.query)
        if url.path == "/":
            route.fulfill(path=str(assets / "index.html"))
        elif url.path == "/app.js":
            route.fulfill(body="", content_type="text/javascript")
        elif url.path == "/style.css":
            route.fulfill(path=str(assets / "style.css"))
        elif url.path == "/api/evidence":
            queries.append(query)
            items = [{**records[0], "id": "group-1", "evidence_count": 3, "alert_count": 0}] if query.get("group") else list(records)
            if query.get("sort") == ["score"]:
                items.sort(key=lambda row: row["alert_score"], reverse=query.get("order") == ["desc"])
            route.fulfill(json={"items": items, "total": len(items), "page_size": len(items), "next_cursor": None})
        else:
            route.fulfill(json={"items": [], "total": 0, "names": {}})

    with playwright.sync_playwright() as engine:
        try:
            browser = engine.chromium.launch(channel="chrome", headless=True)
        except playwright.Error as error:
            pytest.skip(f"Chrome is required for browser evidence checks: {error}")
        try:
            page = browser.new_page(viewport={"width": 2000, "height": 1000})
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.route("**/*", respond)
            page.goto("http://slips.test/")
            page.add_script_tag(content=script)
            page.evaluate("""async mode => {
              state.activeTab = 'evidence';
              document.querySelectorAll('main > .panel').forEach(panel => panel.classList.remove('active'));
              byId('evidence').classList.add('active');
              byId('evidence-view').value = mode;
              await loadEvidence();
              if (mode !== 'individual') selectEvidenceGroup(state.pages.evidence.items[0]);
            }""", mode)
            rows = page.locator("#evidence-records-table tbody tr[data-clickable]")
            rows.first.wait_for()
            assert rows.count() == 3
            rows.first.click()
            page.wait_for_function("state.evidenceDetail.record?.id === 'record-1'")
            assert rows.count() == 3
            page.locator("#evidence-detail button", has_text="next ↓").click()
            page.wait_for_function("state.evidenceDetail.record?.id === 'record-2'")
            assert page.locator("#evidence-records-table tr.selected").get_attribute("data-evidence-id") == "record-2"
            rows.nth(1).focus()
            before = len(queries)
            page.evaluate("async () => { await loadEvidence(); await loadEvidence(); }")
            assert len(queries) == before + 2
            assert rows.count() == 3
            assert page.locator("#evidence-records-table tr.selected").get_attribute("data-evidence-id") == "record-2"
            assert page.evaluate("document.activeElement.dataset.evidenceId") == "record-2"
            page.locator("#evidence-record-sort-score").click()
            page.wait_for_function("document.querySelector('#evidence-records-table tbody tr')?.dataset.evidenceId === 'record-3'")
            assert rows.count() == 3
            assert not errors, errors
        finally:
            browser.close()


@pytest.mark.parametrize("timestamp,status,uncertain", [
    (254.819068, "certificate is not yet valid", True),
    (0, "certificate has expired", True),
    (None, "certificate is not yet valid", True),
    ("invalid timestamp", "certificate has expired", True),
    (1440000000, "certificate is not yet valid", False),
    ("2015-08-19T00:00:00Z", "certificate has expired", False),
    (1440000000, "ok", False),
    (254.819068, "self signed certificate", False),
    (254.819068, "unable to get local issuer certificate", False),
])
def test_tls_validation_uses_capture_clock(
    timestamp: float | str | None, status: str, uncertain: bool
) -> None:
    """Distinguish missing capture dates from recorded TLS chain failures.

    Parameters:
        timestamp: Recorded capture time, which may be relative or missing.
        status: Original sensor validation text that must remain unchanged.
        uncertain: Whether the date-specific result cannot be interpreted.
    """
    _factory = ModuleFactory()
    if not shutil.which("node"):
        pytest.skip("Node.js is required for TLS presentation checks")
    fixture = json.dumps({"starttime": timestamp, "validation_status": status})
    script = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('modules/web_interface/app.js', 'utf8');
const context = {Date: class extends Date {
  static now() { throw new Error('Must not validate against today'); }
}};
vm.createContext(context);
for (const name of ['flowValue', 'tlsValidationStatus', 'protocolOutcome']) {
  const definition = source.match(new RegExp('function ' + name + '\\([^]*?\\n\\}'));
  assert.ok(definition, name);
  vm.runInContext(definition[0], context);
}
const flow = FIXTURE;
const original = JSON.stringify(flow);
const result = context.tlsValidationStatus(flow);
assert.equal(result.uncertain, UNCERTAIN);
assert.equal(result.text, UNCERTAIN ? 'Certificate dates unknown' : flow.validation_status);
assert.equal(context.protocolOutcome('ssl', flow), result.text);
assert.ok(result.note.includes('capture') || result.note.includes('captured'));
assert.equal(JSON.stringify(flow), original, 'The source result must remain intact');
""".replace("FIXTURE", fixture).replace("UNCERTAIN", json.dumps(uncertain))
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr


def test_overview_uses_counter_without_scanning_retained_evidence(
    tmp_path: Path,
) -> None:
    """Keep the first Overview response independent of retained Redis size.

    Parameters:
        tmp_path: Isolated output directory for durable web data.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "history.sqlite"
    reader.redis_port = 6379
    reader.redis = Mock()
    reader.redis.hgetall.side_effect = lambda key: (
        {
            "wlan0": json.dumps(
                {
                    "interface": "wlan0",
                    "connected": True,
                    "host_ip": "10.0.0.25",
                    "local_network": "10.0.0.0/24",
                    "gateway_ip": "10.0.0.1",
                    "dns_servers": ["10.0.0.53"],
                    "changed_at": 100.0,
                }
            )
        }
        if key == "network_states"
        else {"analysis_start": "100"} if key == "analysis" else {}
    )
    redis_values = {
        "number_of_alerts": "0",
        "number_of_evidence": "123456",
        "processed_flows_by_profiler_so_far": "42",
    }
    reader.redis.get.side_effect = redis_values.get
    reader._redis_evidence = Mock(
        side_effect=AssertionError("Overview must not scan retained evidence")
    )
    reader._module_rows = Mock(return_value=[])
    reader._firewall_overview = Mock(
        return_value={
            "current": 0,
            "added": 0,
            "discarded": 0,
            "impact": {"packets": 0, "flows": 0, "evidence": 0},
        }
    )
    initialize_history(reader.history_path)
    with connect_history(reader.history_path) as history:
        history.executemany(
            "INSERT INTO error_events(event_time,module,message,line) VALUES (?,?,?,?)",
            [(90, "OldModule", "old", "old"), (110, "Profiler", "current", "current")],
        )
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("CREATE TABLE alerts (alert_id TEXT)")
        connection.execute("CREATE TABLE evidence (evidence_id TEXT)")

    result = reader.overview()

    assert result["counts"]["evidence"] == 123456
    assert result["network_states"][0]["dns_servers"] == ["10.0.0.53"]
    assert "computer_addresses" in result
    assert "computer_name" in result
    assert result["evidence_details_loaded"] is False
    reader._redis_evidence.assert_not_called()
    assert result["counts"]["module_errors"] == 1
    assert [item["module"] for item in result["recent_errors"]] == ["Profiler"]
    reader._module_rows.assert_called_once_with(None, {"Profiler": 1}, False)


@pytest.mark.parametrize(
    "input_type, finished, live_ip, expected_refresh",
    [
        ("interface", False, "10.0.1.25", True),
        ("interface", False, "10.0.0.25", False),
        ("interface", True, "10.0.1.25", False),
        ("pcap", False, "10.0.1.25", False),
    ],
)
def test_network_panel_uses_current_interface_after_saved_state_stalls(
    input_type: str,
    finished: bool,
    live_ip: str,
    expected_refresh: bool,
) -> None:
    """Refresh a stale live network card without changing saved history.

    Parameters:
        input_type: Run input kind.
        finished: Whether the run already ended.
        live_ip: Current address seen by the operating system.
        expected_refresh: Whether live collection should replace the card.
    """
    _module_factory = ModuleFactory()
    analysis = {
        "input_type": input_type,
        "interface": "en0",
        "analysis_end": "done" if finished else "",
    }
    saved = {
        "interface": "en0",
        "addresses": [{"ip": "10.0.0.25"}],
        "host_ip": "10.0.0.25",
        "changed_at": 100.0,
    }
    current = {
        "interface": "en0",
        "addresses": [{"ip": live_ip}],
        "host_ip": live_ip,
        "gateway_ip": "10.0.1.1",
    }
    with patch(
        "modules.web_interface.server.collect_network_state",
        return_value=current,
    ) as collect:
        result = RunDataReader._current_network_states(
            analysis,
            [saved],
            {"ipv4": [live_ip], "ipv6": []},
        )

    if expected_refresh:
        collect.assert_called_once_with("en0", 1)
        assert result[0]["host_ip"] == live_ip
        assert result[0]["live_reading"] is True
        assert result[0]["saved_changed_at"] == 100.0
        assert "live_reading" not in saved
    else:
        collect.assert_not_called()
        assert result == [saved]


def test_save_network_name_labels_router_and_early_run_records(
    tmp_path: Path,
) -> None:
    """Persist a current network name without attaching it to another router.

    Parameters:
        tmp_path: Isolated permanent database location.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = Path("output/test-run")
    reader.host_profiles_path = tmp_path / "hosts.sqlite"
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {
        "input_type": "interface",
        "interface": "en0",
    }
    saved_state = {
        "gateway_mac": "aa:bb:cc:dd:ee:01",
        "history": [],
    }
    reader.redis.hget.side_effect = lambda key, field: {
        ("PIDs", "main"): "123",
        ("network_states", "en0"): json.dumps(saved_state),
    }.get((key, field))
    current = {
        "connected": True,
        "gateway_mac": "aa:bb:cc:dd:ee:01",
    }
    with patch(
        "modules.web_interface.server.collect_network_state",
        return_value=current,
    ):
        result = reader.save_network_name(
            "en0", "gateway:aa:bb:cc:dd:ee:01", "Home Wi-Fi"
        )
        with pytest.raises(ValueError, match="network changed"):
            reader.save_network_name(
                "en0", "gateway:aa:bb:cc:dd:ee:02", "Wrong router"
            )

    assert result == {
        "network_id": "gateway:aa:bb:cc:dd:ee:01",
        "name": "Home Wi-Fi",
    }
    assert HostProfileStore.network_names(
        reader.host_profiles_path,
        ["gateway:aa:bb:cc:dd:ee:01", "run:output/test-run:123"],
    ) == {
        "gateway:aa:bb:cc:dd:ee:01": "Home Wi-Fi",
        "run:output/test-run:123": "Home Wi-Fi",
    }
    assert reader._named_network_states([current])[0]["name"] == ("Home Wi-Fi")


def test_network_name_without_router_mac_is_scoped_to_current_run(
    tmp_path: Path,
) -> None:
    """Keep an unknown router's name separate from another run.

    Parameters:
        tmp_path: Isolated permanent database location.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = Path("output/test-run")
    reader.host_profiles_path = tmp_path / "hosts.sqlite"
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {
        "input_type": "interface",
        "interface": "en0",
    }
    reader.redis.hget.side_effect = lambda key, field: (
        "123" if (key, field) == ("PIDs", "main") else None
    )
    current = {"connected": True, "gateway_mac": ""}
    with patch(
        "modules.web_interface.server.collect_network_state",
        return_value=current,
    ):
        result = reader.save_network_name(
            "en0", "run:output/test-run:123", "Hotel Ethernet"
        )

    assert result["name"] == "Hotel Ethernet"
    assert reader._named_network_states([current])[0]["name"] == (
        "Hotel Ethernet"
    )
    assert HostProfileStore.network_names(
        reader.host_profiles_path,
        ["run:output/test-run:123", "run:output/another-run:456"],
    ) == {"run:output/test-run:123": "Hotel Ethernet"}


def test_historical_host_network_can_be_named_explicitly(
    tmp_path: Path,
) -> None:
    """Let a user identify an older unknown network without guessing its router.

    Parameters:
        tmp_path: Isolated permanent database location.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    store = HostProfileStore(path, "old-run", lambda _: {}, [])
    store.observe_hostname("printer", "profile_192.168.1.20")
    reader = RunDataReader.__new__(RunDataReader)
    reader.host_profiles_path = path

    saved = reader.save_profile_network_name(
        "192.168.1.20", "run:old-run", "Previous home Wi-Fi"
    )

    assert saved["name"] == "Previous home Wi-Fi"
    assert (
        HostProfileStore.read(path, "192.168.1.20")[0]["network_label"]
        == "Previous home Wi-Fi"
    )
    with pytest.raises(ValueError, match="unavailable"):
        reader.save_profile_network_name(
            "192.168.1.20", "run:another-network", "Wrong network"
        )
    with pytest.raises(ValueError, match="at most 80"):
        reader.save_profile_network_name(
            "192.168.1.20", "run:old-run", "x" * 81
        )


def test_detection_network_is_resolved_by_event_time(tmp_path: Path) -> None:
    """Resolve historical detections to the network seen at their timestamp.

    Parameters:
        tmp_path: Isolated permanent profile database location.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    HostProfileStore(path, "run-one", lambda _: {}, [])
    with sqlite3.connect(path) as connection:
        connection.executemany(
            "INSERT INTO hosts VALUES (?, ?, ?, ?, ?)",
            [
                (
                    "gateway:aa:aa:aa:aa:aa:aa",
                    "192.168.1.20",
                    "Old Wi-Fi",
                    100,
                    200,
                ),
                (
                    "gateway:bb:bb:bb:bb:bb:bb",
                    "192.168.1.20",
                    "New Wi-Fi",
                    300,
                    400,
                ),
            ],
        )
        connection.execute(
            "INSERT INTO network_names VALUES (?, ?)",
            ("gateway:bb:bb:bb:bb:bb:bb", "Current Wi-Fi"),
        )
        connection.execute(
            "INSERT INTO host_endpoint_observations "
            "SELECT network_id,ip,first_seen,last_seen FROM hosts"
        )

    assert HostProfileStore.network_for_observation(
        path, "192.168.1.20", 150
    ) == {
        "network_id": "gateway:aa:aa:aa:aa:aa:aa",
        "network_name": "",
        "network_label": "Old Wi-Fi",
    }
    assert HostProfileStore.network_for_observation(
        path, "192.168.1.20", 350
    ) == {
        "network_id": "gateway:bb:bb:bb:bb:bb:bb",
        "network_name": "Current Wi-Fi",
        "network_label": "Current Wi-Fi",
    }
    assert (
        HostProfileStore.network_for_observation(path, "192.168.1.20", 250)[
            "network_label"
        ]
        == "Unknown network (not recorded)"
    )
    reader = RunDataReader.__new__(RunDataReader)
    reader.host_profiles_path = path
    grouped_item = {
        "profile_ip": "192.168.1.20",
        "first_timestamp": 150,
        "timestamp": 350,
    }
    reader._annotate_detection_networks(
        [grouped_item], "profile_ip", "timestamp", "first_timestamp"
    )
    assert grouped_item["network_label"] == "Multiple networks"


def test_detection_network_uses_capture_state_between_host_sightings(
    tmp_path: Path,
) -> None:
    """Attribute local detections from interface history across sparse flows.

    Parameters:
        tmp_path: Isolated permanent database directory.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "hosts.sqlite"
    HostProfileStore(path, "test-run", lambda _: {}, [])
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO hosts VALUES (?, ?, ?, ?, ?)",
            ("gateway:aa:aa:aa:aa:aa:aa", "192.168.1.20", "Old", 100, 100),
        )
        connection.executemany(
            "INSERT INTO network_names VALUES (?, ?)",
            [
                ("gateway:aa:aa:aa:aa:aa:aa", "Home Wi-Fi"),
                ("gateway:bb:bb:bb:bb:bb:bb", "Guest Wi-Fi"),
            ],
        )
    old = {
        "connected": True,
        "changed_at": 50,
        "local_network": "192.168.1.0/24",
        "gateway_mac": "aa:aa:aa:aa:aa:aa",
    }
    current = {
        "connected": True,
        "changed_at": 150,
        "local_network": "192.168.1.0/24",
        "gateway_mac": "bb:bb:bb:bb:bb:bb",
        "history": [old],
    }
    reader = RunDataReader.__new__(RunDataReader)
    reader.host_profiles_path = path
    reader.output_dir = Path("output/test-run")
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {"en0": json.dumps(current)}
    reader.redis.hget.return_value = "123"
    items = [
        {"profile_ip": "192.168.1.20", "timestamp": 140},
        {"profile_ip": "192.168.1.20", "timestamp": 175},
        {"profile_ip": "fe80::1234", "timestamp": 175},
        {
            "profile_ip": "192.168.1.20",
            "first_timestamp": 140,
            "timestamp": 175,
        },
        {"profile_ip": "192.168.1.20", "timestamp": 25},
        {"profile_ip": "10.0.0.20", "timestamp": 175},
    ]

    reader._annotate_detection_networks(
        items, "profile_ip", "timestamp", "first_timestamp"
    )

    assert [item["network_label"] for item in items] == [
        "Home Wi-Fi",
        "Guest Wi-Fi",
        "Guest Wi-Fi",
        "Multiple networks",
        "Unknown network (not recorded)",
        "Unknown network (not recorded)",
    ]


@pytest.mark.parametrize(
    "origin,expected_status",
    [
        ("http://127.0.0.1:55000", 200),
        ("http://unrelated.example", 403),
    ],
)
def test_network_name_post_requires_same_origin(
    origin: str, expected_status: int
) -> None:
    """Accept JSON edits from the page and reject another web origin.

    Parameters:
        origin: Origin supplied by the browser.
        expected_status: HTTP response status.
    """
    _module_factory = ModuleFactory()
    body = json.dumps(
        {
            "interface": "en0",
            "network_id": "gateway:aa:bb:cc:dd:ee:01",
            "name": "Home Wi-Fi",
        }
    ).encode()
    reader = Mock()
    reader.save_network_name.return_value = {
        "network_id": "gateway:aa:bb:cc:dd:ee:01",
        "name": "Home Wi-Fi",
    }
    handler = RequestHandler.__new__(RequestHandler)
    handler.path = "/api/network-name"
    handler.headers = {
        "Host": "127.0.0.1:55000",
        "Origin": origin,
        "Cookie": f"{SESSION_COOKIE_NAME}={issue_token()}",
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    }
    handler.rfile = BytesIO(body)
    handler.server = SimpleNamespace(reader=reader)
    handler._send_json = Mock()

    handler.do_POST()

    if expected_status == 200:
        assert handler._send_json.call_args.args == (
            reader.save_network_name.return_value,
        )
        reader.save_network_name.assert_called_once_with(
            "en0", "gateway:aa:bb:cc:dd:ee:01", "Home Wi-Fi"
        )
    else:
        assert handler._send_json.call_args.args[1] == expected_status
        reader.save_network_name.assert_not_called()


def test_network_name_post_routes_historical_profile() -> None:
    """The Host workspace editor passes the selected profile to the server."""
    _module_factory = ModuleFactory()
    body = json.dumps(
        {
            "ip": "192.168.1.20",
            "network_id": "run:old-run",
            "name": "Previous home Wi-Fi",
        }
    ).encode()
    reader = Mock()
    reader.save_profile_network_name.return_value = {
        "network_id": "run:old-run",
        "name": "Previous home Wi-Fi",
    }
    handler = RequestHandler.__new__(RequestHandler)
    handler.path = "/api/network-name"
    handler.headers = {
        "Host": "127.0.0.1:55000",
        "Origin": "http://127.0.0.1:55000",
        "Cookie": f"{SESSION_COOKIE_NAME}={issue_token()}",
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    }
    handler.rfile = BytesIO(body)
    handler.server = SimpleNamespace(reader=reader)
    handler._send_json = Mock()

    handler.do_POST()

    reader.save_profile_network_name.assert_called_once_with(
        "192.168.1.20", "run:old-run", "Previous home Wi-Fi"
    )
    reader.save_network_name.assert_not_called()


@pytest.mark.parametrize("triage", [{}, {"status": "to_analyze", "labels": ["lab"]}])
def test_host_annotation_post_saves_name_and_note(triage: dict) -> None:
    """Route the Host editor's fields to permanent storage.

    Parameters:
        triage: Optional workflow fields from the current editor.
    """
    _module_factory = ModuleFactory()
    body = json.dumps(
        {
            "ip": "192.168.1.20",
            "network_id": "gateway:aa:bb:cc:dd:ee:01",
            "name": "My iPad",
            "note": "Kitchen tablet",
            **triage,
        }
    ).encode()
    reader = Mock()
    reader.save_host_annotation.return_value = {
        "ip": "192.168.1.20",
        "name": "My iPad",
        "note": "Kitchen tablet",
    }
    handler = RequestHandler.__new__(RequestHandler)
    handler.path = "/api/host-annotation"
    handler.headers = {
        "Host": "127.0.0.1:55000",
        "Origin": "http://127.0.0.1:55000",
        "Cookie": f"{SESSION_COOKIE_NAME}={issue_token()}",
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    }
    handler.rfile = BytesIO(body)
    handler.server = SimpleNamespace(reader=reader)
    handler._send_json = Mock()

    handler.do_POST()

    reader.save_host_annotation.assert_called_once_with(
        "192.168.1.20",
        "gateway:aa:bb:cc:dd:ee:01",
        "My iPad",
        "Kitchen tablet",
        **triage,
    )
    handler._send_json.assert_called_once_with(
        reader.save_host_annotation.return_value
    )


def test_host_workspace_includes_permanent_identity_clues(
    tmp_path: Path,
) -> None:
    """Expose cross-run host names through the Host workspace response.

    Parameters:
        tmp_path: Isolated permanent host database location.
    """
    _module_factory = ModuleFactory()
    path = tmp_path / "host_profiles.sqlite"
    store = HostProfileStore(path, "old-run", lambda _: {}, [])
    store.observe_ip_info("8.8.8.8", {"reverse_dns": "dns.google"})
    reader = RunDataReader.__new__(RunDataReader)
    reader.host_profiles_path = path
    reader._live_host = Mock(
        return_value={
            "ip": "8.8.8.8",
            "observed_at": 100.0,
            "live": False,
        }
    )
    reader._attach_current_host_scores = Mock()
    reader._host_ips = Mock(return_value=["8.8.8.8"])
    reader._host_load = Mock(return_value={})
    reader._ti_for_ip = Mock(return_value={})
    reader.alerts = Mock(return_value={"total": 0, "items": []})
    reader._host_finding_stats = Mock(return_value={
        "8.8.8.8": {"evidence": 0, "peak": None, "threat_rank": -1},
    })

    host = reader.host("8.8.8.8")

    assert host["permanent_profiles"][0]["network_id"] == "public"
    assert host["permanent_profiles"][0]["facts"][0]["value"] == ("dns.google")


def test_overview_evidence_counts_scans_only_when_requested(
    tmp_path: Path,
) -> None:
    """Load retained evidence attribution through the explicit endpoint.

    Parameters:
        tmp_path: Isolated output directory for the empty durable database.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader._redis_evidence = Mock(
        return_value=[
            {"module": "arp"},
            {"module": "arp"},
            {"module": "flow_alerts"},
        ]
    )
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("CREATE TABLE evidence (evidence_id TEXT)")

    result = reader.overview_evidence_counts()

    assert result["evidence"] == 3
    assert result["modules"] == {"arp": 2, "flow_alerts": 1}
    assert result["source"] == "redis"
    reader._redis_evidence.assert_called_once_with()


@pytest.mark.parametrize(
    "analysis, now, expected",
    [
        ({"analysis_start": "100"}, 160.0, 60.0),
        (
            {"analysis_start": "100", "analysis_end": "130"},
            160.0,
            30.0,
        ),
        ({}, 160.0, None),
        ({"analysis_start": "200"}, 160.0, 0.0),
    ],
)
def test_run_uptime_seconds(
    analysis: dict, now: float, expected: float | None
) -> None:
    """Calculate live uptime and freeze completed run duration."""
    _module_factory = ModuleFactory()

    assert RunDataReader._run_uptime_seconds(analysis, now) == expected


def test_firewall_overview_counts_rule_transitions() -> None:
    """Expose active, added, and discarded enforcement totals."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.redis = Mock()
    reader.redis.zrange.return_value = [("10.0.0.1", 100.0)]
    reader.redis.hgetall.return_value = {
        "10.0.0.1": "{}",
        "10.0.0.2": "{}",
    }
    history = [
        {"action": "blocked", "ip": "10.0.0.1"},
        {"action": "blocked", "ip": "10.0.0.2"},
        {"action": "unblocked", "ip": "10.0.0.3"},
        {"action": "unblock failed", "ip": "10.0.0.4"},
    ]
    reader._firewall_history = Mock(return_value=history)
    reader._firewall_attack_estimate = Mock(
        return_value={"packets": 8, "flows": 3, "evidence": 1}
    )

    result = reader._firewall_overview()

    assert result == {
        "current": 2,
        "added": 2,
        "discarded": 1,
        "impact": {"packets": 8, "flows": 3, "evidence": 1},
    }
    reader._firewall_attack_estimate.assert_called_once_with(
        history, {"10.0.0.1": 100.0}
    )


def test_metadata_and_logs_endpoints_are_bounded(tmp_path: Path) -> None:
    """Read supporting run facts without loading the full overview."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.history_path = tmp_path / "history.sqlite"
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    (metadata_dir / "info.txt").write_text(
        "Slips version: 1.2.3\nBranch: local-web-page\nSlips start date: 50\n",
        encoding="utf-8",
    )
    initialize_history(reader.history_path)
    with connect_history(reader.history_path) as history:
        history.execute(
            "INSERT INTO error_events(event_time, module, message, line) "
            "VALUES (?, ?, ?, ?)",
            (100.0, "Profiler", "failed once", "raw line"),
        )

    metadata = reader.metadata()
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {}
    logs = reader.logs()

    assert metadata["items"]["Slips version"] == "1.2.3"
    assert metadata["items"]["Branch"] == "local-web-page"
    assert logs["total"] == 1
    assert logs["items"][0]["module"] == "Profiler"
    assert logs["items"][0]["message"] == "failed once"
    assert logs["items"][0]["line"] == "raw line"


def test_logs_show_the_final_exception_in_traceback_summary(
    tmp_path: Path,
) -> None:
    """Make the cause visible in the log table as well as the raw drawer."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.history_path = tmp_path / "history.sqlite"
    initialize_history(reader.history_path)
    with connect_history(reader.history_path) as history:
        history.execute(
            "INSERT INTO error_events(event_time, module, message, line) "
            "VALUES (?, ?, ?, ?)",
            (
                100.0,
                "brute_force_detector",
                "Traceback (most recent call last):",
                "Traceback (most recent call last):\n"
                '  File "detector.py", line 461\n'
                "RecursionError: maximum recursion depth exceeded",
            ),
        )

    item = reader.logs({"scope": ["history"]})["items"][0]
    assert (
        "RecursionError: maximum recursion depth exceeded" in item["message"]
    )
    assert '  File "detector.py", line 461' in item["line"]


def test_log_rows_open_the_colored_raw_console() -> None:
    """Keep each log row clickable with its exact source line visible."""
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    index_source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )
    style_source = Path("modules/web_interface/style.css").read_text(
        encoding="utf-8"
    )

    assert "function openLog(record)" in app_source
    assert 'openDrawer("RUNTIME LOG", record.module || "Slips")' in app_source
    assert "record.line || record.message" in app_source
    assert "], openLog);" in app_source
    assert "function appendHighlightedLogText" in app_source
    assert '<th data-sort="event_time">Time</th>' in index_source
    assert '<th data-sort="level">Level</th>' in index_source
    assert '<th data-sort="module">Module</th>' in index_source
    assert ".log-console-titlebar" in style_source
    assert ".log-console-level.critical" in style_source
    assert ".log-token-reference" in style_source


@pytest.mark.parametrize(
    "mode, expected_score, expected_threshold",
    [
        ("ratl", 1.6, 5.0),
        ("atl", 5.0, 15.0),
    ],
)
def test_score_fields_use_real_slips_detector_value(
    mode: str, expected_score: float, expected_threshold: float
) -> None:
    """Select the same ATL or RATL value that Slips compares to its threshold."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.score_mode = mode
    reader.alert_threshold = expected_threshold

    result = reader._score_fields(5.0, 1.6, "test capture")

    assert result["alert_score"] == expected_score
    assert result["alert_threshold"] == expected_threshold
    assert result["alert_score_mode"] == mode.upper()


def test_empty_notice_uid_is_not_reported_as_a_flow(tmp_path) -> None:
    """Ignore a historical Zeek notice link that contains no UID.

    Parameters:
        tmp_path: Isolated flow database location.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    reader.redis.hget.return_value = None
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "INSERT INTO evidence_flows VALUES ('notice-1', '')"
        )

    assert reader._flow_uids_for_evidence("notice-1") == []


def test_flows_for_evidence_falls_back_to_evidence_uids(tmp_path) -> None:
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    reader.redis.hget.return_value = None
    reader._redis_evidence = Mock(
        return_value=[{"id": "evidence-1", "uid": ["flow-1"]}]
    )
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE flows (uid TEXT, flow TEXT, label TEXT, "
            "profileid TEXT, twid TEXT, aid TEXT)"
        )
        connection.execute(
            "CREATE TABLE altflows (uid TEXT, flow TEXT, label TEXT, "
            "profileid TEXT, twid TEXT, flow_type TEXT)"
        )
        connection.execute(
            "INSERT INTO flows VALUES (?, ?, ?, ?, ?, ?)",
            (
                "flow-1",
                json.dumps({"saddr": "10.0.0.1"}),
                "benign",
                "",
                "",
                "",
            ),
        )

    result = reader.flows_for_evidence("evidence-1")

    assert result["total"] == 1
    assert result["items"][0]["uid"] == "flow-1"
    assert result["items"][0]["network_flow"]["table"] == "flows"
    assert result["items"][0]["protocol_flows"] == []
    assert result["network_flow_total"] == 1
    assert result["protocol_flow_total"] == 0


@pytest.mark.parametrize("primary", [True, False])
@pytest.mark.parametrize("protocol_count", [0, 23])
def test_flow_details_reads_only_selected_uid_with_protocol_pages(
    tmp_path: Path, primary: bool, protocol_count: int,
) -> None:
    """Keep primary data and every related record accessible through bounded reads.

    Parameters:
        tmp_path: Isolated run database.
        primary: Whether the connection record was retained.
        protocol_count: Number of retained protocol records sharing the UID.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    uid = "C'selected/flow+%"
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript("CREATE TABLE flows(uid TEXT,flow TEXT,label TEXT);"
            "CREATE INDEX flow_uid ON flows(uid);"
            "CREATE TABLE altflows(uid TEXT,flow TEXT,flow_type TEXT);"
            "CREATE INDEX alt_uid ON altflows(uid);")
        if primary:
            connection.execute("INSERT INTO flows VALUES (?,?,'malicious')", (uid, json.dumps({"saddr":"fe80::1", "daddr":"ff02::fb", "dport":5353})))
        for index in range(protocol_count):
            connection.execute("INSERT INTO altflows VALUES (?,?,'dns')", (uid, json.dumps({"query":f"query-{index}.local"})))
        connection.execute("INSERT INTO altflows VALUES ('unrelated','{}','http')")

    page = reader.flow_details(uid, {})
    assert page["uid"] == uid
    assert bool(page["network_flow"]) is primary
    if primary:
        assert page["network_flow"]["label"] == "malicious"
        assert page["network_flow"]["flow"]["dport"] == 5353
    assert page["protocol_flow_total"] == protocol_count
    assert len(page["protocol_flows"]) == min(protocol_count, 20)
    assert all(record["uid"] == uid and record["table"] == "altflows" for record in page["protocol_flows"])
    if protocol_count:
        second = reader.flow_details(uid, {"cursor":[page["next_cursor"]]})
        assert [row["flow"]["query"] for row in second["protocol_flows"]] == [f"query-{index}.local" for index in range(20, protocol_count)]
        assert second["next_cursor"] is None
    else:
        assert page["next_cursor"] is None
    assert reader.flow_details("missing", {})["protocol_flows"] == []


@pytest.mark.parametrize("limit,expected", [("bad",20),("0",1),("999",100)])
def test_flow_details_bounds_protocol_request(
    tmp_path: Path, limit: str, expected: int,
) -> None:
    """Bound protocol work even for invalid or oversized request limits.

    Parameters:
        tmp_path: Isolated legacy database containing only alternative flows.
        limit: Requested protocol page size.
        expected: Maximum returned records for the request.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("CREATE TABLE altflows(uid TEXT,flow TEXT,flow_type TEXT)")
        connection.executemany("INSERT INTO altflows VALUES ('u','{}','dns')", [()] * 105)
    result = reader.flow_details("u", {"limit":[limit]})
    assert result["network_flow"] is None
    assert len(result["protocol_flows"]) == expected
    assert result["next_cursor"] == str(expected)


def test_flow_details_route_decodes_uid_and_preserves_pagination() -> None:
    """Forward a URL-encoded flow UID and its protocol paging parameters."""
    _module_factory = ModuleFactory()
    handler = RequestHandler.__new__(RequestHandler)
    handler.server = Mock()
    handler.server.reader.flow_details.return_value = {"uid":"C/unsafe+%"}
    handler.server.reader.response_metadata.return_value = {}
    query = {"limit":["20"],"cursor":["40"]}
    assert handler._api_response("/api/flows/C%2Funsafe%2B%25", query)["uid"] == "C/unsafe+%"
    handler.server.reader.flow_details.assert_called_once_with("C/unsafe+%", query)


def test_flows_for_evidence_reads_durable_conn_and_altflows(tmp_path) -> None:
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE flows (uid TEXT, flow TEXT, label TEXT, "
            "profileid TEXT, twid TEXT, aid TEXT)"
        )
        connection.execute(
            "CREATE TABLE altflows (uid TEXT, flow TEXT, label TEXT, "
            "profileid TEXT, twid TEXT, flow_type TEXT)"
        )
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "INSERT INTO flows VALUES (?, ?, ?, ?, ?, ?)",
            (
                "flow-1",
                json.dumps({"saddr": "10.0.0.1"}),
                "benign",
                "",
                "",
                "",
            ),
        )
        connection.execute(
            "INSERT INTO altflows VALUES (?, ?, ?, ?, ?, ?)",
            (
                "flow-1",
                json.dumps(
                    {
                        "query": "aaa.com",
                        "qtype_name": "A",
                        "rcode_name": "NXDOMAIN",
                        "answers": [],
                    }
                ),
                "benign",
                "",
                "",
                "dns",
            ),
        )
        connection.execute(
            "INSERT INTO evidence_flows VALUES (?, ?)",
            ("evidence-1", "flow-1"),
        )
        connection.execute(
            "INSERT INTO evidence_flows VALUES (?, ?)",
            ("evidence-1", "older-flow-without-raw-record"),
        )

    result = reader.flows_for_evidence("evidence-1")

    assert result["total"] == 1
    assert result["network_flow_total"] == 1
    assert result["protocol_flow_total"] == 1
    assert result["linked_uid_count"] == 2
    assert result["unavailable_flow_count"] == 1
    group = result["items"][0]
    assert group["network_flow"]["table"] == "flows"
    assert group["protocol_flows"][0]["table"] == "altflows"
    assert group["protocol_flows"][0]["flow"]["query"] == "aaa.com"
    assert group["protocol_flows"][0]["flow"]["rcode_name"] == "NXDOMAIN"


def test_flows_for_evidence_recovers_pruned_dga_from_zeek(
    tmp_path: Path,
) -> None:
    """Show recent linked DNS flows after size retention removed SQLite rows.

    Parameters:
        tmp_path: Isolated output directory and flow database.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("CREATE TABLE flows (uid TEXT, flow TEXT)")
        connection.execute("CREATE TABLE altflows (uid TEXT, flow TEXT)")
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "INSERT INTO evidence_flows VALUES (?, ?)",
            ("dga-evidence", "dns-flow "),
        )
    logs = tmp_path / "zeek_files"
    logs.mkdir()
    (logs / "conn.log").write_text(
        json.dumps(
            {
                "ts": 100,
                "uid": "dns-flow",
                "id.orig_h": "192.168.1.135",
                "id.resp_h": "192.168.1.1",
                "service": "dns",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (logs / "dns.log").write_text(
        json.dumps(
            {
                "ts": 100,
                "uid": "dns-flow",
                "query": "bad.example",
                "rcode_name": "NXDOMAIN",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = reader.flows_for_evidence("dga-evidence")

    assert result["total"] == 1
    assert result["recovered_flow_count"] == 1
    assert result["unavailable_flow_count"] == 0
    group = result["items"][0]
    assert group["network_flow"]["source"] == "zeek_log"
    assert group["protocol_flows"][0]["flow_type"] == "dns"
    assert group["protocol_flows"][0]["flow"]["query"] == "bad.example"

    archive = tmp_path / "web_interface" / "zeek_recovery"
    archive.mkdir(parents=True)
    for name in ("conn.log", "dns.log"):
        (logs / name).rename(archive / name)
    archived = reader.flows_for_evidence("dga-evidence")
    assert archived["total"] == 1
    assert archived["protocol_flow_total"] == 1


@pytest.mark.parametrize("protocol,needs_connection", [("arp", False), ("dns", True)])
def test_protocol_only_flows_recover_connections_when_expected(
    tmp_path: Path, protocol: str, needs_connection: bool,
) -> None:
    """Recover a missing conn row even when its protocol row already exists.

    Parameters:
        tmp_path: Isolated offline analysis.
        protocol: Protocol recorded separately by Zeek.
        needs_connection: Whether a conn row is expected for this protocol.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript("CREATE TABLE flows(uid TEXT, flow TEXT);"
            "CREATE TABLE altflows(uid TEXT, flow TEXT, flow_type TEXT);"
            "CREATE TABLE evidence_flows(evidence_id TEXT, uid TEXT);")
        connection.execute("INSERT INTO altflows VALUES ('uid', '{}', ?)", (protocol,))
        connection.execute("INSERT INTO evidence_flows VALUES ('evidence', 'uid')")
    logs = tmp_path / "zeek_files"
    logs.mkdir()
    (logs / "conn.log").write_text(json.dumps({"uid": "uid", "ts": 100, "service": protocol}) + "\n")
    group = reader.flow_details("uid", {})
    assert reader._needs_connection_record({"protocol_flows": group["protocol_flows"]}) is needs_connection
    assert bool(group["network_flow"]) is needs_connection
    assert group["protocol_flow_total"] == 1
    evidence = reader.flows_for_evidence("evidence")
    assert bool(evidence["items"][0]["network_flow"]) is needs_connection
    assert evidence["recovered_flow_count"] == int(needs_connection)


def test_api_routes_evidence_flow_ids() -> None:
    _module_factory = ModuleFactory()
    handler = RequestHandler.__new__(RequestHandler)
    handler.server = Mock()
    handler.server.reader.response_metadata.return_value = {}
    handler.server.reader.flows_for_evidence.return_value = {
        "items": [],
        "count": 0,
    }

    result = handler._api_response("/api/evidence/evidence-1/flows", {})

    assert result["count"] == 0
    handler.server.reader.flows_for_evidence.assert_called_once_with(
        "evidence-1"
    )

    handler.server.reader.evidence_for_host.return_value = {
        "items": [],
        "total": 2,
    }
    host_result = handler._api_response("/api/hosts/10.0.0.1/evidence", {})

    assert host_result["total"] == 2
    handler.server.reader.evidence_for_host.assert_called_once_with(
        "10.0.0.1", {}
    )

    handler.server.reader.score_history.return_value = {
        "timeline": [],
        "threshold": 5.0,
    }
    score_result = handler._api_response(
        "/api/hosts/10.0.0.1/score-history", {"range": ["all"]}
    )

    assert score_result["threshold"] == 5.0
    handler.server.reader.score_history.assert_called_once_with(
        "10.0.0.1", {"range": ["all"]}
    )


def test_api_routes_host_name_lookup() -> None:
    """Route the bounded name lookup before individual host paths."""
    _module_factory = ModuleFactory()
    handler = RequestHandler.__new__(RequestHandler)
    handler.server = Mock()
    handler.server.reader.response_metadata.return_value = {}
    handler.server.reader.host_names.return_value = {
        "names": {"10.0.0.1": {"name": "laptop", "source": "Hostname"}}
    }
    query = {"ip": ["10.0.0.1"]}

    result = handler._api_response("/api/host-names", query)

    assert result["names"]["10.0.0.1"]["name"] == "laptop"
    handler.server.reader.host_names.assert_called_once_with(query)


@pytest.mark.parametrize(
    "evidence_type, expected",
    [
        ("ML_LINEAR_MALICIOUS_FLOW", "ml_linear_model"),
        ("UNSOLICITED_ARP", "arp"),
        ("SUSPICIOUS_USER_AGENT", "http_analyzer"),
        ("HTTP_IP_HOST", "http_analyzer"),
        ("HTTP_BINARY_POST_WITHOUT_CONTENT_TYPE", "http_analyzer"),
        ("HTTP_BINARY_RESPONSE_AS_HTML", "http_analyzer"),
        ("HORIZONTAL_PORT_SCAN", "network_discovery"),
        ("CONNECTION_WITHOUT_DNS", "flow_alerts"),
    ],
)
def test_module_for_evidence(evidence_type: str, expected: str) -> None:
    _module_factory = ModuleFactory()

    assert RunDataReader._module_for_evidence(evidence_type) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (["one", "two"], ["one", "two"]),
        ('["one", "two"]', ["one", "two"]),
        ("one", ["one"]),
        (None, []),
    ],
)
def test_id_list_normalizes_redis_alert_values(
    value: object, expected: list[str]
) -> None:
    _module_factory = ModuleFactory()

    assert RunDataReader._id_list(value) == expected


def test_web_returns_durable_connection_without_dns_and_linked_alert(
    tmp_path,
) -> None:
    """Return all durable records without interpreting detection configuration."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "history.sqlite"
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {}
    reader.redis.hget.return_value = None
    timewindow_pipeline = Mock()
    timewindow_pipeline.execute.return_value = [[]]
    score_pipeline = Mock()
    score_pipeline.execute.return_value = [1.26]
    reader.redis.pipeline.side_effect = [timewindow_pipeline, score_pipeline]
    reader._ti_for_ip = Mock(return_value={})
    initialize_history(reader.history_path)
    now = time.time()
    with sqlite3.connect(reader.history_path) as connection:
        connection.execute(
            "INSERT INTO host_snapshots VALUES (?, ?, ?)",
            (
                "10.0.0.1",
                now,
                json.dumps(
                    {
                        "ip": "10.0.0.1",
                        "scope": "local",
                        "all_ips": ["10.0.0.1"],
                        "hostname": "workstation",
                    }
                ),
            ),
        )
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE alerts (alert_id TEXT, alert_time REAL, "
            "ip_alerted TEXT, timewindow TEXT, tw_start TEXT, "
            "tw_end TEXT, label TEXT)"
        )
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT, evidence_time REAL, "
            "profile_ip TEXT, timewindow TEXT, threat_level TEXT, "
            "evidence_type TEXT, source_module TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.execute(
            "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "alert-1",
                now - 1,
                "10.0.0.1",
                "timewindow1",
                "",
                "",
                "malicious",
            ),
        )
        connection.execute(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "evidence-1",
                now - 2,
                "10.0.0.1",
                "timewindow1",
                "high",
                "CONNECTION_WITHOUT_DNS",
                "conn_analyzer",
                "Durable evidence",
                1.0,
                "{}",
            ),
        )
        connection.execute(
            "INSERT INTO alert_evidence VALUES (?, ?)",
            ("alert-1", "evidence-1"),
        )

    host = reader.host("10.0.0.1")
    evidence_page = reader.evidence(
        {"range": ["all"], "search": ["CONNECTION_WITHOUT_DNS"]}
    )
    grouped_evidence_page = reader.evidence(
        {"range": ["all"], "group": ["host_type"]}
    )
    alert_page = reader.alerts(
        {"range": ["all"], "search": ["alert-1"], "limit": ["1"]}
    )

    assert host["live"] is False
    assert host["hostname"] == "workstation"
    assert host["evidence_count"] == 1
    assert host["alert_count"] == 1
    assert host["alert_score"] == pytest.approx(0.4032)
    assert host["alert_threshold"] == 5.0
    assert host["alerts"][0]["alert_id"] == "alert-1"
    assert host["alerts"][0]["evidence_count"] == 1
    assert evidence_page["full_total"] == 1
    assert evidence_page["total"] == 1
    assert (
        evidence_page["items"][0]["evidence_type"] == "CONNECTION_WITHOUT_DNS"
    )
    assert evidence_page["items"][0]["alert_ids"] == ["alert-1"]
    assert evidence_page["items"][0]["module"] == "conn_analyzer"
    assert grouped_evidence_page["items"][0]["module"] == "conn_analyzer"
    assert alert_page["full_total"] == 1
    assert alert_page["total"] == 1
    assert alert_page["items"][0]["evidence"][0]["id"] == "evidence-1"
    assert host["alerts"][0]["threat_level"] == "high"


@pytest.mark.parametrize(
    "threat, expected",
    [
        ("critical_or_more", {"critical"}),
        ("high", {"high"}),
        ("high_or_more", {"high", "critical"}),
        ("medium_or_more", {"medium", "high", "critical"}),
        ("low_or_more", {"low", "medium", "high", "critical"}),
        ("info_or_more", {"info", "low", "medium", "high", "critical"}),
    ],
)
@pytest.mark.parametrize("grouped", [False, True])
def test_evidence_threat_minimum_filter(
    tmp_path: Path, threat: str, expected: set[str], grouped: bool
) -> None:
    """Apply inclusive threat thresholds to grouped and individual evidence.

    Parameters:
        tmp_path: Isolated SQLite storage.
        threat: Exact level or inclusive threshold.
        expected: Levels that should remain visible.
        grouped: Whether the query aggregates evidence by type.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader._annotate_detection_networks = Mock()
    reader._annotate_whitelisted_evidence = Mock()
    reader._annotate_p2p_reporters = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT, evidence_time REAL, "
            "profile_ip TEXT, timewindow TEXT, threat_level TEXT, "
            "evidence_type TEXT, source_module TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        for rank, level in enumerate(("info", "low", "medium", "high", "critical")):
            connection.execute(
                "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (level, rank + 1, "10.0.0.1", "timewindow1", level,
                 level.upper(), "test", level, 1.0, "{}"),
            )

    query = {"range": ["all"], "threat": [threat]}
    if grouped:
        query["group"] = ["type"]
    page = reader.evidence(query)

    assert {item["threat_level"] for item in page["items"]} == expected
    assert page["total"] == len(expected)


@pytest.mark.parametrize("grouped", [False, True])
def test_evidence_review_filter_keeps_verdicts_visible(
    tmp_path: Path, grouped: bool
) -> None:
    """Review verdict filtering applies to grouped and individual evidence."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader._annotate_detection_networks = Mock()
    reader._annotate_whitelisted_evidence = Mock()
    reader._annotate_p2p_reporters = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "CREATE TABLE evidence(evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, source_module TEXT, "
            "description TEXT, confidence REAL, data TEXT);"
            "CREATE TABLE evidence_flows(evidence_id TEXT, uid TEXT);"
            "CREATE TABLE alert_evidence(alert_id TEXT, evidence_id TEXT);"
            "INSERT INTO evidence VALUES "
            "('reviewed',1,'10.0.0.1','timewindow1','low','ARP_SCAN','arp','scan',1,'{}'),"
            "('other',2,'10.0.0.1','timewindow1','low','ARP_SCAN','arp','scan',1,'{}');"
        )
    reader.save_review("evidence", {
        "id": "reviewed", "action": "review", "status": "false_positive",
        "note": "Router discovery"
    })
    query = {"range": ["all"], "review": ["false_positive"]}
    if grouped:
        query["group"] = ["host_type"]
    page = reader.evidence(query)
    assert page["total"] == 1
    assert page["items"][0]["evidence_count" if grouped else "id"] == (
        1 if grouped else "reviewed"
    )


def test_host_names_resolves_live_and_historical_identity(
    tmp_path: Path,
) -> None:
    """Return bounded names for displayed IPs from live and saved data.

    Parameters:
        tmp_path: Temporary history database location.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.history_path = tmp_path / "history.sqlite"
    reader.host_profiles_path = tmp_path / "missing-host-profiles.sqlite"
    initialize_history(reader.history_path)
    with sqlite3.connect(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO host_snapshots VALUES (?, ?, ?)",
            [
                (
                    "10.0.0.1",
                    1,
                    json.dumps({"hostname": "saved-host"}),
                ),
                (
                    "10.0.0.2",
                    1,
                    json.dumps({"dns": {"domains": ["device.local"]}}),
                ),
            ],
        )
    reader.redis = Mock()
    reader.redis.pipeline.return_value.execute.return_value = [
        "current-host", None, None, None,
        None, None, None, None,
        None, json.dumps({"domains": ["new.local"]}), None, None,
        None, None, None, None,
    ]
    reader.cache = Mock()
    reader.cache.hget.return_value = "cached.example"

    result = reader.host_names(
        {
            "ip": [
                "10.0.0.1",
                "10.0.0.2",
                "10.0.0.3",
                "2001:0DB8:0:0::5",
                "invalid",
            ]
        }
    )

    assert result["names"] == {
        "10.0.0.1": {"name": "current-host", "source": "Hostname"},
        "10.0.0.2": {"name": "device.local", "source": "DNS"},
        "10.0.0.3": {"name": "new.local", "source": "DNS"},
        "2001:0DB8:0:0::5": {"name": "cached.example", "source": "rDNS"},
    }
    assert reader.redis.pipeline.return_value.hget.call_count == 16
    reader.cache.hget.assert_called_once_with(
        "IPsInfo:reverse_dns", "2001:db8::5"
    )


def test_host_names_prefers_saved_name_then_vendor(tmp_path: Path) -> None:
    """Show a manual name or vendor beside IPs in alert labels.

    Parameters:
        tmp_path: Isolated history and permanent profile paths.
    """
    _module_factory = ModuleFactory()
    profile_path = tmp_path / "permanent" / "hosts.sqlite"
    network = {
        "local_network": "192.168.1.0/24",
        "gateway_mac": "aa:bb:cc:dd:ee:01",
    }
    store = HostProfileStore(
        profile_path, "run-one", lambda _: network, ["en0"]
    )
    store.observe_flow(
        SimpleNamespace(
            interface="en0",
            starttime="100",
            type_="conn",
            saddr="192.168.1.20",
            daddr="8.8.8.8",
        )
    )
    reader = RunDataReader.__new__(RunDataReader)
    reader.host_profiles_path = profile_path
    reader.history_path = tmp_path / "history.sqlite"
    initialize_history(reader.history_path)
    with sqlite3.connect(reader.history_path) as connection:
        connection.execute(
            "INSERT INTO host_snapshots VALUES (?, ?, ?)",
            ("192.168.1.21", 1, json.dumps({"mac_vendor": "Samsung"})),
        )
    reader.redis = Mock()
    reader.redis.pipeline.return_value.execute.return_value = [
        "learned-name",
        None,
        "Apple",
        None,
        None,
        None,
    ]
    reader.cache = Mock()
    reader.cache.hget.return_value = None

    saved = reader.save_host_annotation(
        "192.168.1.20",
        "gateway:aa:bb:cc:dd:ee:01",
        "My tablet",
        "Kitchen iPad",
    )
    names = reader.host_names({"ip": ["192.168.1.20", "192.168.1.21"]})

    assert saved["note"] == "Kitchen iPad"
    assert names["names"]["192.168.1.20"] == {
        "name": "My tablet",
        "source": "User name",
    }
    assert names["names"]["192.168.1.21"] == {
        "name": "Samsung device",
        "source": "MAC vendor",
    }

    with pytest.raises(ValueError, match="profile is unavailable"):
        reader.save_host_annotation(
            "192.168.1.20",
            "gateway:aa:bb:cc:dd:ee:02",
            "Wrong network",
            "Do not save",
        )


@pytest.mark.parametrize("redis_output", [None, "output/different"])
def test_validate_run_identity_rejects_missing_or_stale_redis(
    redis_output: str | None,
) -> None:
    """Reject requests unless Redis identifies the exact configured run."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = Path("output/current")
    reader.redis_port = 32768
    reader.redis = Mock()
    reader.redis.hgetall.return_value = (
        {"output_dir": redis_output} if redis_output is not None else {}
    )

    with pytest.raises(RunMismatchError):
        reader.validate_run_identity()


def test_firewall_marks_overdue_and_returns_transition_history(
    tmp_path: Path,
) -> None:
    """Expose stale enforcement and deduplicated block/unblock events."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.redis = Mock()
    reader.redis.zrange.return_value = [("101.36.97.74", 1787757891.0)]
    reader.redis.hgetall.return_value = {
        "101.36.97.74": json.dumps(
            {
                "unblock_at": "2026-08-26T18:38:10+02:00",
                "remaining_timewindows": 0,
            }
        )
    }
    reader._profile_evidence_count = Mock(return_value=27)
    reader._profile_alert_count = Mock(return_value=1)
    log_dir = tmp_path / "blocking"
    log_dir.mkdir()
    (log_dir / "blocking.log").write_text(
        "2026/08/26 17:24:51.100000 - Blocked all traffic from: 101.36.97.74\n"
        "2026/08/26 17:24:51.200000 - Blocked all traffic to: 101.36.97.74\n"
        "2026/08/26 18:38:11.000000 - IP 101.36.97.74 is unblocked in timewindow3.\n",
        encoding="utf-8",
    )

    with patch(
        "modules.web_interface.server.time.time", return_value=1787781085.0
    ):
        payload = reader.firewall({})

    assert payload["items"][0]["status"] == "overdue"
    assert payload["items"][0]["remaining_seconds"] == 0
    assert payload["history_total"] == 2
    assert payload["history_next_cursor"] is None
    assert [event["action"] for event in payload["history"]] == [
        "unblocked",
        "blocked",
    ]
    assert payload["history"][1]["details"] == "traffic from + to"


def test_firewall_estimates_attempts_inside_block_intervals(
    tmp_path: Path,
) -> None:
    """Count source packets, flows, and evidence only while rules were active."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.history_path = tmp_path / "web_interface" / "history.sqlite"
    reader.sqlite_path = tmp_path / "databases" / "flows.sqlite"
    reader.redis = Mock()
    initialize_history(reader.history_path)
    reader.sqlite_path.parent.mkdir()
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO flow_index "
            "(uid, flow_rowid, event_time, src_ip, dst_ip, proto, app_proto, "
            "bytes, packets, source_packets, label) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "before",
                    1,
                    90,
                    "10.0.0.8",
                    "10.0.0.1",
                    "tcp",
                    "",
                    0,
                    5,
                    5,
                    "",
                ),
                (
                    "blocked-1",
                    2,
                    110,
                    "10.0.0.8",
                    "10.0.0.1",
                    "tcp",
                    "",
                    0,
                    7,
                    7,
                    "",
                ),
                (
                    "reverse",
                    3,
                    120,
                    "10.0.0.1",
                    "10.0.0.8",
                    "tcp",
                    "",
                    0,
                    9,
                    9,
                    "",
                ),
                (
                    "blocked-2",
                    4,
                    140,
                    "10.0.0.8",
                    "10.0.0.1",
                    "tcp",
                    "",
                    0,
                    3,
                    3,
                    "",
                ),
                (
                    "unblocked",
                    5,
                    170,
                    "10.0.0.8",
                    "10.0.0.1",
                    "tcp",
                    "",
                    0,
                    8,
                    8,
                    "",
                ),
                (
                    "reblocked",
                    6,
                    220,
                    "10.0.0.8",
                    "10.0.0.1",
                    "tcp",
                    "",
                    0,
                    4,
                    4,
                    "",
                ),
            ],
        )
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?)",
            [
                ("before", 95, "10.0.0.8"),
                ("blocked", 130, "10.0.0.8"),
                ("unblocked", 180, "10.0.0.8"),
                ("reblocked", 225, "10.0.0.8"),
            ],
        )
    history = [
        {"timestamp": 100, "ip": "10.0.0.8", "action": "blocked"},
        {"timestamp": 150, "ip": "10.0.0.8", "action": "unblocked"},
        {"timestamp": 200, "ip": "10.0.0.8", "action": "blocked"},
    ]

    with patch("modules.web_interface.server.time.time", return_value=250):
        result = reader._firewall_attack_estimate(history, {"10.0.0.8": 200})

    assert result["packets"] == 14
    assert result["flows"] == 3
    assert result["evidence"] == 2
    assert result["blocked_intervals"] == 2
    assert result["by_ip"]["10.0.0.8"] == {
        "packets": 14,
        "flows": 3,
        "evidence": 2,
    }


def test_firewall_includes_schedule_missing_from_blocked_set(
    tmp_path: Path,
) -> None:
    """Keep legacy scheduled rules visible even without a blocked timestamp."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.redis = Mock()
    reader.redis.zrange.return_value = []
    reader.redis.hgetall.return_value = {
        "147.32.80.6": json.dumps(
            {
                "unblock_at": None,
                "remaining_timewindows": None,
                "recovered": True,
                "recovery_status": "legacy metadata",
                "origin_run": "unknown",
                "rule_comment": "Slips rule",
            }
        )
    }
    reader._profile_evidence_count = Mock(return_value=10)
    reader._profile_alert_count = Mock(return_value=1)

    with patch(
        "modules.web_interface.server.time.time", return_value=1787781085.0
    ):
        payload = reader.firewall({})

    assert payload["total"] == 1
    assert payload["items"][0]["ip"] == "147.32.80.6"
    assert payload["items"][0]["blocked_at"] is None
    assert payload["items"][0]["status"] == "stale"
    assert payload["items"][0]["recovered"] is True
    assert payload["items"][0]["recovery_status"] == "legacy metadata"
    assert payload["items"][0]["rule_comment"] == "Slips rule"


def test_firewall_tab_renders_transition_history() -> None:
    """Keep the durable firewall history visible in the browser tab."""
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    index_source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )

    assert 'id="firewall-history-table"' in index_source
    assert 'id="firewall-history-pager"' in index_source
    assert 'id="overview-firewall-impact"' in index_source
    assert 'id="firewall-impact-summary"' in index_source
    assert '<th data-sort="origin">Rule origin</th>' in index_source
    assert "row.stopped_packets" in app_source
    assert "row.stopped_flows" in app_source
    assert "row.evidence_while_blocked" in app_source
    assert "row.recovery_status" in app_source
    assert 'renderTable("firewall-history-table", history' in app_source


def test_arp_poisoning_parser_tracks_extensions_and_releases(
    tmp_path: Path,
) -> None:
    """Build host state from durable poison, extension, and release events."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    log_dir = tmp_path / "arp_poisoner"
    log_dir.mkdir()
    (log_dir / "arp_poisoning.log").write_text(
        "2026/08/28 10:00:00.000000+0200 - Poisoned 10.0.0.8 at aa:bb:cc:dd:ee:08.\n"
        "2026/08/28 10:00:01.000000+0200 - Current TW: 7. Registered a request to stop poisoning 10.0.0.8 at the end of: timewindow8. IP will be poisoned for 1 more timewindows. Timestamp to stop poisoning: 2026-08-28T12:00:00+02:00) \n"
        "2026/08/28 10:10:00.000000+0200 - Current TW: 7. Registered a request to stop poisoning 10.0.0.8 at the end of: timewindow9. IP will be poisoned for 2 more timewindows. Timestamp to stop poisoning: 2026-08-28T13:00:00+02:00) \n"
        "2026/08/28 10:20:00.000000+0200 - Poisoned 10.0.0.9 at aa:bb:cc:dd:ee:09.\n"
        "2026/08/28 10:20:01.000000+0200 - Current TW: 8. Registered a request to stop poisoning 10.0.0.9 at the end of: timewindow9. IP will be poisoned for 1 more timewindows. Timestamp to stop poisoning: 2026-08-28T11:00:00+02:00) \n"
        "2026/08/28 11:00:01.000000+0200 - Done poisoning 10.0.0.9. The poisoning lasted 1 timewindows. (1.0hrs - From 2026/08/28 10:20:00.000000+0200 to 2026/08/28 11:00:01.000000+0200).\n",
        encoding="utf-8",
    )

    now = reader._event_timestamp("2026-08-28T13:00:01+02:00")
    with patch("modules.web_interface.server.time.time", return_value=now):
        result = reader._arp_poisoning_events()

    hosts = {item["ip"]: item for item in result["hosts"]}
    assert hosts["10.0.0.8"]["status"] == "release due"
    assert hosts["10.0.0.8"]["release_tw"] == "timewindow9"
    assert hosts["10.0.0.8"]["extra_timewindows"] == 2
    assert hosts["10.0.0.8"]["remaining_seconds"] == 0
    assert hosts["10.0.0.9"]["status"] == "released"
    assert hosts["10.0.0.9"]["released_at"] == pytest.approx(
        reader._event_timestamp("2026/08/28 11:00:01.000000+0200")
    )
    actions = [item["action"] for item in result["events"]]
    assert actions.count("poisoned") == 2
    assert actions.count("scheduled") == 2
    assert actions.count("extended") == 1
    assert actions.count("released") == 1


def test_arp_evidence_uses_only_durable_arp_detections(
    tmp_path: Path,
) -> None:
    """Return ARP evidence with durable flow and alert relationships."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "arp-1",
                    20,
                    "10.0.0.8",
                    "7",
                    "high",
                    "MITM_ARP_ATTACK",
                    "ARP packets claim different MACs",
                    0.9,
                    "{}",
                ),
                (
                    "dns-1",
                    30,
                    "10.0.0.9",
                    "7",
                    "low",
                    "DGA_NXDOMAINS",
                    "Not ARP",
                    1.0,
                    "{}",
                ),
            ],
        )
        connection.executemany(
            "INSERT INTO evidence_flows VALUES (?, ?)",
            [("arp-1", "flow-1"), ("arp-1", "flow-2")],
        )
        connection.execute(
            "INSERT INTO alert_evidence VALUES (?, ?)",
            ("alert-1", "arp-1"),
        )

    result = reader._arp_evidence()

    assert result["total"] == 1
    assert result["counts"] == {"MITM_ARP_ATTACK": 1}
    assert [item["evidence_type"] for item in result["items"]] == [
        "MITM_ARP_ATTACK"
    ]
    assert result["items"][0]["flow_count"] == 2
    assert result["items"][0]["alert_count"] == 1


@pytest.mark.parametrize(
    "hide_excluded, expected_descriptions",
    [
        (False, ["Excluded ARP", "Scored ARP"]),
        (True, ["Scored ARP"]),
    ],
)
def test_arp_evidence_exclusion_filter(
    tmp_path: Path, hide_excluded: bool, expected_descriptions: list[str]
) -> None:
    """Filter whitelisted ARP evidence before limiting rows and counts.

    Parameters:
        tmp_path: Isolated run database location.
        hide_excluded: Whether excluded evidence should be omitted.
        expected_descriptions: Descriptions visible in newest-first order.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, threat_level TEXT, "
            "evidence_type TEXT, description TEXT, confidence REAL, "
            "whitelisted INTEGER)"
        )
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "scored",
                    1,
                    "10.0.0.8",
                    "high",
                    "MITM_ARP_ATTACK",
                    "Scored ARP",
                    0.9,
                    0,
                ),
                (
                    "excluded",
                    2,
                    "10.0.0.8",
                    "high",
                    "MITM_ARP_ATTACK",
                    "Excluded ARP",
                    0.9,
                    1,
                ),
            ],
        )

    result = reader._arp_evidence(hide_excluded=hide_excluded)

    assert result["total"] == len(expected_descriptions)
    assert result["counts"] == {"MITM_ARP_ATTACK": len(expected_descriptions)}
    assert [
        item["description"] for item in result["items"]
    ] == expected_descriptions


def test_arp_poisoning_summarizes_current_module_state(tmp_path: Path) -> None:
    """Summarize active, overdue, and released ARP isolation records."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.redis = Mock()
    reader.redis.hget.return_value = None
    reader._processes = {}
    log_dir = tmp_path / "arp_poisoner"
    log_dir.mkdir()
    (log_dir / "arp_poisoning.log").touch()
    reader._arp_poisoning_events = Mock(
        return_value={
            "hosts": [
                {"ip": "10.0.0.8", "status": "poisoned"},
                {"ip": "10.0.0.9", "status": "release due"},
                {"ip": "10.0.0.10", "status": "released"},
            ],
            "events": [
                {"ip": "10.0.0.8", "action": "poisoned"},
                {"ip": "10.0.0.10", "action": "released"},
            ],
        }
    )
    reader._arp_evidence = Mock(
        return_value={
            "items": [{"evidence_type": "ARP_SCAN"}],
            "total": 4,
            "counts": {"ARP_SCAN": 4},
        }
    )

    result = reader.arp_poisoning({"hide_excluded": ["1"]})

    assert result["module"] == {
        "enabled": False,
        "state": "stopped",
        "pid": None,
    }
    assert result["counts"] == {
        "active": 2,
        "released": 1,
        "hosts": 3,
        "transitions": 2,
        "evidence": 4,
    }
    assert result["evidence_counts"] == {"ARP_SCAN": 4}
    reader._arp_evidence.assert_called_once_with(hide_excluded=True)


def test_arp_poisoning_tab_is_wired_and_every_column_is_sortable() -> None:
    """Keep all ARP state, history, and evidence columns sortable."""
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    index_source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )
    server_source = Path("modules/web_interface/server.py").read_text(
        encoding="utf-8"
    )
    section = index_source.split('<section id="arp-poisoning"', 1)[1].split(
        '<section id="p2p"', 1
    )[0]

    assert 'data-tab="arp-poisoning"' in index_source
    assert 'id="arp-poisoning-hosts-table"' in section
    assert 'id="arp-poisoning-events-table"' in section
    assert 'id="arp-poisoning-evidence-table"' in section
    assert section.count("<th ") == section.count('data-sort="')
    assert 'api("arpPoisoning", path)' in app_source
    assert "bindLocalTableSort(id, renderArpPoisoning)" in app_source
    assert 'path == "/api/arp-poisoning"' in server_source


def test_evidence_cursor_is_stable_when_newer_rows_arrive(tmp_path) -> None:
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    f"evidence-{number}",
                    float(number),
                    "10.0.0.1",
                    "tw",
                    "low",
                    "UNKNOWN_PORT",
                    "",
                    1.0,
                    "{}",
                )
                for number in range(1, 5)
            ],
        )

    first = reader.evidence({"range": ["all"], "limit": ["2"]})
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "newer",
                10.0,
                "10.0.0.1",
                "tw",
                "high",
                "UNKNOWN_PORT",
                "",
                1.0,
                "{}",
            ),
        )
    second = reader.evidence(
        {
            "range": ["all"],
            "limit": ["2"],
            "cursor": [first["next_cursor"]],
        }
    )

    assert [item["id"] for item in first["items"]] == [
        "evidence-4",
        "evidence-3",
    ]
    assert [item["id"] for item in second["items"]] == [
        "evidence-2",
        "evidence-1",
    ]


@pytest.mark.parametrize("search", ["UNKNOWN_PORT", "unknown port", "scored", "100%",
    "info", "none", "1970", "01/01/1970", "00:00:01", "1.0", "0", "%", "_"])
def test_host_evidence_search_covers_displayed_columns(
    tmp_path: Path, search: str
) -> None:
    """Match evidence type, its readable name, handling, and confidence.

    Parameters:
        tmp_path: Isolated durable database path.
        search: A value shown in the host evidence table.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "CREATE TABLE evidence(evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT);"
            "CREATE TABLE evidence_flows(evidence_id TEXT, uid TEXT);"
            "CREATE TABLE alert_evidence(alert_id TEXT, evidence_id TEXT);"
            "INSERT INTO evidence VALUES "
            "('e1', 1, '10.0.0.1', 'tw', 'info', 'UNKNOWN_PORT', "
            "'A connection', 1, '{}');"
        )

    result = reader.evidence(
        {"range": ["all"], "profile": ["10.0.0.1"], "search": [search]}
    )

    assert result["total"] == 1
    assert result["items"][0]["evidence_type"] == "UNKNOWN_PORT"


@pytest.mark.parametrize("device", [False, True])
def test_host_flow_pages_match_device_traffic_scope(tmp_path: Path, device: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep traffic totals, plot data and paged flows on the same address set.

    Parameters:
        tmp_path: Isolated run databases.
        device: Combine verified aliases when the selected IP has no traffic.
        monkeypatch: Use the isolated capture's live clock.
    """
    _factory = ModuleFactory()
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: 2_000_000_000.0)
    reader = _network_scope_reader(tmp_path)
    ip = "192.168.12.1"
    query = {"range": ["all"], "network": ["current"], "limit": ["1"]}
    if device:
        query["device"] = ["1"]
    page = reader.flows_for_host(ip, query)
    traffic = reader.traffic_summary(ip, query)
    load = reader._host_load(ip, query)
    assert page["host_ips"] == traffic["host_ips"]
    assert page["total"] == load["flows"] == (2 if device else 0)
    assert sum(point["inbound_flows"] + point["outbound_flows"]
        for point in traffic["timeline"]) == page["total"]
    assert sum(point["inbound_bytes"] + point["outbound_bytes"]
        for point in traffic["timeline"]) == load["bytes"] == (60 if device else 0)
    if device:
        assert set(page["host_ips"]) == {"192.168.1.20", "fe80::20"}
        assert len(page["items"]) == 1
        second = reader.flows_for_host(ip, {**query, "cursor": [page["next_cursor"]]})
        assert {page["items"][0]["uid"], second["items"][0]["uid"]} == {
            "current-v4", "current-v6"
        }
        assert second["next_cursor"] is None


def test_host_flows_exclude_mac_alias_addresses(tmp_path) -> None:
    """Only the selected profile IP may contribute host-workspace flows."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "history.sqlite"
    initialize_history(reader.history_path)
    raw_rows = [
        (
            "outbound",
            json.dumps(
                {
                    "saddr": "10.0.0.1",
                    "daddr": "8.8.8.8",
                    "sport": 1000,
                    "dport": 53,
                }
            ),
            "benign",
            "",
            "",
            "",
        ),
        (
            "inbound",
            json.dumps(
                {
                    "saddr": "1.1.1.1",
                    "daddr": "fe80::1",
                    "sport": 443,
                    "dport": 2000,
                }
            ),
            "malicious",
            "",
            "",
            "",
        ),
    ]
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE flows (uid TEXT, flow TEXT, label TEXT, "
            "profileid TEXT, twid TEXT, aid TEXT)"
        )
        connection.executemany(
            "INSERT INTO flows VALUES (?, ?, ?, ?, ?, ?)", raw_rows
        )
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO flow_index "
            "(uid, flow_rowid, event_time, src_ip, dst_ip, proto, "
            "app_proto, bytes, packets, label) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "outbound",
                    1,
                    20.0,
                    "10.0.0.1",
                    "8.8.8.8",
                    "udp",
                    "dns",
                    100,
                    2,
                    "benign",
                ),
                (
                    "inbound",
                    2,
                    10.0,
                    "1.1.1.1",
                    "fe80::1",
                    "tcp",
                    "ssl",
                    200,
                    3,
                    "malicious",
                ),
            ],
        )

    result = reader.flows_for_host("10.0.0.1", {"range": ["all"]})

    assert result["total"] == 1
    assert [item["direction"] for item in result["items"]] == ["outbound"]
    assert [item["peer"] for item in result["items"]] == ["8.8.8.8"]
    assert result["host_ips"] == ["10.0.0.1"]


def test_metrics_response_never_exceeds_requested_points(tmp_path) -> None:
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.history_path = tmp_path / "history.sqlite"
    initialize_history(reader.history_path)
    now = time.time()
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO runtime_metrics_1s VALUES (?, ?, ?, ?, ?)",
            [
                (
                    now - number,
                    number % 100,
                    100 + number,
                    number % 10,
                    number % 7,
                )
                for number in range(2000)
            ],
        )

    result = reader.metrics({"range": ["1h"], "max_points": ["100"]})

    assert result["page_size"] <= 100
    assert result["max_points"] == 100


def test_durable_module_counts_survive_redis_window_expiry(tmp_path) -> None:
    """Test module health uses durable evidence after Redis cleanup."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    database_path = tmp_path / "flows.sqlite"
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("CREATE TABLE evidence (evidence_type TEXT)")
        connection.executemany(
            "INSERT INTO evidence VALUES (?)",
            [
                ("ML_LINEAR_MALICIOUS_FLOW",),
                ("ML_LINEAR_MALICIOUS_FLOW",),
                ("ARP_SCAN",),
            ],
        )
        counts = reader._durable_evidence_counts(connection)

    assert counts["ml_linear_model"] == 2
    assert counts["arp"] == 1


def test_module_rows_exclude_internal_threads(mocker) -> None:
    """Verify PID bookkeeping threads are not presented as Slips modules."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {
        "flow_alerts": "123",
        "dns_without_connection_timeout_checker_thread": "124",
        "web_interface_history": "125",
        "web_interface_detection_backfill": "126",
    }
    reader.redis.smembers.return_value = set()
    process = Mock()
    process.is_running.return_value = True
    process.status.return_value = "sleeping"
    process.memory_info.return_value = Mock(rss=1024 * 1024)
    process.cpu_percent.return_value = 0
    process_constructor = mocker.patch(
        "modules.web_interface.server.psutil.Process",
        side_effect=psutil.NoSuchProcess(123),
    )
    mocker.patch(
        "modules.web_interface.server.psutil.virtual_memory",
        return_value=Mock(total=100 * 1024 * 1024),
    )
    reader._processes = {123: process}

    rows = reader._module_rows(Counter(), {}, analysis_complete=False)

    assert rows[0]["memory_percent"] == 1.0
    assert [row["name"] for row in rows] == ["flow_alerts"]
    process_constructor.assert_not_called()


@pytest.mark.parametrize("saved_view", [False, True])
def test_live_evidence_range_uses_newest_capture_timestamp(
    tmp_path: Path, saved_view: bool
) -> None:
    """Test offline evidence ranges follow capture time instead of wall time.

    Parameters:
        tmp_path: Independent detection database.
        saved_view: Whether the capture has been reopened for viewing.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    reader.saved_view = saved_view
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                ("old", 100.0, "10.0.0.1", "tw", "low", "OLD", "", 1.0, "{}"),
                (
                    "current",
                    7300.0,
                    "10.0.0.1",
                    "tw",
                    "high",
                    "CURRENT",
                    "",
                    1.0,
                    "{}",
                ),
            ],
        )

    result = reader.evidence({"range": ["live"]})

    assert result["total"] == 1
    assert result["full_total"] == 2
    assert result["items"][0]["id"] == "current"


@pytest.mark.parametrize("saved_view", [False, True])
def test_full_run_keeps_mixed_clock_evidence(
    tmp_path: Path, saved_view: bool
) -> None:
    """Keep identical saved evidence IDs even when Zeek logs mix clocks.

    Parameters:
        tmp_path: Independent detection database.
        saved_view: Whether the reader represents a reopened snapshot.
    """
    _factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    reader.redis.hget.return_value = "zeek_folder"
    reader.saved_view = saved_view
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute("CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)")
        connection.execute("CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)")
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(key, timestamp, "10.0.0.1", "tw", "low", "TEST", "", 1.0, "{}")
             for key, timestamp in [("relative", 254.819), ("calendar", 1632302615.44)]],
        )
    full = reader.evidence({"range": ["all"]})
    recent = reader.evidence({"range": ["24h"]})
    assert {row["id"] for row in full["items"]} == {"relative", "calendar"}
    assert {row["id"] for row in recent["items"]} == {"calendar"}


@pytest.mark.parametrize(
    ("network_state", "expected"),
    [
        ({"connected": True, "changed_at": 200, "gateway_mac": "AA",
          "history": [
              {"connected": True, "changed_at": 100, "gateway_mac": "BB"},
              {"connected": True, "changed_at": 150, "gateway_mac": "AA"},
          ]}, 150.0),
        ({"connected": True, "changed_at": 200, "gateway_mac": "",
          "history": [
              {"connected": True, "changed_at": 150, "gateway_mac": ""},
          ]}, 200.0),
        ({"connected": False, "changed_at": 200, "gateway_mac": "AA"}, None),
    ],
)
def test_current_network_scope_stops_at_prior_connection(
    network_state: dict, expected: float | None
) -> None:
    """A repeated IP on an older network must not enter the current scope.

    Parameters:
        network_state: Current snapshot and retained network history.
        expected: Earliest accepted detection timestamp.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {
        "input_type": "interface", "interface": "en0"
    }
    reader.redis.hget.return_value = json.dumps(network_state)

    assert reader._current_network_start() == expected
    assert reader._scoped_start({"network": ["current"]}, 180) == (
        max(expected, 180) if expected is not None else float("inf")
    )


def test_current_network_scope_filters_durable_detection_pages(
    tmp_path: Path,
) -> None:
    """Grouped alerts and evidence exclude older detections from the same IP.

    Parameters:
        tmp_path: Isolated run database directory.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {
        "input_type": "interface", "interface": "en0"
    }
    reader.redis.hget.side_effect = lambda key, field: (
        json.dumps({"connected": True, "changed_at": 20,
                    "gateway_mac": "aa"})
        if key == "network_states" else "interface"
    )
    reader.score_mode = "ratl"
    reader._ip_context_for_ip = Mock(return_value={})
    reader._annotate_detection_networks = Mock()
    reader._annotate_whitelisted_evidence = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "CREATE TABLE alerts(alert_id TEXT PRIMARY KEY, ip_alerted TEXT, "
            "alert_time REAL, label TEXT, accumulated_ratl REAL);"
            "CREATE TABLE evidence(evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT);"
            "CREATE TABLE alert_evidence(alert_id TEXT, evidence_id TEXT);"
            "CREATE TABLE evidence_flows(evidence_id TEXT, uid TEXT);"
            "INSERT INTO alerts VALUES "
            "('old','192.0.2.5',10,'malicious',5),"
            "('current','192.0.2.5',30,'malicious',6);"
            "INSERT INTO evidence VALUES "
            "('old',10,'192.0.2.5','tw','low','SCAN','old',0.8,'{}'),"
            "('current',30,'192.0.2.5','tw','low','SCAN','current',0.8,'{}');"
            "INSERT INTO alert_evidence VALUES ('old','old'),('current','current');"
        )

    query = {"range": ["all"], "network": ["current"]}
    grouped = reader.alerts({**query, "group": ["host"]})
    individual = reader.alerts({**query, "details": ["false"]})
    evidence = reader.evidence(query)
    grouped_evidence = reader.evidence({**query, "group": ["host_type"]})
    all_alerts = reader.alerts({"range": ["all"], "group": ["host"]})
    scoped_host_counts = reader._host_page_counts(["192.0.2.5"], 20)

    assert grouped["matching_total"] == 1
    assert grouped["items"][0]["alert_count"] == 1
    assert individual["total"] == 1
    assert individual["items"][0]["alert_id"] == "current"
    assert evidence["total"] == 1
    assert evidence["items"][0]["id"] == "current"
    assert grouped_evidence["matching_total"] == 1
    assert all_alerts["matching_total"] == 2
    assert scoped_host_counts["192.0.2.5"] == {"alerts": 1, "evidence": 1}


@pytest.mark.parametrize("active", [True, False])
def test_device_grouping_verifies_own_interface_after_many_addresses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, active: bool,
) -> None:
    """Group verified own addresses despite roaming history, excluding next hops.

    Parameters:
        tmp_path: Isolated retained host and evidence data.
        monkeypatch: Provide one monitored interface and a fixed capture clock.
        active: Whether the interface capture is still running.
    """
    _module_factory = ModuleFactory()
    now = 2_000_000_000.0
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: now)
    reader = _network_scope_reader(tmp_path)
    reader.cache = None
    mac = "50:ed:3c:39:bc:d9"
    own = ["192.168.1.247", "fe80::4d6:6ff0:6f58:42b7", "2001:4860:1::247"]
    old = [f"10.1.0.{index}" for index in range(1, 22)]
    with connect_history(reader.history_path) as connection:
        connection.execute("DELETE FROM host_snapshots")
        connection.executemany("INSERT INTO host_snapshots VALUES (?,?,?)", [
            (ip, now, json.dumps({"ip":ip,"mac":mac,
                "scope":"public" if ip in {own[-1],"8.8.8.8"} else "local"}))
            for ip in [*own,*old,"8.8.8.8","192.168.1.1"]])
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("DELETE FROM evidence")
        connection.execute("DELETE FROM alerts")
        connection.executemany("INSERT INTO evidence(evidence_id,profile_ip,evidence_time,evidence_type,threat_level) "
            "VALUES (?,?,?,'UNKNOWN_PORT','high')", [(ip,ip,now-10) for ip in own])
        connection.executemany("INSERT INTO alerts VALUES (?,?,?,'malicious',5)",
            [(ip,ip,now-10) for ip in own])
        connection.executemany("INSERT INTO alert_evidence VALUES (?,?)", [(ip,ip) for ip in own])
    previous_hgetall = reader.redis.hgetall.side_effect
    reader.redis.hgetall.side_effect = lambda key: (
        {"input_type":"interface","interface":"en0", **({} if active else {"analysis_end":"1"})}
        if key == "analysis" else previous_hgetall(key))
    addresses = [SimpleNamespace(family=psutil.AF_LINK,address=mac),
        *[SimpleNamespace(family=socket.AF_INET if ":" not in ip else socket.AF_INET6,
                         address=ip+"%en0" if ip.startswith("fe80:") else ip) for ip in own]]
    monkeypatch.setattr("modules.web_interface.server.psutil.net_if_addrs",
        lambda: {"en0":addresses,"en1":[SimpleNamespace(family=socket.AF_INET,address="192.168.1.1")]})
    keys = reader._device_key_map()
    if not active:
        assert not any(ip in keys for ip in own)
        return
    assert {keys[ip] for ip in own} == {f"mac:{mac}"}
    assert not any(ip in keys for ip in [*old,"8.8.8.8","192.168.1.1"])
    query = {"device":["1"],"range":["all"],"network":["current"]}
    inventory = reader.hosts(query)
    own_groups = [item for item in inventory["items"] if set(item["device_ips"]) & set(own)]
    assert len(own_groups) == 1
    assert set(own_groups[0]["device_ips"]) == set(own)
    assert own_groups[0]["evidence_count"] == 3
    evidence = reader.evidence({**query,"group":["host"]})
    assert evidence["total"] == 1
    assert evidence["items"][0]["evidence_count"] == 3
    alerts = reader.alerts({**query,"group":["host"]})
    assert alerts["total"] == 1
    assert alerts["items"][0]["alert_count"] == 3
    assert set(reader._host_ips(own[0],query)) == set(own)


@pytest.mark.parametrize("indexed", [True, False])
@pytest.mark.parametrize("bounded", [True, False])
def test_host_finding_queries_choose_indexes_without_changing_filters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, indexed: bool, bounded: bool,
) -> None:
    """Use covering indexes while keeping exact scoped findings.

    Parameters:
        tmp_path: Isolated retained evidence.
        monkeypatch: Fix the active capture clock.
        indexed: Include current indexes or use a legacy database.
        bounded: Select one hour instead of all retained history.
    """
    _module_factory = ModuleFactory()
    now = 2_000_000_000.0
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: now)
    reader = _network_scope_reader(tmp_path)
    ip = "192.168.1.20"
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("DELETE FROM evidence")
        connection.execute("ALTER TABLE evidence ADD COLUMN accumulated_threat_level REAL")
        if indexed:
            connection.executescript("CREATE INDEX evidence_profile_time_idx ON evidence(profile_ip,evidence_time);"
                "CREATE INDEX evidence_group_cover_idx ON evidence(profile_ip,evidence_type,evidence_time,"
                "threat_level,source_module,whitelisted,accumulated_ratl,accumulated_threat_level);")
        connection.executemany("INSERT INTO evidence(evidence_id,profile_ip,evidence_time,threat_level,accumulated_ratl,whitelisted) "
            "VALUES (?,?,?,?,?,?)", [(f"{index}-{kind}",ip,ts,level,score,excluded)
                for index in range(600) for kind,ts,level,score,excluded in (
                    ("old",now-7200,"medium",0.49,0),("recent",now-30,"low",0.1,0),
                    ("excluded",now-30,"critical",99,1))])
    statements: list[str] = []
    original = reader._connect_sqlite

    def traced_connection() -> sqlite3.Connection:
        """Record read queries used by host counts and score statistics.

        Returns:
            A read-only connection with query tracing enabled.
        """
        connection = original()
        connection.set_trace_callback(statements.append)
        return connection

    reader._connect_sqlite = traced_connection
    query = {"range":["live" if bounded else "all"],"hide_excluded":["1"]}
    stats = reader._host_finding_stats([ip],query)[ip]
    count = reader._host_page_counts([ip],query=query)[ip]
    assert stats == {"evidence":600 if bounded else 1200,"peak":0.1 if bounded else 0.49,
                     "threat_rank":1 if bounded else 2}
    assert count == {"evidence":stats["evidence"],"alerts":0}
    aggregates = [sql for sql in statements if "FROM evidence" in sql and "GROUP BY profile_ip" in sql]
    assert len(aggregates) == 2
    with original() as connection:
        for sql in aggregates:
            if indexed:
                expected = "evidence_group_cover_idx"
                assert f"INDEXED BY {expected}" in sql
                plan = " ".join(str(row[3]) for row in connection.execute("EXPLAIN QUERY PLAN "+sql))
                assert expected in plan
                assert "COVERING INDEX" in plan
            else:
                assert "INDEXED BY" not in sql


def test_hosts_batch_findings_once_before_sorting_and_paging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sort the full inventory from one finding aggregate instead of per-row reads.

    Parameters:
        tmp_path: Isolated retained hosts and evidence.
        monkeypatch: Fix the active capture clock.
    """
    _module_factory = ModuleFactory()
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: 2_000_000_000.0)
    reader = _network_scope_reader(tmp_path)
    reader._host_finding_stats = Mock(wraps=reader._host_finding_stats)
    query = {"range":["all"],"sort":["peak_score"],"limit":["1"]}
    first = reader.hosts(query)
    assert first["items"][0]["peak_alert_score"] == 1
    assert reader._host_finding_stats.call_count == 1
    assert len(reader._host_finding_stats.call_args.args[0]) == 8
    assert first["next_cursor"]
    reader.hosts({**query,"cursor":[first["next_cursor"]]})
    assert reader._host_finding_stats.call_count == 2


@pytest.mark.parametrize("sort", ["last_seen", "ip", "hostname", "bytes"])
def test_hosts_findings_follow_search_and_page(
    tmp_path: Path, sort: str,
) -> None:
    """Read findings only for returned hosts when filtering does not need them.

    Parameters:
        tmp_path: Isolated inventory and findings.
        sort: A column that does not depend on evidence statistics.
    """
    _module_factory = ModuleFactory()
    reader = _network_scope_reader(tmp_path)
    reader._host_finding_stats = Mock(wraps=reader._host_finding_stats)

    page = reader.hosts({"range": ["all"], "sort": [sort], "limit": ["1"]})

    reader._host_finding_stats.assert_called_once()
    assert reader._host_finding_stats.call_args.args[0] == [page["items"][0]["ip"]]
    assert page["total"] == 8
    reader._host_finding_stats.reset_mock()
    empty = reader.hosts({"range": ["all"], "search": ["absent-host-token"]})
    assert empty["total"] == 0
    assert reader._host_finding_stats.call_args.args[0] == []


@pytest.mark.parametrize("scope", ["", "local"])
def test_device_search_filters_before_traffic_and_preserves_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scope: str,
) -> None:
    """A match on one address keeps all device members without unrelated work.

    Parameters:
        tmp_path: Isolated inventory and real traffic rows.
        monkeypatch: Match the live clock to the fixture timestamps.
        scope: Optional local scope combined with the search.
    """
    _module_factory = ModuleFactory()
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: 2_000_000_000.0)
    reader = _network_scope_reader(tmp_path)
    reader._host_page_loads = Mock(wraps=reader._host_page_loads)
    reader._host_page_counts = Mock(wraps=reader._host_page_counts)
    reader._host_finding_stats = Mock(wraps=reader._host_finding_stats)
    page = reader.hosts({"range": ["all"], "device": ["1"],
                         "search": ["fe80::20"], "scope": [scope]})

    members = {"192.168.12.1", "192.168.1.20", "fe80::20"}
    assert page["total"] == 1
    assert set(page["items"][0]["device_ips"]) == members
    assert set(reader._host_page_loads.call_args.args[0]) == members
    assert set(reader._host_finding_stats.call_args.args[0]) == members
    assert reader._host_page_counts.call_args.kwargs["include_evidence"] is False
    assert page["items"][0]["load"]["flows"] == 4
    assert page["items"][0]["evidence_count"] == 1


def test_device_search_keeps_unfiltered_offline_range_clock(tmp_path: Path) -> None:
    """An old search match cannot move the offline interval back to itself.

    Parameters:
        tmp_path: Isolated offline inventory and traffic timestamps.
    """
    _module_factory = ModuleFactory()
    reader = _network_scope_reader(tmp_path)
    reader.redis.hget.side_effect = None
    reader.redis.hget.return_value = "pcap"
    with connect_history(reader.history_path) as connection:
        connection.execute("UPDATE host_snapshots SET observed_at=1")
        connection.execute("UPDATE flow_index SET event_time=20000 WHERE src_ip='192.168.13.1'")
        connection.execute("UPDATE flow_index SET event_time=100 WHERE src_ip!='192.168.13.1'")

    page = reader.hosts({"range": ["live"], "device": ["1"], "search": ["fe80::20"]})

    assert page["total"] == 0


@pytest.mark.parametrize("group", ["", "host_type"])
@pytest.mark.parametrize("narrowed", ["", "profile", "type"])
@pytest.mark.parametrize("indexed", [True, False])
def test_bounded_evidence_search_uses_existing_covering_index(
    tmp_path: Path, group: str, narrowed: str, indexed: bool,
) -> None:
    """Use a covering time scan while preserving selective and legacy queries.

    Parameters:
        tmp_path: Isolated detection database.
        group: Individual records or host/type groups.
        narrowed: Optional selective host or type filter.
        indexed: Whether the existing time covering index is available.
    """
    _module_factory = ModuleFactory()
    reader = _network_scope_reader(tmp_path)
    reader.redis.hget.side_effect = None
    reader.redis.hget.return_value = "pcap"
    if indexed:
        with sqlite3.connect(reader.sqlite_path) as connection:
            connection.execute("CREATE INDEX evidence_time_cover_idx ON evidence("
                "evidence_time,evidence_id,profile_ip,evidence_type,threat_level,"
                "source_module,whitelisted,accumulated_ratl)")
    statements: list[str] = []
    original = reader._connect_sqlite

    def traced_connection() -> sqlite3.Connection:
        """Trace database reads.

        Returns:
            A read-only connection recording each SQL statement.
        """
        connection = original()
        connection.set_trace_callback(statements.append)
        return connection

    reader._connect_sqlite = traced_connection
    query = {"range": ["24h"], "search": ["scan"], "group": [group],
             "compact": ["1"], "hide_excluded": ["1"]}
    if narrowed:
        query[narrowed] = ["ARP_SCAN" if narrowed == "type" else "192.168.1.22"]
    result = reader.evidence(query)

    assert result["total"] == (1 if narrowed == "profile" else 2)
    selections = [statement for statement in statements if " LIKE " in statement]
    assert selections
    assert all(("INDEXED BY evidence_time_cover_idx" in statement) == (indexed and not narrowed)
               for statement in selections[:2])
    with original() as connection:
        assert reader._evidence_page_source(connection, False, False) == "evidence"


def test_device_view_combines_local_addresses_before_paging(
    tmp_path: Path,
) -> None:
    """MAC-matched local IPv4/IPv6 share lists, while public IPs stay separate.

    Parameters:
        tmp_path: Isolated history and detection databases.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "history.sqlite"
    reader.score_mode = "ratl"
    reader.cache = None
    reader.redis = Mock()
    reader._attach_current_host_scores = Mock()
    reader._ip_context_for_ip = Mock(return_value={})
    reader._annotate_detection_networks = Mock()
    reader._annotate_whitelisted_evidence = Mock()
    initialize_history(reader.history_path)
    mac = "aa:bb:cc:dd:ee:ff"
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO host_snapshots VALUES (?, ?, ?)",
            [(ip, time_seen, json.dumps({
                "ip": ip, "mac": mac, "scope": scope,
                "max_threat_level": "high",
            })) for ip, time_seen, scope in (
                ("10.0.0.1", 10, "local"),
                ("fe80::1", 11, "local"),
                ("8.8.8.8", 12, "public"),
            )],
        )
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "CREATE TABLE alerts(alert_id TEXT PRIMARY KEY, ip_alerted TEXT, "
            "alert_time REAL, label TEXT, accumulated_ratl REAL);"
            "CREATE TABLE evidence(evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT, accumulated_ratl REAL);"
            "CREATE TABLE alert_evidence(alert_id TEXT, evidence_id TEXT);"
            "CREATE TABLE evidence_flows(evidence_id TEXT, uid TEXT);"
            "INSERT INTO alerts VALUES "
            "('v4','10.0.0.1',10,'malicious',5),"
            "('v6','fe80::1',11,'malicious',6);"
            "INSERT INTO evidence VALUES "
            "('v4',10,'10.0.0.1','tw','high','SCAN','scan',0.8,'{}',5),"
            "('v6',11,'fe80::1','tw','high','SCAN','scan',0.8,'{}',6);"
            "INSERT INTO alert_evidence VALUES ('v4','v4'),('v6','v6');"
        )

    device_id = f"mac:{mac}"
    query = {"range": ["all"], "device": ["1"]}
    inventory = reader.hosts(query)
    alert_groups = reader.alerts({**query, "group": ["host"]})
    evidence_groups = reader.evidence({**query, "group": ["host_type"]})
    device_alerts = reader.alerts({**query, "device_id": [device_id],
                                   "details": ["false"]})
    device_evidence = reader.evidence({**query, "device_id": [device_id]})
    first_page = reader.hosts({**query, "limit": ["1"],
                               "sort": ["ip"], "order": ["asc"]})
    second_page = reader.hosts({**query, "limit": ["1"],
                                "sort": ["ip"], "order": ["asc"],
                                "cursor": [first_page["next_cursor"]]})

    assert reader._host_ips("10.0.0.1", query) == ["10.0.0.1", "fe80::1"]
    assert reader._host_ips("8.8.8.8", query) == ["8.8.8.8"]
    assert inventory["total"] == 2
    grouped = next(item for item in inventory["items"] if item["device_id"] == device_id)
    assert set(grouped["device_ips"]) == {"10.0.0.1", "fe80::1"}
    assert alert_groups["total"] == 1
    assert alert_groups["items"][0]["alert_count"] == 2
    assert evidence_groups["total"] == 1
    assert evidence_groups["items"][0]["evidence_count"] == 2
    assert device_alerts["total"] == 2
    assert device_evidence["total"] == 2
    assert first_page["next_cursor"]
    assert first_page["items"][0]["device_id"] != second_page["items"][0]["device_id"]


@pytest.mark.parametrize(
    "range_name, duration",
    [("5m", 300), ("15m", 900), ("live", 3600)],
)
def test_live_range_uses_wall_clock_for_interface_runs(
    mocker: MockerFixture, range_name: str, duration: int
) -> None:
    """Keep stale detections outside a rolling interval during idle capture.

    Parameters:
        mocker: Pytest patch helper.
        range_name: Requested rolling range.
        duration: Expected number of seconds in that range.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.redis = Mock()
    reader.redis.hget.return_value = "interface"
    mocker.patch("modules.web_interface.server.time.time", return_value=10_000)

    start, end, range_name = reader._time_bounds(
        {"range": [range_name]}, latest_event=7_000
    )

    assert (start, end, range_name) == (
        10_000 - duration,
        10_000,
        range_name,
    )


def test_host_load_reports_directional_flows_and_bytes(tmp_path) -> None:
    """Test host totals separate inbound, outbound, and internal traffic."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.history_path = tmp_path / "history.sqlite"
    reader._host_ips = Mock(return_value=["10.0.0.1"])
    initialize_history(reader.history_path)
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO flow_index "
            "(uid, flow_rowid, event_time, src_ip, dst_ip, proto, "
            "app_proto, bytes, packets, label) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                ("in", 1, 1.0, "8.8.8.8", "10.0.0.1", "tcp", "", 100, 2, ""),
                ("out", 2, 2.0, "10.0.0.1", "1.1.1.1", "udp", "", 200, 3, ""),
                ("self", 3, 3.0, "10.0.0.1", "10.0.0.1", "tcp", "", 50, 1, ""),
            ],
        )

    load = reader._host_load("10.0.0.1")

    assert load["flows"] == 3
    assert load["inbound_flows"] == 1
    assert load["outbound_flows"] == 1
    assert load["inbound_bytes"] == 100
    assert load["outbound_bytes"] == 200


def test_host_score_history_reports_peaks_resets_and_missing_coverage(
    tmp_path,
) -> None:
    """Return bounded real score samples and distinguish unscored evidence."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.score_mode = "ratl"
    reader.alert_threshold = 5.0
    reader._live_host = Mock(return_value={"live": False})
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "accumulated_threat_level REAL, accumulated_ratl REAL)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?)",
            [
                ("unscored", 100.0, "10.0.0.1", "timewindow1", None, None),
                ("rise", 110.0, "10.0.0.1", "timewindow1", 3.0, 1.0),
                ("cross", 120.0, "10.0.0.1", "timewindow1", 18.0, 6.0),
                ("alert-reset", 130.0, "10.0.0.1", "timewindow1", 1.5, 0.5),
                ("tw-reset", 200.0, "10.0.0.1", "timewindow2", 0.6, 0.2),
            ],
        )

    result = reader.score_history(
        "10.0.0.1", {"range": ["all"], "max_points": ["100"]}
    )

    assert result["evidence_total"] == 5
    assert result["scored_evidence"] == 4
    assert result["coverage"] == pytest.approx(0.8)
    assert result["peak_score"] == 6.0
    assert result["threshold"] == 5.0
    assert result["reset_count"] == 2
    assert [point["reset_reason"] for point in result["timeline"]] == [
        "",
        "",
        "score decreased (possible reset)",
        "time window changed",
    ]

    custom = reader.score_history(
        "10.0.0.1",
        {
            "range": ["custom"],
            "from": ["115"],
            "to": ["135"],
            "max_points": ["100"],
        },
    )

    assert custom["range"] == "custom"
    assert custom["evidence_total"] == 2
    assert [point["ts"] for point in custom["timeline"]] == [120.0, 130.0]


def _group_records_reader(tmp_path: Path) -> RunDataReader:
    """Create mixed local and peer records spanning several cursor pages.

    Parameters:
        tmp_path: Private fixture database directory.

    Returns:
        Reader with 123 evidence records and no live Redis or whitelist access.
    """
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    reader._annotate_detection_networks = Mock()
    reader._annotate_whitelisted_evidence = Mock()
    reader._annotate_p2p_reporters = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, evidence_time REAL, "
            "profile_ip TEXT, timewindow TEXT, threat_level TEXT, evidence_type TEXT, "
            "description TEXT, confidence REAL, data TEXT, accumulated_ratl REAL, "
            "whitelisted INTEGER, source_module TEXT);"
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT);"
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT);"
        )
        for index in range(123):
            identifier = f"record-{index:03}"
            peer = index % 4 == 0
            description = f"{'alpha' if index % 2 else 'beta'} connection {index:03}"
            if index == 3:
                description += " needle"
            data = {"record_type": "P2P_REPORT", "peer_report": {
                "peer_id": f"reporter-{index % 8}", "peer_ip": "192.0.2.200",
                "provenance": [{"evidence_type": "UNKNOWN_PORT", "module": "conn_analyzer", "description": description}],
            }} if peer else {}
            connection.execute("INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
                identifier, 1700000000 + index, "192.0.2.20", "timewindow1",
                ["info", "low", "medium", "high", "critical"][index % 5],
                "UNKNOWN_PORT", description, (index % 11) / 10, json.dumps(data),
                None if index == 120 else index / 1000, int(index == 121),
                Modules.P2P_TRUST.value if peer else Modules.CONN_ANALYZER.value,
            ))
            for flow in range(index % 4):
                connection.execute("INSERT INTO evidence_flows VALUES (?,?)", (identifier, f"flow-{index}-{flow}"))
            if index % 6 == 0:
                connection.execute("INSERT INTO alert_evidence VALUES (?,?)", (f"alert-{index}", identifier))
    return reader


@pytest.mark.parametrize("origin, count", [("", 123), ("p2p", 31), ("local", 92)])
def test_group_record_source_filter_precedes_cursor_pagination(tmp_path: Path, origin: str, count: int) -> None:
    """Filter all group records without losing source constraints on later pages.

    Parameters:
        tmp_path: Isolated evidence database.
        origin: All sources, received reports, or local detections.
        count: Expected total before pagination.
    """
    _factory = ModuleFactory()
    reader = _group_records_reader(tmp_path)
    query = {"range": ["all"], "profile": ["192.0.2.20"], "origin": [origin], "limit": ["7"]}
    identifiers = []
    while True:
        result = reader.evidence(query)
        assert result["total"] == count
        for item in result["items"]:
            if origin:
                assert (item["module"] == Modules.P2P_TRUST.value) == (origin == "p2p")
            identifiers.append(item["id"])
        if not result["next_cursor"]:
            break
        query["cursor"] = [result["next_cursor"]]
    assert len(identifiers) == len(set(identifiers)) == count


@pytest.mark.parametrize("search, record_search, expected", [
    ("alpha", "needle", ["record-003"]), ("beta", "needle", []),
    ("", "0.123-no-match", []), ("", "0.122", ["record-122"]),
])
def test_group_record_search_intersects_parent_search(tmp_path: Path, search: str, record_search: str, expected: list[str]) -> None:
    """Search beyond the first page while retaining the parent Evidence query.

    Parameters:
        tmp_path: Isolated evidence database.
        search: Parent Evidence search.
        record_search: Additional record search, including stored numeric scores.
        expected: Matching evidence IDs across the complete group.
    """
    _factory = ModuleFactory()
    reader = _group_records_reader(tmp_path)
    result = reader.evidence({"range": ["all"], "profile": ["192.0.2.20"],
        "search": [search], "record_search": [record_search], "limit": ["2"]})
    assert [item["id"] for item in result["items"]] == expected
    assert result["total"] == len(expected)


@pytest.mark.parametrize("parent, record, count", [
    ("", "high", 24), ("high_or_more", "high", 24),
    ("low", "high", 0), ("critical", "info", 0),
])
def test_group_threat_filter_intersects_parent_filter(tmp_path: Path, parent: str, record: str, count: int) -> None:
    """Narrow a group without bypassing the main Evidence threat selection.

    Parameters:
        tmp_path: Isolated evidence database.
        parent: Main Evidence threat filter.
        record: Additional threat filter inside the group.
        count: Matching records across all pages.
    """
    _factory = ModuleFactory()
    reader = _group_records_reader(tmp_path)
    result = reader.evidence({"range": ["all"], "profile": ["192.0.2.20"],
        "threat": [parent], "record_threat": [record], "limit": ["7"]})
    assert result["total"] == count
    assert all(item["threat_level"] == record for item in result["items"])


def test_evidence_sorting_is_server_side_and_stable(tmp_path) -> None:
    """Test evidence sort parameters order the complete result before paging."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                ("z", 1.0, "192.0.2.20", "tw", "low", "B", "", 1.0, "{}"),
                ("a", 2.0, "192.0.2.10", "tw", "high", "A", "", 1.0, "{}"),
            ],
        )

    result = reader.evidence(
        {"range": ["all"], "sort": ["host"], "order": ["asc"]}
    )

    assert [item["id"] for item in result["items"]] == ["a", "z"]
    assert result["sort"] == "host"
    assert result["order"] == "asc"


@pytest.mark.parametrize("group", ["", "host_type"])
@pytest.mark.parametrize("order", ["asc", "desc"])
def test_evidence_score_sort_keeps_excluded_after_numbers(
    tmp_path, group: str, order: str
) -> None:
    """Keep excluded evidence together after scored rows across pages.

    Parameters:
        tmp_path: Isolated durable evidence database.
        group: Individual or host-and-type table layout.
        order: Numeric score direction.
    """
    factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = factory.create_redis_publisher_obj().r
    reader._runtime_whitelist_rules = Mock(return_value=[])
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT, accumulated_ratl REAL, "
            "whitelisted INTEGER)"
        )
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                ("low", 1, "10.0.0.1", "tw", "low", "A", "", 1, "{}", 1, 0),
                ("high", 2, "10.0.0.1", "tw", "low", "B", "", 1, "{}", 5, 0),
                (
                    "excluded-low",
                    3,
                    "10.0.0.1",
                    "tw",
                    "low",
                    "C",
                    "",
                    1,
                    "{}",
                    0,
                    1,
                ),
                (
                    "excluded-high",
                    4,
                    "10.0.0.1",
                    "tw",
                    "low",
                    "D",
                    "",
                    1,
                    "{}",
                    8,
                    1,
                ),
                (
                    "mixed-scored",
                    5,
                    "10.0.0.1",
                    "tw",
                    "low",
                    "E",
                    "",
                    1,
                    "{}",
                    9,
                    0,
                ),
                (
                    "mixed-excluded",
                    6,
                    "10.0.0.1",
                    "tw",
                    "low",
                    "E",
                    "",
                    1,
                    "{}",
                    0,
                    1,
                ),
            ],
        )

    query = {
        "range": ["all"],
        "sort": ["score"],
        "order": [order],
        "limit": ["2"],
    }
    if group:
        query["group"] = [group]
    items = []
    seen_cursors = set()
    while True:
        page = reader.evidence(query)
        assert page["sort"] == "score"
        assert page["order"] == order
        items.extend(page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
        assert cursor not in seen_cursors
        seen_cursors.add(cursor)
        query["cursor"] = [cursor]

    assert len(items) == (5 if group else 6)
    assert len({item["id"] for item in items}) == len(items)
    statuses = [item["whitelisted"] for item in items]
    assert statuses == sorted(statuses)
    numeric_scores = [
        item["alert_score"] for item in items if not item["whitelisted"]
    ]
    assert numeric_scores == sorted(numeric_scores, reverse=order == "desc")

    query.pop("cursor", None)
    query["hide_excluded"] = ["1"]
    visible = []
    while True:
        page = reader.evidence(query)
        visible.extend(page["items"])
        if not page["next_cursor"]:
            break
        query["cursor"] = [page["next_cursor"]]

    assert page["full_total"] == 6
    assert page["total"] == 3
    assert len(visible) == 3
    assert all(not item["whitelisted"] for item in visible)
    if group:
        mixed = next(item for item in visible if item["evidence_type"] == "E")
        assert mixed["evidence_count"] == 1
        assert mixed["alert_score"] == 9


def test_host_flow_filter_hides_only_exclusively_excluded_evidence(
    tmp_path,
) -> None:
    """Keep unlinked and scored flows while paging past excluded ones.

    Parameters:
        tmp_path: Isolated run and web history databases.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "history.sqlite"
    initialize_history(reader.history_path)
    uids = ["unlinked", "mixed", "scored", "excluded"]
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE flows (uid TEXT, flow TEXT, label TEXT)"
        )
        connection.executemany(
            "INSERT INTO flows VALUES (?, ?, ?)",
            [(uid, "{}", "") for uid in uids],
        )
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "whitelisted INTEGER)"
        )
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "CREATE INDEX evidence_flows_uid_idx ON evidence_flows(uid)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?)",
            [("excluded", 1), ("scored", 0)],
        )
        connection.executemany(
            "INSERT INTO evidence_flows VALUES (?, ?)",
            [
                ("excluded", "excluded"),
                ("excluded", "mixed"),
                ("scored", "mixed"),
                ("scored", "scored"),
            ],
        )
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO flow_index "
            "(uid, flow_rowid, event_time, src_ip, dst_ip, "
            "bytes, packets) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (uid, index, index, "10.0.0.1", "8.8.8.8", 1, 1)
                for index, uid in enumerate(uids, start=1)
            ],
        )

    assert reader.flows_for_host("10.0.0.1", {"range": ["all"]})["total"] == 4
    query = {"range": ["all"], "hide_excluded": ["1"], "limit": ["2"]}
    first = reader.flows_for_host("10.0.0.1", query)
    query["cursor"] = [first["next_cursor"]]
    second = reader.flows_for_host("10.0.0.1", query)

    assert first["total"] == second["total"] == 3
    assert [item["uid"] for item in first["items"] + second["items"]] == [
        "scored",
        "mixed",
        "unlinked",
    ]


def test_p2p_evidence_page_shows_reporter_peer_ids(tmp_path) -> None:
    """Recover reporter identities for existing P2P evidence in one query.

    Parameters:
        tmp_path: Isolated permanent trust database location.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    items = [
        {
            "evidence_type": "MALICIOUS_IP_FROM_P2P_NETWORK",
            "profile_ip": "8.8.8.8",
            "description": "Replied to this lookup, peers: peer-a (192.0.2.1), peer-b (192.0.2.2).",
        },
        {
            "evidence_type": "MALICIOUS_IP_FROM_P2P_NETWORK",
            "profile_ip": "9.9.9.9",
            "description": "Reported by peers: old-peer (192.0.2.3).",
        },
        {"evidence_type": "DNS_WITHOUT_CONNECTION", "profile_ip": "8.8.8.8"},
    ]

    reader._annotate_p2p_reporters(items)

    assert items[0]["reporting_peers"] == ["peer-a", "peer-b"]
    assert items[1]["reporting_peers"] == []
    assert "Historical reports from peers" in items[1]["description"]
    assert "reporting_peers" not in items[2]


@pytest.mark.parametrize(
    "description, evidence_type, expected",
    [
        (
            "attacking another peer: 192.168.1.147 (peer-1). "
            "confidence: 1.0",
            "P2P_REPORT",
            "Received from P2P peer 192.168.1.147 (peer-1): "
            "reputation report about IP 198.51.100.7; confidence 1.0. "
            "No victim or attack details were provided.",
        ),
        (
            "attacking another peer:  (peer-2). confidence: 0.05",
            "P2P_REPORT",
            "Received from P2P peer peer-2 (IP unavailable): "
            "reputation report about IP 198.51.100.7; confidence 0.05. "
            "No victim or attack details were provided.",
        ),
        (
            "Received from P2P peer peer-2: reputation report",
            "P2P_REPORT",
            "Received from P2P peer peer-2: reputation report",
        ),
        (
            "attacking another peer: 192.168.1.147 (peer-1). "
            "confidence: 1.0",
            "MALICIOUS_IP_FROM_P2P_NETWORK",
            "attacking another peer: 192.168.1.147 (peer-1). "
            "confidence: 1.0",
        ),
    ],
)
def test_legacy_p2p_report_description_names_sender_and_subject(
    description: str, evidence_type: str, expected: str
) -> None:
    """Clarify older report text while preserving unrelated evidence.

    Parameters:
        description: Stored evidence description.
        evidence_type: Signal type associated with the description.
        expected: Wording served by the web API.
    """
    _module_factory = ModuleFactory()
    item = {
        "description": description,
        "evidence_type": evidence_type,
        "profile_ip": "198.51.100.7",
    }

    RunDataReader._clarify_legacy_p2p_report(item)

    assert item["description"] == expected


def test_host_evidence_excludes_mac_alias_profiles(
    tmp_path,
) -> None:
    """Test a host evidence page covers only the selected profile IP."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "low",
                    3.0,
                    "10.0.0.1",
                    "tw",
                    "low",
                    "DNS",
                    "first",
                    0.2,
                    "{}",
                ),
                (
                    "high",
                    2.0,
                    "2001:db8::1",
                    "tw",
                    "high",
                    "SCAN",
                    "second",
                    0.9,
                    "{}",
                ),
                (
                    "other",
                    4.0,
                    "203.0.113.4",
                    "tw",
                    "high",
                    "OTHER",
                    "excluded",
                    1.0,
                    "{}",
                ),
            ],
        )

    result = reader.evidence_for_host(
        "10.0.0.1",
        {"range": ["all"], "sort": ["confidence"], "order": ["desc"]},
    )

    assert result["total"] == 1
    assert [item["id"] for item in result["items"]] == ["low"]


def test_host_evidence_searches_all_durable_evidence_fields(tmp_path) -> None:
    """Test host evidence search includes raw fields and linked identifiers."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    reader._host_ips = Mock(return_value=["10.0.0.1"])
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.execute(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "evidence-id",
                1.0,
                "10.0.0.1",
                "tw",
                "low",
                "DNS",
                "",
                0.2,
                '{"attacker": "raw-field-token"}',
            ),
        )
        connection.execute(
            "INSERT INTO evidence_flows VALUES (?, ?)",
            ("evidence-id", "flow-identifier-token"),
        )
        connection.execute(
            "INSERT INTO alert_evidence VALUES (?, ?)",
            ("alert-identifier-token", "evidence-id"),
        )

    for search in (
        "raw-field-token",
        "flow-identifier-token",
        "alert-identifier-token",
    ):
        result = reader.evidence_for_host(
            "10.0.0.1", {"range": ["all"], "search": [search]}
        )

        assert [item["id"] for item in result["items"]] == ["evidence-id"]


def test_ip_context_prefers_rdns_and_reports_ti_feeds() -> None:
    """Test cached IP context returns rDNS, DNS fallback, and TI feed names."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader._ti_for_ip = Mock(
        return_value={
            "reverse_dns": "rdns.example.test",
            "threatintelligence": {"source": ["feed-a", "feed-b"]},
        }
    )

    context = reader._ip_context_for_ip(
        "192.0.2.1", {"domains": ["domain.example.test"]}
    )

    assert context == {
        "dns_name": "rdns.example.test",
        "dns_name_source": "rDNS",
        "ti_feeds": ["feed-a", "feed-b"],
    }

    reader._ti_for_ip.return_value = {}
    fallback = reader._ip_context_for_ip(
        "192.0.2.1", {"domains": ["domain.example.test"]}
    )

    assert fallback["dns_name"] == "domain.example.test"
    assert fallback["dns_name_source"] == "DNS"
    assert fallback["ti_feeds"] == []


def test_run_metadata_reads_info_file(tmp_path) -> None:
    """Test the overview metadata parser preserves technical run facts."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    (metadata_dir / "info.txt").write_text(
        "Slips version: 1.2.3\nBranch: develop\nCommand: ./slips.py -w\n",
        encoding="utf-8",
    )

    metadata = reader._run_metadata()

    assert metadata == {
        "Slips version": "1.2.3",
        "Branch": "develop",
        "Command": "./slips.py -w",
    }


def test_evidence_aggregation_groups_host_and_type(tmp_path) -> None:
    """Test repeated evidence becomes one bounded host/type aggregate."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                ("one", 1.0, "10.0.0.1", "tw", "low", "SCAN", "", 1.0, "{}"),
                ("two", 2.0, "10.0.0.1", "tw", "high", "SCAN", "", 1.0, "{}"),
                ("three", 3.0, "10.0.0.1", "tw", "low", "DNS", "", 1.0, "{}"),
            ],
        )
        connection.executemany(
            "INSERT INTO evidence_flows VALUES (?, ?)",
            [("one", "flow-1"), ("two", "flow-2")],
        )

    result = reader.evidence(
        {
            "range": ["all"],
            "group": ["host_type"],
            "sort": ["evidence"],
            "order": ["desc"],
        }
    )

    assert result["total"] == 2
    assert result["matching_total"] == 3
    assert result["full_total"] == 3
    assert result["items"][0]["evidence_type"] == "SCAN"
    assert result["items"][0]["evidence_count"] == 2
    assert result["items"][0]["flow_count"] == 2
    assert result["items"][0]["threat_level"] == "high"
    assert "_grouped_evidence" not in result["items"][0]

    by_type = reader.evidence({"range": ["all"], "group": ["type"]})
    by_host = reader.evidence({"range": ["all"], "group": ["host"]})
    assert by_type["total"] == 2
    assert by_type["items"][0]["profile_ip"] == ""
    assert by_host["total"] == 1
    assert by_host["items"][0]["evidence_type"] == ""
    assert by_host["items"][0]["evidence_count"] == 3

    compact_page = reader.evidence(
        {
            "range": ["all"],
            "group": ["host_type"],
            "compact": ["1"],
            "limit": ["1"],
        }
    )
    assert compact_page["total"] == 2
    assert compact_page["items"][0]["flow_count"] is None
    assert compact_page["next_cursor"]
    next_page = reader.evidence(
        {
            "range": ["all"],
            "group": ["host_type"],
            "compact": ["1"],
            "limit": ["1"],
            "cursor": [compact_page["next_cursor"]],
        }
    )
    assert next_page["total"] == 2
    assert len(next_page["items"]) == 1


@pytest.mark.parametrize(
    "range_name,index_kind,expected_scan_alerts",
    [
        ("custom", "none", 1),
        ("custom", "time", 1),
        ("custom", "alert_cover", 1),
        ("all", "alert_cover", 2),
    ],
)
def test_type_grouping_counts_alerts_only_for_visible_groups(
    tmp_path: Path,
    range_name: str,
    index_kind: str,
    expected_scan_alerts: int,
) -> None:
    """Keep type groups and alert counts correct across range and index plans.

    Parameters:
        tmp_path: Isolated flows database directory.
        range_name: Selected evidence time range.
        index_kind: Available index used by the alert-count query.
        expected_scan_alerts: Alerts linked to visible scan evidence.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    reader.redis.hget.return_value = ""
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT, whitelisted INTEGER DEFAULT 0)"
        )
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, 'tw', 'low', ?, '', 1, '{}', 0)",
            [
                ("old", 10, "10.0.0.1", "SCAN"),
                ("scan", 140, "10.0.0.2", "SCAN"),
                ("dns", 150, "10.0.0.3", "DNS"),
            ],
        )
        connection.executemany(
            "INSERT INTO alert_evidence VALUES (?, ?)",
            [("a-old", "old"), ("a-scan", "scan"), ("a-dns", "dns")],
        )
        if index_kind == "time":
            connection.execute(
                "CREATE INDEX evidence_time_idx ON evidence(evidence_time)"
            )
        elif index_kind == "alert_cover":
            connection.execute(
                "CREATE INDEX evidence_alert_group_idx ON evidence("
                "evidence_id, evidence_type, profile_ip, evidence_time, "
                "whitelisted)"
            )
            connection.execute(
                "CREATE INDEX alert_evidence_evidence_idx "
                "ON alert_evidence(evidence_id)"
            )
    query = {
        "range": [range_name],
        "from": ["100"],
        "to": ["200"],
        "group": ["type"],
        "compact": ["1"],
        "sort": ["type"],
        "order": ["asc"],
        "limit": ["1"],
    }

    first = reader.evidence(query)
    second = reader.evidence(
        {**query, "cursor": [first["next_cursor"]]}
    )

    assert first["total"] == second["total"] == 2
    assert first["items"][0]["evidence_type"] == "DNS"
    assert first["items"][0]["alert_count"] == 1
    assert second["items"][0]["evidence_type"] == "SCAN"
    assert second["items"][0]["alert_count"] == expected_scan_alerts
    if range_name == "all":
        sorted_by_alerts = reader.evidence(
            {**query, "sort": ["alert"], "order": ["desc"], "limit": ["2"]}
        )
        assert [item["evidence_type"] for item in sorted_by_alerts["items"]] == [
            "SCAN",
            "DNS",
        ]


@pytest.mark.parametrize("group", ["type", "host", "host_type"])
@pytest.mark.parametrize("device", [False, True])
@pytest.mark.parametrize("hide_excluded", [False, True])
def test_compact_evidence_preserves_scoped_alert_links(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    group: str,
    device: bool,
    hide_excluded: bool,
) -> None:
    """Keep compact pages equivalent across time, exclusion and device filters.

    Parameters:
        tmp_path: Isolated detection databases.
        monkeypatch: Fix the capture clock.
        group: Evidence grouping selected in the browser.
        device: Combine verified address aliases.
        hide_excluded: Omit evidence excluded by the whitelist.
    """
    _module_factory = ModuleFactory()
    now = 2_000_000_000.0
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: now)
    reader = _network_scope_reader(tmp_path)
    reader._device_key_map = Mock(
        return_value={
            "192.168.1.20": "mac:aa:bb:cc:dd:ee:ff",
            "fe80::20": "mac:aa:bb:cc:dd:ee:ff",
        }
    )
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "DELETE FROM evidence; DELETE FROM alert_evidence;"
            "CREATE INDEX evidence_group_cover_idx ON evidence(profile_ip,"
            "evidence_type,evidence_time,threat_level,source_module,whitelisted,accumulated_ratl);"
            "CREATE INDEX evidence_alert_group_idx ON evidence(evidence_id,"
            "evidence_type,profile_ip,evidence_time,whitelisted);"
            "CREATE INDEX alert_evidence_evidence_idx ON alert_evidence(evidence_id);"
        )
        records = [
            ("old", now - 7200, "192.168.1.20", "SCAN", 0),
            ("scan", now - 30, "192.168.1.20", "SCAN", 0),
            ("alias", now - 20, "fe80::20", "SCAN", 0),
            ("dns", now - 10, "192.168.1.20", "DNS", 0),
            ("excluded", now - 5, "192.168.1.20", "SCAN", 1),
            ("future", now + 10, "192.168.1.20", "SCAN", 0),
        ]
        connection.executemany(
            "INSERT INTO evidence(evidence_id,evidence_time,profile_ip,"
            "evidence_type,whitelisted,threat_level,accumulated_ratl) "
            "VALUES (?,?,?,?,?,'low',0.1)",
            records,
        )
        connection.executemany(
            "INSERT INTO alert_evidence VALUES (?,?)",
            [(f"alert-{identifier}", identifier) for identifier, *_ in records]
            + [("second-alert", "scan")],
        )
    query = {
        "range": ["live"],
        "group": [group],
        "device": ["1" if device else "0"],
        "hide_excluded": ["1" if hide_excluded else "0"],
        "limit": ["1"],
    }
    expected = reader.evidence({**query, "limit": ["100"]})
    items = []
    while True:
        page = reader.evidence({**query, "compact": ["1"]})
        assert page["total"] == expected["total"]
        assert (
            page["matching_total"]
            == expected["matching_total"]
            == (3 if hide_excluded else 4)
        )
        items.extend(page["items"])
        if not page["next_cursor"]:
            break
        query["cursor"] = [page["next_cursor"]]
    assert [
        (item["id"], item["evidence_count"], item["alert_count"])
        for item in items
    ] == [
        (item["id"], item["evidence_count"], item["alert_count"])
        for item in expected["items"]
    ]
    assert sum(item["alert_count"] for item in items) == (
        4 if hide_excluded else 5
    )


def test_alert_aggregation_groups_each_host(tmp_path) -> None:
    """Test repeated alerts become one aggregate per affected host."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {}
    reader.sqlite_path = tmp_path / "flows.sqlite"
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            "CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, alert_time REAL, "
            "ip_alerted TEXT, timewindow TEXT, tw_start TEXT, tw_end TEXT, "
            "label TEXT)"
        )
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, "
            "evidence_time REAL, profile_ip TEXT, timewindow TEXT, "
            "threat_level TEXT, evidence_type TEXT, description TEXT, "
            "confidence REAL, data TEXT)"
        )
        connection.execute(
            "CREATE TABLE evidence_flows (evidence_id TEXT, uid TEXT)"
        )
        connection.execute(
            "CREATE TABLE alert_evidence (alert_id TEXT, evidence_id TEXT)"
        )
        connection.executemany(
            "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                ("a1", 1.0, "10.0.0.1", "tw", "", "", "malicious"),
                ("a2", 2.0, "10.0.0.1", "tw", "", "", "malicious"),
                ("a3", 3.0, "10.0.0.2", "tw", "", "", "malicious"),
            ],
        )
        connection.execute(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "e1",
                1.0,
                "10.0.0.1",
                "tw",
                "high",
                "SCAN",
                "Scan detected",
                1.0,
                "{}",
            ),
        )
        connection.executemany(
            "INSERT INTO alert_evidence VALUES (?, ?)",
            [("a1", "e1"), ("a2", "e1")],
        )

    result = reader.alerts(
        {
            "range": ["all"],
            "group": ["host"],
            "sort": ["alerts"],
            "order": ["desc"],
        }
    )
    compact_result = reader.alerts(
        {
            "range": ["all"],
            "search": ["a1"],
            "details": ["false"],
            "summary": ["1"],
            "modules": ["1"],
        }
    )

    assert result["total"] == 2
    assert result["full_total"] == 3
    assert result["items"][0]["ip_alerted"] == "10.0.0.1"
    assert result["items"][0]["alert_count"] == 2
    assert result["items"][0]["evidence_count"] == 2
    assert result["items"][0]["threat_level"] == "high"
    first_page = reader.alerts(
        {
            "range": ["all"],
            "group": ["host"],
            "sort": ["alerts"],
            "order": ["desc"],
            "limit": ["1"],
        }
    )
    second_page = reader.alerts(
        {
            "range": ["all"],
            "group": ["host"],
            "sort": ["alerts"],
            "order": ["desc"],
            "limit": ["1"],
            "cursor": [first_page["next_cursor"]],
        }
    )
    assert first_page["total"] == second_page["total"] == 2
    assert first_page["items"][0]["ip_alerted"] == "10.0.0.1"
    assert second_page["items"][0]["ip_alerted"] == "10.0.0.2"
    assert second_page["items"][0]["threat_level"] == "info"
    assert second_page["next_cursor"] is None
    assert compact_result["items"][0]["evidence_count"] == 1
    assert compact_result["items"][0]["threat_level"] == "high"
    assert compact_result["items"][0]["evidence_type"] == "SCAN"
    assert compact_result["items"][0]["summary"] == "Scan detected"
    assert compact_result["items"][0]["evidence_types"] == [
        {"type": "SCAN", "count": 1}
    ]
    assert len(compact_result["items"][0]["evidence_modules"]) == 1
    assert compact_result["items"][0]["evidence_modules"][0]["module"]
    assert "evidence" not in compact_result["items"][0]
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("e2", 2.0, "10.0.0.1", "tw", "low", "UNKNOWN_PORT",
             "Unknown port", 1.0, "{}"),
        )
        connection.execute("INSERT INTO alert_evidence VALUES (?, ?)",
                           ("a1", "e2"))
    mixed_result = reader.alerts(
        {"range": ["all"], "search": ["a1"], "details": ["false"],
         "summary": ["1"]}
    )
    assert mixed_result["items"][0]["evidence_types"] == [
        {"type": "SCAN", "count": 1}, {"type": "UNKNOWN_PORT", "count": 1}
    ]
    by_type = reader.alerts(
        {"range": ["all"], "search": ["unknown port"], "details": ["false"],
         "summary": ["1"]}
    )
    assert [item["alert_id"] for item in by_type["items"]] == ["a1"]
    exact_detail = reader.alerts(
        {"range": ["all"], "review": ["all"], "alert_id": ["a1"],
         "limit": ["1"]}
    )
    assert exact_detail["total"] == 1
    assert [item["id"] for item in exact_detail["items"][0]["evidence"]] == [
        "e2", "e1"
    ]
    assert reader.alerts(
        {"range": ["all"], "review": ["all"], "alert_id": ["a"]}
    )["total"] == 0
    detail_id = "f0ddef53-5ed7-4337-ad92-920ddaf26af7"
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?)",
            (detail_id, 4.0, "10.0.0.1", "tw", "", "", "malicious"),
        )
        connection.execute(
            "INSERT INTO alert_evidence VALUES (?, ?)", (detail_id, "e1")
        )
    old_browser_detail = reader.alerts(
        {"range": ["all"], "review": ["all"], "limit": ["1"],
         "search": [detail_id]}
    )
    assert old_browser_detail["total"] == 1
    assert old_browser_detail["items"][0]["alert_id"] == detail_id
    assert [item["id"] for item in old_browser_detail["items"][0][
        "evidence"
    ]] == ["e1"]


@pytest.mark.parametrize(
    "threat, expected",
    [
        ("critical_or_more", {"critical"}),
        ("high", {"high"}),
        ("high_or_more", {"high", "critical"}),
        ("medium_or_more", {"medium", "high", "critical"}),
        ("low_or_more", {"low", "medium", "high", "critical"}),
        ("info_or_more", {"info", "low", "medium", "high", "critical"}),
    ],
)
@pytest.mark.parametrize("grouped", [False, True])
def test_alert_threat_minimum_filter(
    tmp_path: Path, threat: str, expected: set[str], grouped: bool
) -> None:
    """Filter alert hosts and individual alerts before pagination.

    Parameters:
        tmp_path: Isolated SQLite storage.
        threat: Exact level or inclusive threshold.
        expected: Threat levels that should remain visible.
        grouped: Whether the query aggregates alerts by host.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.score_mode = "ratl"
    reader._ip_context_for_ip = Mock(return_value={})
    reader._annotate_detection_networks = Mock()
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "CREATE TABLE alerts(alert_id TEXT PRIMARY KEY, alert_time REAL, "
            "ip_alerted TEXT, label TEXT, accumulated_ratl REAL);"
            "CREATE TABLE evidence(evidence_id TEXT, threat_level TEXT);"
            "CREATE TABLE alert_evidence(alert_id TEXT, evidence_id TEXT);"
        )
        for rank, level in enumerate(("info", "low", "medium", "high", "critical")):
            connection.execute(
                "INSERT INTO alerts VALUES (?, ?, ?, ?, ?)",
                (level, rank + 1, f"10.0.0.{rank + 1}", "malicious", rank),
            )
            connection.execute(
                "INSERT INTO evidence VALUES (?, ?)", (level, level)
            )
            connection.execute(
                "INSERT INTO alert_evidence VALUES (?, ?)", (level, level)
            )

    query = {"range": ["all"], "threat": [threat], "details": ["false"]}
    if grouped:
        query["group"] = ["host"]
    page = reader.alerts(query)

    assert {item["threat_level"] for item in page["items"]} == expected
    assert page["total"] == len(expected)


@pytest.mark.parametrize(
    "threat, expected",
    [
        ("critical_or_more", {"10.0.0.5"}),
        ("high", {"10.0.0.4"}),
        ("high_or_more", {"10.0.0.4", "10.0.0.5"}),
        ("medium_or_more", {"10.0.0.3", "10.0.0.4", "10.0.0.5"}),
        ("low_or_more", {"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}),
        ("info_or_more", {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}),
    ],
)
def test_hosts_filter_by_maximum_threat_level(
    tmp_path: Path, threat: str, expected: set[str]
) -> None:
    """Test Host Inventory applies the threat filter before pagination."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "history.sqlite"
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {}
    reader._host_load = Mock(
        return_value={"flows": 0, "bytes": 0, "packets": 0, "last_seen": 0}
    )
    reader._profile_evidence_count = Mock(return_value=0)
    reader._profile_alert_count = Mock(return_value=0)
    initialize_history(reader.history_path)
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("CREATE TABLE evidence (profile_ip TEXT)")
        connection.execute("CREATE TABLE alerts (ip_alerted TEXT)")
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO host_snapshots VALUES (?, ?, ?)",
            [
                (f"10.0.0.{rank + 1}", rank + 1,
                 json.dumps({"ip": f"10.0.0.{rank + 1}", "scope": "local",
                             "max_threat_level": level}))
                for rank, level in enumerate(("info", "low", "medium", "high", "critical"))
            ],
        )

    result = reader.hosts({"range": ["all"], "threat": [threat]})

    assert result["total"] == len(expected)
    assert result["full_total"] == 5
    assert {item["ip"] for item in result["items"]} == expected
    if threat == "high_or_more":
        reader._current_profile_threats = Mock(
            return_value={"10.0.0.1": "critical", "10.0.0.4": "low"}
        )
        live_result = reader.hosts({"range": ["all"], "threat": [threat]})
        assert {item["ip"] for item in live_result["items"]} == {
            "10.0.0.1", "10.0.0.5"
        }


def test_hosts_page_batches_identity_and_counts(tmp_path: Path) -> None:
    """Load a host page with bounded queries instead of one call per row.

    Parameters:
        tmp_path: Isolated run databases.
    """
    factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "history.sqlite"
    reader.redis = factory.logger
    reader.cache = Mock()
    reader.score_mode = "ratl"
    reader.alert_threshold = 5.0
    reader._attach_current_host_scores = Mock()
    reader._live_host = Mock(side_effect=AssertionError("per-host Redis read"))
    reader._host_load = Mock(side_effect=AssertionError("per-host SQL read"))
    initialize_history(reader.history_path)
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("CREATE TABLE evidence (profile_ip TEXT)")
        connection.execute("CREATE TABLE alerts (ip_alerted TEXT)")
        connection.execute("INSERT INTO evidence VALUES ('10.0.0.1')")
        connection.execute("INSERT INTO alerts VALUES ('10.0.0.2')")
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO host_snapshots VALUES (?, ?, ?)",
            [
                ("10.0.0.1", 1.0, json.dumps({"ip": "10.0.0.1"})),
                ("10.0.0.2", 2.0, json.dumps({"ip": "10.0.0.2"})),
            ],
        )
        connection.execute(
            "INSERT INTO flow_index "
            "(uid, flow_rowid, event_time, src_ip, dst_ip, bytes, packets) "
            "VALUES ('one', 1, 3, '10.0.0.1', '10.0.0.2', 100, 2)"
        )
    reader.redis.pipeline.return_value.execute.return_value = [
        {},
        None,
        {"host_name": "computer"},
        None,
    ]
    reader.cache.pipeline.return_value.execute.return_value = [
        "printer.local",
        None,
        None,
        None,
    ]

    page = reader.hosts({"range": ["all"]})

    by_ip = {item["ip"]: item for item in page["items"]}
    assert by_ip["10.0.0.1"]["hostname"] == "computer"
    assert by_ip["10.0.0.2"]["dns_name"] == "printer.local"
    assert by_ip["10.0.0.1"]["evidence_count"] == 1
    assert by_ip["10.0.0.2"]["alert_count"] == 1
    assert by_ip["10.0.0.1"]["load"]["outbound_bytes"] == 100
    assert by_ip["10.0.0.2"]["load"]["inbound_bytes"] == 100
    reader.redis.pipeline.return_value.execute.assert_called_once_with()
    reader.cache.pipeline.return_value.execute.assert_called_once_with()


def test_hosts_show_and_sort_real_past_peak_score(tmp_path) -> None:
    """Return full-run persisted score peaks and sort the complete inventory."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "history.sqlite"
    reader.score_mode = "ratl"
    reader.alert_threshold = 5.0
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {}
    reader._host_load = Mock(
        return_value={"flows": 0, "bytes": 0, "packets": 0, "last_seen": 0}
    )
    reader._profile_evidence_count = Mock(return_value=0)
    reader._profile_alert_count = Mock(return_value=0)
    initialize_history(reader.history_path)
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE evidence (profile_ip TEXT, "
            "accumulated_threat_level REAL, accumulated_ratl REAL)"
        )
        connection.execute("CREATE TABLE alerts (ip_alerted TEXT)")
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?)",
            [
                ("10.0.0.1", 3.0, 1.0),
                ("10.0.0.1", 18.0, 6.0),
                ("10.0.0.2", 9.0, 3.0),
            ],
        )
        connection.execute("INSERT INTO alerts VALUES (?)", ("10.0.0.1",))
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO host_snapshots VALUES (?, ?, ?)",
            [
                (
                    "10.0.0.1",
                    1.0,
                    json.dumps({"ip": "10.0.0.1", "scope": "local"}),
                ),
                (
                    "10.0.0.2",
                    2.0,
                    json.dumps({"ip": "10.0.0.2", "scope": "local"}),
                ),
            ],
        )

    result = reader.hosts(
        {"range": ["all"], "sort": ["peak_score"], "order": ["desc"]}
    )

    assert [item["ip"] for item in result["items"]] == [
        "10.0.0.1",
        "10.0.0.2",
    ]
    assert [item["peak_alert_score"] for item in result["items"]] == [
        6.0,
        3.0,
    ]
    assert result["sort"] == "peak_score"
    assert result["order"] == "desc"
    alerted = reader.hosts({"range": ["all"], "alerts_only": ["1"]})
    assert [item["ip"] for item in alerted["items"]] == ["10.0.0.1"]


def test_hosts_live_range_uses_indexed_flow_clock(tmp_path) -> None:
    """Test capture-relative traffic is not compared with wall-clock snapshots."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.history_path = tmp_path / "history.sqlite"
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {}
    reader._host_load = Mock(
        return_value={
            "flows": 1,
            "bytes": 100,
            "packets": 2,
            "last_seen": 4000,
        }
    )
    reader._profile_evidence_count = Mock(return_value=0)
    reader._profile_alert_count = Mock(return_value=0)
    initialize_history(reader.history_path)
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("CREATE TABLE evidence (profile_ip TEXT)")
        connection.execute("CREATE TABLE alerts (ip_alerted TEXT)")
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO host_snapshots VALUES (?, ?, ?)",
            [
                (
                    "10.0.0.1",
                    2_000_000_000.0,
                    json.dumps({"ip": "10.0.0.1", "scope": "local"}),
                ),
                (
                    "10.0.0.2",
                    2_000_000_001.0,
                    json.dumps({"ip": "10.0.0.2", "scope": "local"}),
                ),
            ],
        )
        connection.executemany(
            "INSERT INTO flow_index "
            "(uid, flow_rowid, event_time, src_ip, dst_ip, proto, "
            "app_proto, bytes, packets, label) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "recent",
                    1,
                    4000.0,
                    "10.0.0.1",
                    "8.8.8.8",
                    "udp",
                    "dns",
                    100,
                    2,
                    "benign",
                ),
                (
                    "old",
                    2,
                    100.0,
                    "10.0.0.2",
                    "1.1.1.1",
                    "tcp",
                    "ssl",
                    200,
                    3,
                    "benign",
                ),
            ],
        )

    result = reader.hosts({"range": ["live"]})
    full_run = reader.hosts({"range": ["all"]})

    assert result["total"] == 1
    assert result["full_total"] == 2
    assert result["items"][0]["ip"] == "10.0.0.1"
    assert full_run["total"] == 2


def test_p2p_reports_enabled_listener_and_healthy_empty_network(
    tmp_path, monkeypatch
) -> None:
    """Expose a listening P2P module even before any peers are discovered."""
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output" / "run"
    log_dir = output_dir / "p2p_trust"
    log_dir.mkdir(parents=True)
    log_dir.joinpath("p2p.log").write_text(
        "[*] Your Multiaddress Is:  "
        "/ip4/10.0.0.1/tcp/32768/p2p/QmLocalPeer\n",
        encoding="utf-8",
    )
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.return_value = None
    reader.redis.hget.side_effect = lambda key, field: (
        "123" if (key, field) == ("PIDs", "p2p_trust") else None
    )
    reader.redis.hgetall.side_effect = lambda key: (
        {"analysis_start": "2026-08-25T23:07:20"} if key == "analysis" else {}
    )
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    result = reader.p2p()

    assert result["enabled"] is True
    assert result["local_peer_id"] == "QmLocalPeer"
    assert result["counts"]["connected"] == 0
    assert result["peers"] == []


def test_p2p_activity_keeps_report_content_from_retained_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Expose the full bounded telemetry message for report inspection."""
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output" / "run"
    output_dir.mkdir(parents=True)
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.return_value = None
    reader.redis.hget.return_value = None
    reader.redis.hgetall.return_value = {}
    reader.redis.zrange.return_value = []
    record = {
        "direction": "received",
        "message_type": "report",
        "peer": "QmRemotePeer",
        "target": "8.8.8.8",
        "report_time": 100.0,
        "timestamp": 101.0,
        "message": {
            "key": "8.8.8.8",
            "evaluation": {"score": 0.7, "confidence": 0.8},
        },
    }
    reader.redis.lrange.return_value = [json.dumps(record)]

    result = reader.p2p()

    reader.redis.lrange.assert_called_once_with("p2p_message_history", 0, 999)
    assert result["activity"][0]["message"]["evaluation"] == {
        "score": 0.7,
        "confidence": 0.8,
    }


def test_p2p_uses_redis_identity_and_live_peer_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Prefer Redis identity and expose live peer updates without log data."""
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output" / "run"
    output_dir.mkdir(parents=True)
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.side_effect = lambda key: {
        "multiAddress": ("/ip4/10.0.0.1/tcp/6668/p2p/QmRedisLocalPeer"),
        "p2p:active_connection:connection-a": json.dumps(
            {
                "peer_id": "QmRemotePeer",
                "protocol": "tcp",
                "local_ip": "10.0.0.1",
                "local_port": "6668",
                "remote_ip": "192.0.2.10",
                "remote_port": "51000",
                "authenticated": True,
                "connected": True,
            }
        ),
    }.get(key)
    reader.redis.smembers.return_value = {"connection-a"}
    reader.redis.hget.side_effect = lambda key, field: (
        "123" if (key, field) == ("PIDs", "p2p_trust") else None
    )
    reader.redis.hgetall.side_effect = lambda key: {
        "analysis": {"analysis_start": "2026-08-25T23:07:20"},
        "peer_info": {
            "QmRemotePeer": json.dumps(
                {
                    "ip": "192.0.2.10",
                    "reliability": 0.75,
                    "timestamp": 1649445643,
                }
            )
        },
    }.get(key, {})
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    result = reader.p2p()

    assert result["listener"] == (
        "/ip4/10.0.0.1/tcp/6668/p2p/QmRedisLocalPeer"
    )
    assert result["local_peer_id"] == "QmRedisLocalPeer"
    assert result["counts"]["connected"] == 1
    assert result["peers"] == [
        {
            "peer_id": "QmRemotePeer",
            "ip": "192.0.2.10",
            "connected": True,
            "trust": (0.75 * 0.7) / 2,
            "report_accuracy": [],
            "confirmed_reports": 0,
            "false_reports": 0,
            "reliability": 0.75,
            "first_seen": 1649445643.0,
            "last_seen": 1649445643.0,
            "reports_received": 0,
            "connections": [
                {
                    "peer_id": "QmRemotePeer",
                    "protocol": "tcp",
                    "local_ip": "10.0.0.1",
                    "local_port": "6668",
                    "remote_ip": "192.0.2.10",
                    "remote_port": "51000",
                    "authenticated": True,
                    "connected": True,
                }
            ],
        }
    ]


@pytest.mark.parametrize(
    "cached_trust,expected_trust", [(None, 0.305), ("0.61", 0.305)]
)
def test_p2p_uses_verified_peer_ip_and_persistent_trust_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cached_trust: str | None,
    expected_trust: float,
) -> None:
    """Ignore a loopback peer update and retain the authenticated endpoint.

    Parameters:
        tmp_path: Isolated trust database directory.
        monkeypatch: Changes to that isolated directory.
        cached_trust: Optional current model cache entry.
        expected_trust: Trust recomputed from reliable local inputs.
    """
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output" / "run"
    output_dir.mkdir(parents=True)
    trust_path = tmp_path / "permanent" / "p2p_trust_runtime" / "trustdb.db"
    trust_path.parent.mkdir(parents=True)
    with sqlite3.connect(trust_path) as connection:
        connection.executescript(
            "CREATE TABLE go_reliability (peerid TEXT, reliability REAL, update_time REAL);"
            "CREATE TABLE peer_ips (peerid TEXT, ipaddress TEXT, update_time REAL);"
            "CREATE TABLE peer_addresses (peerid TEXT, ipaddress TEXT, update_time REAL);"
            "CREATE TABLE slips_reputation (ipaddress TEXT, score REAL, confidence REAL, source TEXT);"
            "CREATE TABLE reports (reporter_peerid TEXT, reported_key TEXT, "
            "score REAL, confidence REAL, update_time REAL);"
            "INSERT INTO go_reliability VALUES ('QmLostPeer', 0.8, 300);"
            "INSERT INTO peer_ips VALUES ('QmLostPeer', '127.0.0.1', 300);"
            "INSERT INTO peer_addresses VALUES ('QmLostPeer', '192.168.1.249', 200);"
            "INSERT INTO slips_reputation VALUES ('192.168.1.249', 0, 0.05, 'local');"
        )
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.return_value = None
    reader.redis.hget.return_value = None
    reader.redis.hgetall.side_effect = lambda key: {
        "analysis": {"analysis_start": "0"},
        "peer_info": {
            "QmLostPeer": json.dumps(
                {"ip": "127.0.0.1", "timestamp": 300, "reliability": 0.8}
            )
        },
        "peer_trust": (
            {"192.168.1.249": cached_trust} if cached_trust else {}
        ),
    }.get(key, {})
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    peer = reader.p2p()["peers"][0]

    assert peer["ip"] == "192.168.1.249"
    assert peer["trust"] == pytest.approx(expected_trust)


@pytest.mark.parametrize("interfaces", ["en0", "en0,en1"])
@pytest.mark.parametrize("connected", [True, False])
def test_identity_returns_current_named_network_in_any_tab(interfaces: str, connected: bool) -> None:
    """The heartbeat includes every live monitored IP, even between connections.

    Parameters:
        interfaces: One or multiple monitored interfaces.
        connected: Whether the stored network state reports a connection.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {
        "input_type": "interface",
        "interface": interfaces,
    }
    reader.redis.hget.return_value = json.dumps(
        {"interface": "en0", "connected": connected, "host_ip": "192.0.2.4"}
    )
    reader._named_network_states = Mock(
        return_value=[
            {
                "name": "Office",
                "network_id": "router-1",
                "host_ip": "192.0.2.4",
            }
        ]
    )

    current_addresses = {
        "en0": [SimpleNamespace(family=socket.AF_INET,address="192.0.2.4"),
            SimpleNamespace(family=socket.AF_INET6,address="fe80::4%en0"),
            SimpleNamespace(family=socket.AF_INET6,address="fd00::4"),
            SimpleNamespace(family=socket.AF_INET6,address="2001:db8::4"),
            SimpleNamespace(family=socket.AF_INET6,address="2001:db8::5")],
        "en1": [SimpleNamespace(family=socket.AF_INET,address="198.51.100.4")],
    }
    expected = {
        "interface": "en0",
        "connected": True,
        "name": "Office",
        "network_id": "router-1",
        "host_ip": "192.0.2.4",
    } if connected else {"interface":"en0", "connected":False}
    expected["host_addresses"] = {
        "ipv4": ["192.0.2.4"] + (["198.51.100.4"] if "," in interfaces else []),
        "ipv6": ["fe80::4", "fd00::4", "2001:db8::4", "2001:db8::5"],
    }
    with patch("modules.web_interface.server.psutil.net_if_addrs", return_value=current_addresses):
        assert reader._current_header_network() == expected
        current_addresses["en0"][4].address = "2001:db8::6"
        assert reader._current_header_network()["host_addresses"]["ipv6"][-1] == "2001:db8::6"
    reader.redis.hset.assert_not_called()


def test_p2p_marks_recently_active_message_sender_online(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Show peers online for a short period after their latest message."""
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output" / "run"
    output_dir.mkdir(parents=True)
    now = time.time()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.return_value = None
    reader.redis.hget.return_value = None
    reader.redis.hgetall.side_effect = lambda key: {
        "analysis": {"analysis_start": str(now - 60)},
        "peer_info": {
            "QmSlowPeer": json.dumps(
                {
                    "ip": "192.0.2.40",
                    "connected": True,
                    "last_activity": now - 30,
                }
            )
        },
    }.get(key, {})
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    result = reader.p2p()

    assert result["counts"]["connected"] == 1
    assert result["peers"][0]["peer_id"] == "QmSlowPeer"
    assert result["peers"][0]["connected"] is True


def test_p2p_does_not_show_failed_connection_as_online(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep a recent failed dial offline until authenticated activity arrives."""
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output" / "run"
    output_dir.mkdir(parents=True)
    now = time.time()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.return_value = None
    reader.redis.hget.return_value = None
    reader.redis.hgetall.side_effect = lambda key: {
        "analysis": {"analysis_start": str(now - 60)},
        "peer_info": {
            "QmFailedPeer": json.dumps(
                {
                    "ip": "192.0.2.41",
                    "connected": False,
                    "last_activity": now - 1,
                }
            )
        },
    }.get(key, {})
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    result = reader.p2p()

    assert result["counts"]["connected"] == 0
    assert result["peers"][0]["connected"] is False


@pytest.mark.parametrize(
    "connected_peers,peer_state,expected",
    [
        (["QmPeer"], {"connected": True}, {"QmPeer"}),
        (["QmPeer"], {"connected": False}, set()),
        (["QmPeer"], {}, set()),
        ("invalid", {"connected": True}, set()),
    ],
)
def test_legacy_connected_p2p_peers_require_consistent_state(
    connected_peers: object,
    peer_state: dict,
    expected: set[str],
) -> None:
    """Use compatible connectivity only when both legacy records agree.

    Parameters:
        connected_peers: Decoded legacy connected-peer registry.
        peer_state: Legacy state stored for the peer.
        expected: Peer IDs considered connected.
    """
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.redis = Mock()
    reader.redis.get.return_value = connected_peers

    result = reader._legacy_connected_p2p_peers({"QmPeer": peer_state})

    assert result == expected


def test_p2p_uses_legacy_connectivity_without_connection_updates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Show active peers reported by the bundled legacy macOS Pigeon."""
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output" / "run"
    output_dir.mkdir(parents=True)
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.side_effect = lambda key: {
        "connected_peers": json.dumps(["QmLegacyPeer"]),
    }.get(key)
    reader.redis.smembers.return_value = set()
    reader.redis.hget.return_value = None
    reader.redis.hgetall.side_effect = lambda key: {
        "analysis": {"analysis_start": "2026-08-25T23:07:20"},
        "peer_info": {
            "QmLegacyPeer": json.dumps(
                {
                    "connected": True,
                    "ip": "192.0.2.20",
                    "reliability": 1.0,
                    "timestamp": time.time(),
                }
            )
        },
    }.get(key, {})
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    result = reader.p2p()

    assert result["counts"]["connected"] == 1
    assert result["peers"][0]["peer_id"] == "QmLegacyPeer"
    assert result["peers"][0]["connected"] is True
    assert result["peers"][0]["connections"] == []


def test_p2p_report_counter_is_not_limited_to_latest_500(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Count every report from this run while limiting returned report rows."""
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output" / "run"
    output_dir.mkdir(parents=True)
    trust_path = tmp_path / "permanent" / "p2p_trust_runtime" / "trustdb.db"
    trust_path.parent.mkdir(parents=True)
    with sqlite3.connect(trust_path) as connection:
        connection.execute(
            "CREATE TABLE go_reliability "
            "(peerid TEXT, reliability REAL, update_time REAL)"
        )
        connection.execute(
            "CREATE TABLE peer_ips "
            "(peerid TEXT, ipaddress TEXT, update_time REAL)"
        )
        connection.execute(
            "INSERT INTO peer_ips VALUES (?, ?, ?)",
            ("QmOldPeer", "192.0.2.25", 900),
        )
        connection.execute(
            "CREATE TABLE reports "
            "(reporter_peerid TEXT, reported_key TEXT, score REAL, "
            "confidence REAL, update_time REAL)"
        )
        connection.executemany(
            "INSERT INTO reports VALUES (?, ?, ?, ?, ?)",
            [
                (
                    "QmRemotePeer",
                    f"192.0.2.{index}",
                    0.5,
                    0.8,
                    1000 + index,
                )
                for index in range(501)
            ]
            + [
                (
                    "QmOldPeer",
                    f"198.51.100.{index}",
                    0.5,
                    0.8,
                    index,
                )
                for index in range(20)
            ],
        )

    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.return_value = None
    reader.redis.hget.return_value = None
    reader.redis.hgetall.side_effect = lambda key: (
        {"analysis_start": "1000"} if key == "analysis" else {}
    )
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    result = reader.p2p()

    assert len(result["reports"]) == 200
    assert result["counts"]["reports_received"] == 501
    peer_counts = {
        peer["peer_id"]: peer["reports_received"] for peer in result["peers"]
    }
    assert peer_counts == {"QmRemotePeer": 501, "QmOldPeer": 0}


def test_p2p_received_reports_survive_raw_report_compaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Show current-window message counts after raw trust rows are removed.

    Parameters:
        tmp_path: Isolated run and trust-database location.
        monkeypatch: Changes the process working directory for the test.
    """
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path / "output" / "run"
    reader.output_dir.mkdir(parents=True)
    reader.redis = Mock()
    reader.redis.get.return_value = "2"
    reader.redis.hget.return_value = None
    reader.redis.hgetall.side_effect = lambda key: {
        "p2p_message_counts_2": {
            "received:report": "7",
            "received:blame": "2",
        },
        "p2p_reports_by_peer_2": {"QmRemotePeer": "9"},
    }.get(key, {})
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    result = reader.p2p()

    assert result["counts"]["reports_received"] == 9
    assert result["peers"][0]["reports_received"] == 9


def test_host_workspace_live_range_uses_run_wide_flow_clock(tmp_path) -> None:
    """Exclude an inactive host from Live using the newest run-wide flow."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.history_path = tmp_path / "history.sqlite"
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader._host_ips = Mock(return_value=["10.0.0.1"])
    reader._live_host = Mock(return_value={})
    reader.score_mode = "ratl"
    reader.alert_threshold = 5.0
    initialize_history(reader.history_path)
    with connect_history(reader.history_path) as connection:
        connection.executemany(
            "INSERT INTO flow_index "
            "(uid, flow_rowid, event_time, src_ip, dst_ip, proto, "
            "app_proto, bytes, packets, label) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "inactive-host-flow",
                    1,
                    100.0,
                    "10.0.0.1",
                    "8.8.8.8",
                    "udp",
                    "dns",
                    100,
                    2,
                    "benign",
                ),
                (
                    "run-clock-flow",
                    2,
                    4000.0,
                    "10.0.0.2",
                    "1.1.1.1",
                    "tcp",
                    "ssl",
                    200,
                    3,
                    "benign",
                ),
            ],
        )
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute(
            "CREATE TABLE flows (uid TEXT, flow TEXT, label TEXT)"
        )
        connection.execute(
            "INSERT INTO flows VALUES (?, ?, ?)",
            ("inactive-host-flow", "{}", "benign"),
        )
        connection.execute(
            "CREATE TABLE evidence (evidence_id TEXT, evidence_time REAL, "
            "profile_ip TEXT, timewindow TEXT, accumulated_ratl REAL)"
        )
        connection.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?)",
            [
                ("inactive-evidence", 100, "10.0.0.1", "timewindow1", 1.0),
                ("run-clock-evidence", 4000, "10.0.0.2", "timewindow1", 2.0),
            ],
        )

    live_flows = reader.flows_for_host("10.0.0.1", {"range": ["live"]})
    full_flows = reader.flows_for_host("10.0.0.1", {"range": ["all"]})
    live_summary = reader.traffic_summary("10.0.0.1", {"range": ["live"]})
    live_score = reader.score_history("10.0.0.1", {"range": ["live"]})

    assert live_flows["total"] == 0
    assert live_flows["items"] == []
    assert full_flows["total"] == 1
    assert live_summary["timeline"] == []
    assert live_score["timeline"] == []
    assert live_score["evidence_total"] == 0


def test_host_workspace_range_is_used_for_evidence_and_reset() -> None:
    """Send the selected host range to evidence and reset its cursor."""
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    evidence_loader = app_source.split("async function loadHostEvidence()", 1)[
        1
    ].split("async function loadHostFlows()", 1)[0]
    host_binding = app_source.split('bindRange("host", "hostFlows"', 1)[
        1
    ].split("bindTableSort", 1)[0]

    assert "const params = hostRangeParams();" in evidence_loader
    assert 'range: "all"' not in evidence_loader
    assert 'resetPage("host-evidence");' in host_binding


def test_p2p_trust_history_honors_selected_range(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Filter plotted history while preserving each peer's latest reliability."""
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output" / "run"
    output_dir.mkdir(parents=True)
    trust_path = tmp_path / "permanent" / "p2p_trust_runtime" / "trustdb.db"
    trust_path.parent.mkdir(parents=True)
    with sqlite3.connect(trust_path) as connection:
        connection.execute(
            "CREATE TABLE go_reliability "
            "(peerid TEXT, reliability REAL, update_time REAL)"
        )
        connection.execute(
            "CREATE TABLE peer_ips "
            "(peerid TEXT, ipaddress TEXT, update_time REAL)"
        )
        connection.execute(
            "CREATE TABLE reports "
            "(reporter_peerid TEXT, reported_key TEXT, score REAL, "
            "confidence REAL, update_time REAL)"
        )
        connection.executemany(
            "INSERT INTO go_reliability VALUES (?, ?, ?)",
            [("QmOldPeer", 0.25, 100), ("QmRecentPeer", 0.75, 4000)],
        )
        connection.executemany(
            "INSERT INTO peer_ips VALUES (?, ?, ?)",
            [
                ("QmOldPeer", "192.0.2.1", 100),
                ("QmRecentPeer", "192.0.2.2", 4000),
            ],
        )

    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.return_value = None
    reader.redis.hget.return_value = None
    reader.redis.hgetall.side_effect = lambda key: (
        {"analysis_start": "0"} if key == "analysis" else {}
    )
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    result = reader.p2p({"range": ["live"]})

    assert result["trust_range"] == "live"
    assert [row["peer_id"] for row in result["trust_history"]] == [
        "QmRecentPeer"
    ]
    assert {peer["peer_id"] for peer in result["peers"]} == {
        "QmOldPeer",
        "QmRecentPeer",
    }
    recent_peer = next(
        peer for peer in result["peers"]
        if peer["peer_id"] == "QmRecentPeer"
    )
    assert recent_peer["reliability"] == result["trust_history"][0]["reliability"] == 0.75
    assert recent_peer["trust"] == pytest.approx(0.2625)


def test_p2p_trust_full_history_keeps_first_detection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep the first and latest reliability samples after history grows large.

    Parameters:
        tmp_path: Isolated trust database directory.
        monkeypatch: Runs the reader against the isolated directory.
    """
    _module_factory = ModuleFactory()
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output" / "run"
    output_dir.mkdir(parents=True)
    trust_path = tmp_path / "permanent" / "p2p_trust_runtime" / "trustdb.db"
    trust_path.parent.mkdir(parents=True)
    with sqlite3.connect(trust_path) as connection:
        connection.execute(
            "CREATE TABLE go_reliability "
            "(peerid TEXT, reliability REAL, update_time REAL)"
        )
        connection.execute(
            "CREATE TABLE peer_ips "
            "(peerid TEXT, ipaddress TEXT, update_time REAL)"
        )
        connection.execute(
            "CREATE TABLE reports "
            "(reporter_peerid TEXT, reported_key TEXT, score REAL, "
            "confidence REAL, update_time REAL)"
        )
        connection.execute(
            "INSERT INTO peer_ips VALUES ('QmPeer', '192.0.2.1', 50)"
        )
        connection.executemany(
            "INSERT INTO go_reliability VALUES (?, ?, ?)",
            (("QmPeer", 0.9, float(index)) for index in range(100, 2601)),
        )

    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = output_dir
    reader.redis = Mock()
    reader.redis.get.return_value = None
    reader.redis.hget.return_value = None
    reader.redis.hgetall.side_effect = lambda key: (
        {"analysis_start": "0"} if key == "analysis" else {}
    )
    reader.redis.zrange.return_value = []
    reader.redis.lrange.return_value = []

    result = reader.p2p({"range": ["all"]})

    assert result["trust_history"][0]["timestamp"] == 100
    assert result["trust_history"][-1]["timestamp"] == 2600
    assert len(result["trust_history"]) <= 2002
    assert result["peers"][0]["first_seen"] == 50


def test_p2p_api_forwards_selected_history_range() -> None:
    """Forward the P2P history selector through the HTTP API route."""
    _module_factory = ModuleFactory()
    handler = RequestHandler.__new__(RequestHandler)
    handler.server = Mock()
    handler.server.reader.response_metadata.return_value = {}
    handler.server.reader.p2p.return_value = {"trust_history": []}
    query = {"range": ["1h"]}

    result = handler._api_response("/api/p2p", query)

    assert result["trust_history"] == []
    handler.server.reader.p2p.assert_called_once_with(query)


def test_p2p_reliability_chart_uses_compact_range_control() -> None:
    """Wire the compact peer chart to the selected API history range."""
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    html_source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )
    css_source = Path("modules/web_interface/style.css").read_text(
        encoding="utf-8"
    )

    assert 'id="p2p-range"' in html_source
    assert 'id="p2p-trust-chart"' in html_source
    assert "function renderP2PMetricChart" in app_source
    assert "/api/p2p?range=${encodeURIComponent(range)}" in app_source
    assert 'byId("p2p-range").addEventListener("change"' in app_source
    assert (
        ".compact-line-chart { height: 130px; min-height: 130px; }"
        in css_source
    )


def test_alerts_default_to_grouped_by_host() -> None:
    """Show host groups and a resizable empty pane before selection."""
    _module_factory = ModuleFactory()
    html_source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )

    assert (
        'id="alerts-workspace" class="alerts-workspace" data-panes="1"'
        in html_source
    )
    assert (
        'id="alerts-list-pane" class="alerts-pane alerts-list-pane" hidden'
        in html_source
    )
    assert (
        'id="alerts-detail-pane" class="alerts-pane alerts-detail-pane" hidden'
        in html_source
    )
    assert 'id="alerts-host-divider"' in html_source
    assert 'id="alerts-detail-divider"' in html_source
    assert 'params.set("group", "host")' in app_source
    assert "function initAlertPaneResize()" in app_source
    assert "Alerts grouped by host. Select a host" in html_source
    assert 'data-alert-group="individual"' in html_source
    assert 'id="alerts-empty-pane"' in html_source
    assert 'id="alerts-evidence-pane"' in html_source


def test_header_shows_monitored_interface_addresses() -> None:
    """Expose and render IPv4 and IPv6 addresses from monitored interfaces."""
    _module_factory = ModuleFactory()
    interface_addresses = {
        "eth0": [
            Mock(family=socket.AF_INET, address="192.0.2.10"),
            Mock(family=socket.AF_INET6, address="2001:db8::10%eth0"),
            Mock(family=socket.AF_INET6, address="::1"),
        ],
        "wlan0": [
            Mock(family=socket.AF_INET, address="198.51.100.20"),
        ],
    }

    with patch(
        "modules.web_interface.server.psutil.net_if_addrs",
        return_value=interface_addresses,
    ):
        addresses = RunDataReader._interface_addresses("eth0, wlan0")

    assert addresses == {
        "ipv4": ["192.0.2.10", "198.51.100.20"],
        "ipv6": ["2001:db8::10"],
    }
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    index_source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )
    assert 'id="run-addresses"' in index_source
    assert "data.host_addresses || {}" in app_source
    assert "function renderHeaderAddresses(data, network)" in app_source


def test_header_uptime_ticks_from_server_baseline() -> None:
    """Show run uptime below Updated and advance it only while running."""
    _module_factory = ModuleFactory()
    app_source = Path("modules/web_interface/app.js").read_text(
        encoding="utf-8"
    )
    index_source = Path("modules/web_interface/index.html").read_text(
        encoding="utf-8"
    )

    assert 'id="run-uptime">Uptime —</small>' in index_source
    assert "function renderHeaderUptime()" in app_source
    assert 'state.runUptimeRunning = run.state === "running"' in app_source
    assert "state.runUptimeSeconds + elapsed" in app_source
    assert "window.setInterval(renderHeaderUptime, 1000)" in app_source


def test_p2p_live_state_prunes_expired_connection_record() -> None:
    """Do not display an indexed peer as connected after its tuple TTL expires."""
    _module_factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.redis = Mock()
    reader.redis.smembers.return_value = {"expired-connection"}
    reader.redis.get.return_value = None

    assert reader._live_p2p_connections() == []
    reader.redis.srem.assert_called_once_with(
        "p2p:active_connections", "expired-connection"
    )


@pytest.mark.parametrize(
    "heartbeat, disconnected_at, now, expected_connected",
    [
        (100.0, 0.0, 110.0, True),
        (100.0, 0.0, 116.0, False),
        (100.0, 100.0, 101.0, False),
        (None, None, 101.0, False),
        ("invalid", "invalid", 101.0, False),
    ],
)
def test_backend_status_requires_a_fresh_attached_heartbeat(
    heartbeat: object,
    disconnected_at: object,
    now: float,
    expected_connected: bool,
) -> None:
    """
    Distinguish a retained HTTP page from its live Slips backend.

    Parameters:
        heartbeat: Last heartbeat value from history metadata.
        disconnected_at: Explicit backend shutdown value.
        now: Current time used for deterministic freshness checks.
        expected_connected: Expected backend connectivity result.
    """
    _module_factory = ModuleFactory()

    status = RunDataReader._backend_status(heartbeat, disconnected_at, now)

    assert status["connected"] is expected_connected
    assert status["timeout_seconds"] == 15


def test_response_metadata_exposes_stale_backend_status(
    tmp_path: Path,
) -> None:
    """Report a stale collector heartbeat even while HTTP remains available."""
    _module_factory = ModuleFactory()
    history_path = tmp_path / "history.sqlite"
    initialize_history(history_path)
    with connect_history(history_path) as connection:
        connection.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
            ("backend_heartbeat_at", "100"),
        )
    reader = RunDataReader.__new__(RunDataReader)
    reader.history_path = history_path
    reader.output_dir = tmp_path
    reader.analysis_start = "saved-analysis-start"

    with patch("modules.web_interface.server.time.time", return_value=116):
        metadata = reader.response_metadata()

    assert metadata["run_identity"]["analysis_start"] == "saved-analysis-start"
    assert metadata["backend_status"] == {
        "connected": False,
        "last_seen": 100.0,
        "age_seconds": 16.0,
        "timeout_seconds": 15,
    }


@pytest.mark.parametrize("selected_range,expected", [("all", [-0.5, 0.85]), ("live", [0.85])])
def test_calculated_trust_history_preserves_actual_signed_samples(
    tmp_path: Path, selected_range: str, expected: list[float]
) -> None:
    """Read measured trust without applying today's reputation to old values.

    Parameters:
        tmp_path: Isolated permanent database directory.
        selected_range: Requested chart range.
        expected: Recorded trust values inside that range.
    """
    _factory = ModuleFactory()
    path = tmp_path / "trustdb.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE peer_trust_history(peerid TEXT, trust REAL, update_time REAL)")
        connection.executemany("INSERT INTO peer_trust_history VALUES (?, ?, ?)", [("peer", -0.5, 100), ("peer", 0.85, 4000)])
    reader = RunDataReader.__new__(RunDataReader)
    reader.redis = Mock()
    reader.redis.hget.return_value = "pcap"
    result = reader._p2p_calculated_trust_history(path, {"range": [selected_range]})
    assert [row["trust"] for row in result] == expected
    assert reader._p2p_calculated_trust_history(tmp_path / "missing.db", {}) == []
    assert not (tmp_path / "missing.db").exists()


@pytest.mark.parametrize("table,metric", [("go_reliability", "reliability"), ("peer_trust_history", "trust")])
def test_p2p_chart_work_is_bounded_with_large_history(
    tmp_path: Path, table: str, metric: str
) -> None:
    """Read a large history under a SQLite instruction budget, keeping endpoints.

    Parameters:
        tmp_path: Isolated database directory.
        table: Metric history table.
        metric: Stored score column.
    """
    _factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.redis = Mock()
    reader.redis.hget.return_value = "pcap"
    with sqlite3.connect(tmp_path / "large-history.db") as connection:
        connection.execute(f"CREATE TABLE {table} (peerid TEXT, {metric} REAL, update_time REAL)")
        connection.execute(f"CREATE INDEX peer_time ON {table}(peerid, update_time)")
        connection.executemany(
            f"INSERT INTO {table} VALUES (?, ?, ?)",
            ((peer, index / 100000, float(index)) for peer in ("first", "second") for index in range(100000)),
        )
        instructions = 0
        def progress() -> int:
            """Interrupt a regression that scans or sorts the full history.

            Returns:
                Nonzero once the bounded-read instruction budget is exhausted.
            """
            nonlocal instructions
            instructions += 1000
            return int(instructions > 500000)
        connection.set_progress_handler(progress, 1000)
        history, latest, selected_range = reader._p2p_metric_history(connection, table, metric, {"range": ["all"]})
        assert 2 <= len(history) <= 2000
        assert selected_range == "all"
        for peer in ("first", "second"):
            rows = [row for row in history if row["peer_id"] == peer]
            assert rows[0]["timestamp"] == 0
            assert rows[-1]["timestamp"] == 99999
            assert latest[peer]["timestamp"] == 99999
        assert instructions < 500000


@pytest.mark.parametrize("values", [(0.1, 0.9), (0.9, 0.1)])
def test_p2p_reliability_uses_last_update_within_the_same_second(
    tmp_path: Path, values: tuple[float, float],
) -> None:
    """Keep table and chart values consistent with the trust model's latest row.

    Parameters:
        tmp_path: Isolated metric database.
        values: Two successive reliability updates at the same timestamp.
    """
    _factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.redis = Mock()
    reader.redis.hget.return_value = "pcap"
    with sqlite3.connect(tmp_path / "ties.db") as connection:
        connection.execute("CREATE TABLE go_reliability(id INTEGER PRIMARY KEY, peerid TEXT, reliability REAL, update_time REAL)")
        connection.execute("CREATE INDEX peer_time ON go_reliability(peerid, update_time DESC, reliability)")
        connection.executemany("INSERT INTO go_reliability(peerid,reliability,update_time) VALUES ('peer',?,100)",
                               [(value,) for value in values])
        history, latest, _ = reader._p2p_metric_history(
            connection, "go_reliability", "reliability", {"range": ["all"]})

    assert latest["peer"]["reliability"] == values[-1]
    assert [row["reliability"] for row in history] == list(values)


def test_run_config_cache_detects_snapshot_edits(tmp_path: Path) -> None:
    """Reuse an immutable snapshot and reload it when its contents change.

    Parameters:
        tmp_path: Isolated run metadata directory.
    """
    _factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    snapshot = metadata / "slips.yaml"
    snapshot.write_text("parameters: {permanent_dir: first}\n")
    with patch("modules.web_interface.server.yaml.safe_load", wraps=yaml.safe_load) as load:
        assert reader._run_config()[0]["parameters"]["permanent_dir"] == "first"
        assert reader._run_config()[0]["parameters"]["permanent_dir"] == "first"
        assert load.call_count == 1
        snapshot.write_text("parameters: {permanent_dir: changed}\n")
        assert reader._run_config()[0]["parameters"]["permanent_dir"] == "changed"
        assert load.call_count == 2


@pytest.mark.parametrize('group', ['', 'host_type', 'type'])
def test_missing_evidence_scores_remain_null_in_individual_and_group_views(tmp_path: Path, group: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Return missing values as null while preserving explicitly saved zero.

    Parameters:
        tmp_path: Isolated API databases.
        group: Individual or grouped evidence layout.
        monkeypatch: Freeze the fixture clock.
    """
    _factory = ModuleFactory()
    reader = _network_scope_reader(tmp_path)
    reader.score_mode = 'atl'
    monkeypatch.setattr('modules.web_interface.server.time.time', lambda: 2_000_000_000.)
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("ALTER TABLE evidence ADD COLUMN accumulated_threat_level REAL")
        connection.execute("UPDATE evidence SET accumulated_threat_level=NULL,accumulated_ratl=NULL")
    page = reader.evidence({'range':['all'], 'group':[group]})
    assert page['items']
    assert all(item['alert_score'] is None for item in page['items'])
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("UPDATE evidence SET accumulated_threat_level=0,accumulated_ratl=0")
    page = reader.evidence({'range':['all'], 'group':[group]})
    assert all(item['alert_score'] == 0 for item in page['items'])


def test_pcap_score_history_keeps_current_remainder_on_capture_clock(tmp_path: Path) -> None:
    """Avoid stretching an old PCAP's score chart to today's wall-clock time.

    Parameters:
        tmp_path: Isolated finite-input database.
    """
    _factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / 'flows.sqlite'
    reader.score_mode = 'atl'
    reader.alert_threshold = 1.2
    reader._live_host = Mock(return_value={'live':True})
    reader._attach_current_host_scores = Mock(side_effect=lambda rows: rows[0].update(alert_score=.32, alert_score_twid='timewindow1'))
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute('CREATE TABLE evidence(evidence_id TEXT,evidence_time REAL,profile_ip TEXT,timewindow TEXT,accumulated_threat_level REAL)')
        connection.execute("INSERT INTO evidence VALUES ('trigger',1668887061,'1.2.3.4','timewindow1',1.28)")
    history = reader.score_history('1.2.3.4',{'range':['all']})
    assert history['peak_score'] == 1.28
    assert history['timeline'][-1]['score'] == .32
    assert history['timeline'][-1]['ts'] == pytest.approx(1668887061.001, rel=0, abs=.0001)
    assert history['timeline'][-1]['current'] is True


@pytest.mark.parametrize("source,value", [
    ("192.0.2.10", "192.0.2.10->*:902"),
    ("2001:db8::10", "[2001:db8::10]->*:902"),
])
def test_web_destination_port_rule_round_trip(tmp_path: Path, source: str, value: str) -> None:
    """Save, list, reload and remove narrow rules without changing other ports.

    Parameters:
        tmp_path: Isolated run directory.
        source: Source address entered in the editor.
        value: Canonical value expected in the file and table.
    """
    factory = ModuleFactory()
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    configured = tmp_path / "personal.conf"
    configured.write_text(f"ip,{source},src,alerts,ARP_SCAN\n")
    (metadata / "run.yaml").write_text(
        "whitelists:\n  enable_local_whitelist: true\n"
        f"  local_whitelist_path: {configured}\n"
    )
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.redis = Mock()
    reader.cache = Mock()
    hashes: dict = {}
    reader.redis.hset.side_effect = lambda name, key, data: hashes.setdefault(name, {}).__setitem__(key, data)
    reader.redis.hgetall.side_effect = lambda name: hashes.get(name, {})
    reader.redis.hexists.side_effect = lambda name, key: key in hashes.get(name, {})
    reader.redis.hdel.side_effect = lambda name, key: hashes.get(name, {}).pop(key, None)
    reader.response_metadata = Mock(return_value={"backend_status": {"connected": True}})
    saved = reader.save_whitelist_rule("add", source, "src", "alerts", "UNKNOWN_PORT", dst_port=902)
    assert saved["value"] == value
    assert saved["dst_port"] == "902"
    reader.save_whitelist_rule("add", source, "src", "alerts", "UNKNOWN_PORT", dst_port=903)
    payload = reader.whitelists()
    assert payload["supports_dst_port_rules"]
    rule = next(row for row in payload["rules"] if row["value"] == value)
    assert rule["managed"]
    assert rule["dst_port"] == "902"
    assert "destination port is 902" in rule["effect"]
    whitelist = factory.create_whitelist_obj()
    whitelist.parser.local_whitelist_path = str(configured)
    assert whitelist.parser.parse()
    assert whitelist.parser.whitelisted_ips[f"{value}|UNKNOWN_PORT"]["dst_port"] == "902"
    reader.save_whitelist_rule("remove", value, "src", "alerts", "UNKNOWN_PORT")
    assert f"ip,{value}," not in configured.read_text()
    assert f"ip,{source},src,alerts,ARP_SCAN" in configured.read_text()
    remaining = reader._runtime_whitelist_rules()
    assert len(remaining) == 1
    assert remaining[0]["dst_port"] == "903"


@pytest.mark.parametrize("value,port,direction,ignored,kind", [
    ("192.0.2.10", 0, "src", "alerts", "ip"),
    ("192.0.2.10", 65536, "src", "alerts", "ip"),
    ("192.0.2.10", True, "src", "alerts", "ip"),
    ("192.0.2.10", 902.5, "src", "alerts", "ip"),
    ("192.0.2.10", "abc", "src", "alerts", "ip"),
    ("192.0.2.10:50000", 902, "src", "alerts", "ip"),
    ("*:50000", 902, "src", "alerts", "ip"),
    ("192.0.2.0/24", 902, "src", "alerts", "ip"),
    ("192.0.2.10", 902, "dst", "alerts", "ip"),
    ("192.0.2.10", 902, "both", "alerts", "ip"),
    ("192.0.2.10", 902, "src", "flows", "ip"),
    ("192.0.2.10", 902, "src", "both", "ip"),
    ("192.0.2.10", 902, "both", "blocking", "ip"),
    ("/example", 902, "both", "flows", "uri"),
    ("192.0.2.10->*:903", 902, "src", "alerts", "ip"),
])
def test_web_rejects_invalid_destination_port_condition(
    value: str, port: object, direction: str, ignored: str, kind: str,
) -> None:
    """Reject unsafe combinations before accessing the whitelist file.

    Parameters:
        value: Submitted source or URI.
        port: Invalid destination port or incompatible condition.
        direction: Selected endpoint side.
        ignored: Selected suppression mode.
        kind: Selected rule type.
    """
    _factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    with pytest.raises(ValueError):
        reader.save_whitelist_rule("add", value, direction, ignored, rule_type=kind, dst_port=port)


@pytest.mark.parametrize("source,side,port,kind,proto,indicator,expected", [
    ("192.0.2.10", "SRC", 902, "UNKNOWN_PORT", "tcp", "IP", True),
    ("192.0.2.11", "SRC", 902, "UNKNOWN_PORT", "tcp", "IP", False),
    ("192.0.2.10", "DST", 902, "UNKNOWN_PORT", "tcp", "IP", False),
    ("192.0.2.10", "SRC", 903, "UNKNOWN_PORT", "tcp", "IP", False),
    ("192.0.2.10", "SRC", 902, "ARP_SCAN", "tcp", "IP", False),
    ("192.0.2.10", "SRC", 902, "UNKNOWN_PORT", "icmp", "IP", False),
    ("example.com", "SRC", 902, "UNKNOWN_PORT", "tcp", "DOMAIN", False),
])
def test_web_explains_only_matching_destination_port_rules(
    source: str, side: str, port: int, kind: str, proto: str, indicator: str, expected: bool,
) -> None:
    """Keep the displayed whitelist reason consistent with the detection matcher.

    Parameters:
        source: Evidence entity address or domain.
        side: Entity direction.
        port: Destination port.
        kind: Evidence type.
        proto: Evidence protocol.
        indicator: Direct IP or indirectly resolved domain.
        expected: Whether this rule should be displayed as matching.
    """
    _factory = ModuleFactory()
    reader = RunDataReader.__new__(RunDataReader)
    rule = {"type": "IP address", "value": "192.0.2.10->*:902", "direction": "src",
            "ignore": "alerts", "evidence_type": "UNKNOWN_PORT", "dst_port": "902"}
    record = {"attacker": {"value": source, "direction": side, "ioc_type": indicator,
                           "DNS_resolution": ["192.0.2.10"] if indicator == "DOMAIN" else []},
              "dst_port": port, "evidence_type": kind, "proto": proto}
    assert bool(reader._whitelist_matches_for_record(record, [rule])) is expected


def test_offline_whitelist_lists_destination_port(tmp_path: Path) -> None:
    """Explain the same destination condition when only a captured file remains.

    Parameters:
        tmp_path: Isolated captured metadata directory.
    """
    _factory = ModuleFactory()
    snapshot = tmp_path / "whitelist.conf"
    snapshot.write_text("ip,192.0.2.10->*:902,src,alerts,UNKNOWN_PORT\n")
    reader = RunDataReader.__new__(RunDataReader)
    reader.output_dir = tmp_path
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {}
    reader._metadata_snapshot = Mock(return_value=snapshot)
    rules = reader._runtime_whitelist_rules()
    assert len(rules) == 1
    assert rules[0]["dst_port"] == "902"
    assert rules[0]["evidence_type"] == "UNKNOWN_PORT"
    assert "destination port is 902" in rules[0]["effect"]
