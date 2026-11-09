"""Network membership across reconnects, reused IPs and grouped web history."""

import json
import sqlite3
from pathlib import Path

import pytest

from modules.web_interface.history import connect_history
from modules.web_interface.network_scope import NetworkScope, network_visits, record_network_visits
from modules.web_interface.server import RunDataReader
from slips_files.core.database.sqlite_db.detection_history import EVIDENCE_NETWORK_INDEX_SQL
from slips_files.core.database.sqlite_db.host_profiles import HostProfileStore
from tests.module_factory import ModuleFactory
from tests.unit.modules.web_interface.test_server import _network_scope_reader


def repeated_visits(tmp_path: Path) -> RunDataReader:
    """Create Home/Guest/Home visits with one IP reused on both networks.

    Parameters:
        tmp_path: Isolated database directory.

    Returns:
        Reader holding retained network-tagged and legacy records.
    """
    reader = _network_scope_reader(tmp_path)
    state = json.loads(reader.redis.hget("network_states", "en0"))
    home = HostProfileStore.network_id_for_state(state, "")
    guest_state = {**state, "gateway_mac": "aa:bb:cc:dd:ee:02"}
    guest = HostProfileStore.network_id_for_state(guest_state, "")
    state["history"] = [
        {**state, "changed_at": 1_999_995_000},
        {**guest_state, "changed_at": 1_999_997_000},
        {"connected": False, "changed_at": 1_999_999_300},
    ]
    original_hget = reader.redis.hget.side_effect
    reader.redis.hget.side_effect = lambda key, field: (
        json.dumps(state) if key == "network_states" else original_hget(key, field)
    )
    with sqlite3.connect(reader.sqlite_path) as connection:
        for identifier, stamp, network, excluded in [
            ("home-old", 1_999_996_000, home, 0),
            ("home-excluded", 1_999_996_500, home, 1),
            ("guest-same-ip", 1_999_998_000, guest, 0),
            ("home-new", 1_999_999_900, home, 0),
            ("legacy-home", 1_999_995_500, "", 0),
            ("legacy-guest", 1_999_997_500, "", 0),
            ("legacy-unknown", 1_999_994_000, "", 0),
        ]:
            data = json.dumps({"detection_provenance": {"network_id": network}})
            connection.execute(
                "INSERT INTO evidence VALUES (?,?,'192.168.1.22','tw','high','SCAN',"
                "'network_discovery','retained finding',1,?,2,?)",
                (identifier, stamp, data, excluded),
            )
            if identifier in {"home-old", "guest-same-ip", "home-new"}:
                connection.execute("INSERT INTO alerts VALUES (?,'192.168.1.22',?,'malicious',5)", (identifier, stamp))
                connection.execute("INSERT INTO alert_evidence VALUES (?,?)", (identifier, identifier))
        for identifier, stamp in [("home-old", 1_999_996_000), ("home-new", 1_999_999_900)]:
            flow = json.dumps({"saddr": "192.168.1.22", "daddr": "8.8.8.8", "sport": 1234, "dport": 443})
            connection.execute("INSERT INTO flows VALUES (?,?,'benign')", (identifier, flow))
            connection.execute("INSERT INTO evidence_flows VALUES (?,?)", (identifier, identifier))
    with connect_history(reader.history_path) as connection:
        for identifier, stamp in [("home-old", 1_999_996_000), ("home-new", 1_999_999_900)]:
            connection.execute(
                "INSERT INTO flow_index VALUES (?,1,?,'192.168.1.22','8.8.8.8','tcp','',100,2,1,'benign')",
                (identifier, stamp),
            )
    return reader


@pytest.mark.parametrize("mode", ["", "host", "type", "host_type"])
@pytest.mark.parametrize("network,expected", [("current", 4), ("connection", 2)])
@pytest.mark.parametrize("hide_excluded", [False, True])
def test_revisiting_network_includes_earlier_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str,
    network: str, expected: int, hide_excluded: bool,
) -> None:
    """Include earlier Home visits, exclude Guest and preserve counts.

    Parameters:
        tmp_path: Isolated run databases.
        monkeypatch: Fix the interface capture clock.
        mode: Evidence grouping mode.
        network: Network or single-connection scope.
        expected: Visible evidence before excluded records.
        hide_excluded: Hide stored whitelist exclusions.
    """
    _factory = ModuleFactory()
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: 2_000_000_000.0)
    reader = repeated_visits(tmp_path)
    query = {"range": ["7d"], "network": [network], "limit": ["100"]}
    if mode:
        query["group"] = [mode]
    if hide_excluded:
        query["hide_excluded"] = ["1"]
    elif network == "current":
        expected += 1
    payload = reader.evidence(query)
    assert payload.get("matching_total", payload["total"]) == expected
    assert sum(item.get("evidence_count", 1) for item in payload["items"]) == expected
    assert getattr(reader, "_active_network_scope", None) is None
    if not mode:
        identifiers = {item["id"] for item in payload["items"]}
        assert not identifiers & {"guest-same-ip", "legacy-guest", "legacy-unknown", "old"}
        assert ("home-old" in identifiers) == (network == "current")
    with sqlite3.connect(reader.sqlite_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 9


@pytest.mark.parametrize("network,expected", [("current", 3), ("connection", 2)])
def test_alert_host_flow_and_score_views_share_membership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, network: str, expected: int,
) -> None:
    """Keep alerts, host totals, flows and plots consistent across visits.

    Parameters:
        tmp_path: Isolated run databases.
        monkeypatch: Fix the capture clock.
        network: Network or connection scope.
        expected: Matching alert count.
    """
    _factory = ModuleFactory()
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: 2_000_000_000.0)
    reader = repeated_visits(tmp_path)
    query = {"range": ["7d"], "network": [network], "hide_excluded": ["1"]}
    alerts = reader.alerts(query)
    grouped = reader.alerts({**query, "group": ["host"]})
    assert alerts["total"] == grouped["matching_total"] == expected
    host = reader.host("192.168.1.22", query)
    assert host["alert_count"] == expected
    assert host["evidence_count"] == (4 if network == "current" else 2)
    flow_count = 2 if network == "current" else 1
    assert host["load"]["flows"] == flow_count
    assert reader.flows_for_host("192.168.1.22", query)["total"] == flow_count
    traffic = reader.traffic_summary("192.168.1.22", query)
    assert sum(point["outbound_flows"] for point in traffic["timeline"]) == flow_count
    scores = reader.score_history("192.168.1.22", query)
    assert bool(scores["timeline"])
    assert reader.overview_evidence_counts(query)["evidence"] == (5 if network == "current" else 2)


@pytest.mark.parametrize("timestamp,identity,expected", [
    (12, "home", True), (22, "home", True), (12, "guest", False),
    (12, "", True), (22, "", False), (32, "run:old", True),
    (5, "", False), (float("nan"), "", False),
])
def test_membership_prefers_recorded_network(
    timestamp: float, identity: str, expected: bool,
) -> None:
    """Prefer explicit identity and require proof for untagged events.

    Parameters:
        timestamp: Observation time.
        identity: Explicit identity, if any.
        expected: Whether the observation matches Home.
    """
    _factory = ModuleFactory()
    scope = NetworkScope("home", ((10, "home"), (20, "guest"), (30, "home")), 30)
    assert scope.matches(timestamp, identity) is expected


@pytest.mark.parametrize("network", ["current", "connection"])
def test_group_queries_resolve_membership_once(
    tmp_path: Path, network: str,
) -> None:
    """Keep repeated aggregates off JSON payloads after resolving membership.

    Parameters:
        tmp_path: Isolated run databases.
        network: Selected network or current connection.
    """
    _factory = ModuleFactory()
    reader = repeated_visits(tmp_path)._for_network_scope({"network": [network]})
    with reader._connect_sqlite() as connection:
        expected = {row[0] for row in connection.execute("SELECT evidence_id FROM evidence")}
        reader._active_network_scope.materialize_evidence(connection)
        plan = [str(row[3]) for row in connection.execute("EXPLAIN QUERY PLAN SELECT COUNT(*) FROM evidence")]
        assert any("s USING PRIMARY KEY" in step for step in plan)
        connection.create_function("json_valid", 1, lambda _: pytest.fail("Membership reparsed"))
        for _ in range(3):
            actual = {row[0] for row in connection.execute("SELECT evidence_id FROM evidence")}
            assert actual == expected
            assert connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == len(expected)


@pytest.mark.parametrize("group", ["host", "host_type", "type"])
def test_connection_groups_use_indexed_network_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, group: str,
) -> None:
    """Keep grouped reads off large JSON payloads and past-network records.

    Parameters:
        tmp_path: Isolated capture and history databases.
        monkeypatch: Fix capture time and inspect request-local SQL work.
        group: Supported evidence grouping.
    """
    _factory = ModuleFactory()
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: 2_000_000_000.0)
    reader = _network_scope_reader(tmp_path)
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("ALTER TABLE evidence ADD COLUMN accumulated_threat_level REAL")
        connection.execute("DELETE FROM evidence")
        payload = json.dumps({"interface": "en0", "details": "x" * 4096})
        connection.executemany(
            "INSERT INTO evidence(evidence_id,evidence_time,profile_ip,evidence_type,threat_level,"
            "source_module,whitelisted,data,accumulated_ratl) VALUES (?,?,?,'SCAN','low','arp',0,?,1)",
            ((f"record-{index}", 1_999_990_000 if index < 10000 else 1_999_999_900,
              f"192.168.1.{index % 50 + 1}", payload) for index in range(10500)),
        )
        connection.execute(EVIDENCE_NETWORK_INDEX_SQL)
    original_connect = reader._connect_sqlite
    parsed = 0
    instructions = 0

    def json_valid(value: str | None) -> int:
        """Count payload decoding that should be served from the expression index.

        Parameters:
            value: Stored JSON.

        Returns:
            Whether the value contains JSON.
        """
        nonlocal parsed
        parsed += 1
        try:
            json.loads(value)
        except (TypeError, ValueError):
            return 0
        return 1

    def progress() -> int:
        """Interrupt repeated history scans or per-group nested scans.

        Returns:
            Nonzero after the request's instruction budget.
        """
        nonlocal instructions
        instructions += 1000
        return int(instructions > 1000000)

    def connect() -> sqlite3.Connection:
        """Instrument the scoped query without changing its data or planner.

        Returns:
            Actual network-filtered reader connection.
        """
        connection = original_connect()
        connection.create_function("json_valid", 1, json_valid, deterministic=True)
        connection.set_progress_handler(progress, 1000)
        return connection

    scoped = reader._for_network_scope({"network": ["connection"]})
    original_connect = scoped._connect_sqlite
    monkeypatch.setattr(scoped, "_connect_sqlite", connect)
    result = scoped.evidence({"range": ["connection"], "network": ["connection"],
                              "group": [group], "device": ["1"], "compact": ["1"],
                              "hide_excluded": ["1"], "sort": ["time"]})
    assert result["matching_total"] == result["full_total"] == 500
    assert result["total"] == (1 if group == "type" else 50)
    assert sum(row["evidence_count"] for row in result["items"]) == 500
    assert parsed == 0
    assert instructions < 1000000
    stats = scoped._host_finding_stats(
        [f"192.168.1.{index + 1}" for index in range(50)],
        {"range": ["connection"], "network": ["connection"]},
    )
    assert sum(row["evidence"] for row in stats.values()) == 500
    assert parsed == 0


def test_flow_membership_reads_indexed_interface_without_payload(tmp_path: Path) -> None:
    """Use compact interface metadata without reopening a raw connection record.

    Parameters:
        tmp_path: Isolated network and flow stores.
    """
    _factory = ModuleFactory()
    reader = _network_scope_reader(tmp_path)._for_network_scope({"network": ["connection"]})
    with connect_history(reader.history_path) as connection:
        connection.execute("INSERT INTO flow_interfaces VALUES ('current-v4','en0')")
    with reader._connect_history() as connection:
        connection.create_function("json_valid", 1, lambda _: pytest.fail("Raw payload decoded"))
        assert connection.execute("SELECT uid FROM flow_index WHERE uid='current-v4'").fetchone()[0] == "current-v4"


def test_visit_ledger_is_bounded_and_survives_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bound transitions and preserve the uninterrupted same-router boundary.

    Parameters:
        tmp_path: Isolated web history.
        monkeypatch: Reduce the transition limit for this test.
    """
    _factory = ModuleFactory()
    monkeypatch.setattr("modules.web_interface.network_scope.MAX_NETWORK_VISITS", 3)
    path = tmp_path / "history.sqlite"
    state = {"connected": True, "gateway_mac": "aa:bb:cc:dd:ee:01", "changed_at": 50}
    state["history"] = [{**state, "changed_at": stamp} for stamp in range(10, 50, 10)]
    visits = record_network_visits(path, "en0", state, "test")
    assert [stamp for stamp, _ in visits] == [30, 40, 50]
    saved = {"connected": True, "gateway_mac": state["gateway_mac"], "changed_at": 50, "start": 10}
    restarted = record_network_visits(path, "en0", {**state, "changed_at": 60}, "test2", saved)
    assert [stamp for stamp, _ in restarted] == [40, 50, 60]
    assert len({identity for _, identity in restarted}) == 1


@pytest.mark.parametrize("history", [None, "invalid", [None, {}, {"changed_at": "nan"}]])
def test_invalid_visit_snapshots_are_ignored(history: object) -> None:
    """Ignore malformed history without assigning unknown records to Home.

    Parameters:
        history: Invalid network history payload.
    """
    _factory = ModuleFactory()
    state = {"connected": True, "changed_at": 50, "gateway_mac": "aa", "history": history}
    assert network_visits(state, "test") == ((50.0, "gateway:aa"),)


@pytest.mark.parametrize("mode", ["saved_view", "archive_mode", "pcap"])
def test_saved_and_file_views_do_not_adopt_current_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str,
) -> None:
    """Keep offline evidence independent of the computer's present network.

    Parameters:
        tmp_path: Isolated databases.
        monkeypatch: Fix the capture clock.
        mode: Offline reader variant.
    """
    _factory = ModuleFactory()
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: 2_000_000_000.0)
    reader = repeated_visits(tmp_path)
    if mode == "pcap":
        original_hget = reader.redis.hget.side_effect
        original_hgetall = reader.redis.hgetall.side_effect
        reader.redis.hget.side_effect = lambda key, field: "pcap" if (key, field) == ("analysis", "input_type") else original_hget(key, field)
        reader.redis.hgetall.side_effect = lambda key: {"input_type": "pcap"} if key == "analysis" else original_hgetall(key)
    else:
        setattr(reader, mode, True)
    assert reader.evidence({"range": ["all"], "network": ["current"]})["total"] == 9
