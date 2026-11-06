"""Packet-to-connection matching preserves direction and tuple reuse boundaries."""

import json
import sqlite3
from threading import RLock
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.module_factory import ModuleFactory
from slips_files.core.database.database_manager import DBManager
from slips_files.core.database.sqlite_db.database import SQLiteDB
from slips_files.core.database.sqlite_db.packet_flows import find_packet_flow


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("ipv6", [False, True])
@pytest.mark.parametrize("variant", ["match", "old", "future", "wrong_port", "wrong_proto", "ambiguous", "reused"])
def test_find_packet_flow_respects_tuple_interval_and_ambiguity(
    reverse: bool, ipv6: bool, variant: str,
) -> None:
    """Resolve request and response packets without guessing between connections.

    Parameters:
        reverse: Match a response packet against the original connection direction.
        ipv6: Use IPv6 endpoints.
        variant: Matching, stale, mismatched or reused connection scenario.
    """
    _factory = ModuleFactory()
    src, dst = ("2001:db8::1", "2001:db8::2") if ipv6 else ("192.0.2.1", "192.0.2.2")
    packet = {"saddr":src, "daddr":dst, "sport":12345, "dport":80, "proto":"tcp", "timestamp":100.5}
    flow = {"saddr":src, "daddr":dst, "sport":"12345", "dport":"80", "proto":"TCP", "dur":1.0}
    if reverse:
        packet.update(saddr=dst,daddr=src,sport=80,dport=12345)
    if variant == "old":
        packet["timestamp"] = 102
    elif variant == "future":
        packet["timestamp"] = 99
    elif variant == "wrong_port":
        packet["dport"] = 443
    elif variant == "wrong_proto":
        packet["proto"] = "udp"
    with sqlite3.connect(":memory:") as db:
        db.executescript("CREATE TABLE flows(uid TEXT,flow TEXT,profileid TEXT,twid TEXT,event_time REAL);"
                         "CREATE INDEX flows_profile_tw_idx ON flows(profileid,twid);")
        db.execute("INSERT INTO flows VALUES (?,?,?,?,?)",("real",json.dumps(flow),f"profile_{src}","timewindow1",100))
        if variant in {"ambiguous", "reused"}:
            db.execute("INSERT INTO flows VALUES (?,?,?,?,?)",("other",json.dumps(flow),f"profile_{src}","timewindow1",100 if variant == "ambiguous" else 80))
        queries = []
        db.set_trace_callback(queries.append)
        result = SQLiteDB.get_flow_for_packet(SimpleNamespace(conn_lock=RLock(),conn=db),packet)
        if variant in {"match", "reused"}:
            assert result["uid"] == "real"
            assert result["flow"] == flow
            assert result["profileid"] == f"profile_{src}"
        else:
            assert result is None
        plan = db.execute("EXPLAIN QUERY PLAN "+queries[0]).fetchall()
        assert any("flows_profile_tw_idx" in row[3] for row in plan)


@pytest.mark.parametrize("packet", [{}, {"saddr":"a", "daddr":"b", "sport":1,"dport":2,"proto":"icmp","timestamp":100},
    {"saddr":"a", "daddr":"b", "sport":1,"dport":2,"proto":"tcp","timestamp":float("nan")},
    {"saddr":"a", "daddr":"b", "sport":-1,"dport":2,"proto":"tcp","timestamp":100}])
def test_find_packet_flow_rejects_invalid_packet_or_missing_schema(packet: dict) -> None:
    """Leave unresolved packets unlinked instead of fabricating an identifier.

    Parameters:
        packet: Incomplete or invalid packet metadata.
    """
    _factory = ModuleFactory()
    with sqlite3.connect(":memory:") as db:
        assert find_packet_flow(db,packet) is None
        assert find_packet_flow(db,{"saddr":"a","daddr":"b","sport":1,"dport":2,"proto":"tcp","timestamp":100}) is None


def test_packet_flow_facade_forwards_without_altering_packet() -> None:
    """Forward packet metadata through the database facade unchanged."""
    _factory = ModuleFactory()
    manager = DBManager.__new__(DBManager)
    manager.sqlite = Mock()
    packet = {"timestamp":100}
    result = manager.get_flow_for_packet(packet)
    manager.sqlite.get_flow_for_packet.assert_called_once_with(packet)
    assert result is manager.sqlite.get_flow_for_packet.return_value
