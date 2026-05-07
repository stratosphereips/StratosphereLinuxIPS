# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for alert-bounded graph construction."""

from modules.graph_structure.graph_builder import GraphBuilder
from tests.module_factory import ModuleFactory


def _conn_record():
    """
    Build a representative new_flow record.

    Returns:
        Buffered connection flow record.
    """
    return {
        "channel": "new_flow",
        "profileid": "profile_192.168.1.10",
        "twid": "timewindow1",
        "interpreted_state": "Established",
        "label": "benign",
        "flow": {
            "uid": "C1",
            "type_": "conn",
            "starttime": "1.0",
            "dur": 3.0,
            "saddr": "192.168.1.10",
            "daddr": "8.8.8.8",
            "sport": "44444",
            "dport": "443",
            "proto": "tcp",
            "appproto": "ssl",
            "state": "SF",
            "pkts": 4,
            "spkts": 2,
            "dpkts": 2,
            "bytes": 900,
            "sbytes": 300,
            "dbytes": 600,
            "interface": "eth0",
        },
    }


def _dns_record():
    """
    Build a representative DNS protocol record.

    Returns:
        Buffered DNS flow record.
    """
    return {
        "channel": "new_dns",
        "profileid": "profile_192.168.1.10",
        "twid": "timewindow1",
        "flow": {
            "uid": "D1",
            "type_": "dns",
            "starttime": "2.0",
            "saddr": "192.168.1.10",
            "daddr": "192.168.1.1",
            "sport": "53000",
            "dport": "53",
            "proto": "udp",
            "query": "example.com",
            "answers": ["93.184.216.34"],
            "rcode_name": "NOERROR",
            "qtype_name": "A",
            "interface": "eth0",
        },
    }


def _http_record():
    """
    Build a representative HTTP protocol record.

    Returns:
        Buffered HTTP flow record.
    """
    return {
        "channel": "new_http",
        "profileid": "profile_192.168.1.10",
        "twid": "timewindow1",
        "flow": {
            "uid": "H1",
            "type_": "http",
            "starttime": "3.0",
            "saddr": "192.168.1.10",
            "daddr": "93.184.216.34",
            "sport": "44445",
            "dport": "80",
            "proto": "tcp",
            "method": "GET",
            "host": "example.com",
            "uri": "/index.html",
            "user_agent": "Mozilla/5.0",
            "status_code": "200",
            "interface": "eth0",
        },
    }


def _ssl_record():
    """
    Build a representative SSL protocol record.

    Returns:
        Buffered SSL flow record.
    """
    return {
        "channel": "new_ssl",
        "profileid": "profile_192.168.1.10",
        "twid": "timewindow1",
        "flow": {
            "uid": "S1",
            "type_": "ssl",
            "starttime": "4.0",
            "saddr": "192.168.1.10",
            "daddr": "93.184.216.34",
            "sport": "44446",
            "dport": "443",
            "proto": "tcp",
            "server_name": "example.com",
            "ja3": "ja3hash",
            "ja3s": "ja3shash",
            "interface": "eth0",
        },
    }


def _arp_record():
    """
    Build a representative ARP protocol record.

    Returns:
        Buffered ARP flow record.
    """
    return {
        "channel": "new_arp",
        "profileid": "profile_192.168.1.10",
        "twid": "timewindow1",
        "flow": {
            "uid": "A1",
            "type_": "arp",
            "starttime": "5.0",
            "saddr": "192.168.1.10",
            "daddr": "192.168.1.1",
            "smac": "aa:aa:aa:aa:aa:aa",
            "dmac": "bb:bb:bb:bb:bb:bb",
            "operation": "request",
            "interface": "eth0",
        },
    }


def _evidence_record():
    """
    Build a representative evidence record.

    Returns:
        Evidence dictionary.
    """
    return {
        "id": "E1",
        "evidence_type": "UNKNOWN_PORT",
        "description": "Connection to an unknown destination port.",
        "threat_level": "medium",
        "confidence": 0.8,
        "timestamp": "1970/01/01 00:00:04.000000+0000",
        "profile": {"ip": "192.168.1.10"},
        "timewindow": {"number": 1},
        "uid": ["C1"],
        "attacker": {"ioc_type": "IP", "value": "192.168.1.10"},
        "victim": {"ioc_type": "IP", "value": "8.8.8.8"},
    }


def _alert_record():
    """
    Build a representative alert record.

    Returns:
        Alert dictionary.
    """
    return {
        "id": "ALERT1",
        "profile": {"ip": "192.168.1.10"},
        "timewindow": {"number": 1},
        "correl_id": ["E1"],
        "accumulated_threat_level": 5.0,
        "confidence": 0.9,
        "threat_level": "CRITICAL",
        "last_flow_datetime": "1970-01-01T00:00:04+00:00",
    }


def test_build_window_graph_creates_sparse_heterogeneous_rows():
    """The graph should contain only observed heterogeneous nodes and edges."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    builder = GraphBuilder(["192.168.1.0/24"])
    graph = builder.build_window_graph(
        window_index=0,
        alert=_alert_record(),
        flow_records=[_conn_record()],
        protocol_records=[
            _dns_record(),
            _http_record(),
            _ssl_record(),
            _arp_record(),
        ],
        evidence_records=[_evidence_record()],
    )

    node_types = {node["node_type"] for node in graph["nodes"]}
    edge_types = {edge["edge_type"] for edge in graph["edges"]}
    node_ids = {node["node_id"] for node in graph["nodes"]}

    assert {
        "profile",
        "ip",
        "network",
        "port",
        "flow",
        "evidence",
        "alert",
    }.issubset(node_types)
    assert {"domain", "url", "user_agent", "mac"}.issubset(node_types)
    assert "network:192.168.1.0/24" in node_ids
    assert "network:internet" in node_ids
    assert {
        "profile_has_ip",
        "flow_from_ip",
        "flow_to_ip",
        "flow_to_port",
        "attempted_port",
        "has_open_port",
        "dns_queried",
        "dns_resolved_to",
        "http_requested",
        "used_user_agent",
        "tls_server_name",
        "arp_maps",
        "evidence_refs_flow",
        "evidence_about_entity",
        "alert_contains_evidence",
    }.issubset(edge_types)
    assert graph["metadata"]["flow_count"] == 1
    assert graph["metadata"]["protocol_event_count"] == 4
    assert graph["metadata"]["evidence_count"] == 1


def test_build_transition_stores_actions_and_reward_placeholder():
    """Transitions should link consecutive graph IDs and keep action metadata."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    transition = GraphBuilder.build_transition(
        "graph:0:ALERT1",
        "graph:1:ALERT2",
        [{"ip": "192.168.1.10", "block": True}],
    )

    assert transition["from_graph_id"] == "graph:0:ALERT1"
    assert transition["to_graph_id"] == "graph:1:ALERT2"
    assert transition["action_count"] == 1
    assert transition["reward"] is None


def test_build_window_graph_normalizes_scalar_uid_and_alert_evidence_ids():
    """Scalar UID and alert evidence fields should not be split by character."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    evidence = _evidence_record()
    evidence["uid"] = "C1"
    alert = _alert_record()
    alert["correl_id"] = "E1"
    builder = GraphBuilder(["192.168.1.0/24"])

    graph = builder.build_window_graph(
        window_index=0,
        alert=alert,
        flow_records=[_conn_record()],
        protocol_records=[],
        evidence_records=[evidence],
    )

    node_ids = {node["node_id"] for node in graph["nodes"]}
    assert "flow:C1" in node_ids
    assert "evidence:E1" in node_ids
    assert "evidence:E" not in node_ids
    assert "evidence:1" not in node_ids
