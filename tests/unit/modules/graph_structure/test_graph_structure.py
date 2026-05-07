# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for the graph_structure Slips module."""

import json
from unittest.mock import patch

from modules.graph_structure.graph_builder import GraphBuilder
from modules.graph_structure.graph_storage import GraphStorage
from modules.graph_structure.graph_structure import FLOW_CHANNELS
from tests.module_factory import ModuleFactory


def _message(channel, payload):
    """
    Build a Slips-compatible Redis pub/sub message.

    Parameters:
        channel: Redis channel name.
        payload: Message payload.

    Returns:
        Pub/sub message dictionary.
    """
    payload = dict(payload)
    payload["version"] = "test-version"
    return {"channel": channel, "data": json.dumps(payload)}


def _new_flow_payload(uid="C1"):
    """
    Build a minimal new_flow payload.

    Parameters:
        uid: Flow UID.

    Returns:
        Decoded channel payload.
    """
    return {
        "profileid": "profile_192.168.1.10",
        "twid": "timewindow1",
        "interpreted_state": "Established",
        "label": "benign",
        "flow": {
            "uid": uid,
            "type_": "conn",
            "starttime": "1.0",
            "saddr": "192.168.1.10",
            "daddr": "8.8.8.8",
            "sport": "44444",
            "dport": "443",
            "proto": "tcp",
            "state": "SF",
            "pkts": 2,
            "spkts": 1,
            "dpkts": 1,
            "bytes": 20,
            "sbytes": 10,
            "dbytes": 10,
            "interface": "eth0",
        },
    }


def _evidence_payload(uid="C1", evidence_id="E1"):
    """
    Build a minimal evidence_added payload.

    Parameters:
        uid: Flow UID referenced by evidence.
        evidence_id: Evidence ID.

    Returns:
        Decoded evidence payload.
    """
    return {
        "id": evidence_id,
        "evidence_type": "UNKNOWN_PORT",
        "description": "Connection to an unknown destination port.",
        "threat_level": "medium",
        "confidence": 0.8,
        "timestamp": "1970/01/01 00:00:01.000000+0000",
        "profile": {"ip": "192.168.1.10"},
        "timewindow": {"number": 1},
        "uid": [uid],
        "attacker": {"ioc_type": "IP", "value": "192.168.1.10"},
        "victim": {"ioc_type": "IP", "value": "8.8.8.8"},
    }


def _alert_payload(alert_id="ALERT1", evidence_id="E1"):
    """
    Build a minimal new_alert payload.

    Parameters:
        alert_id: Alert ID.
        evidence_id: Correlated evidence ID.

    Returns:
        Decoded alert payload.
    """
    return {
        "id": alert_id,
        "profile": {"ip": "192.168.1.10"},
        "timewindow": {"number": 1},
        "correl_id": [evidence_id],
        "accumulated_threat_level": 5.0,
        "confidence": 0.9,
        "threat_level": "CRITICAL",
        "last_flow_datetime": "1970-01-01T00:00:01+00:00",
    }


def test_disabled_module_does_not_subscribe():
    """Disabled graph_structure should stop without subscribing."""
    module_factory = ModuleFactory()
    graph_structure = module_factory.create_graph_structure_obj(enabled=False)

    graph_structure.subscribe_to_channels()
    result = graph_structure.pre_main()

    assert result == 1
    assert graph_structure.channels == {}
    graph_structure.db.subscribe.assert_not_called()


def test_enabled_module_subscribes_to_required_existing_channels():
    """Enabled graph_structure should subscribe only to existing channels."""
    module_factory = ModuleFactory()
    graph_structure = module_factory.create_graph_structure_obj(enabled=True)

    graph_structure.subscribe_to_channels()

    assert set(FLOW_CHANNELS).issubset(graph_structure.channels)
    assert "evidence_added" in graph_structure.channels
    assert "new_alert" in graph_structure.channels
    assert "new_blocking" in graph_structure.channels


def test_handle_data_message_normalizes_flow_and_evidence_buffers():
    """Data messages should be buffered by semantic channel class."""
    module_factory = ModuleFactory()
    graph_structure = module_factory.create_graph_structure_obj(enabled=True)

    graph_structure._handle_data_message(
        "new_flow", _message("new_flow", _new_flow_payload())
    )
    graph_structure._handle_data_message(
        "evidence_added",
        _message("evidence_added", _evidence_payload()),
    )

    assert graph_structure.flow_records[0]["flow"]["uid"] == "C1"
    assert graph_structure.flow_records[0]["channel"] == "new_flow"
    assert graph_structure.evidence_records[0]["id"] == "E1"


def test_alert_writes_graph_and_resets_window_buffers(tmp_path):
    """An alert should close the current window and write graph files."""
    module_factory = ModuleFactory()
    graph_structure = module_factory.create_graph_structure_obj(
        enabled=True, output_dir=str(tmp_path)
    )
    graph_structure.storage.prepare(GraphBuilder.schema())
    graph_structure.db.get_local_network.return_value = "192.168.1.0/24"
    graph_structure.db.is_whitelisted_evidence.return_value = False
    graph_structure.flow_records = [
        graph_structure._flow_record("new_flow", _new_flow_payload())
    ]
    graph_structure.evidence_records = [_evidence_payload()]

    graph_structure._handle_alert_message(
        _message("new_alert", _alert_payload())
    )

    graph_root = tmp_path / "graph-structure"
    window_dir = graph_root / "windows" / "window_0_ALERT1"
    nodes = GraphStorage.load_jsonl(str(window_dir / "nodes.jsonl"))
    edges = GraphStorage.load_jsonl(str(window_dir / "edges.jsonl"))

    assert graph_structure.written_graph_count == 1
    assert graph_structure.flow_records == []
    assert graph_structure.evidence_records == []
    assert (window_dir / "metadata.json").is_file()
    assert any(node["node_type"] == "alert" for node in nodes)
    assert any(edge["edge_type"] == "alert_contains_evidence" for edge in edges)


def test_second_alert_writes_transition_with_blocking_action(tmp_path):
    """Actions observed between alerts should be stored on the transition."""
    module_factory = ModuleFactory()
    graph_structure = module_factory.create_graph_structure_obj(
        enabled=True, output_dir=str(tmp_path)
    )
    graph_structure.storage.prepare(GraphBuilder.schema())
    graph_structure.db.get_local_network.return_value = "192.168.1.0/24"
    graph_structure.db.is_whitelisted_evidence.return_value = False

    graph_structure.flow_records = [
        graph_structure._flow_record("new_flow", _new_flow_payload("C1"))
    ]
    graph_structure.evidence_records = [_evidence_payload("C1", "E1")]
    graph_structure._handle_alert_message(
        _message("new_alert", _alert_payload("ALERT1", "E1"))
    )

    graph_structure._handle_data_message(
        "new_blocking",
        _message("new_blocking", {"ip": "192.168.1.10", "block": True}),
    )
    graph_structure.flow_records = [
        graph_structure._flow_record("new_flow", _new_flow_payload("C2"))
    ]
    graph_structure.evidence_records = [_evidence_payload("C2", "E2")]
    graph_structure._handle_alert_message(
        _message("new_alert", _alert_payload("ALERT2", "E2"))
    )

    transitions = GraphStorage.load_jsonl(
        str(tmp_path / "graph-structure" / "transitions.jsonl")
    )

    assert len(transitions) == 1
    assert transitions[0]["from_graph_id"] == "graph:0:ALERT1"
    assert transitions[0]["to_graph_id"] == "graph:1:ALERT2"
    assert transitions[0]["action_count"] == 1
    assert transitions[0]["actions"][0]["block"] is True


def test_shutdown_writes_manifest_without_open_window_graph(tmp_path):
    """Shutdown should report open-window counts without writing a graph."""
    module_factory = ModuleFactory()
    graph_structure = module_factory.create_graph_structure_obj(
        enabled=True, output_dir=str(tmp_path)
    )
    graph_structure.storage.prepare(GraphBuilder.schema())
    graph_structure.flow_records = [
        graph_structure._flow_record("new_flow", _new_flow_payload())
    ]

    graph_structure.shutdown_gracefully()

    manifest_path = tmp_path / "graph-structure" / "manifest.json"
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)

    assert manifest["written_graph_count"] == 0
    assert manifest["open_window_discarded"] is True
    assert manifest["open_window_flow_count"] == 1
    assert not (tmp_path / "graph-structure" / "windows" / "window_0_ALERT1").exists()


def test_pre_main_prepares_storage_without_dropping_privileges(tmp_path):
    """pre_main should prepare schema output when enabled."""
    module_factory = ModuleFactory()
    graph_structure = module_factory.create_graph_structure_obj(
        enabled=True, output_dir=str(tmp_path)
    )

    with patch("modules.graph_structure.graph_structure.utils") as mock_utils:
        result = graph_structure.pre_main()

    assert result is None
    assert (tmp_path / "graph-structure" / "schema.json").is_file()
    mock_utils.drop_root_privs_permanently.assert_called_once()
