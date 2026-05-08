# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for the graph_structure viewer data loader."""

import json

from scripts.graph_structure_viewer import GraphStructureDataStore
from tests.module_factory import ModuleFactory


def _write_json(path, data):
    """
    Write a JSON file for viewer tests.

    Parameters:
        path: Destination path.
        data: JSON-serializable value.

    Returns:
        None.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
        handle.write("\n")


def _write_jsonl(path, rows):
    """
    Write a JSONL file for viewer tests.

    Parameters:
        path: Destination path.
        rows: Rows to write.

    Returns:
        None.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row))
            handle.write("\n")


def _create_graph_structure_output(tmp_path):
    """
    Create minimal graph_structure output.

    Parameters:
        tmp_path: Pytest temporary path.

    Returns:
        Path to the Slips output directory.
    """
    output_dir = tmp_path / "output"
    graph_root = output_dir / "graph-structure"
    _write_json(
        graph_root / "schema.json",
        {
            "schema_version": "1.0",
            "node_types": ["alert", "ip"],
            "edge_types": ["alert_contains_evidence"],
            "feature_allowlists": {"alert": ["id"]},
        },
    )
    _write_jsonl(
        graph_root / "graphs.jsonl",
        [
            {
                "graph_id": "graph:0:A1",
                "window_index": 0,
                "alert_id": "A1",
                "node_count": 1,
                "edge_count": 0,
                "nodes_path": "windows/window_0_A1/nodes.jsonl",
                "edges_path": "windows/window_0_A1/edges.jsonl",
                "metadata_path": "windows/window_0_A1/metadata.json",
            },
            {
                "graph_id": "graph:1:A2",
                "window_index": 1,
                "alert_id": "A2",
                "node_count": 1,
                "edge_count": 0,
                "nodes_path": "windows/window_1_A2/nodes.jsonl",
                "edges_path": "windows/window_1_A2/edges.jsonl",
                "metadata_path": "windows/window_1_A2/metadata.json",
            },
        ],
    )
    _write_jsonl(
        graph_root / "transitions.jsonl",
        [
            {
                "from_graph_id": "graph:0:A1",
                "to_graph_id": "graph:1:A2",
                "actions": [{"block": True}],
                "action_count": 1,
                "reward": None,
            }
        ],
    )
    for index, alert_id in ((0, "A1"), (1, "A2")):
        window = graph_root / "windows" / f"window_{index}_{alert_id}"
        _write_jsonl(
            window / "nodes.jsonl",
            [
                {
                    "graph_id": f"graph:{index}:{alert_id}",
                    "node_id": f"alert:{alert_id}",
                    "node_type": "alert",
                    "features": {"id": alert_id},
                }
            ],
        )
        _write_jsonl(window / "edges.jsonl", [])
        _write_json(
            window / "metadata.json",
            {
                "graph_id": f"graph:{index}:{alert_id}",
                "window_index": index,
                "alert_id": alert_id,
            },
        )
    return output_dir


def test_index_loads_schema_graphs_and_transitions(tmp_path):
    """The viewer index should expose run-level graph metadata."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    output_dir = _create_graph_structure_output(tmp_path)
    data_store = GraphStructureDataStore(str(output_dir))

    index = data_store.index()

    assert index["schema"]["schema_version"] == "1.0"
    assert len(index["graphs"]) == 2
    assert len(index["transitions"]) == 1
    assert "overview" in index["documentation"]


def test_graph_payload_loads_one_window(tmp_path):
    """The viewer should load one graph window by index."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    output_dir = _create_graph_structure_output(tmp_path)
    data_store = GraphStructureDataStore(str(output_dir))

    payload = data_store.graph_payload("0")

    assert payload["metadata"]["graph_id"] == "graph:0:A1"
    assert payload["summary"]["node_count"] == 1
    assert payload["summary"]["node_types"] == {"alert": 1}


def test_combined_payload_adds_transition_edges(tmp_path):
    """The all-windows view should include synthetic transition edges."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    output_dir = _create_graph_structure_output(tmp_path)
    data_store = GraphStructureDataStore(str(output_dir))

    payload = data_store.graph_payload("all")
    edge_types = {edge["edge_type"] for edge in payload["edges"]}

    assert payload["metadata"]["graph_count"] == 2
    assert payload["summary"]["node_count"] == 2
    assert "graph_transition" in edge_types
