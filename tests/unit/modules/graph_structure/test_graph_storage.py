# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for graph storage helpers."""

from modules.graph_structure.graph_builder import GraphBuilder
from modules.graph_structure.graph_storage import GraphStorage
from tests.module_factory import ModuleFactory


def _minimal_graph():
    """
    Build a minimal graph dictionary for storage tests.

    Returns:
        Graph dictionary.
    """
    return {
        "graph_id": "graph:0:ALERT1",
        "window_index": 0,
        "alert_id": "ALERT1",
        "metadata": {
            "schema_version": "1.0",
            "graph_id": "graph:0:ALERT1",
            "window_index": 0,
            "alert_id": "ALERT1",
            "node_count": 1,
            "edge_count": 1,
        },
        "nodes": [
            {
                "graph_id": "graph:0:ALERT1",
                "node_id": "flow:C1",
                "node_type": "flow",
                "features": {
                    "uid": "C1",
                    "profileid": "profile_192.168.1.10",
                    "twid": "timewindow1",
                    "interface": "eth0",
                },
            }
        ],
        "edges": [
            {
                "graph_id": "graph:0:ALERT1",
                "edge_id": "edge:0",
                "source": "flow:C1",
                "target": "ip:192.168.1.10",
                "edge_type": "flow_from_ip",
                "features": {
                    "uid": "C1",
                    "profileid": "profile_192.168.1.10",
                    "twid": "timewindow1",
                    "interface": "eth0",
                },
            }
        ],
    }


def test_write_graph_creates_sparse_table_layout(tmp_path):
    """Storage should write schema, metadata, nodes, and edges."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    storage = GraphStorage(str(tmp_path / "graph-structure"))
    storage.prepare(GraphBuilder.schema())
    storage.write_graph(_minimal_graph())

    window_dir = tmp_path / "graph-structure" / "windows" / "window_0_ALERT1"
    assert (tmp_path / "graph-structure" / "schema.json").is_file()
    assert (tmp_path / "graph-structure" / "graphs.jsonl").is_file()
    assert (window_dir / "nodes.jsonl").is_file()
    assert (window_dir / "edges.jsonl").is_file()
    assert (window_dir / "metadata.json").is_file()

    nodes = GraphStorage.load_jsonl(str(window_dir / "nodes.jsonl"))
    edges = GraphStorage.load_jsonl(str(window_dir / "edges.jsonl"))
    assert nodes[0]["node_id"] == "flow:C1"
    assert edges[0]["edge_type"] == "flow_from_ip"


def test_filter_rows_supports_partial_observability_filters():
    """Rows should be filterable by visibility fields."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    rows = _minimal_graph()["nodes"]
    visible = GraphStorage.filter_rows(
        rows,
        profileid="profile_192.168.1.10",
        interface="eth0",
        twid="timewindow1",
        uids=["C1"],
    )
    hidden = GraphStorage.filter_rows(rows, profileid="profile_10.0.0.2")

    assert visible == rows
    assert hidden == []


def test_filter_rows_supports_uid_lists():
    """Rows with UID lists should match agent visibility filters."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    rows = [
        {
            "features": {
                "uid": ["C1", "C2"],
                "profileid": "profile_192.168.1.10",
            }
        }
    ]

    visible = GraphStorage.filter_rows(rows, uids=["C2"])
    hidden = GraphStorage.filter_rows(rows, uids=["C3"])

    assert visible == rows
    assert hidden == []
