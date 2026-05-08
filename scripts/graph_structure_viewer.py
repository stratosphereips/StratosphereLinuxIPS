# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Serve an interactive local viewer for graph_structure output."""

import argparse
import json
import mimetypes
import os
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qs, urlparse


ASSET_DIR = Path(__file__).parent / "graph_structure_viewer_assets"
SMART_NODE_THRESHOLD = 1800
SMART_EDGE_THRESHOLD = 8000
COLLAPSED_ENTITY_NODE_TYPES = {"flow"}
FLOW_EDGE_TYPES = {"flow_from_ip", "flow_to_ip", "flow_to_port"}


class GraphStructureDataStore:
    """Load graph_structure JSONL tables for the local viewer."""

    def __init__(self, output_path: str):
        """
        Create a graph data store.

        Parameters:
            output_path: Slips output directory or graph-structure directory.

        Returns:
            None.
        """
        self.graph_root = self._find_graph_root(Path(output_path))
        self._graph_cache: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def _find_graph_root(output_path: Path) -> Path:
        """
        Locate the graph-structure directory for a Slips output path.

        Parameters:
            output_path: Slips output directory or graph-structure directory.

        Returns:
            Path to the graph-structure directory.
        """
        if output_path.name == "graph-structure":
            graph_root = output_path
        else:
            graph_root = output_path / "graph-structure"

        if not graph_root.exists():
            raise FileNotFoundError(
                f"Could not find graph-structure output at {graph_root}"
            )
        return graph_root

    @staticmethod
    def _load_json(path: Path, default: Optional[Any] = None) -> Any:
        """
        Load a JSON file.

        Parameters:
            path: JSON path to read.
            default: Value returned when the file does not exist.

        Returns:
            Decoded JSON value or the supplied default.
        """
        if not path.exists():
            return default
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    @staticmethod
    def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
        """
        Load a JSONL table.

        Parameters:
            path: JSONL file path.

        Returns:
            List of decoded JSON rows.
        """
        rows = []
        if not path.exists():
            return rows
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    rows.append(json.loads(line))
        return rows

    @staticmethod
    def _count_by(rows: Iterable[Dict[str, Any]], field: str) -> Dict[str, int]:
        """
        Count rows by a field value.

        Parameters:
            rows: Rows to count.
            field: Field name to group by.

        Returns:
            Dictionary from field value to count.
        """
        counts: Dict[str, int] = {}
        for row in rows:
            value = str(row.get(field, "unknown"))
            counts[value] = counts.get(value, 0) + 1
        return counts

    @staticmethod
    def _feature_keys_by_type(
        rows: Iterable[Dict[str, Any]], type_field: str
    ) -> Dict[str, List[str]]:
        """
        Collect feature keys observed for each row type.

        Parameters:
            rows: Node or edge rows.
            type_field: Type field to group by.

        Returns:
            Dictionary mapping each type to sorted feature keys.
        """
        keys_by_type: Dict[str, set] = {}
        for row in rows:
            row_type = str(row.get(type_field, "unknown"))
            keys_by_type.setdefault(row_type, set()).update(
                (row.get("features") or {}).keys()
            )
        return {
            row_type: sorted(keys)
            for row_type, keys in sorted(keys_by_type.items())
        }

    def index(self) -> Dict[str, Any]:
        """
        Return graph run metadata for the viewer sidebar.

        Returns:
            Dictionary with schema, graph metadata, transitions, and docs.
        """
        schema = self._load_json(self.graph_root / "schema.json", {})
        graphs = self._load_jsonl(self.graph_root / "graphs.jsonl")
        transitions = self._load_jsonl(self.graph_root / "transitions.jsonl")
        manifest = self._load_json(self.graph_root / "manifest.json", {})
        totals = {
            "graph_count": len(graphs),
            "node_count": sum(graph.get("node_count", 0) for graph in graphs),
            "edge_count": sum(graph.get("edge_count", 0) for graph in graphs),
        }
        return {
            "graph_root": os.fspath(self.graph_root),
            "schema": schema,
            "graphs": graphs,
            "transitions": transitions,
            "manifest": manifest,
            "totals": totals,
            "smart_thresholds": {
                "node_count": SMART_NODE_THRESHOLD,
                "edge_count": SMART_EDGE_THRESHOLD,
            },
            "documentation": self.documentation(schema),
        }

    @staticmethod
    def documentation(schema: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build short documentation text shown inside the viewer.

        Parameters:
            schema: Stored graph schema.

        Returns:
            Documentation dictionary for node, edge, and graph metadata.
        """
        return {
            "overview": (
                "Each graph is one alert-bounded event window. The viewer "
                "keeps the canonical sparse JSONL tables on disk, but uses "
                "smaller derived views for large browser visualizations. "
                "All-windows smart mode shows the alert sequence; large "
                "single-window smart mode collapses flow nodes into counted "
                "entity relations. All-windows entity mode also collapses "
                "evidence nodes into counted alert-to-entity relations."
            ),
            "interaction": (
                "Hover a node or edge to inspect its type and main features. "
                "Click to pin details. Use the connection controls to hide, "
                "expand, or restore local neighborhoods without changing the "
                "stored graph. Use the layout sliders to increase link "
                "length, node gap, repulsion, component spacing, and label "
                "size for dense windows. Slider values update while dragged; "
                "the layout is recalculated after release so the graph does "
                "not rotate on every small adjustment."
            ),
            "node_types": schema.get("node_types", []),
            "edge_types": schema.get("edge_types", []),
            "feature_allowlists": schema.get("feature_allowlists", {}),
        }

    def graph_payload(self, selector: str, view: str = "raw") -> Dict[str, Any]:
        """
        Return one graph or the combined graph sequence.

        Parameters:
            selector: Window index, graph ID, or all.
            view: raw, smart, overview, or entity.

        Returns:
            Graph payload with nodes, edges, metadata, and summaries.
        """
        if view == "smart":
            return self.smart_payload(selector)
        if view == "overview":
            if selector == "all":
                return self.window_overview_payload()
            return self.entity_payload(selector)
        if view == "entity":
            return self.entity_payload(selector)
        if view != "raw":
            raise KeyError(f"Unknown graph view: {view}")

        if selector == "all":
            return self.combined_payload()

        graph = self._select_graph(selector)
        cache_key = str(graph["graph_id"])
        if cache_key not in self._graph_cache:
            self._graph_cache[cache_key] = self._load_graph(graph)
        return self._graph_cache[cache_key]

    def smart_payload(self, selector: str) -> Dict[str, Any]:
        """
        Return the browser-safe view for a selector.

        Parameters:
            selector: Window index, graph ID, or all.

        Returns:
            Window overview, entity overview, or raw graph payload.
        """
        if selector == "all":
            return self.window_overview_payload()

        graph = self._select_graph(selector)
        if (
            graph.get("node_count", 0) > SMART_NODE_THRESHOLD
            or graph.get("edge_count", 0) > SMART_EDGE_THRESHOLD
        ):
            return self.entity_payload(selector)
        payload = self.graph_payload(selector)
        return {
            **payload,
            "metadata": {
                **payload.get("metadata", {}),
                "view_mode": "raw",
                "smart_view_reason": "below_large_graph_threshold",
            },
        }

    def window_overview_payload(self) -> Dict[str, Any]:
        """
        Return one compact node per alert-bounded window.

        Returns:
            Graph payload with window nodes and transition edges.
        """
        graphs = self._load_jsonl(self.graph_root / "graphs.jsonl")
        transitions = self._load_jsonl(self.graph_root / "transitions.jsonl")
        graph_by_id = {graph["graph_id"]: graph for graph in graphs}
        nodes = [
            self._window_node(graph)
            for graph in sorted(graphs, key=lambda item: item["window_index"])
        ]
        edges = []
        for index, transition in enumerate(transitions):
            from_graph = graph_by_id.get(transition.get("from_graph_id"))
            to_graph = graph_by_id.get(transition.get("to_graph_id"))
            if not from_graph or not to_graph:
                continue
            edges.append(
                {
                    "graph_id": "all",
                    "edge_id": f"transition:{index}",
                    "source": self._window_node_id(from_graph),
                    "target": self._window_node_id(to_graph),
                    "edge_type": "graph_transition",
                    "features": transition,
                }
            )

        metadata = {
            "graph_id": "all",
            "window_index": "all",
            "alert_id": "all",
            "view_mode": "window_overview",
            "graph_count": len(graphs),
            "transition_count": len(transitions),
            "raw_node_count": sum(
                graph.get("node_count", 0) for graph in graphs
            ),
            "raw_edge_count": sum(
                graph.get("edge_count", 0) for graph in graphs
            ),
            "notice": (
                "Smart all-windows view shows one node per alert-bounded "
                "window. Switch to Entity overview for a collapsed entity "
                "view or Raw graph to force loading every node and edge."
            ),
        }
        return self._payload_from_rows(nodes, edges, metadata, graphs, transitions)

    @staticmethod
    def _window_node_id(graph: Dict[str, Any]) -> str:
        """
        Build a stable node ID for one graph window.

        Parameters:
            graph: Graph metadata row.

        Returns:
            Window node ID.
        """
        return f"window:{graph['window_index']}"

    def _window_node(self, graph: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build one compact alert-window node.

        Parameters:
            graph: Graph metadata row.

        Returns:
            Node row for the overview graph.
        """
        alert = graph.get("alert") or {}
        features = {
            "window_index": graph.get("window_index"),
            "alert_id": graph.get("alert_id"),
            "graph_id": graph.get("graph_id"),
            "node_count": graph.get("node_count"),
            "edge_count": graph.get("edge_count"),
            "flow_count": graph.get("flow_count"),
            "evidence_count": graph.get("evidence_count"),
            "protocol_event_count": graph.get("protocol_event_count"),
            "window_start_time": graph.get("window_start_time"),
            "window_end_time": graph.get("window_end_time"),
            "confidence": alert.get("confidence"),
            "threat_level": alert.get("threat_level"),
            "accumulated_threat_level": alert.get("accumulated_threat_level"),
        }
        return {
            "graph_id": "all",
            "node_id": self._window_node_id(graph),
            "node_type": "alert_window",
            "features": {
                key: value
                for key, value in features.items()
                if value is not None
            },
        }

    def entity_payload(self, selector: str) -> Dict[str, Any]:
        """
        Return a flow-collapsed entity graph for one selector.

        Parameters:
            selector: Window index, graph ID, or all.

        Returns:
            Entity overview graph payload.
        """
        raw_payload = self.graph_payload(selector)
        return self._entity_payload_from_raw(raw_payload)

    def _entity_payload_from_raw(
        self, raw_payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Collapse flow nodes and aggregate repeated entity edges.

        Parameters:
            raw_payload: Raw graph payload.

        Returns:
            Browser-friendly entity overview payload.
        """
        raw_nodes = raw_payload["nodes"]
        raw_edges = raw_payload["edges"]
        collapse_node_types = set(COLLAPSED_ENTITY_NODE_TYPES)
        if raw_payload.get("metadata", {}).get("window_index") == "all":
            collapse_node_types.add("evidence")
        visible_nodes = [
            dict(node)
            for node in raw_nodes
            if node.get("node_type") not in collapse_node_types
        ]
        visible_ids = {node["node_id"] for node in visible_nodes}
        flow_nodes = {
            node["node_id"]: node
            for node in raw_nodes
            if node.get("node_type") == "flow"
        }
        evidence_nodes = {
            node["node_id"]: node
            for node in raw_nodes
            if node.get("node_type") == "evidence"
        }
        aggregates: Dict[tuple[str, str, str], Dict[str, Any]] = {}
        flow_links = self._flow_links(raw_edges, visible_ids, flow_nodes)

        for edge in raw_edges:
            if (
                edge.get("edge_type") in FLOW_EDGE_TYPES
                or edge.get("source") not in visible_ids
                or edge.get("target") not in visible_ids
            ):
                continue
            self._add_aggregated_edge(
                aggregates,
                raw_payload["metadata"].get("graph_id", "graph"),
                edge["source"],
                edge["target"],
                edge["edge_type"],
                edge.get("features") or {},
                edge.get("edge_id"),
                "duplicate_edges",
            )

        if "evidence" in collapse_node_types:
            self._add_evidence_aggregate_edges(
                aggregates,
                raw_payload["metadata"].get("graph_id", "graph"),
                raw_edges,
                evidence_nodes,
                visible_ids,
            )
        self._add_flow_aggregate_edges(
            aggregates,
            raw_payload["metadata"].get("graph_id", "graph"),
            flow_links,
            flow_nodes,
        )
        edges = self._aggregate_edges_to_rows(aggregates)
        metadata = {
            **raw_payload.get("metadata", {}),
            "view_mode": "entity_overview",
            "raw_node_count": len(raw_nodes),
            "raw_edge_count": len(raw_edges),
            "collapsed_node_types": sorted(collapse_node_types),
            "collapsed_node_count": sum(
                1
                for node in raw_nodes
                if node.get("node_type") in collapse_node_types
            ),
            "aggregated_edge_count": len(edges),
            "notice": (
                "Entity overview hides raw flow nodes and aggregates repeated "
                "relations. Edge count is stored in each edge's count feature."
            ),
        }
        return self._payload_from_rows(
            visible_nodes,
            edges,
            metadata,
            raw_payload.get("graphs", []),
            raw_payload.get("transitions", []),
        )

    @staticmethod
    def _flow_links(
        edges: List[Dict[str, Any]],
        visible_ids: set[str],
        flow_nodes: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Dict[str, List[str]]]:
        """
        Collect visible endpoints attached to each hidden flow node.

        Parameters:
            edges: Raw edge rows.
            visible_ids: Node IDs kept in the entity view.
            flow_nodes: Hidden flow nodes by node ID.

        Returns:
            Mapping from flow node ID to source IPs, destination IPs, and ports.
        """
        links: Dict[str, Dict[str, List[str]]] = {}
        for edge in edges:
            edge_type = edge.get("edge_type")
            source = edge.get("source")
            target = edge.get("target")
            if source not in flow_nodes or target not in visible_ids:
                continue
            flow_id = str(source)
            flow_links = links.setdefault(
                flow_id, {"source_ips": [], "target_ips": [], "ports": []}
            )
            if edge_type == "flow_from_ip":
                flow_links["source_ips"].append(str(target))
            elif edge_type == "flow_to_ip":
                flow_links["target_ips"].append(str(target))
            elif edge_type == "flow_to_port":
                flow_links["ports"].append(str(target))
        return links

    def _add_flow_aggregate_edges(
        self,
        aggregates: Dict[tuple[str, str, str], Dict[str, Any]],
        graph_id: str,
        flow_links: Dict[str, Dict[str, List[str]]],
        flow_nodes: Dict[str, Dict[str, Any]],
    ) -> None:
        """
        Add aggregate edges derived from hidden flow nodes.

        Parameters:
            aggregates: Mutable aggregate edge dictionary.
            graph_id: Graph ID for generated edge rows.
            flow_links: Visible endpoints attached to each hidden flow.
            flow_nodes: Hidden flow node rows by node ID.

        Returns:
            None.
        """
        for flow_id, links in flow_links.items():
            flow = flow_nodes.get(flow_id, {})
            features = flow.get("features") or {}
            for source in links["source_ips"]:
                for target in links["target_ips"]:
                    if source == target:
                        continue
                    self._add_aggregated_edge(
                        aggregates,
                        graph_id,
                        source,
                        target,
                        "aggregated_flow_to_ip",
                        features,
                        flow_id,
                        "hidden_flow_nodes",
                    )
                for port in links["ports"]:
                    self._add_aggregated_edge(
                        aggregates,
                        graph_id,
                        source,
                        port,
                        "aggregated_flow_to_port",
                        features,
                        flow_id,
                        "hidden_flow_nodes",
                    )

    def _add_evidence_aggregate_edges(
        self,
        aggregates: Dict[tuple[str, str, str], Dict[str, Any]],
        graph_id: str,
        edges: List[Dict[str, Any]],
        evidence_nodes: Dict[str, Dict[str, Any]],
        visible_ids: set[str],
    ) -> None:
        """
        Add alert-to-entity aggregate edges for hidden evidence nodes.

        Parameters:
            aggregates: Mutable aggregate edge dictionary.
            graph_id: Graph ID for generated edge rows.
            edges: Raw edge rows.
            evidence_nodes: Hidden evidence node rows by node ID.
            visible_ids: Node IDs kept in the entity view.

        Returns:
            None.
        """
        alert_sources: Dict[str, List[str]] = {}
        entity_targets: Dict[str, List[str]] = {}
        for edge in edges:
            source = edge.get("source")
            target = edge.get("target")
            edge_type = edge.get("edge_type")
            if edge_type == "alert_contains_evidence":
                if source in visible_ids and target in evidence_nodes:
                    alert_sources.setdefault(str(target), []).append(str(source))
                elif target in visible_ids and source in evidence_nodes:
                    alert_sources.setdefault(str(source), []).append(str(target))
            elif edge_type == "evidence_about_entity":
                if source in evidence_nodes and target in visible_ids:
                    entity_targets.setdefault(str(source), []).append(str(target))
                elif target in evidence_nodes and source in visible_ids:
                    entity_targets.setdefault(str(target), []).append(str(source))

        for evidence_id, alerts in alert_sources.items():
            evidence = evidence_nodes.get(evidence_id, {})
            features = evidence.get("features") or {}
            for alert in alerts:
                for entity in entity_targets.get(evidence_id, []):
                    self._add_aggregated_edge(
                        aggregates,
                        graph_id,
                        alert,
                        entity,
                        "aggregated_evidence_about_entity",
                        features,
                        evidence_id,
                        "hidden_evidence_nodes",
                    )

    @staticmethod
    def _add_aggregated_edge(
        aggregates: Dict[tuple[str, str, str], Dict[str, Any]],
        graph_id: str,
        source: str,
        target: str,
        edge_type: str,
        features: Dict[str, Any],
        sample_id: Optional[str],
        collapsed_from: str,
    ) -> None:
        """
        Add one observation to an aggregate edge accumulator.

        Parameters:
            aggregates: Mutable aggregate edge dictionary.
            graph_id: Graph ID for the generated edge.
            source: Source node ID.
            target: Target node ID.
            edge_type: Edge type.
            features: Edge or flow features to summarize.
            sample_id: Representative raw edge or flow ID.
            collapsed_from: Collapse reason.

        Returns:
            None.
        """
        key = (str(source), str(target), str(edge_type))
        aggregate = aggregates.setdefault(
            key,
            {
                "graph_id": graph_id,
                "source": str(source),
                "target": str(target),
                "edge_type": str(edge_type),
                "count": 0,
                "sample_ids": [],
                "uids": [],
                "protocols": set(),
                "app_protocols": set(),
                "interfaces": set(),
                "profileids": set(),
                "twids": set(),
                "states": set(),
                "total_bytes": 0.0,
                "total_packets": 0.0,
                "collapsed_from": collapsed_from,
            },
        )
        aggregate["count"] += 1
        if sample_id and len(aggregate["sample_ids"]) < 8:
            aggregate["sample_ids"].append(sample_id)
        uid = features.get("uid")
        if uid and len(aggregate["uids"]) < 8:
            aggregate["uids"].append(uid)
        for source_key, target_key in (
            ("proto", "protocols"),
            ("appproto", "app_protocols"),
            ("interface", "interfaces"),
            ("profileid", "profileids"),
            ("twid", "twids"),
            ("state", "states"),
        ):
            value = features.get(source_key)
            if value is not None:
                aggregate[target_key].add(str(value))
        aggregate["total_bytes"] += GraphStructureDataStore._numeric(
            features.get("bytes")
        )
        aggregate["total_packets"] += GraphStructureDataStore._numeric(
            features.get("pkts")
        )

    @staticmethod
    def _numeric(value: Any) -> float:
        """
        Convert a feature value to a number for aggregation.

        Parameters:
            value: Feature value.

        Returns:
            Numeric value, or zero when conversion fails.
        """
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _aggregate_edges_to_rows(
        aggregates: Dict[tuple[str, str, str], Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Convert edge accumulators to graph edge rows.

        Parameters:
            aggregates: Aggregate edge dictionary.

        Returns:
            Sorted list of edge rows.
        """
        rows = []
        for index, key in enumerate(sorted(aggregates)):
            aggregate = aggregates[key]
            features = {
                "count": aggregate["count"],
                "collapsed_from": aggregate["collapsed_from"],
                "sample_ids": aggregate["sample_ids"],
                "uids": aggregate["uids"],
                "protocols": sorted(aggregate["protocols"]),
                "app_protocols": sorted(aggregate["app_protocols"]),
                "interfaces": sorted(aggregate["interfaces"]),
                "profileids": sorted(aggregate["profileids"]),
                "twids": sorted(aggregate["twids"]),
                "states": sorted(aggregate["states"]),
                "total_bytes": int(aggregate["total_bytes"]),
                "total_packets": int(aggregate["total_packets"]),
            }
            rows.append(
                {
                    "graph_id": aggregate["graph_id"],
                    "edge_id": f"aggregate:{index}",
                    "source": aggregate["source"],
                    "target": aggregate["target"],
                    "edge_type": aggregate["edge_type"],
                    "features": {
                        field: value
                        for field, value in features.items()
                        if value not in (None, "", [], {})
                    },
                }
            )
        return rows

    def _select_graph(self, selector: str) -> Dict[str, Any]:
        """
        Select graph metadata by index or graph ID.

        Parameters:
            selector: Window index or graph ID.

        Returns:
            Matching graph metadata row.
        """
        graphs = self._load_jsonl(self.graph_root / "graphs.jsonl")
        for graph in graphs:
            if str(graph.get("window_index")) == selector:
                return graph
            if str(graph.get("graph_id")) == selector:
                return graph
        raise KeyError(f"Unknown graph selector: {selector}")

    def _load_graph(self, graph: Dict[str, Any]) -> Dict[str, Any]:
        """
        Load one graph window from its table paths.

        Parameters:
            graph: Graph metadata row from graphs.jsonl.

        Returns:
            Graph payload.
        """
        nodes_path = self.graph_root / graph.get("nodes_path", "")
        edges_path = self.graph_root / graph.get("edges_path", "")
        metadata_path = self.graph_root / graph.get("metadata_path", "")
        nodes = self._load_jsonl(nodes_path)
        edges = self._load_jsonl(edges_path)
        metadata = self._load_json(metadata_path, graph)
        return self._payload_from_rows(nodes, edges, metadata, [graph])

    def combined_payload(self) -> Dict[str, Any]:
        """
        Return all windows as one combined graph with transition edges.

        Returns:
            Combined graph payload.
        """
        graphs = self._load_jsonl(self.graph_root / "graphs.jsonl")
        transitions = self._load_jsonl(self.graph_root / "transitions.jsonl")
        prefixes = {
            graph["graph_id"]: f"g{graph['window_index']}::"
            for graph in graphs
        }
        nodes = []
        edges = []

        for graph in graphs:
            payload = self.graph_payload(str(graph["window_index"]))
            prefix = prefixes[graph["graph_id"]]
            for node in payload["nodes"]:
                nodes.append(self._copy_node_for_combined(node, graph, prefix))
            for edge in payload["edges"]:
                edges.append(self._copy_edge_for_combined(edge, graph, prefix))

        for index, transition in enumerate(transitions):
            edge = self._transition_edge(index, transition, graphs, prefixes)
            if edge:
                edges.append(edge)

        metadata = {
            "graph_id": "all",
            "window_index": "all",
            "alert_id": "all",
            "graph_count": len(graphs),
            "transition_count": len(transitions),
            "node_count": len(nodes),
            "edge_count": len(edges),
        }
        return self._payload_from_rows(nodes, edges, metadata, graphs, transitions)

    @staticmethod
    def _copy_node_for_combined(
        node: Dict[str, Any], graph: Dict[str, Any], prefix: str
    ) -> Dict[str, Any]:
        """
        Copy one node into the combined graph namespace.

        Parameters:
            node: Original node row.
            graph: Graph metadata row.
            prefix: Combined graph ID prefix.

        Returns:
            Namespaced node row.
        """
        copied = dict(node)
        copied["node_id"] = f"{prefix}{node['node_id']}"
        copied["graph_id"] = "all"
        copied["features"] = {
            **(node.get("features") or {}),
            "source_graph_id": graph["graph_id"],
            "window_index": graph["window_index"],
            "original_node_id": node["node_id"],
        }
        return copied

    @staticmethod
    def _copy_edge_for_combined(
        edge: Dict[str, Any], graph: Dict[str, Any], prefix: str
    ) -> Dict[str, Any]:
        """
        Copy one edge into the combined graph namespace.

        Parameters:
            edge: Original edge row.
            graph: Graph metadata row.
            prefix: Combined graph ID prefix.

        Returns:
            Namespaced edge row.
        """
        copied = dict(edge)
        copied["edge_id"] = f"{prefix}{edge['edge_id']}"
        copied["source"] = f"{prefix}{edge['source']}"
        copied["target"] = f"{prefix}{edge['target']}"
        copied["graph_id"] = "all"
        copied["features"] = {
            **(edge.get("features") or {}),
            "source_graph_id": graph["graph_id"],
            "window_index": graph["window_index"],
            "original_edge_id": edge["edge_id"],
        }
        return copied

    @staticmethod
    def _transition_edge(
        index: int,
        transition: Dict[str, Any],
        graphs: List[Dict[str, Any]],
        prefixes: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """
        Build a synthetic edge linking alert nodes across windows.

        Parameters:
            index: Transition row index.
            transition: Transition metadata row.
            graphs: Graph metadata rows.
            prefixes: Combined graph prefixes by graph ID.

        Returns:
            Synthetic transition edge, or None when graph IDs are missing.
        """
        graph_by_id = {graph["graph_id"]: graph for graph in graphs}
        from_graph = graph_by_id.get(transition.get("from_graph_id"))
        to_graph = graph_by_id.get(transition.get("to_graph_id"))
        if not from_graph or not to_graph:
            return None

        source = (
            f"{prefixes[from_graph['graph_id']]}"
            f"alert:{from_graph['alert_id']}"
        )
        target = (
            f"{prefixes[to_graph['graph_id']]}"
            f"alert:{to_graph['alert_id']}"
        )
        return {
            "graph_id": "all",
            "edge_id": f"transition:{index}",
            "source": source,
            "target": target,
            "edge_type": "graph_transition",
            "features": transition,
        }

    def _payload_from_rows(
        self,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        metadata: Dict[str, Any],
        graphs: List[Dict[str, Any]],
        transitions: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Build a viewer payload from graph table rows.

        Parameters:
            nodes: Node rows.
            edges: Edge rows.
            metadata: Graph metadata.
            graphs: Related graph metadata rows.
            transitions: Optional transition metadata rows.

        Returns:
            Viewer graph payload.
        """
        return {
            "metadata": metadata,
            "graphs": graphs,
            "transitions": transitions or self._related_transitions(metadata),
            "nodes": nodes,
            "edges": edges,
            "summary": {
                "node_count": len(nodes),
                "edge_count": len(edges),
                "node_types": self._count_by(nodes, "node_type"),
                "edge_types": self._count_by(edges, "edge_type"),
                "node_features": self._feature_keys_by_type(
                    nodes, "node_type"
                ),
                "edge_features": self._feature_keys_by_type(
                    edges, "edge_type"
                ),
            },
        }

    def _related_transitions(
        self, metadata: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Return transitions touching one graph.

        Parameters:
            metadata: Graph metadata.

        Returns:
            List of transition rows.
        """
        graph_id = metadata.get("graph_id")
        transitions = self._load_jsonl(self.graph_root / "transitions.jsonl")
        return [
            transition
            for transition in transitions
            if graph_id
            in (
                transition.get("from_graph_id"),
                transition.get("to_graph_id"),
            )
        ]


class ViewerRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler serving the viewer and graph API."""

    data_store: GraphStructureDataStore

    def do_GET(self) -> None:
        """
        Handle an HTTP GET request.

        Returns:
            None.
        """
        parsed = urlparse(self.path)
        if parsed.path == "/api/index":
            self._send_json(self.data_store.index())
            return

        if parsed.path.startswith("/api/graph/"):
            selector = parsed.path.rsplit("/", 1)[-1]
            view = parse_qs(parsed.query).get("view", ["raw"])[0]
            self._send_graph(selector, view)
            return

        if parsed.path == "/api/graph":
            query = parse_qs(parsed.query)
            selector = query.get("selector", ["all"])[0]
            view = query.get("view", ["raw"])[0]
            self._send_graph(selector, view)
            return

        self._send_static(parsed.path)

    def do_HEAD(self) -> None:
        """
        Handle an HTTP HEAD request for static viewer assets.

        Returns:
            None.
        """
        parsed = urlparse(self.path)
        if parsed.path in ("/api/index", "/api/graph") or parsed.path.startswith(
            "/api/graph/"
        ):
            self._send_json({}, include_body=False)
            return
        self._send_static(parsed.path, include_body=False)

    def log_message(self, format_string: str, *args: Any) -> None:
        """
        Log HTTP requests to stderr with the standard handler format.

        Parameters:
            format_string: Format string from BaseHTTPRequestHandler.
            args: Format values.

        Returns:
            None.
        """
        sys.stderr.write(f"{self.address_string()} - {format_string % args}\n")

    def _send_graph(self, selector: str, view: str = "raw") -> None:
        """
        Send a graph payload response.

        Parameters:
            selector: Window index, graph ID, or all.
            view: raw, smart, overview, or entity.

        Returns:
            None.
        """
        try:
            payload = self.data_store.graph_payload(selector, view)
        except KeyError as error:
            self._send_json({"error": str(error)}, status=404)
            return
        self._send_json(payload)

    def _send_json(
        self,
        payload: Dict[str, Any],
        status: int = 200,
        include_body: bool = True,
    ) -> None:
        """
        Send a JSON response.

        Parameters:
            payload: JSON-serializable payload.
            status: HTTP status code.
            include_body: Whether to write the response body.

        Returns:
            None.
        """
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def _send_static(self, request_path: str, include_body: bool = True) -> None:
        """
        Send a static viewer asset.

        Parameters:
            request_path: Request path.
            include_body: Whether to write the response body.

        Returns:
            None.
        """
        asset_name = "index.html" if request_path in ("", "/") else request_path
        asset_name = asset_name.lstrip("/")
        if ".." in Path(asset_name).parts:
            self.send_error(404, "Viewer asset not found")
            return
        asset_path = ASSET_DIR / asset_name
        if not asset_path.exists() or not asset_path.is_file():
            self.send_error(404, "Viewer asset not found")
            return

        body = asset_path.read_bytes()
        content_type = (
            mimetypes.guess_type(asset_path.name)[0]
            or "application/octet-stream"
        )
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if include_body:
            self.wfile.write(body)


def build_handler(
    data_store: GraphStructureDataStore,
) -> type[ViewerRequestHandler]:
    """
    Create a request handler bound to a graph data store.

    Parameters:
        data_store: Loaded graph data store.

    Returns:
        ViewerRequestHandler subclass with attached data store.
    """

    class BoundViewerRequestHandler(ViewerRequestHandler):
        """Request handler bound to one graph data store."""

    BoundViewerRequestHandler.data_store = data_store
    return BoundViewerRequestHandler


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed command-line namespace.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Serve an interactive local webpage for graph_structure output."
        )
    )
    parser.add_argument(
        "output",
        help="Slips output directory or its graph-structure directory.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind host.")
    parser.add_argument(
        "--port", type=int, default=8765, help="HTTP bind port."
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not open the browser automatically.",
    )
    return parser.parse_args()


def main() -> None:
    """
    Start the local graph viewer web server.

    Returns:
        None.
    """
    args = parse_args()
    data_store = GraphStructureDataStore(args.output)
    handler = build_handler(data_store)
    server = ThreadingHTTPServer((args.host, args.port), handler)
    url = f"http://{args.host}:{args.port}/"
    print(f"Serving graph_structure viewer for {data_store.graph_root}")
    print(f"Open {url}")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping graph_structure viewer.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
