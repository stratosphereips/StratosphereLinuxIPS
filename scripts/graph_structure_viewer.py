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
        return {
            "graph_root": os.fspath(self.graph_root),
            "schema": schema,
            "graphs": graphs,
            "transitions": transitions,
            "manifest": manifest,
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
                "loads the sparse node and edge JSONL tables directly and "
                "keeps graph-level metadata and transitions available in the "
                "side panels."
            ),
            "interaction": (
                "Hover a node or edge to inspect its type and main features. "
                "Click to pin details. Use the connection controls to hide, "
                "expand, or restore local neighborhoods without changing the "
                "stored graph."
            ),
            "node_types": schema.get("node_types", []),
            "edge_types": schema.get("edge_types", []),
            "feature_allowlists": schema.get("feature_allowlists", {}),
        }

    def graph_payload(self, selector: str) -> Dict[str, Any]:
        """
        Return one graph or the combined graph sequence.

        Parameters:
            selector: Window index, graph ID, or all.

        Returns:
            Graph payload with nodes, edges, metadata, and summaries.
        """
        if selector == "all":
            return self.combined_payload()

        graph = self._select_graph(selector)
        cache_key = str(graph["graph_id"])
        if cache_key not in self._graph_cache:
            self._graph_cache[cache_key] = self._load_graph(graph)
        return self._graph_cache[cache_key]

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
            self._send_graph(selector)
            return

        if parsed.path == "/api/graph":
            selector = parse_qs(parsed.query).get("selector", ["all"])[0]
            self._send_graph(selector)
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

    def _send_graph(self, selector: str) -> None:
        """
        Send a graph payload response.

        Parameters:
            selector: Window index, graph ID, or all.

        Returns:
            None.
        """
        try:
            payload = self.data_store.graph_payload(selector)
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
