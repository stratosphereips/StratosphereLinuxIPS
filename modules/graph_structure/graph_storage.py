# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Storage helpers for sparse alert-window graph tables."""

import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Set


class GraphStorage:
    """Writes and reads dependency-free JSONL graph table files."""

    def __init__(self, output_dir: str):
        """
        Create graph storage rooted at the given output directory.

        Parameters:
            output_dir: Directory where graph-structure output is stored.

        Returns:
            None.
        """
        self.output_dir = output_dir
        self.windows_dir = os.path.join(self.output_dir, "windows")
        self.schema_path = os.path.join(self.output_dir, "schema.json")
        self.graphs_path = os.path.join(self.output_dir, "graphs.jsonl")
        self.transitions_path = os.path.join(
            self.output_dir, "transitions.jsonl"
        )
        self.manifest_path = os.path.join(self.output_dir, "manifest.json")

    def prepare(self, schema: Dict[str, Any]) -> None:
        """
        Create storage directories and write the schema file.

        Parameters:
            schema: Schema dictionary to store in schema.json.

        Returns:
            None.
        """
        os.makedirs(self.windows_dir, exist_ok=True)
        self._write_json(self.schema_path, schema)

    @staticmethod
    def _safe_filename(value: Any) -> str:
        """
        Convert an arbitrary identifier into a safe path component.

        Parameters:
            value: Raw identifier.

        Returns:
            Filename-safe string.
        """
        value = str(value)
        value = re.sub(r"[^A-Za-z0-9_.-]", "_", value)
        return value[:160] or "unknown"

    @staticmethod
    def _write_json(path: str, data: Dict[str, Any]) -> None:
        """
        Write a JSON object with stable formatting.

        Parameters:
            path: Destination path.
            data: JSON-serializable dictionary.

        Returns:
            None.
        """
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, sort_keys=True, indent=2)
            handle.write("\n")

    @staticmethod
    def _append_jsonl(path: str, row: Dict[str, Any]) -> None:
        """
        Append one row to a JSONL file.

        Parameters:
            path: Destination JSONL path.
            row: JSON-serializable row.

        Returns:
            None.
        """
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True))
            handle.write("\n")

    def window_dir(self, window_index: int, alert_id: str) -> str:
        """
        Return the directory for one graph window.

        Parameters:
            window_index: Sequential window index.
            alert_id: Alert ID that closed the window.

        Returns:
            Window directory path.
        """
        dirname = f"window_{window_index}_{self._safe_filename(alert_id)}"
        return os.path.join(self.windows_dir, dirname)

    def write_graph(self, graph: Dict[str, Any]) -> None:
        """
        Write one graph's node table, edge table, and metadata.

        Parameters:
            graph: Graph dictionary returned by GraphBuilder.

        Returns:
            None.
        """
        window_path = self.window_dir(graph["window_index"], graph["alert_id"])
        os.makedirs(window_path, exist_ok=True)

        nodes_path = os.path.join(window_path, "nodes.jsonl")
        edges_path = os.path.join(window_path, "edges.jsonl")
        metadata_path = os.path.join(window_path, "metadata.json")

        for node in graph["nodes"]:
            self._append_jsonl(nodes_path, node)
        for edge in graph["edges"]:
            self._append_jsonl(edges_path, edge)

        metadata = dict(graph["metadata"])
        metadata["nodes_path"] = os.path.relpath(nodes_path, self.output_dir)
        metadata["edges_path"] = os.path.relpath(edges_path, self.output_dir)
        metadata["metadata_path"] = os.path.relpath(
            metadata_path, self.output_dir
        )
        self._write_json(metadata_path, metadata)
        self._append_jsonl(self.graphs_path, metadata)

    def append_transition(self, transition: Dict[str, Any]) -> None:
        """
        Append a graph-to-graph transition row.

        Parameters:
            transition: Transition metadata dictionary.

        Returns:
            None.
        """
        self._append_jsonl(self.transitions_path, transition)

    def write_manifest(self, manifest: Dict[str, Any]) -> None:
        """
        Write run-level graph module metadata.

        Parameters:
            manifest: Run metadata dictionary.

        Returns:
            None.
        """
        self._write_json(self.manifest_path, manifest)

    @staticmethod
    def load_jsonl(path: str) -> List[Dict[str, Any]]:
        """
        Load a JSONL file into memory.

        Parameters:
            path: JSONL path.

        Returns:
            List of decoded rows.
        """
        rows = []
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    rows.append(json.loads(line))
        return rows

    @staticmethod
    def filter_rows(
        rows: Iterable[Dict[str, Any]],
        profileid: Optional[str] = None,
        interface: Optional[str] = None,
        twid: Optional[str] = None,
        uids: Optional[Iterable[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Return rows visible under simple profile/interface/timewindow filters.

        Parameters:
            rows: Node or edge rows from canonical graph tables.
            profileid: Optional Slips profile visibility filter.
            interface: Optional network interface visibility filter.
            twid: Optional timewindow visibility filter.
            uids: Optional flow UID visibility filter.

        Returns:
            Filtered rows.
        """
        uid_set = set(str(uid) for uid in (uids or []))
        return [
            row
            for row in rows
            if GraphStorage._row_is_visible(
                row,
                profileid=profileid,
                interface=interface,
                twid=twid,
                uids=uid_set,
            )
        ]

    @staticmethod
    def _row_is_visible(
        row: Dict[str, Any],
        profileid: Optional[str],
        interface: Optional[str],
        twid: Optional[str],
        uids: Set[str],
    ) -> bool:
        """
        Check whether one canonical row matches visibility constraints.

        Parameters:
            row: Node or edge row.
            profileid: Optional Slips profile visibility filter.
            interface: Optional network interface visibility filter.
            twid: Optional timewindow visibility filter.
            uids: UID set visibility filter.

        Returns:
            True when the row matches all supplied filters.
        """
        features = row.get("features", {})
        if profileid and features.get("profileid") != profileid:
            return False
        if interface and features.get("interface") != interface:
            return False
        if twid and features.get("twid") != twid:
            return False
        if uids:
            row_uid = features.get("uid")
            if row_uid in (None, ""):
                row_uid = []
            elif isinstance(row_uid, (list, tuple, set)):
                row_uid = list(row_uid)
            else:
                row_uid = [row_uid]
            row_uids = features.get("uids", [])
            if row_uids in (None, ""):
                row_uids = []
            elif isinstance(row_uids, str):
                row_uids = [row_uids]
            elif not isinstance(row_uids, (list, tuple, set)):
                row_uids = [row_uids]
            row_uids = set(str(uid) for uid in row_uid + list(row_uids))
            if not row_uids.intersection(uids):
                return False
        return True
