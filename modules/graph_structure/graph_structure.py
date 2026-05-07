# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Slips module that writes alert-bounded sparse graph structures."""

import os
from typing import Any, Dict, Iterable, List, Optional

from slips_files.common.abstracts.imodule import IModule
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils

from .graph_builder import GraphBuilder
from .graph_storage import GraphStorage


FLOW_CHANNELS = (
    "new_flow",
    "new_dns",
    "new_http",
    "new_ssl",
    "new_ssh",
    "new_arp",
    "new_dhcp",
    "new_smtp",
    "new_notice",
    "new_downloaded_file",
    "new_software",
    "new_tunnel",
    "new_weird",
)

EVIDENCE_CHANNELS = ("evidence_added",)
ACTION_CHANNELS = ("new_blocking",)
ALERT_CHANNELS = ("new_alert",)
ALL_CHANNELS = FLOW_CHANNELS + EVIDENCE_CHANNELS + ACTION_CHANNELS + ALERT_CHANNELS


class GraphStructure(IModule):
    """Create sparse heterogeneous graph tables for each alert window."""

    name = "graph_structure"
    description = "Builds sparse heterogeneous graphs for alert-bounded windows."
    authors = ["Sebastian Garcia", "Alya Gomaa"]

    def init(self):
        """
        Initialize graph buffers and read graph module configuration.

        Returns:
            None.
        """
        self.enabled = self.read_configuration()
        self.storage = GraphStorage(
            os.path.join(self.parent_output_dir, "graph-structure")
        )
        self.flow_records: List[Dict[str, Any]] = []
        self.protocol_records: List[Dict[str, Any]] = []
        self.evidence_records: List[Dict[str, Any]] = []
        self.transition_actions: List[Dict[str, Any]] = []
        self.previous_graph_id: Optional[str] = None
        self.previous_alert_id: Optional[str] = None
        self.window_index = 0
        self.written_graph_count = 0
        self._batch_size = 50

    def read_configuration(self) -> bool:
        """
        Read whether graph generation is enabled.

        Returns:
            True when graph_structure.enabled is configured as true.
        """
        conf = ConfigParser()
        return conf.graph_structure_enabled()

    def subscribe_to_channels(self):
        """
        Subscribe to channels used to build and close graph windows.

        Returns:
            None.
        """
        self.channels = {}
        if not self.enabled:
            return

        for channel in ALL_CHANNELS:
            self.channels[channel] = self.db.subscribe(channel)

    def pre_main(self):
        """
        Prepare output storage before the main loop starts.

        Returns:
            1 when the module is disabled and should stop, otherwise None.
        """
        if not self.enabled:
            self.print("graph_structure is disabled in slips.yaml.", 2, 0)
            return 1

        self.storage.prepare(GraphBuilder.schema())
        utils.drop_root_privs_permanently()

    def main(self):
        """
        Drain buffered channels and write a graph when an alert arrives.

        Returns:
            1 when disabled, otherwise None.
        """
        if not self.enabled:
            return 1

        self._drain_data_channels()
        self._drain_alert_channels()

    def _drain_data_channels(self) -> None:
        """
        Drain flow, evidence, and action channels before processing alerts.

        Returns:
            None.
        """
        for channel in FLOW_CHANNELS + EVIDENCE_CHANNELS + ACTION_CHANNELS:
            for _ in range(self._batch_size):
                msg = self.get_msg(channel)
                if not msg:
                    break
                self._handle_data_message(channel, msg)

    def _drain_alert_channels(self) -> None:
        """
        Drain alert channels after data channels.

        Returns:
            None.
        """
        for channel in ALERT_CHANNELS:
            for _ in range(self._batch_size):
                msg = self.get_msg(channel)
                if not msg:
                    break
                self._handle_alert_message(msg)

    def _handle_data_message(self, channel: str, msg: dict) -> None:
        """
        Store one non-alert message in the current window buffer.

        Parameters:
            channel: Redis channel name.
            msg: Redis pub/sub message.

        Returns:
            None.
        """
        payload = self._payload_without_version(msg)
        if not isinstance(payload, dict):
            return

        if channel == "evidence_added":
            self.evidence_records.append(payload)
        elif channel == "new_blocking":
            self.transition_actions.append(payload)
        elif channel == "new_flow":
            self.flow_records.append(self._flow_record(channel, payload))
        else:
            self.protocol_records.append(self._flow_record(channel, payload))

    def _handle_alert_message(self, msg: dict) -> None:
        """
        Close the current alert-bounded window and write its graph.

        Parameters:
            msg: Redis pub/sub message containing an Alert dictionary.

        Returns:
            None.
        """
        alert = self._payload_without_version(msg)
        if not isinstance(alert, dict):
            return

        evidence_records = self._filtered_evidence_records()
        local_networks = self._local_networks()
        builder = GraphBuilder(local_networks)
        graph = builder.build_window_graph(
            window_index=self.window_index,
            alert=alert,
            flow_records=self.flow_records,
            protocol_records=self.protocol_records,
            evidence_records=evidence_records,
            previous_graph_id=self.previous_graph_id,
            previous_alert_id=self.previous_alert_id,
            orphan_actions=(
                self.transition_actions
                if self.previous_graph_id is None
                else []
            ),
        )
        self.storage.write_graph(graph)

        if self.previous_graph_id:
            transition = GraphBuilder.build_transition(
                self.previous_graph_id,
                graph["graph_id"],
                self.transition_actions,
            )
            self.storage.append_transition(transition)

        self.previous_graph_id = graph["graph_id"]
        self.previous_alert_id = graph["alert_id"]
        self.written_graph_count += 1
        self.window_index += 1
        self._reset_window_buffers()

    @staticmethod
    def _payload_without_version(msg: dict) -> Any:
        """
        Decode a Redis message and remove Slips transport metadata.

        Parameters:
            msg: Redis pub/sub message.

        Returns:
            Decoded payload.
        """
        payload = utils.get_msg_payload(msg)
        if isinstance(payload, dict):
            payload = dict(payload)
            payload.pop("version", None)
        return payload

    @staticmethod
    def _flow_record(channel: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a channel payload into a graph flow record.

        Parameters:
            channel: Redis channel name.
            payload: Decoded channel payload.

        Returns:
            Buffered flow record.
        """
        return {
            "channel": channel,
            "profileid": payload.get("profileid"),
            "twid": payload.get("twid"),
            "flow": payload.get("flow") or {},
            "stime": payload.get("stime"),
            "interpreted_state": payload.get("interpreted_state"),
            "label": payload.get("label"),
            "module_labels": payload.get("module_labels"),
            "source_type": payload.get("type"),
        }

    def _filtered_evidence_records(self) -> List[Dict[str, Any]]:
        """
        Return evidence records that Slips has not marked as whitelisted.

        Returns:
            List of evidence records to include in the graph.
        """
        filtered = []
        for evidence in self.evidence_records:
            evidence_id = evidence.get("id")
            if evidence_id and self._is_whitelisted_evidence(evidence_id):
                continue
            filtered.append(evidence)
        return filtered

    def _is_whitelisted_evidence(self, evidence_id: str) -> bool:
        """
        Check whether evidence should be filtered from graph output.

        Parameters:
            evidence_id: Evidence UUID.

        Returns:
            True when the DB marks the evidence as whitelisted.
        """
        try:
            return bool(self.db.is_whitelisted_evidence(evidence_id))
        except Exception:
            return False

    def _local_networks(self) -> List[str]:
        """
        Collect known local networks from config and observed interfaces.

        Returns:
            List of CIDR network strings.
        """
        networks = set()
        networks.update(self._configured_client_networks())
        for interface in self._observed_interfaces():
            try:
                local_network = self.db.get_local_network(interface)
            except Exception:
                local_network = None
            if local_network:
                networks.add(str(local_network))
        return sorted(networks)

    def _configured_client_networks(self) -> List[str]:
        """
        Return client IP/network entries configured in slips.yaml.

        Returns:
            List of configured client network strings.
        """
        try:
            client_ips = self.conf.client_ips()
        except Exception:
            client_ips = []
        return [str(client_ip) for client_ip in client_ips or []]

    def _observed_interfaces(self) -> Iterable[str]:
        """
        Return interfaces observed in buffered flow records.

        Returns:
            Iterable of interface names.
        """
        interfaces = set()
        for record in self.flow_records + self.protocol_records:
            flow = record.get("flow") or {}
            interface = flow.get("interface")
            if interface:
                interfaces.add(interface)
        return interfaces

    def _reset_window_buffers(self) -> None:
        """
        Start a new open alert-bounded window after writing a graph.

        Returns:
            None.
        """
        self.flow_records = []
        self.protocol_records = []
        self.evidence_records = []
        self.transition_actions = []

    def shutdown_gracefully(self):
        """
        Write manifest metadata without emitting an incomplete final graph.

        Returns:
            None.
        """
        if not self.enabled:
            return

        manifest = {
            "schema_version": GraphBuilder.schema()["schema_version"],
            "written_graph_count": self.written_graph_count,
            "last_graph_id": self.previous_graph_id,
            "open_window_discarded": True,
            "open_window_flow_count": len(self.flow_records),
            "open_window_protocol_event_count": len(self.protocol_records),
            "open_window_evidence_count": len(self.evidence_records),
            "open_window_action_count": len(self.transition_actions),
        }
        self.storage.write_manifest(manifest)
