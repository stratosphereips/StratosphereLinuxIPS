# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Build sparse heterogeneous alert-window graphs from Slips records."""

import ipaddress
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


SCHEMA_VERSION = "1.0"

NODE_TYPES = [
    "profile",
    "ip",
    "network",
    "port",
    "domain",
    "url",
    "user_agent",
    "mac",
    "software",
    "file",
    "flow",
    "evidence",
    "alert",
]

EDGE_TYPES = [
    "profile_has_ip",
    "ip_belongs_to_network",
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
    "ssh_session",
    "downloaded_file",
    "arp_maps",
    "dhcp_requested",
    "software_seen",
    "evidence_refs_flow",
    "evidence_about_entity",
    "alert_contains_evidence",
]

COMMON_FLOW_FEATURES = [
    "uid",
    "uids",
    "type_",
    "flow_source",
    "starttime",
    "endtime",
    "dur",
    "saddr",
    "daddr",
    "sport",
    "dport",
    "proto",
    "appproto",
    "state",
    "history",
    "interpreted_state",
    "pkts",
    "spkts",
    "dpkts",
    "bytes",
    "sbytes",
    "dbytes",
    "smac",
    "dmac",
    "interface",
    "profileid",
    "twid",
    "label",
    "channel",
]

FLOW_TYPE_FEATURES = {
    "dns": [
        "query",
        "qclass_name",
        "qtype_name",
        "rcode_name",
        "answers",
        "TTLs",
    ],
    "http": [
        "method",
        "host",
        "uri",
        "version",
        "user_agent",
        "request_body_len",
        "response_body_len",
        "status_code",
        "status_msg",
        "resp_mime_types",
        "resp_fuids",
    ],
    "ssl": [
        "version",
        "sslversion",
        "cipher",
        "resumed",
        "established",
        "subject",
        "issuer",
        "validation_status",
        "curve",
        "server_name",
        "ja3",
        "ja3s",
        "is_DoH",
    ],
    "ssh": [
        "version",
        "auth_success",
        "auth_attempts",
        "client",
        "server",
        "cipher_alg",
        "mac_alg",
        "compression_alg",
        "kex_alg",
        "host_key_alg",
        "host_key",
    ],
    "dhcp": [
        "client_addr",
        "server_addr",
        "host_name",
        "requested_addr",
        "smac",
    ],
    "files": [
        "size",
        "md5",
        "source",
        "analyzers",
        "sha1",
        "tx_hosts",
        "rx_hosts",
    ],
    "arp": [
        "src_hw",
        "dst_hw",
        "operation",
        "smac",
        "dmac",
    ],
    "software": [
        "software",
        "software_name",
        "unparsed_version",
        "version_major",
        "version_minor",
        "http_browser",
    ],
    "notice": [
        "note",
        "msg",
        "scanned_port",
        "scanning_ip",
        "dst",
    ],
    "smtp": ["last_reply"],
    "tunnel": ["tunnel_type", "action"],
    "weird": ["name", "addl"],
}

FEATURE_ALLOWLISTS = {
    "flow_common": COMMON_FLOW_FEATURES,
    "flow_by_type": FLOW_TYPE_FEATURES,
    "evidence": [
        "id",
        "evidence_type",
        "description",
        "threat_level",
        "confidence",
        "timestamp",
        "profileid",
        "twid",
        "uid",
        "interface",
        "attacker",
        "victim",
        "proto",
        "dst_port",
        "src_port",
        "method",
        "rel_id",
    ],
    "alert": [
        "id",
        "profile",
        "timewindow",
        "last_evidence",
        "accumulated_threat_level",
        "correl_id",
        "last_flow_datetime",
        "threat_level",
        "confidence",
    ],
}


class GraphBuilder:
    """Builds one sparse graph for an alert-bounded Slips event window."""

    def __init__(self, local_networks: Optional[Iterable[str]] = None):
        """
        Create a builder with the local networks known for this run.

        Parameters:
            local_networks: Iterable of CIDR strings or ipaddress networks.

        Returns:
            None.
        """
        self.local_networks = self._parse_networks(local_networks or [])
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self.edge_keys: Set[Tuple[Any, ...]] = set()

    @staticmethod
    def schema() -> Dict[str, Any]:
        """
        Return the graph schema written next to generated graph tables.

        Returns:
            Dictionary containing schema version, node types, edge types, and
            feature allowlists.
        """
        return {
            "schema_version": SCHEMA_VERSION,
            "node_types": NODE_TYPES,
            "edge_types": EDGE_TYPES,
            "feature_allowlists": FEATURE_ALLOWLISTS,
        }

    @staticmethod
    def _parse_networks(networks: Iterable[str]) -> List[Any]:
        """
        Convert configured local network values into ipaddress networks.

        Parameters:
            networks: Iterable of network-like values.

        Returns:
            List of parsed IPv4 or IPv6 networks.
        """
        parsed = []
        for network in networks:
            try:
                parsed.append(ipaddress.ip_network(str(network), strict=False))
            except ValueError:
                continue
        return parsed

    @staticmethod
    def _values_as_list(value: Any) -> List[Any]:
        """
        Normalize scalar or iterable metadata values into a list.

        Parameters:
            value: Metadata value that may be scalar, list-like, or empty.

        Returns:
            List of values with empty values removed.
        """
        if value in (None, "", [], {}):
            return []
        if isinstance(value, (list, tuple, set)):
            return [item for item in value if item not in (None, "")]
        return [value]

    @staticmethod
    def _has_value(value: Any) -> bool:
        """
        Check whether a feature value should be stored.

        Parameters:
            value: Candidate value.

        Returns:
            True when the value carries information worth storing.
        """
        return value is not None and value not in ("", [], {})

    @staticmethod
    def _profile_ip(profileid: Optional[str]) -> Optional[str]:
        """
        Extract an IP address from a Slips profile ID.

        Parameters:
            profileid: Profile identifier such as profile_192.0.2.10.

        Returns:
            IP string if one can be extracted, otherwise None.
        """
        if not profileid or not str(profileid).startswith("profile_"):
            return None
        return str(profileid).split("profile_", 1)[1]

    @staticmethod
    def _safe_id_part(value: Any) -> str:
        """
        Convert a value into a stable graph node identifier component.

        Parameters:
            value: Raw identifier value.

        Returns:
            String representation suitable for use inside node IDs.
        """
        return str(value).strip()

    def _add_node(
        self,
        graph_id: str,
        node_type: str,
        key: Any,
        features: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Add or merge a graph node.

        Parameters:
            graph_id: Identifier of the graph being built.
            node_type: Semantic node type.
            key: Stable entity key inside the node type.
            features: Optional node features.

        Returns:
            Node ID.
        """
        node_id = f"{node_type}:{self._safe_id_part(key)}"
        clean_features = self._clean_features(features or {})
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "graph_id": graph_id,
                "node_id": node_id,
                "node_type": node_type,
                "features": clean_features,
            }
            return node_id

        existing = self.nodes[node_id]["features"]
        for name, value in clean_features.items():
            if name not in existing or not self._has_value(existing[name]):
                existing[name] = value
        return node_id

    def _add_edge(
        self,
        graph_id: str,
        source: str,
        target: str,
        edge_type: str,
        features: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Add one sparse graph edge if the exact relation is not already stored.

        Parameters:
            graph_id: Identifier of the graph being built.
            source: Source node ID.
            target: Target node ID.
            edge_type: Semantic relation type.
            features: Optional edge features.

        Returns:
            None.
        """
        clean_features = self._clean_features(features or {})
        edge_key = (
            source,
            target,
            edge_type,
            clean_features.get("uid"),
            clean_features.get("evidence_id"),
            clean_features.get("alert_id"),
            clean_features.get("channel"),
        )
        if edge_key in self.edge_keys:
            return

        self.edge_keys.add(edge_key)
        self.edges.append(
            {
                "graph_id": graph_id,
                "edge_id": f"edge:{len(self.edges)}",
                "source": source,
                "target": target,
                "edge_type": edge_type,
                "features": clean_features,
            }
        )

    def _clean_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove empty feature values while preserving false and zero values.

        Parameters:
            features: Raw feature dictionary.

        Returns:
            Feature dictionary suitable for JSON serialization.
        """
        return {
            key: value
            for key, value in features.items()
            if self._has_value(value)
        }

    def _network_for_ip(self, ip_value: str) -> Tuple[str, Dict[str, Any]]:
        """
        Resolve an IP address to a local network or the internet node.

        Parameters:
            ip_value: IPv4 or IPv6 address string.

        Returns:
            Tuple of network node key and network features.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_value)
        except ValueError:
            return "internet", {"name": "internet", "scope": "internet"}

        for network in self.local_networks:
            if ip_obj in network:
                cidr = str(network)
                return cidr, {"cidr": cidr, "scope": "local"}

        return "internet", {"name": "internet", "scope": "internet"}

    def _add_ip_with_network(
        self,
        graph_id: str,
        ip_value: Optional[str],
        features: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Add an IP node and its network membership edge.

        Parameters:
            graph_id: Identifier of the graph being built.
            ip_value: IP address value.
            features: Optional IP node features.

        Returns:
            IP node ID, or None when no IP was provided.
        """
        if not ip_value:
            return None

        ip_node = self._add_node(
            graph_id,
            "ip",
            ip_value,
            {"ip": ip_value, **(features or {})},
        )
        network_key, network_features = self._network_for_ip(ip_value)
        network_node = self._add_node(
            graph_id,
            "network",
            network_key,
            network_features,
        )
        self._add_edge(
            graph_id,
            ip_node,
            network_node,
            "ip_belongs_to_network",
            {"ip": ip_value},
        )
        return ip_node

    def _add_profile(
        self, graph_id: str, profileid: Optional[str]
    ) -> Optional[str]:
        """
        Add a Slips profile node and its profile IP edge.

        Parameters:
            graph_id: Identifier of the graph being built.
            profileid: Slips profile ID.

        Returns:
            Profile node ID, or None when no profile was provided.
        """
        if not profileid:
            return None

        profile_node = self._add_node(
            graph_id, "profile", profileid, {"profileid": profileid}
        )
        profile_ip = self._profile_ip(profileid)
        ip_node = self._add_ip_with_network(
            graph_id, profile_ip, {"profileid": profileid}
        )
        if ip_node:
            self._add_edge(
                graph_id,
                profile_node,
                ip_node,
                "profile_has_ip",
                {"profileid": profileid},
            )
        return profile_node

    @staticmethod
    def _flow_uid(flow: Dict[str, Any], fallback: str) -> str:
        """
        Return a stable UID for a flow-like record.

        Parameters:
            flow: Flow dictionary.
            fallback: Fallback identifier.

        Returns:
            UID string.
        """
        if flow.get("uid"):
            return str(flow["uid"])
        uids = GraphBuilder._values_as_list(flow.get("uids"))
        if uids:
            return str(uids[0])
        return fallback

    @staticmethod
    def _port_node_key(port: Any, proto: Any) -> Optional[str]:
        """
        Build a stable port node key from port and protocol values.

        Parameters:
            port: Port value.
            proto: Transport protocol value.

        Returns:
            Port node key, or None when no port is available.
        """
        if port in (None, ""):
            return None
        proto_value = str(proto or "").lower() or "unknown"
        return f"{port}/{proto_value}"

    @staticmethod
    def _is_established(flow: Dict[str, Any]) -> bool:
        """
        Check whether a flow appears to have reached an established state.

        Parameters:
            flow: Flow dictionary.

        Returns:
            True when Slips or Zeek state indicates an established flow.
        """
        values = [
            str(flow.get("interpreted_state", "")),
            str(flow.get("state", "")),
        ]
        return any("estab" in value.lower() or value == "SF" for value in values)

    def _flow_features(
        self, record: Dict[str, Any], flow: Dict[str, Any], uid: str
    ) -> Dict[str, Any]:
        """
        Extract the module-relevant feature subset for a flow.

        Parameters:
            record: Buffered channel record.
            flow: Flow dictionary from the record.
            uid: Stable flow UID.

        Returns:
            Feature dictionary.
        """
        flow_type = flow.get("type_", "")
        allowed = list(COMMON_FLOW_FEATURES)
        allowed += FLOW_TYPE_FEATURES.get(flow_type, [])
        features = {key: flow.get(key) for key in allowed if key in flow}
        features.update(
            {
                "uid": uid,
                "profileid": record.get("profileid"),
                "twid": record.get("twid"),
                "channel": record.get("channel"),
                "label": record.get("label"),
                "module_labels": record.get("module_labels"),
                "interpreted_state": record.get("interpreted_state"),
            }
        )
        return self._clean_features(features)

    def _add_flow_record(
        self, graph_id: str, record: Dict[str, Any], fallback_index: int
    ) -> None:
        """
        Add nodes and edges derived from a buffered flow or protocol event.

        Parameters:
            graph_id: Identifier of the graph being built.
            record: Buffered flow record.
            fallback_index: Index used when the flow has no UID.

        Returns:
            None.
        """
        flow = record.get("flow") or {}
        if not isinstance(flow, dict):
            return

        uid = self._flow_uid(flow, f"{record.get('channel')}:{fallback_index}")
        flow_node = self._add_node(
            graph_id,
            "flow",
            uid,
            self._flow_features(record, flow, uid),
        )
        profileid = record.get("profileid")
        self._add_profile(graph_id, profileid)

        base_edge_features = {
            "uid": uid,
            "profileid": profileid,
            "twid": record.get("twid"),
            "interface": flow.get("interface"),
            "channel": record.get("channel"),
        }
        src_ip = self._add_ip_with_network(
            graph_id,
            flow.get("saddr"),
            {"profileid": profileid, "interface": flow.get("interface")},
        )
        dst_ip = self._add_ip_with_network(
            graph_id,
            flow.get("daddr"),
            {"interface": flow.get("interface")},
        )
        if src_ip:
            self._add_edge(
                graph_id, flow_node, src_ip, "flow_from_ip", base_edge_features
            )
        if dst_ip:
            self._add_edge(
                graph_id, flow_node, dst_ip, "flow_to_ip", base_edge_features
            )

        self._add_port_edges(
            graph_id, flow, flow_node, src_ip, dst_ip, base_edge_features
        )
        self._add_protocol_edges(
            graph_id, flow, flow_node, src_ip, dst_ip, base_edge_features
        )

    def _add_port_edges(
        self,
        graph_id: str,
        flow: Dict[str, Any],
        flow_node: str,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        base_features: Dict[str, Any],
    ) -> None:
        """
        Add flow-to-port, attempted-port, and open-port relations.

        Parameters:
            graph_id: Identifier of the graph being built.
            flow: Flow dictionary.
            flow_node: Flow node ID.
            src_ip: Source IP node ID.
            dst_ip: Destination IP node ID.
            base_features: Shared edge features.

        Returns:
            None.
        """
        port_key = self._port_node_key(flow.get("dport"), flow.get("proto"))
        if not port_key:
            return

        port_node = self._add_node(
            graph_id,
            "port",
            port_key,
            {"port": flow.get("dport"), "proto": flow.get("proto")},
        )
        self._add_edge(
            graph_id, flow_node, port_node, "flow_to_port", base_features
        )
        if src_ip:
            self._add_edge(
                graph_id, src_ip, port_node, "attempted_port", base_features
            )
        if dst_ip and self._is_established(flow):
            self._add_edge(
                graph_id, dst_ip, port_node, "has_open_port", base_features
            )

    def _add_protocol_edges(
        self,
        graph_id: str,
        flow: Dict[str, Any],
        flow_node: str,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        base_features: Dict[str, Any],
    ) -> None:
        """
        Add protocol-specific semantic relations.

        Parameters:
            graph_id: Identifier of the graph being built.
            flow: Flow dictionary.
            flow_node: Flow node ID.
            src_ip: Source IP node ID.
            dst_ip: Destination IP node ID.
            base_features: Shared edge features.

        Returns:
            None.
        """
        flow_type = flow.get("type_")
        if flow_type == "dns":
            self._add_dns_edges(graph_id, flow, flow_node, src_ip, base_features)
        elif flow_type == "http":
            self._add_http_edges(
                graph_id, flow, flow_node, src_ip, base_features
            )
        elif flow_type == "ssl":
            self._add_ssl_edges(graph_id, flow, flow_node, base_features)
        elif flow_type == "ssh" and src_ip and dst_ip:
            self._add_edge(
                graph_id, src_ip, dst_ip, "ssh_session", base_features
            )
        elif flow_type == "files":
            self._add_file_edges(graph_id, flow, flow_node, base_features)
        elif flow_type == "arp":
            self._add_arp_edges(graph_id, flow, base_features)
        elif flow_type == "dhcp":
            self._add_dhcp_edges(graph_id, flow, src_ip, base_features)
        elif flow_type == "software":
            self._add_software_edges(graph_id, flow, src_ip, base_features)

    def _add_dns_edges(
        self,
        graph_id: str,
        flow: Dict[str, Any],
        flow_node: str,
        src_ip: Optional[str],
        base_features: Dict[str, Any],
    ) -> None:
        """
        Add DNS query and answer relations.

        Parameters:
            graph_id: Identifier of the graph being built.
            flow: DNS flow dictionary.
            flow_node: Flow node ID.
            src_ip: Source IP node ID.
            base_features: Shared edge features.

        Returns:
            None.
        """
        query = flow.get("query")
        if not query:
            return

        domain_node = self._add_node(
            graph_id, "domain", query, {"domain": query}
        )
        source = src_ip or flow_node
        self._add_edge(
            graph_id,
            source,
            domain_node,
            "dns_queried",
            {**base_features, "query": query},
        )
        for answer in self._extract_answer_ips(flow.get("answers", [])):
            answer_node = self._add_ip_with_network(graph_id, answer)
            if answer_node:
                self._add_edge(
                    graph_id,
                    domain_node,
                    answer_node,
                    "dns_resolved_to",
                    {**base_features, "query": query},
                )

    @staticmethod
    def _extract_answer_ips(answers: Any) -> List[str]:
        """
        Extract IP answers from Zeek or Suricata DNS answer formats.

        Parameters:
            answers: DNS answers field.

        Returns:
            List of IP address strings.
        """
        if isinstance(answers, (str, dict)):
            answers = [answers]

        extracted = []
        for answer in answers or []:
            if isinstance(answer, dict):
                candidates = [
                    answer.get("rdata"),
                    answer.get("rrdata"),
                    answer.get("answer"),
                ]
            else:
                candidates = [answer]
            for candidate in candidates:
                if not candidate:
                    continue
                try:
                    ipaddress.ip_address(str(candidate))
                except ValueError:
                    continue
                extracted.append(str(candidate))
        return extracted

    def _add_http_edges(
        self,
        graph_id: str,
        flow: Dict[str, Any],
        flow_node: str,
        src_ip: Optional[str],
        base_features: Dict[str, Any],
    ) -> None:
        """
        Add HTTP request and user-agent relations.

        Parameters:
            graph_id: Identifier of the graph being built.
            flow: HTTP flow dictionary.
            flow_node: Flow node ID.
            src_ip: Source IP node ID.
            base_features: Shared edge features.

        Returns:
            None.
        """
        host = flow.get("host")
        uri = flow.get("uri") or ""
        if host:
            domain_node = self._add_node(
                graph_id, "domain", host, {"domain": host}
            )
            url = f"http://{host}{uri}"
            url_node = self._add_node(graph_id, "url", url, {"url": url})
            self._add_edge(
                graph_id,
                flow_node,
                url_node,
                "http_requested",
                {**base_features, "method": flow.get("method"), "host": host},
            )
            self._add_edge(
                graph_id,
                url_node,
                domain_node,
                "http_requested",
                {**base_features, "host": host},
            )

        user_agent = flow.get("user_agent")
        if user_agent and src_ip:
            ua_node = self._add_node(
                graph_id,
                "user_agent",
                user_agent,
                {"user_agent": user_agent},
            )
            self._add_edge(
                graph_id,
                src_ip,
                ua_node,
                "used_user_agent",
                base_features,
            )

    def _add_ssl_edges(
        self,
        graph_id: str,
        flow: Dict[str, Any],
        flow_node: str,
        base_features: Dict[str, Any],
    ) -> None:
        """
        Add TLS server name relation.

        Parameters:
            graph_id: Identifier of the graph being built.
            flow: SSL/TLS flow dictionary.
            flow_node: Flow node ID.
            base_features: Shared edge features.

        Returns:
            None.
        """
        server_name = flow.get("server_name")
        if not server_name:
            return

        domain_node = self._add_node(
            graph_id, "domain", server_name, {"domain": server_name}
        )
        self._add_edge(
            graph_id,
            flow_node,
            domain_node,
            "tls_server_name",
            {**base_features, "server_name": server_name},
        )

    def _add_file_edges(
        self,
        graph_id: str,
        flow: Dict[str, Any],
        flow_node: str,
        base_features: Dict[str, Any],
    ) -> None:
        """
        Add downloaded file relation.

        Parameters:
            graph_id: Identifier of the graph being built.
            flow: Files flow dictionary.
            flow_node: Flow node ID.
            base_features: Shared edge features.

        Returns:
            None.
        """
        file_key = flow.get("md5") or flow.get("sha1") or flow.get("uid")
        if not file_key:
            return

        file_node = self._add_node(
            graph_id,
            "file",
            file_key,
            {
                "md5": flow.get("md5"),
                "sha1": flow.get("sha1"),
                "size": flow.get("size"),
                "source": flow.get("source"),
            },
        )
        self._add_edge(
            graph_id, flow_node, file_node, "downloaded_file", base_features
        )

    def _add_arp_edges(
        self,
        graph_id: str,
        flow: Dict[str, Any],
        base_features: Dict[str, Any],
    ) -> None:
        """
        Add ARP MAC-to-IP mapping relations.

        Parameters:
            graph_id: Identifier of the graph being built.
            flow: ARP flow dictionary.
            base_features: Shared edge features.

        Returns:
            None.
        """
        for mac_field, ip_field in (("smac", "saddr"), ("dmac", "daddr")):
            mac = flow.get(mac_field)
            ip_value = flow.get(ip_field)
            if not mac or not ip_value:
                continue
            mac_node = self._add_node(graph_id, "mac", mac, {"mac": mac})
            ip_node = self._add_ip_with_network(graph_id, ip_value)
            if ip_node:
                self._add_edge(
                    graph_id,
                    mac_node,
                    ip_node,
                    "arp_maps",
                    {**base_features, "operation": flow.get("operation")},
                )

    def _add_dhcp_edges(
        self,
        graph_id: str,
        flow: Dict[str, Any],
        src_ip: Optional[str],
        base_features: Dict[str, Any],
    ) -> None:
        """
        Add DHCP requested-address relation.

        Parameters:
            graph_id: Identifier of the graph being built.
            flow: DHCP flow dictionary.
            src_ip: Source IP node ID.
            base_features: Shared edge features.

        Returns:
            None.
        """
        requested = flow.get("requested_addr")
        requested_node = self._add_ip_with_network(graph_id, requested)
        if src_ip and requested_node:
            self._add_edge(
                graph_id,
                src_ip,
                requested_node,
                "dhcp_requested",
                base_features,
            )

    def _add_software_edges(
        self,
        graph_id: str,
        flow: Dict[str, Any],
        src_ip: Optional[str],
        base_features: Dict[str, Any],
    ) -> None:
        """
        Add software observation relation.

        Parameters:
            graph_id: Identifier of the graph being built.
            flow: Software flow dictionary.
            src_ip: Source IP node ID.
            base_features: Shared edge features.

        Returns:
            None.
        """
        software = flow.get("software") or flow.get("software_name")
        if not software or not src_ip:
            return

        software_node = self._add_node(
            graph_id,
            "software",
            software,
            {
                "software": software,
                "version_major": flow.get("version_major"),
                "version_minor": flow.get("version_minor"),
                "unparsed_version": flow.get("unparsed_version"),
            },
        )
        self._add_edge(
            graph_id, src_ip, software_node, "software_seen", base_features
        )

    def _add_evidence(
        self, graph_id: str, evidence: Dict[str, Any]
    ) -> Optional[str]:
        """
        Add an evidence node and its referenced-flow/entity relations.

        Parameters:
            graph_id: Identifier of the graph being built.
            evidence: Evidence dictionary.

        Returns:
            Evidence node ID, or None when no evidence ID exists.
        """
        evidence_id = evidence.get("id")
        if not evidence_id:
            return None

        profileid = self._evidence_profileid(evidence)
        twid = self._evidence_twid(evidence)
        features = {
            key: evidence.get(key)
            for key in FEATURE_ALLOWLISTS["evidence"]
            if key in evidence
        }
        features.update({"profileid": profileid, "twid": twid})
        evidence_node = self._add_node(
            graph_id, "evidence", evidence_id, features
        )

        for uid in self._values_as_list(evidence.get("uid")):
            flow_node = self._add_node(
                graph_id,
                "flow",
                uid,
                {
                    "uid": uid,
                    "profileid": profileid,
                    "twid": twid,
                    "source": "evidence_reference",
                },
            )
            self._add_edge(
                graph_id,
                evidence_node,
                flow_node,
                "evidence_refs_flow",
                {
                    "evidence_id": evidence_id,
                    "uid": uid,
                    "profileid": profileid,
                    "twid": twid,
                },
            )

        for entity in (evidence.get("attacker"), evidence.get("victim")):
            entity_node = self._entity_node(graph_id, entity)
            if entity_node:
                self._add_edge(
                    graph_id,
                    evidence_node,
                    entity_node,
                    "evidence_about_entity",
                    {
                        "evidence_id": evidence_id,
                        "profileid": profileid,
                        "twid": twid,
                    },
                )

        return evidence_node

    @staticmethod
    def _evidence_profileid(evidence: Dict[str, Any]) -> Optional[str]:
        """
        Read the profile ID from an evidence dictionary.

        Parameters:
            evidence: Evidence dictionary.

        Returns:
            Profile ID string, or None.
        """
        profile = evidence.get("profile") or {}
        if isinstance(profile, dict) and profile.get("ip"):
            return f"profile_{profile['ip']}"
        return None

    @staticmethod
    def _evidence_twid(evidence: Dict[str, Any]) -> Optional[str]:
        """
        Read the timewindow ID from an evidence dictionary.

        Parameters:
            evidence: Evidence dictionary.

        Returns:
            Timewindow ID string, or None.
        """
        timewindow = evidence.get("timewindow") or {}
        if isinstance(timewindow, dict) and "number" in timewindow:
            return f"timewindow{timewindow['number']}"
        return None

    def _entity_node(
        self, graph_id: str, entity: Optional[Dict[str, Any]]
    ) -> Optional[str]:
        """
        Add a node for an evidence attacker or victim entity.

        Parameters:
            graph_id: Identifier of the graph being built.
            entity: Attacker or victim dictionary.

        Returns:
            Entity node ID, or None.
        """
        if not isinstance(entity, dict):
            return None

        value = entity.get("value")
        if not value:
            return None

        ioc_type = str(entity.get("ioc_type", "")).upper()
        if ioc_type == "IP":
            return self._add_ip_with_network(graph_id, value, entity)
        if ioc_type == "DOMAIN":
            return self._add_node(graph_id, "domain", value, entity)
        if ioc_type == "URL":
            return self._add_node(graph_id, "url", value, entity)
        return self._add_node(graph_id, "domain", value, entity)

    def _add_alert(
        self, graph_id: str, alert: Dict[str, Any]
    ) -> Optional[str]:
        """
        Add an alert node and alert-to-evidence relations.

        Parameters:
            graph_id: Identifier of the graph being built.
            alert: Alert dictionary.

        Returns:
            Alert node ID, or None when no alert ID exists.
        """
        alert_id = alert.get("id")
        if not alert_id:
            return None

        features = {
            key: alert.get(key)
            for key in FEATURE_ALLOWLISTS["alert"]
            if key in alert
        }
        alert_node = self._add_node(graph_id, "alert", alert_id, features)
        for evidence_id in self._values_as_list(alert.get("correl_id")):
            evidence_node = self._add_node(
                graph_id,
                "evidence",
                evidence_id,
                {"id": evidence_id, "source": "alert_correl_id"},
            )
            self._add_edge(
                graph_id,
                alert_node,
                evidence_node,
                "alert_contains_evidence",
                {"alert_id": alert_id, "evidence_id": evidence_id},
            )
        return alert_node

    @staticmethod
    def _alert_id(alert: Dict[str, Any], index: int) -> str:
        """
        Return a stable alert ID for graph naming.

        Parameters:
            alert: Alert dictionary.
            index: Window index.

        Returns:
            Alert ID string.
        """
        return str(alert.get("id") or f"alert-{index}")

    @staticmethod
    def _record_timestamp(record: Dict[str, Any]) -> Any:
        """
        Extract a timestamp from a buffered record.

        Parameters:
            record: Buffered record.

        Returns:
            Timestamp value, or None.
        """
        flow = record.get("flow") or {}
        return flow.get("starttime") or record.get("stime")

    def build_window_graph(
        self,
        window_index: int,
        alert: Dict[str, Any],
        flow_records: List[Dict[str, Any]],
        protocol_records: List[Dict[str, Any]],
        evidence_records: List[Dict[str, Any]],
        previous_graph_id: Optional[str] = None,
        previous_alert_id: Optional[str] = None,
        orphan_actions: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Build one sparse graph for the current alert-bounded window.

        Parameters:
            window_index: Sequential graph/window index.
            alert: Alert dictionary that closes the window.
            flow_records: Buffered `new_flow` records.
            protocol_records: Buffered protocol event records.
            evidence_records: Buffered evidence records.
            previous_graph_id: Previous graph ID, if available.
            previous_alert_id: Previous alert ID, if available.
            orphan_actions: Actions before the first graph, if any.

        Returns:
            Graph dictionary containing metadata, nodes, and edges.
        """
        alert_id = self._alert_id(alert, window_index)
        graph_id = f"graph:{window_index}:{alert_id}"

        all_flow_records = flow_records + protocol_records
        for index, record in enumerate(all_flow_records):
            self._add_flow_record(graph_id, record, index)

        for evidence in evidence_records:
            self._add_evidence(graph_id, evidence)

        self._add_alert(graph_id, alert)

        first_timestamp = self._first_timestamp(all_flow_records, evidence_records)
        metadata = {
            "schema_version": SCHEMA_VERSION,
            "graph_id": graph_id,
            "window_index": window_index,
            "alert_id": alert_id,
            "previous_graph_id": previous_graph_id,
            "previous_alert_id": previous_alert_id,
            "window_start_after_alert_id": previous_alert_id,
            "window_closed_by_alert_id": alert_id,
            "window_start_time": first_timestamp,
            "window_end_time": alert.get("last_flow_datetime"),
            "flow_count": len(flow_records),
            "protocol_event_count": len(protocol_records),
            "evidence_count": len(evidence_records),
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "orphan_actions": orphan_actions or [],
            "orphan_action_count": len(orphan_actions or []),
            "alert": alert,
        }
        return {
            "graph_id": graph_id,
            "window_index": window_index,
            "alert_id": alert_id,
            "metadata": metadata,
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
        }

    @staticmethod
    def _first_timestamp(
        flow_records: List[Dict[str, Any]],
        evidence_records: List[Dict[str, Any]],
    ) -> Any:
        """
        Return the first available timestamp from buffered records.

        Parameters:
            flow_records: Buffered flow records.
            evidence_records: Buffered evidence records.

        Returns:
            First timestamp value found, or None.
        """
        for record in flow_records:
            timestamp = GraphBuilder._record_timestamp(record)
            if timestamp:
                return timestamp
        for evidence in evidence_records:
            timestamp = evidence.get("timestamp")
            if timestamp:
                return timestamp
        return None

    @staticmethod
    def build_transition(
        from_graph_id: str,
        to_graph_id: str,
        actions: List[Dict[str, Any]],
        reward: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Build a transition row linking consecutive alert-window graphs.

        Parameters:
            from_graph_id: Previous graph ID.
            to_graph_id: Next graph ID.
            actions: Actions observed between the two graph-closing alerts.
            reward: Optional externally supplied reward value.

        Returns:
            Transition metadata dictionary.
        """
        return {
            "from_graph_id": from_graph_id,
            "to_graph_id": to_graph_id,
            "actions": actions,
            "action_count": len(actions),
            "reward": reward,
        }
