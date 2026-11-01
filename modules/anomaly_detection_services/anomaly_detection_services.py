"""Detect newly active services, unexpected clients, hours and flow lengths."""

import ipaddress
import json
import sqlite3
import time
from collections import OrderedDict
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from modules.supported_module_names import Modules
from slips_files.common.abstracts.imodule import IModule
from slips_files.common.input_type import InputType
from slips_files.common.mac import classify_mac, normalize_mac
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
    Attacker,
    Direction,
    Evidence,
    EvidenceType,
    IoCType,
    Method,
    ProfileID,
    Proto,
    ThreatLevel,
    TimeWindow,
    Victim,
)

from .baseline import ServiceDetector
from .models import Observation, Settings
from .store import BaselineStore
from .hosts import HostInventory


class AnomalyDetectionServices(IModule):
    """Learn independent service relationships from arriving connection logs."""

    name = Modules.ANOMALY_DETECTION_SERVICES.value
    description = "Finds new local services and learns clients, hours and connection lengths"
    authors = ["Sebastian Garcia"]

    def init(self) -> None:
        """Initialize bounded caches without opening a baseline database."""
        self.settings = Settings.from_config(self.conf)
        self.detector = ServiceDetector(self.settings)
        self.host_inventory = HostInventory(self.settings)
        self.store: BaselineStore | None = None
        self.live = self.db.get_input_type() == InputType.INTERFACE or bool(
            getattr(self.args, "growing", False)
        )
        self.interfaces = getattr(self.args, "interface", []) or []
        if isinstance(self.interfaces, str):
            self.interfaces = [self.interfaces]
        self.run_scope = f"run:{self.parent_output_dir}:{self.ppid}"
        self._networks: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self._identities: OrderedDict[tuple, tuple[float, str]] = OrderedDict()
        self._next_flush = 0.0
        self._next_warning = 0.0
        self._next_host_refresh = 0.0
        self._capture_started = time.time()

    def subscribe_to_channels(self) -> None:
        """Consume connection records through the existing flow channel."""
        self.channels = {"new_flow": self.db.subscribe("new_flow")}

    def pre_main(self) -> None:
        """Open live persistent state or an isolated offline-run checkpoint."""
        utils.drop_root_privs_permanently()
        root = (
            Path(self.conf.permanent_dir())
            if self.live
            else Path(self.parent_output_dir)
        )
        self.store = BaselineStore(
            root / self.name / "baseline.sqlite", self.settings
        )
        self.detector.restore(self.store.load())
        self.host_inventory.restore(self.store.load_hosts())
        self._refresh_local_hosts()
        self.print(
            f"Service anomaly mode={self.settings.mode}; "
            f"restored {len(self.detector.services)} services and "
            f"{self.detector.client_count} clients; timezone={self.settings.timezone}; "
            f"new services={self.settings.detect_new_services}; "
            f"host training={self.settings.training_hours:g} hours; "
            f"restored {len(self.host_inventory.hosts)} local hosts",
            1,
            0,
        )

    def _network(self, observation: Observation) -> tuple[str, dict, bool]:
        """Resolve packet-time network context using a bounded live cache.

        Parameters:
            observation: Flow whose interface and timestamp identify context.

        Returns:
            Network scope, recorded state, and whether current MAC lookup is safe.
        """
        return self._network_at(observation.interface, observation.timestamp)

    def _network_at(
        self, interface: str, timestamp: float
    ) -> tuple[str, dict, bool]:
        """Resolve cached network state for a flow or a quiet capture interface.

        Parameters:
            interface: Monitored interface.
            timestamp: Flow time or current capture time.

        Returns:
            Network scope, matching state and whether it is current.
        """
        if not self.live:
            return self.run_scope, {}, False
        if interface == "default" and len(self.interfaces) == 1:
            interface = self.interfaces[0]
        now = time.monotonic()
        cached = self._networks.get(interface)
        if cached is None or cached[0] <= now:
            state = self.db.get_network_state(interface) or {}
            if not isinstance(state, dict):
                state = {}
            self._networks[interface] = now + 5, state
            if len(self._networks) > 16:
                self._networks.popitem(last=False)
        else:
            state = cached[1]
        current = timestamp >= float(state.get("changed_at") or 0)
        if not current:
            candidates = [
                item
                for item in state.get("history", [])
                if isinstance(item, dict)
                and float(item.get("changed_at") or 0) <= timestamp
            ]
            state = max(
                candidates,
                key=lambda item: float(item.get("changed_at") or 0),
                default={},
            )
        gateway = normalize_mac(state.get("gateway_mac"))
        scope = (
            f"gateway:{gateway}:{state.get('local_network', '')}"
            if gateway
            else self.run_scope
        )
        return scope, state, current

    def _refresh_local_hosts(self) -> None:
        """Start the capture computer's clock even without inbound traffic."""
        if not self.live or not self.settings.detect_new_services:
            return
        now = time.monotonic()
        if now < self._next_host_refresh:
            return
        self._next_host_refresh = now + 5
        timestamp = time.time()
        for interface in self.interfaces:
            scope, state, current = self._network_at(interface, timestamp)
            addresses = [state.get("host_ip", "")] + [
                item.get("ip", "")
                for item in state.get("addresses", [])
                if isinstance(item, dict)
            ]
            for ip in dict.fromkeys(addresses):
                if not ip or not self._is_local_host(ip, state):
                    continue
                identity = self._endpoint_identity(
                    ip, state.get("mac", ""), scope, state, current
                )
                host = self.host_inventory.observe_host(
                    scope,
                    identity,
                    ip,
                    max(
                        self._capture_started,
                        float(state.get("changed_at") or 0),
                    ),
                )
                if host is not None:
                    saved = self.host_inventory.hosts[host]
                    saved.last_seen = max(saved.last_seen, timestamp)

    def _is_local_host(self, ip: str, state: dict) -> bool:
        """Limit newly active service findings to locally monitored computers.

        Parameters:
            ip: Endpoint address.
            state: Interface addressing at capture time.

        Returns:
            True for a monitored subnet or a private host in recorded input.
        """
        address = ipaddress.ip_address(ip)
        if (
            address.is_multicast
            or address.is_unspecified
            or address.is_loopback
        ):
            return False
        if not self.live:
            return address.is_private and not address.is_reserved
        networks = [state.get("local_network", "")] + [
            item.get("network", "")
            for item in state.get("addresses", [])
            if isinstance(item, dict)
        ]
        for cidr in networks:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if address in network:
                return not (
                    network.version == 4
                    and network.prefixlen < 31
                    and address
                    in {
                        network.network_address,
                        network.broadcast_address,
                    }
                )
        return False

    def _endpoint_identity(
        self, ip: str, mac: str, scope: str, state: dict, current: bool
    ) -> str:
        """Use a MAC only for a confirmed local endpoint, excluding next hops.

        Parameters:
            ip: Endpoint address.
            mac: Captured endpoint hardware address, if present.
            scope: Verified network or isolated run identity.
            state: Network settings at flow time.
            current: Whether consulting current profile metadata is safe.

        Returns:
            MAC-based local identity or a network-scoped address fallback.
        """
        address = ipaddress.ip_address(ip)
        try:
            network = ipaddress.ip_network(
                state.get("local_network", ""), strict=False
            )
            local = address in network or address.is_link_local
        except ValueError:
            local = False
        if self.live:
            local = local or self._is_local_host(ip, state)
        fallback = f"ip:{ip}"
        if not local:
            return fallback
        mac = normalize_mac(mac)
        cache_key = scope, ip, mac, current
        now = time.monotonic()
        cached = self._identities.get(cache_key)
        if cached and cached[0] > now:
            return cached[1]
        if not mac and current:
            mac = normalize_mac(
                self.db.get_mac_addr_from_profile(f"profile_{ip}")
            )
        identity = fallback
        if classify_mac(mac) in {
            "locally_administered",
            "universally_administered",
        } and mac != normalize_mac(state.get("gateway_mac")):
            identity = f"mac:{mac}"
        self._identities[cache_key] = (
            now + (60 if identity != fallback else 5),
            identity,
        )
        self._identities.move_to_end(cache_key)
        if len(self._identities) > 4096:
            self._identities.popitem(last=False)
        return identity

    def handle_flow(self, payload: dict[str, Any]) -> None:
        """Adapt a flow, resolve identities and emit at most one evidence.

        Parameters:
            payload: Decoded new_flow message.
        """
        flow = payload.get("flow")
        if not isinstance(flow, dict):
            return
        try:
            window = int(str(payload["twid"]).replace("timewindow", ""))
        except (ValueError, TypeError, KeyError):
            return
        observation = Observation.from_zeek(flow)
        if observation is None:
            return
        if (
            self.live
            and observation.interface == "default"
            and len(self.interfaces) == 1
        ):
            observation = replace(observation, interface=self.interfaces[0])
        scope, state, current = self._network(observation)
        try:
            network = ipaddress.ip_network(
                state.get("local_network", ""), strict=False
            )
        except ValueError:
            network = None
        if network and network.version == 4 and network.prefixlen < 31:
            if any(
                ipaddress.ip_address(ip)
                in {network.broadcast_address, network.network_address}
                for ip in (observation.client_ip, observation.server_ip)
            ):
                return
        server = self._endpoint_identity(
            observation.server_ip, flow.get("dmac", ""), scope, state, current
        )
        client = self._endpoint_identity(
            observation.client_ip, flow.get("smac", ""), scope, state, current
        )
        key = json.dumps(
            [scope, server, observation.proto, observation.server_port],
            separators=(",", ":"),
        )
        labels = {
            str(payload.get("label") or "").casefold(),
            str(flow.get("ground_truth_label") or "").casefold(),
        }
        previous = self.detector.services.get(key)
        previously_known = (
            previous is not None
            and previous.summary.count > 0
            and previous.last_seen
            >= observation.timestamp - self.settings.retention_days * 86400
        )
        duplicate = observation.uid in self.detector.seen
        allow_learning = not bool(labels & {"malicious", "malware", "attack"})
        reasons = []
        unexpected_service = False
        if self.settings.detect_new_services and not duplicate:
            for ip, identity in (
                (observation.client_ip, client),
                (observation.server_ip, server),
            ):
                if not self._is_local_host(ip, state):
                    continue
                if (
                    ip == observation.server_ip
                    and not observation.service_reply
                ):
                    continue
                host = self.host_inventory.observe_host(
                    scope,
                    identity,
                    ip,
                    (
                        max(observation.timestamp, self._capture_started)
                        if self.live
                        else observation.timestamp
                    ),
                )
                if host is None or ip != observation.server_ip:
                    continue
                reason = self.host_inventory.check_service(
                    host,
                    observation.proto,
                    observation.server_port,
                    observation.timestamp,
                    allow_learning=allow_learning,
                    previously_known=previously_known,
                )
                if reason:
                    reasons.append(reason)
                port = self.host_inventory.hosts[host].ports.get(
                    f"{observation.proto}:{observation.server_port}"
                )
                unexpected_service = port is not None and not port["normal"]
        reasons.extend(
            self.detector.process(
                observation,
                key,
                client,
                allow_learning=allow_learning and not unexpected_service,
            )
        )
        if reasons:
            self._emit(observation, window, reasons)

    def _emit(
        self, observation: Observation, twid: Any, reasons: list[dict]
    ) -> None:
        """Submit explained statistical evidence through the normal pipeline.

        Parameters:
            observation: Anomalous connection.
            twid: Original flow time window.
            reasons: Client, timing and/or duration explanations.
        """
        window = int(str(twid).replace("timewindow", ""))
        confidence = min(
            0.65, 0.25 + 0.1 * len(reasons) + 0.1 * observation.accepted
        )
        details = []
        for reason in reasons:
            if reason["kind"] == "new_service":
                details.append(
                    f"newly active service: this port was not seen answering during "
                    f"the host's {reason['training_hours']:g}-hour training window "
                    f"({reason['known_services']} known services)"
                )
            elif reason["kind"] == "new_client":
                details.append(
                    f"client absent from retained baseline of {reason['known_clients']} clients"
                )
            elif reason["kind"] == "unusual_time":
                details.append(
                    f"unusual start time {reason['local_time']} "
                    f"for {reason['baseline']} schedule learned over {reason['observed_days']} matching days"
                )
            else:
                details.append(
                    f"unusually {reason['direction']} completed flow: {reason['seconds']:.3f}s; "
                    f"learned range {reason['usual_low_seconds']:.3f}–{reason['usual_high_seconds']:.3f}s "
                    f"from {reason['samples']} {reason['baseline']} samples"
                )
        outcome = (
            "answered connection"
            if observation.accepted
            else "connection attempt"
        )
        self.db.set_evidence(
            Evidence(
                evidence_type=EvidenceType.ANOMALOUS_FLOW,
                description=f"Service anomaly: {observation.client_ip} → "
                f"{observation.server_ip}:{observation.server_port}/{observation.proto}; "
                f"{outcome}; " + "; ".join(details),
                attacker=Attacker(
                    Direction.SRC, IoCType.IP, observation.client_ip
                ),
                victim=Victim(
                    Direction.DST, IoCType.IP, observation.server_ip
                ),
                threat_level=ThreatLevel.LOW,
                profile=ProfileID(observation.client_ip),
                timewindow=TimeWindow(window),
                uid=[observation.uid],
                timestamp=datetime.fromtimestamp(
                    observation.timestamp, timezone.utc
                ).strftime(utils.alerts_format),
                proto=Proto(observation.proto),
                src_port=observation.client_port,
                dst_port=observation.server_port,
                interface=observation.interface,
                method=Method.STATISTICAL,
                confidence=confidence,
            )
        )

    def _checkpoint(self, force: bool = False) -> None:
        """Flush bounded dirty state periodically and retry busy writers later.

        Parameters:
            force: Flush immediately when the module releases its resources.
        """
        now = time.monotonic()
        if self.store is None or (not force and now < self._next_flush):
            return
        self._next_flush = now + self.settings.flush_interval_seconds
        try:
            self.store.save(self.detector, self.host_inventory)
        except sqlite3.OperationalError as error:
            code = getattr(error, "sqlite_errorcode", None)
            busy = code is not None and code & 255 == 5
            if not busy and not (
                code is None
                and str(error).lower()
                in {"database is locked", "database is busy"}
            ):
                raise
            if now >= self._next_warning:
                self.print(
                    "Service baseline checkpoint busy; will retry.", 0, 1
                )
                self._next_warning = now + 60
        if (
            self.detector.capacity_skips or self.host_inventory.capacity_skips
        ) and now >= self._next_warning:
            self.print(
                "Service baseline capacity reached; incomplete client or port lists "
                "do not produce new-client or new-service findings. Review configured limits.",
                0,
                1,
            )
            self._next_warning = now + 60

    def main(self) -> None:
        """Drain a bounded message batch and checkpoint outside profiling."""
        self._refresh_local_hosts()
        for _ in range(32):
            msg = self.get_msg("new_flow")
            if not msg:
                break
            try:
                payload = json.loads(msg["data"])
            except (ValueError, TypeError):
                continue
            if isinstance(payload, dict):
                self.handle_flow(payload)
        self._checkpoint()

    def shutdown_gracefully(self) -> None:
        """Checkpoint learned state and release this module's private writer."""
        if self.store is not None:
            try:
                self._checkpoint(force=True)
            finally:
                self.store.close()
                self.store = None
