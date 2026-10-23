"""Detect unexpected clients, access times and completed flow durations."""

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


class AnomalyDetectionServices(IModule):
    """Learn independent service relationships from arriving connection logs."""

    name = Modules.ANOMALY_DETECTION_SERVICES.value
    description = (
        "Learns service clients, access schedules and session durations"
    )
    authors = ["Sebastian Garcia"]

    def init(self) -> None:
        """Initialize bounded caches without opening a baseline database."""
        self.settings = Settings.from_config(self.conf)
        self.detector = ServiceDetector(self.settings)
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
        self.print(
            f"Service anomaly mode={self.settings.mode}; "
            f"restored {len(self.detector.services)} services and "
            f"{self.detector.client_count} clients; timezone={self.settings.timezone}",
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
        if not self.live:
            return self.run_scope, {}, False
        interface = observation.interface
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
        current = observation.timestamp >= float(state.get("changed_at") or 0)
        if not current:
            candidates = [
                item
                for item in state.get("history", [])
                if isinstance(item, dict)
                and float(item.get("changed_at") or 0) <= observation.timestamp
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
        reasons = self.detector.process(
            observation,
            key,
            client,
            allow_learning=not bool(
                labels & {"malicious", "malware", "attack"}
            ),
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
            if reason["kind"] == "new_client":
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
            self.store.save(self.detector)
        except sqlite3.OperationalError as error:
            code = getattr(error, "sqlite_errorcode", 0) & 0xFF
            if code != sqlite3.SQLITE_BUSY:
                raise
            if now >= self._next_warning:
                self.print(
                    "Service baseline checkpoint busy; will retry.", 0, 1
                )
                self._next_warning = now + 60
        if self.detector.capacity_skips and now >= self._next_warning:
            self.print(
                "Service baseline capacity reached; incomplete client sets "
                "do not produce new-client findings. Review configured limits.",
                0,
                1,
            )
            self._next_warning = now + 60

    def main(self) -> None:
        """Drain a bounded message batch and checkpoint outside profiling."""
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
