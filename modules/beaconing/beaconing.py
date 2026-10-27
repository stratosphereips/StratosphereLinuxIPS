"""Explain strong recurring connections and resemblance to observed malware C2."""

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
from slips_files.common.mac import normalize_mac
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
from .detector import Detector, Observation
from .model import PatternModel
from .settings import Settings, PacketTimingSettings
from .packet_timing import PacketTimingDetector
from .store import Store


class Beaconing(IModule):
    """Analyze numeric conn records without TensorFlow or per-flow database scans."""

    name = Modules.BEACONING.value
    description = "Detects recurring connections and suspected C2 patterns"
    authors = ["Sebastian Garcia"]

    def init(self) -> None:
        """Initialize bounded analysis and packet-time network context caches."""
        self.settings = Settings.from_config(self.conf)
        self.detector = Detector(self.settings)
        self.packet_settings = PacketTimingSettings.from_config(self.conf)
        self.packet_detector = PacketTimingDetector(
            self.packet_settings, self.settings
        )
        self.model: PatternModel | None = None
        self.store: Store | None = None
        self.live = self.db.get_input_type() == InputType.INTERFACE or bool(
            self.args.growing
        )
        self.interfaces = list(self.args.interface or [])
        self.run_scope = f"run:{self.parent_output_dir}:{self.ppid}"
        self.networks: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self.next_flush = 0.0
        self.next_warning = 0.0
        self.next_capacity_warning = 0.0
        self.reported_evictions = 0
        self.reported_candidate_evictions = 0

    def subscribe_to_channels(self) -> None:
        """Consume existing flow summaries without another capture or Redis keys."""
        self.channels = {"new_flow": self.db.subscribe("new_flow")}
        if self.packet_settings.enabled:
            self.channels["new_packet_timing"] = self.db.subscribe(
                "new_packet_timing"
            )

    def pre_main(self) -> None:
        """Restore this capture's state and validate the optional numeric model."""
        utils.drop_root_privs_permanently()
        # Output ownership isolates concurrent interfaces, PCAP runs and computers.
        self.store = Store(
            Path(self.parent_output_dir) / self.name / "channels.sqlite"
        )
        if self.live:
            self.store.load(self.detector, time.time())
        if self.settings.model_file:
            self.model = PatternModel(self.settings.model_file)
        self.print(
            f"Numeric beaconing: {len(self.detector.channels)} restored channels; minimum {self.settings.min_connections} connections; C2 model {self.model.version if self.model else 'disabled'}",
            1,
            0,
        )

    def _scope(
        self, observation: Observation, flow: dict[str, Any]
    ) -> str | None:
        """Separate private addresses across networks using packet-time gateway identity.

        Parameters:
            observation: Original flow endpoint and timestamp.
            flow: Optional observed source MAC.

        Returns:
            Capture/network/client scope, or None for subnet broadcast traffic.
        """
        if not self.live:
            return self.run_scope
        interface = observation.interface
        if interface == "default" and len(self.interfaces) == 1:
            interface = self.interfaces[0]
        now = time.monotonic()
        cached = self.networks.get(interface)
        if cached is None or now >= cached[0]:
            state = self.db.get_network_state(interface) or {}
            state = state if isinstance(state, dict) else {}
            self.networks[interface] = now + 5, state
            if len(self.networks) > 16:
                self.networks.popitem(last=False)
        else:
            state = cached[1]
        if observation.timestamp < float(state.get("changed_at") or 0):
            state = max(
                (
                    s
                    for s in state.get("history", [])
                    if isinstance(s, dict)
                    and float(s.get("changed_at") or 0)
                    <= observation.timestamp
                ),
                key=lambda s: float(s.get("changed_at") or 0),
                default={},
            )
        try:
            network = ipaddress.ip_network(
                state.get("local_network", ""), strict=False
            )
            if (
                network.version == 4
                and network.prefixlen < 31
                and any(
                    ipaddress.ip_address(ip)
                    in {network.broadcast_address, network.network_address}
                    for ip in (observation.src, observation.dst)
                )
            ):
                return None
        except ValueError:
            pass
        gateway = normalize_mac(state.get("gateway_mac"))
        # Missing gateway data falls back to a run, never a reusable private IP.
        scope = (
            f"gateway:{gateway}:{state.get('local_network', '')}"
            if gateway
            else self.run_scope
        )
        source_mac = normalize_mac(flow.get("smac"))
        return json.dumps(
            [scope, interface, source_mac or observation.src],
            separators=(",", ":"),
        )

    def handle_flow(self, payload: dict[str, Any]) -> None:
        """Normalize one original-direction flow and emit an explained finding.

        Parameters:
            payload: Decoded new_flow event.
        """
        flow = payload.get("flow")
        if (
            not isinstance(flow, dict)
            or payload.get("profileid") != f"profile_{flow.get('saddr')}"
        ):
            return
        try:
            window = int(str(payload["twid"]).replace("timewindow", ""))
        except (ValueError, TypeError, KeyError):
            return
        observation = Observation.from_flow(flow)
        if observation is None:
            return
        observation = replace(observation, timewindow=window)
        scope = self._scope(observation, flow)
        if scope is None:
            return
        result = self.detector.process(
            observation,
            scope,
            time.monotonic() if self.live else observation.timestamp,
        )
        if result is None:
            return
        key, stats = result
        score = (
            self.model.score(stats)
            if self.model and observation.proto in self.model.protocols
            else 0.0
        )
        threshold = (
            max(self.settings.c2_score_threshold, self.model.minimum_threshold)
            if self.model
            else 1.0
        )
        suspected = bool(
            self.model
            and observation.proto in self.model.protocols
            and score >= threshold
            and stats["answered"] >= 0.8
        )
        kind = "c2" if suspected else "periodic"
        latest = self.detector.channels[key].events[-1]
        if self.detector.should_alert(key, kind, latest.timestamp, stats):
            self._emit(latest, latest.timewindow, key, stats, score, suspected)

    def _emit(
        self,
        observation: Observation,
        window: int,
        key: str,
        stats: dict[str, Any],
        score: float,
        suspected: bool,
    ) -> None:
        """Submit recurring behavior separately from a suspected malicious pattern.

        Parameters:
            observation: Latest supporting original-direction connection.
            window: Slips time-window number for the triggering event.
            key: Detector channel key.
            stats: Timing and directional size statistics.
            score: Malware-pattern decision score, not a probability.
            suspected: Whether the conservative C2 decision threshold was crossed.
        """
        title = (
            "Suspected C2 pattern"
            if suspected
            else "Strong recurring connections"
        )
        kind = "c2" if suspected else "periodic"
        progress = self.detector.channels[key].reports[kind]
        continuation = progress["continuation"]
        count = progress["count"]
        span = observation.timestamp - progress["started"]
        description = (
            f"{'Continuing ' if continuation else ''}{title}: {observation.src} → {observation.dst}:{observation.port}/{observation.proto}; "
            f"{count} connections over {span:.1f}s; "
            + (
                f"latest {stats['count']} connections: "
                if continuation
                else ""
            )
            + f"period {stats['period']:.3f}s ({1 / stats['period']:.5f} Hz, {stats['mode']}); "
            f"{stats['support']:.0%} timing support, {stats['jitter']:.1%} relative variation, "
            f"{stats['missed']:.0%} missed-cycle intervals; "
            f"median sent/received {stats['sent']:.0f}/{stats['received']:.0f} B, "
            f"duration {stats['duration']:.3f}s; {stats['answered']:.0%} answered."
        )
        if suspected:
            description += f" Resembles labeled C2 examples: pattern score {score:.4f}, model {self.model.version}."
        self.db.set_evidence(
            Evidence(
                evidence_type=(
                    EvidenceType.SUSPECTED_C2_CHANNEL
                    if suspected
                    else EvidenceType.PERIODIC_CONNECTION
                ),
                description=description,
                attacker=Attacker(Direction.SRC, IoCType.IP, observation.src),
                victim=Victim(Direction.DST, IoCType.IP, observation.dst),
                threat_level=(
                    ThreatLevel.LOW if suspected else ThreatLevel.INFO
                ),
                confidence=min(
                    0.85 if suspected else 0.6,
                    stats["support"] * min(1.0, stats["count"] / 30),
                ),
                profile=ProfileID(observation.src),
                timewindow=TimeWindow(window),
                uid=[
                    e.uid
                    for e in list(self.detector.channels[key].events)[-32:]
                ],
                timestamp=datetime.fromtimestamp(
                    observation.timestamp, timezone.utc
                ).strftime(utils.alerts_format),
                proto=Proto(observation.proto),
                dst_port=observation.port,
                interface=observation.interface,
                method=Method.STATISTICAL,
                detection_details={
                    "beaconing": {
                        "connections": count,
                        "span_seconds": span,
                        "window_connections": stats["count"],
                        "window_span_seconds": stats["span"],
                        "continuation": continuation,
                        "next_report_connections": progress["next_count"],
                        "period_seconds": stats["period"],
                    }
                },
            )
        )

    def _checkpoint(self, force: bool = False) -> None:
        """Save dirty windows periodically, retrying lock contention later.

        Parameters:
            force: Save immediately on orderly shutdown.
        """
        now = time.monotonic()
        if self.store is None or (not force and now < self.next_flush):
            return
        self.next_flush = now + self.settings.flush_interval_seconds
        try:
            self.store.save(self.detector)
        except sqlite3.OperationalError as error:
            code = getattr(error, "sqlite_errorcode", None)
            busy = code is not None and code & 255 == 5
            if not busy and not (
                code is None
                and str(error).lower()
                in {"database is locked", "database is busy"}
            ):
                raise
            if now >= self.next_warning:
                self.print(
                    "Beaconing checkpoint busy; retaining changed windows for retry.",
                    0,
                    1,
                )
                self.next_warning = now + 60
        evictions = self.detector.evictions - self.reported_evictions
        candidates = (
            self.detector.candidate_evictions
            - self.reported_candidate_evictions
        )
        if (evictions or candidates) and now >= self.next_capacity_warning:
            self.print(
                (
                    f"Beaconing channel capacity: {evictions} mature windows discarded since the last notice ({self.detector.evictions} total); max_channels={self.settings.max_channels}."
                    if evictions
                    else f"Beaconing candidate capacity: {candidates} short sequences discarded since the last notice; max_candidates={self.settings.max_candidates}."
                ),
                0 if evictions else 2,
                1 if evictions else 0,
            )
            self.reported_evictions = self.detector.evictions
            self.reported_candidate_evictions = (
                self.detector.candidate_evictions
            )
            self.next_capacity_warning = now + 60

    def handle_packet_timing(self, payload: dict[str, Any]) -> None:
        """Assess a bounded summary and submit a connection-linked evidence.

        Parameters:
            payload: Parsed summary routed by the profiler.
        """
        flow = payload.get("flow")
        if (
            not self.packet_settings.enabled
            or not isinstance(flow, dict)
            or payload.get("profileid") != f"profile_{flow.get('saddr')}"
        ):
            return
        try:
            window = int(str(payload["twid"]).replace("timewindow", ""))
            timestamp = flow["starttime"]
            timestamp = (
                timestamp.timestamp()
                if isinstance(timestamp, datetime)
                else float(timestamp)
            )
            observation = Observation(
                str(flow["uid"]),
                timestamp,
                0,
                str(flow["saddr"]),
                str(flow["daddr"]),
                int(flow["dport"]),
                "tcp",
                0,
                0,
                0,
                0,
                True,
                str(flow.get("interface") or "default"),
                window,
            )
        except (KeyError, ValueError, TypeError):
            return
        scope = self._scope(observation, flow)
        finding = (
            self.packet_detector.process(flow, scope)
            if scope is not None
            else None
        )
        if finding is None:
            return
        self.db.set_evidence(
            Evidence(
                evidence_type=EvidenceType[finding["evidence_type"]],
                attacker=Attacker(
                    Direction.SRC, IoCType.IP, finding["source"]
                ),
                victim=Victim(
                    Direction.DST, IoCType.IP, finding["destination"]
                ),
                profile=ProfileID(finding["source"]),
                timewindow=TimeWindow(window),
                threat_level=ThreatLevel[finding["threat"].upper()],
                confidence=finding["confidence"],
                description=finding["description"],
                timestamp=finding["timestamp"],
                uid=[flow["record_id"]],
                src_port=finding["sport"],
                dst_port=finding["dport"],
                proto=Proto.TCP,
                interface=observation.interface,
                method=Method.STATISTICAL,
                detection_details={"packet_timing": finding["details"]},
            )
        )

    def main(self) -> None:
        """Drain a bounded batch, then checkpoint outside the per-flow path."""
        for _ in range(32):
            msg = self.get_msg("new_flow")
            if not msg:
                break
            try:
                payload = json.loads(msg["data"])
                if isinstance(payload, dict):
                    self.handle_flow(payload)
            except (ValueError, TypeError, KeyError) as error:
                if time.monotonic() >= self.next_warning:
                    self.print(f"Invalid beaconing flow: {error}", 0, 1)
                    self.next_warning = time.monotonic() + 60
        if self.packet_settings.enabled:
            for _ in range(8):
                msg = self.get_msg("new_packet_timing")
                if not msg:
                    break
                try:
                    payload = json.loads(msg["data"])
                    if isinstance(payload, dict):
                        self.handle_packet_timing(payload)
                except (ValueError, TypeError, KeyError) as error:
                    if time.monotonic() >= self.next_warning:
                        self.print(
                            f"Invalid packet timing summary: {error}", 0, 1
                        )
                        self.next_warning = time.monotonic() + 60
        self._checkpoint()

    def shutdown_gracefully(self) -> None:
        """Flush connection state and release resources on orderly shutdown."""
        try:
            self._checkpoint(force=True)
        finally:
            if self.store is not None:
                self.store.close()
