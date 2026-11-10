"""Assess bounded packet timing summaries separately from connection-level ML."""

import ipaddress
import math
from collections import Counter, OrderedDict
from dataclasses import replace
from typing import Any

from slips_files.common.flow_direction import tcp_initiator_is_known
from .detector import Observation, features
from .settings import Settings, PacketTimingSettings


class PacketTimingDetector:
    """Measure intra-connection rhythms without classifying packets as conn flows."""

    def __init__(
        self, settings: PacketTimingSettings, parent: Settings
    ) -> None:
        """Prepare a bounded detector using the shared numeric rhythm calculation.

        Parameters:
            settings: Packet-specific collection and decision limits.
            parent: Connection detector period limits and report spacing.
        """
        settings.validate()
        self.settings = settings
        self.parent = parent
        self.rhythm_settings = replace(
            parent,
            min_connections=settings.min_events,
            window_connections=settings.window_events,
            min_span_seconds=settings.min_span_seconds,
            min_period_seconds=settings.min_interval_seconds,
            min_support=settings.min_support,
            jitter_tolerance=settings.jitter_tolerance,
        )
        self.progress: OrderedDict[tuple, dict] = OrderedDict()

    @staticmethod
    def numbers(value: Any, limit: int) -> list[float]:
        """Read a bounded JSON or TSV numeric vector.

        Parameters:
            value: Logged vector or comma-separated TSV field.
            limit: Maximum accepted vector length.

        Returns:
            Finite nonnegative numbers, or an empty list for invalid input.
        """
        if isinstance(value, str):
            value = value.split(",")
        if not isinstance(value, list) or not 0 < len(value) <= limit:
            return []
        try:
            if any(isinstance(item, bool) for item in value):
                return []
            numbers = [float(item) for item in value]
            return (
                numbers
                if all(math.isfinite(item) and item >= 0 for item in numbers)
                else []
            )
        except (TypeError, ValueError):
            return []

    def process(
        self, flow: dict[str, Any], scope: str
    ) -> dict[str, Any] | None:
        """Assess one directional window and limit continuing evidence by count.

        Parameters:
            flow: Parsed Zeek summary, containing no payload content.
            scope: Packet-time network or independent capture identity.

        Returns:
            Explained finding with observed statistics, or None.
        """
        s = self.settings
        if not s.enabled or flow.get("type_") != "packet_timing":
            return None
        if (
            not isinstance(flow.get("uid"), str)
            or not 0 < len(flow["uid"]) <= 256
        ):
            return None
        times = self.numbers(flow.get("times"), s.window_events)
        lengths = self.numbers(flow.get("lengths"), s.window_events)
        if (
            len(times) < s.min_events
            or len(times) != len(lengths)
            or any(length > s.max_payload_bytes for length in lengths)
            or any(length != int(length) for length in lengths)
            or any(b <= a for a, b in zip(times, times[1:]))
        ):
            return None
        kind = str(flow.get("kind"))
        if kind not in {"data", "ack", "keepalive"} or (
            kind != "data" and not s.include_acks
        ):
            return None
        try:
            src, dst = (
                ipaddress.ip_address(flow[name]) for name in ("saddr", "daddr")
            )
            if src == dst or any(
                ip.is_multicast
                or ip.is_loopback
                or ip.is_unspecified
                or ip.is_reserved
                for ip in (src, dst)
            ):
                return None
            sport, dport = int(flow["sport"]), int(flow["dport"])
            if not all(0 < port <= 65535 for port in (sport, dport)):
                return None
            count = int(flow["event_count"])
            orig_bytes, resp_bytes = float(flow["orig_bytes"]), float(
                flow["resp_bytes"]
            )
            if count < len(times) or not all(
                math.isfinite(v) and v >= 0 for v in (orig_bytes, resp_bytes)
            ):
                return None
        except (KeyError, TypeError, ValueError):
            return None
        orig = flow.get("is_orig") in (True, "T")
        sender, receiver = (
            (str(src), str(dst)) if orig else (str(dst), str(src))
        )
        sender_port, receiver_port = (sport, dport) if orig else (dport, sport)
        events = [
            Observation(
                str(i),
                stamp,
                0,
                sender,
                receiver,
                receiver_port,
                "tcp",
                size,
                0,
                1,
                0,
                resp_bytes > 0,
            )
            for i, (stamp, size) in enumerate(zip(times, lengths))
        ]
        stats = features(events, self.rhythm_settings)
        if not stats:
            return None
        services = flow.get("service") or []
        if isinstance(services, str):
            services = [
                value
                for value in services.split(",")
                if value not in {"-", "(empty)", ""}
            ]
        uniform = Counter(lengths).most_common(1)[0][1] / len(lengths)
        suspicious = bool(
            kind == "data"
            and orig
            and dport in s.expected_tls_ports
            and not services
            and tcp_initiator_is_known("tcp", flow.get("history"))
            and bool(flow.get("history"))
            and orig_bytes > 0
            and resp_bytes > 0
            and 0 < stats["sent"] <= s.small_payload_bytes
            and uniform >= s.uniform_size_fraction
            and stats["support"] >= s.suspicious_min_support
            and stats["jitter"] <= s.suspicious_max_jitter
        )
        evidence_type = (
            "SUSPICIOUS_PACKET_HEARTBEAT" if suspicious else "PERIODIC_PACKETS"
        )
        stronger = (
            scope,
            flow["uid"],
            orig,
            kind,
            "SUSPICIOUS_PACKET_HEARTBEAT",
        )
        if not suspicious and stronger in self.progress:
            return None
        key = (scope, flow["uid"], orig, kind, evidence_type)
        previous = self.progress.get(key)
        if previous and times[-1] <= previous["last"]:
            return None
        changed = bool(
            previous
            and max(
                stats["period"] / previous["period"],
                previous["period"] / stats["period"],
            )
            >= 2
        )
        continuation = bool(
            previous and count >= previous["count"] and not changed
        )
        if continuation and count < previous["next_count"]:
            return None
        next_count = self.parent.report_growth_factor
        while next_count <= count:
            next_count *= self.parent.report_growth_factor
        self.progress[key] = {
            "last": times[-1],
            "count": count,
            "next_count": next_count,
            "period": stats["period"],
        }
        self.progress.move_to_end(key)
        while len(self.progress) > s.max_connections * 6:
            self.progress.popitem(last=False)
        label = (
            "Suspicious application heartbeat"
            if suspicious
            else f"Periodic {kind} packets"
        )
        description = (
            f"{label}: {sender}:{sender_port} → {receiver}:{receiver_port}/TCP; "
            f"{len(times)} packets in one connection over {stats['span']:.1f}s; period {stats['period']:.3f}s; "
            f"{stats['support']:.0%} timing support, {stats['jitter']:.1%} relative variation; median payload {stats['sent']:.0f} bytes."
        )
        if suspicious:
            description += f" Application data on port {dport} without a recognized TLS or other application protocol."
        return {
            "source": sender,
            "destination": receiver,
            "sport": sender_port,
            "dport": receiver_port,
            "timestamp": times[-1],
            "evidence_type": evidence_type,
            "description": description,
            "confidence": (
                s.suspicious_confidence
                if suspicious
                else s.periodic_confidence
            ),
            "threat": s.suspicious_threat_level if suspicious else "info",
            "details": {
                **stats,
                "kind": kind,
                "connection_uid": flow["uid"],
                "events_total": count,
                "continuation": continuation,
                "next_report_events": next_count,
                "uniform_size_fraction": uniform,
            },
        }
