"""Bounded vertical scan state, independent of shared database aggregates."""

import math
from collections import OrderedDict
from dataclasses import dataclass, field

from slips_files.common.scan_progress import ConfirmedScan, scan_confidence
from .scan_detector import ScanFlow, Finding
from .scan_settings import ScanSettings


@dataclass(slots=True)
class PortGroup:
    """Distinct failed ports for one scoped source, destination and probe family."""

    seen: float
    ports: OrderedDict[int, ScanFlow] = field(default_factory=OrderedDict)
    reported: float = -math.inf
    confidence: float = 0
    progress: ConfirmedScan | None = None


class VerticalDetector:
    """Keep exact port observations until confirmation, then a compact counter."""

    def __init__(self, settings: ScanSettings) -> None:
        """Initialize bounded state.

        Parameters:
            settings: Validated scan periods, thresholds and memory limits.
        """
        self.settings = settings
        self.groups: OrderedDict[tuple, PortGroup] = OrderedDict()
        self.singletons: OrderedDict[tuple, ScanFlow] = OrderedDict()
        self.clock = 0.0
        self.evictions = 0

    def process(self, flow: ScanFlow, scope: str) -> Finding | None:
        """Observe only the arriving flow's port; no database searches are needed.

        Parameters:
            flow: Validated original-direction connection metadata.
            scope: Interface and network identity.

        Returns:
            Exact initial or approximate continuation evidence, or no finding.
        """
        s = self.settings
        self.clock = max(self.clock, flow.start)
        retention = max(
            s.vertical_window_seconds, s.vertical_alert_cooldown_seconds
        )
        while (
            self.groups
            and next(iter(self.groups.values())).seen < self.clock - retention
        ):
            self.groups.popitem(last=False)
        while (
            self.singletons
            and next(iter(self.singletons.values())).start
            < self.clock - s.vertical_window_seconds
        ):
            self.singletons.popitem(last=False)
        if (
            flow.start < self.clock - s.vertical_window_seconds
            or flow.kind in {"background", "connect"}
        ):
            return None
        prefix = (scope, flow.src, flow.dst, flow.proto)
        if flow.kind == "success":
            for family in ("tcp", "udp", "flags", "unknown"):
                group = self.groups.get((*prefix, family))
                if group:
                    group.ports.pop(flow.port, None)
                first = self.singletons.get((*prefix, family))
                if first and first.port == flow.port:
                    del self.singletons[(*prefix, family)]
            return None
        key = (*prefix, flow.family)
        group = self.groups.get(key)
        if group is None:
            first = self.singletons.get(key)
            if (
                first is None
                or first.port == flow.port
                or first.start < self.clock - s.vertical_window_seconds
            ):
                if first is None or flow.start >= first.start:
                    self.singletons[key] = flow
                    self.singletons.move_to_end(key)
                while len(self.singletons) > 4 * s.vertical_max_groups:
                    self.singletons.popitem(last=False)
                return None
            del self.singletons[key]
            group = PortGroup(self.clock)
            group.ports[first.port] = first
            self.groups[key] = group
        self.groups.move_to_end(key)
        group.seen = self.clock
        while len(self.groups) > s.vertical_max_groups:
            self.groups.popitem(last=False)
            self.evictions += 1
        if (
            group.progress
            and self.clock - group.progress.last
            < s.vertical_alert_cooldown_seconds
        ):
            group.progress.observe(str(flow.port), flow.uid, flow.start)
            if not group.progress.due():
                return None
            count = group.progress.counter.estimate()
            group.progress.reported()
            return Finding(
                (flow,),
                "high" if flow.family in {"tcp", "udp"} else "medium",
                1.0,
                "continuing previously confirmed vertical scan; approximate distinct-port count, with sampled flow IDs",
                self.clock - group.progress.started,
                None,
                count,
                True,
                tuple(group.progress.samples.values()),
            )
        group.progress = None
        for port, probe in list(group.ports.items()):
            if probe.start < self.clock - s.vertical_window_seconds:
                del group.ports[port]
        previous = group.ports.get(flow.port)
        if previous and previous.start > flow.start:
            return None
        group.ports[flow.port] = flow
        group.ports.move_to_end(flow.port)
        if len(group.ports) > s.vertical_max_ports:
            group.ports.popitem(last=False)
            self.evictions += 1
        count = len(group.ports)
        if count < s.vertical_min_ports:
            return None
        strong = flow.family in {"tcp", "udp"}
        confidence = scan_confidence(
            (
                0.85
                if flow.family == "tcp"
                else 0.65 if flow.family in {"udp", "flags"} else 0.45
            ),
            count,
            s.vertical_min_ports,
            strong=strong,
        )
        if (
            self.clock < group.reported + s.vertical_alert_cooldown_seconds
            and confidence <= group.confidence
        ):
            return None
        probes = tuple(group.ports.values())
        group.reported, group.confidence = self.clock, confidence
        if confidence == 1.0 and strong:
            group.progress = ConfirmedScan.seed(
                ((str(p.port), p.uid) for p in probes),
                min(p.start for p in probes),
                self.clock,
                "ports",
            )
            group.ports.clear()
        return Finding(
            probes,
            (
                "high"
                if flow.family in {"tcp", "udp"}
                else "medium" if flow.family in {"udp", "flags"} else "low"
            ),
            confidence,
            (
                "distinct outgoing SYN attempts"
                if flow.family == "tcp"
                else (
                    "distinct unanswered UDP destination ports"
                    if flow.family == "udp"
                    else "incomplete packet history"
                )
            ),
            s.vertical_window_seconds,
            1.0,
        )
