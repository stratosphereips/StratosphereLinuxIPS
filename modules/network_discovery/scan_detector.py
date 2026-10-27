"""Bounded, packet-time horizontal scan analysis independent of databases."""

import ipaddress
import math
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from typing import Any

from slips_files.common.flow_direction import zeek_history_in_final_direction

from .scan_settings import ScanSettings
from .distinct_targets import DistinctTargets
from slips_files.common.scan_progress import scan_confidence


@dataclass(frozen=True, slots=True)
class ScanFlow:
    """Only the connection attributes needed for scan analysis."""

    uid: str
    src: str
    dst: str
    port: int
    proto: str
    start: float
    end: float
    packets: int
    kind: str
    interface: str
    sport: int

    @property
    def family(self) -> str:
        """Return the probe family, grouping rejected and unanswered SYNs."""
        return "tcp" if self.kind in {"syn", "rejected"} else self.kind

    @classmethod
    def from_flow(
        cls, flow: dict[str, Any], summary_state: str = ""
    ) -> "ScanFlow | None":
        """Validate a connection and identify observed probes or successful use.

        Parameters:
            flow: Original-direction flow summary from the profiler.
            summary_state: Coarse profiler state for legacy summaries.

        Returns:
            Compact observation, or None for unsupported or malformed traffic.
        """
        try:
            src = ipaddress.ip_address(flow["saddr"])
            dst = ipaddress.ip_address(flow["daddr"])
            proto = str(flow["proto"]).lower()
            port, sport = int(flow["dport"]), int(flow["sport"])
            start, duration = float(flow["starttime"]), float(
                flow.get("dur", 0)
            )
            spkts, dpkts = int(flow.get("spkts", 0)), int(flow.get("dpkts", 0))
            directional_counts = spkts + dpkts > 0
            if not directional_counts and flow.get("type_") in {
                "argus",
                "nfdump",
            }:
                spkts = int(flow.get("pkts", 0))
            sent, received = int(flow.get("sbytes", 0)), int(
                flow.get("dbytes", 0)
            )
            if (
                proto not in {"tcp", "udp"}
                or not 0 < port <= 65535
                or not 0 <= sport <= 65535
                or not math.isfinite(start)
                or not math.isfinite(duration)
                or not math.isfinite(start + duration)
                or min(start, duration, spkts, dpkts, sent, received) < 0
                or spkts == 0
                or not isinstance(flow["uid"], str)
                or not flow["uid"]
                or src.version != dst.version
                or src == dst
                or any(
                    ip.is_multicast
                    or ip.is_unspecified
                    or ip.is_loopback
                    or str(ip) == "255.255.255.255"
                    for ip in (src, dst)
                )
            ):
                return None
            state = str(flow.get("state", ""))
            # Conn.state_hist falls back to conn_state when history is missing.
            # Only actual packet history establishes that a SYN was observed.
            history = flow.get("history")
            if not history:
                history = flow.get("state_hist", "")
                if history == state:
                    history = ""
            history = zeek_history_in_final_direction(str(history or ""))
            kind = "background"
            if proto == "udp":
                if directional_counts:
                    kind = "success" if dpkts else "udp"
                else:
                    kind = (
                        "success"
                        if summary_state == "Established"
                        else "unknown"
                    )
            elif "S" in history:
                if "h" in history or state in {"SF", "S1", "S2", "S3", "RSTO"}:
                    kind = (
                        "connect"
                        if sent == received == 0
                        and duration <= 3
                        and ("F" in history or "R" in history)
                        else "success"
                    )
                elif state == "REJ" or "r" in history:
                    kind = "rejected"
                else:
                    kind = "syn"
            elif not history and (
                state in {"S0", "REJ", "INT", "S_", "S_R", "S_RA"}
                or summary_state == "Not Established"
            ):
                kind = "unknown"
            elif not history and summary_state == "Established":
                kind = "success"
            elif sent or received or "D" in history or "d" in history:
                kind = (
                    "success"
                    if sent and received and "h" in history
                    else "background"
                )
            elif (
                history
                and set(history) <= {"A", "F"}
                and spkts <= 2
                and dpkts == 0
                and duration <= 1
            ):
                kind = "flags"
            return cls(
                flow["uid"],
                str(src),
                str(dst),
                port,
                proto,
                start,
                start + duration,
                spkts,
                kind,
                str(flow.get("interface") or "default"),
                sport,
            )
        except (KeyError, TypeError, ValueError, OverflowError):
            return None


@dataclass(slots=True)
class Target:
    """Retain one probe and the latest successful use per destination."""

    seen: float
    success: float = -math.inf
    probe: ScanFlow | None = None
    familiar: bool = False


@dataclass(slots=True)
class ScanProgress:
    """Keep a fixed-size counter and small samples after scan confirmation."""

    started: float
    last_probe: float
    family: str = "tcp"
    threat: str = "high"
    counter: DistinctTargets = field(default_factory=DistinctTargets)
    pending: list[ScanFlow] = field(default_factory=list)
    samples: OrderedDict[str, ScanFlow] = field(default_factory=OrderedDict)
    next_milestone: int = 1000


@dataclass(frozen=True, slots=True)
class ProgressBatch:
    """Probes awaiting a single batched P2P exclusion check."""

    flows: tuple[ScanFlow, ...]


@dataclass(slots=True)
class Group:
    """Bound targets for one network, source, protocol and destination port."""

    seen: float
    targets: OrderedDict[str, Target] = field(default_factory=OrderedDict)
    evaluated: float = -math.inf
    counts: Counter[tuple[str, str]] = field(default_factory=Counter)
    reports: dict[str, tuple[float, int, float]] = field(default_factory=dict)
    progress: ScanProgress | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    """An explained scan candidate whose UIDs refer to actual contributing probes."""

    flows: tuple[ScanFlow, ...]
    threat: str
    confidence: float
    reason: str
    window: float
    failure_ratio: float | None
    target_count: int = 0
    approximate: bool = False
    sample_uids: tuple[str, ...] = ()


class ScanDetector:
    """Analyze rolling target counts with bounded memory and no database queries."""

    def __init__(self, settings: ScanSettings) -> None:
        """Initialize analysis limits and empty state.

        Parameters:
            settings: Validated observation and resource limits.
        """
        self.settings = settings
        self.groups: OrderedDict[tuple[str, str, str, int], Group] = (
            OrderedDict()
        )
        self.clock = -math.inf
        self.capacity_evictions = 0
        self._periods = (
            (
                "fast",
                settings.horizontal_fast_window_seconds,
                settings.horizontal_fast_min_targets,
            ),
            (
                "slow",
                settings.horizontal_slow_window_seconds,
                settings.horizontal_slow_min_targets,
            ),
        )

    def process(
        self, flow: ScanFlow, scope: str
    ) -> tuple[Group, Finding | ProgressBatch] | None:
        """Update one target and evaluate eligible groups at a bounded cadence.

        Parameters:
            flow: Validated original-direction connection.
            scope: Capture interface and observed network identity.

        Returns:
            Group and finding or P2P-check batch, or None without a candidate.
        """
        s = self.settings
        # Failed attempts may be logged only after long retransmission timeouts.
        # Their start times, rather than timeout duration, define the scan burst.
        self.clock = max(self.clock, flow.start)
        retention = max(
            s.horizontal_slow_window_seconds,
            s.horizontal_success_history_seconds,
        )
        cutoff = self.clock - retention
        while self.groups and next(iter(self.groups.values())).seen < cutoff:
            self.groups.popitem(last=False)
        if flow.end < cutoff or flow.kind == "background":
            return None
        key = (scope, flow.src, flow.proto, flow.port)
        group = self.groups.get(key)
        if group is None:
            group = Group(self.clock)
            self.groups[key] = group
        group.seen = self.clock
        self.groups.move_to_end(key)
        if group.progress:
            progress = group.progress
            if (
                self.clock - progress.last_probe
                < s.horizontal_alert_cooldown_seconds
            ):
                if (
                    flow.family != progress.family
                    or flow.start < progress.started
                ):
                    return None
                progress.last_probe = max(progress.last_probe, flow.start)
                progress.pending.append(flow)
                if len(progress.pending) < 32:
                    return None
                batch = ProgressBatch(tuple(progress.pending))
                progress.pending.clear()
                return group, batch
            group.progress = None
        if len(self.groups) > s.horizontal_max_groups:
            self.groups.popitem(last=False)
            self.capacity_evictions += 1
        target = group.targets.get(flow.dst)
        before = {
            name: group.counts[(name, flow.family)] // minimum
            for name, _, minimum in self.periods()
        }
        if target is None:
            target = Target(flow.start)
            group.targets[flow.dst] = target
        self.adjust_counts(group, target, -1)
        target.seen = max(target.seen, flow.start)
        group.targets.move_to_end(flow.dst)
        if flow.kind == "success":
            target.success = max(target.success, flow.end)
            if target.probe and flow.end >= target.probe.start:
                target.probe = None
        elif flow.start > target.success and (
            target.probe is None or flow.start >= target.probe.start
        ):
            target.probe = flow
            target.familiar = (
                flow.start - target.success
                <= s.horizontal_success_history_seconds
            )
        if len(group.targets) > s.horizontal_max_targets:
            _, evicted = group.targets.popitem(last=False)
            self.adjust_counts(group, evicted, -1)
            self.capacity_evictions += 1
        self.adjust_counts(group, target, 1)
        if flow.kind == "success":
            return None
        crossed = any(
            group.counts[(name, flow.family)] // minimum > before[name]
            for name, _, minimum in self.periods()
        )
        if (
            not crossed
            and self.clock - group.evaluated
            < s.horizontal_evaluation_interval_seconds
        ):
            return None
        group.evaluated = self.clock
        for dst in [
            dst for dst, t in group.targets.items() if t.seen < cutoff
        ]:
            del group.targets[dst]
        group.counts.clear()
        for target in group.targets.values():
            self.adjust_counts(group, target, 1)
        finding = self.candidate(group, scope, flow.src)
        return (group, finding) if finding else None

    def periods(self) -> tuple[tuple[str, float, int], ...]:
        """Return the fast and slow period names, seconds and target thresholds."""
        return self._periods

    def adjust_counts(self, group: Group, target: Target, delta: int) -> None:
        """Update cached target counts relative to the last full evaluation.

        Parameters:
            group: Group owning the cached counts.
            target: Target being inserted, updated or removed.
            delta: One to add the target, minus one to remove it.
        """
        if target.probe is None or target.familiar:
            return
        for name, window, _ in self.periods():
            if target.probe.start >= group.evaluated - window:
                group.counts[(name, target.probe.family)] += delta

    def forget(self, group: Group, dst: str) -> None:
        """Remove an excluded destination from both state and cached counts.

        Parameters:
            group: Group holding a known Slips P2P connection.
            dst: Destination to exclude from all probe families.
        """
        target = group.targets.pop(dst, None)
        if target:
            self.adjust_counts(group, target, -1)

    def candidate(self, group: Group, scope: str, src: str) -> Finding | None:
        """Include simultaneous multi-service failures in candidate confidence.

        Parameters:
            group: Source and port under consideration.
            scope: Interface and network identity.
            src: Original source address.

        Returns:
            Finding with connectivity context, or None below thresholds.
        """
        s = self.settings
        finding = self.evaluate(group)
        if (
            finding
            and finding.threat == "high"
            and all(p.kind == "syn" for p in finding.flows)
        ):
            ports = set()
            successful = False
            for (other_scope, source, _, port), other in self.groups.items():
                if other_scope != scope or src != source:
                    continue
                for t in other.targets.values():
                    if (
                        t.success
                        >= self.clock - s.horizontal_fast_window_seconds
                    ):
                        successful = True
                    if (
                        t.probe
                        and t.probe.kind == "syn"
                        and t.probe.start
                        >= self.clock - s.horizontal_fast_window_seconds
                    ):
                        ports.add(port)
            if len(ports) >= 3 and not successful:
                finding = Finding(
                    finding.flows,
                    "low",
                    0.4,
                    "unanswered attempts across several services; a network outage is possible",
                    finding.window,
                    finding.failure_ratio,
                )
        if finding:
            previous = group.reports.get(finding.flows[0].family)
            rank = {"low": 1, "medium": 2, "high": 3}[finding.threat]
            if (
                previous
                and self.clock - previous[0]
                < s.horizontal_alert_cooldown_seconds
                and rank <= previous[1]
                and finding.confidence <= previous[2]
            ):
                return None
        return finding

    def evaluate(self, group: Group) -> Finding | None:
        """Compare distinct recent targets in fast and slow rolling periods.

        Parameters:
            group: One bounded source/port group.

        Returns:
            Strongest supported finding, or None for ordinary reconnections.
        """
        s = self.settings
        best = None
        ranks = {"low": 1, "medium": 2, "high": 3}
        for window, minimum in (
            (s.horizontal_fast_window_seconds, s.horizontal_fast_min_targets),
            (s.horizontal_slow_window_seconds, s.horizontal_slow_min_targets),
        ):
            recent = [
                t
                for t in group.targets.values()
                if t.seen >= self.clock - window
            ]
            probes = [
                t.probe
                for t in recent
                if t.probe
                and t.probe.start >= self.clock - window
                and not t.familiar
            ]
            for family, kinds in (
                ("tcp", {"syn", "rejected"}),
                ("connect", {"connect"}),
                ("flags", {"flags"}),
                ("udp", {"udp"}),
                ("unknown", {"unknown"}),
            ):
                previous = group.reports.get(family)
                maximum_rank = (
                    3 if family == "tcp" else (1 if family == "unknown" else 2)
                )
                if (
                    previous
                    and self.clock - previous[0]
                    < s.horizontal_alert_cooldown_seconds
                    and previous[1] >= maximum_rank
                    and (
                        family not in {"tcp", "connect", "udp"}
                        or previous[2] >= 1.0
                    )
                ):
                    continue
                candidates = [p for p in probes if p.kind in kinds]
                if len(candidates) < minimum:
                    continue
                failed = sum(
                    bool(
                        t.probe
                        and t.probe.kind
                        in {"syn", "rejected", "flags", "udp", "unknown"}
                        and t.probe.start >= self.clock - window
                    )
                    for t in recent
                )
                ratio = (
                    len(candidates) if family == "connect" else failed
                ) / max(1, len(recent))
                addresses: dict[int, list[int]] = {}
                for p in candidates:
                    ip = ipaddress.ip_address(p.dst)
                    number = int(ip)
                    prefix = number >> (8 if ip.version == 4 else 64)
                    addresses.setdefault(prefix, []).append(number)
                nearby = max(addresses.values(), key=len)
                structured = (
                    len(nearby) / len(candidates) >= 0.8
                    and len(nearby) / (max(nearby) - min(nearby) + 1) >= 0.5
                )
                rejections = sum(p.kind == "rejected" for p in candidates)
                threat, confidence = "low", 0.45
                reason = "unanswered attempts to many new targets; connectivity failure is also possible"
                if family == "tcp":
                    if ratio < s.horizontal_min_failure_ratio:
                        continue
                    if rejections >= minimum / 2 or structured:
                        threat, confidence = "high", 0.85
                        reason = "new SYN attempts with repeated rejection or concentrated address coverage"
                        confidence = scan_confidence(
                            confidence, len(candidates), minimum, ratio
                        )
                        if confidence == 1.0 and not (
                            structured or rejections >= minimum
                        ):
                            confidence = 0.95
                elif family == "connect":
                    if not structured:
                        continue
                    threat, confidence = "medium", scan_confidence(
                        0.7, len(candidates), minimum
                    )
                    reason = "short connections to many nearby addresses, closed without application data"
                elif family in {"flags", "udp"}:
                    if (
                        not structured
                        or ratio < s.horizontal_min_failure_ratio
                    ):
                        continue
                    threat, confidence = "medium", 0.65
                    if family == "udp":
                        confidence = scan_confidence(
                            confidence, len(candidates), minimum, ratio
                        )
                    reason = (
                        "small ACK/FIN-only probes to many nearby addresses; incomplete capture is also possible"
                        if family == "flags"
                        else "unanswered UDP traffic to many nearby addresses; UDP has no TCP handshake"
                    )
                else:
                    if ratio < s.horizontal_min_failure_ratio:
                        continue
                    reason = "failed-flow summaries without packet history; a new outgoing probe cannot be confirmed"
                previous = group.reports.get(family)
                if (
                    previous
                    and self.clock - previous[0]
                    < s.horizontal_alert_cooldown_seconds
                    and ranks[threat] <= previous[1]
                    and confidence <= previous[2]
                ):
                    continue
                finding = Finding(
                    tuple(candidates),
                    threat,
                    confidence,
                    reason,
                    window,
                    ratio,
                )
                if best is None or (
                    ranks[threat],
                    confidence,
                    len(candidates),
                ) > (ranks[best.threat], best.confidence, len(best.flows)):
                    best = finding
        return best

    def reported(self, group: Group, finding: Finding) -> None:
        """Start cooldown and release target state for a fully supported scan.

        Parameters:
            group: Group that supplied the evidence.
            finding: Emitted finding, after P2P exclusions.
        """
        kind = finding.flows[0].kind
        family = "tcp" if kind in {"syn", "rejected"} else kind
        group.reports[family] = (
            self.clock,
            {"low": 1, "medium": 2, "high": 3}[finding.threat],
            finding.confidence,
        )
        if finding.approximate:
            while group.progress.next_milestone <= finding.target_count:
                group.progress.next_milestone *= 10
        elif finding.confidence == 1.0:
            progress = ScanProgress(
                min(p.start for p in finding.flows),
                self.clock,
                finding.flows[0].family,
                finding.threat,
            )
            for probe in finding.flows:
                progress.counter.add(probe.dst)
            while progress.next_milestone <= len(finding.flows):
                progress.next_milestone *= 10
            group.progress = progress
            group.targets.clear()
            group.counts.clear()

    def progress_candidate(
        self, group: Group, probes: list[ScanFlow]
    ) -> Finding | None:
        """Count eligible probes cheaply and report only powers-of-ten growth.

        Parameters:
            group: Confirmed scan holding only compact progress state.
            probes: Batch after authenticated Slips P2P flows were removed.

        Returns:
            Approximate continuing-scan finding, or None below the next decade.
        """
        progress = group.progress
        for probe in probes:
            progress.counter.add(probe.dst)
            progress.last_probe = max(progress.last_probe, probe.start)
            progress.samples[probe.dst] = probe
            progress.samples.move_to_end(probe.dst)
            if len(progress.samples) > 20:
                progress.samples.popitem(last=False)
        count = progress.counter.estimate()
        if probes and count >= progress.next_milestone:
            return Finding(
                tuple(progress.samples.values()),
                progress.threat,
                1.0,
                "continuing previously confirmed horizontal scan; approximate distinct-target count, with sampled probe flows",
                self.clock - progress.started,
                None,
                count,
                True,
            )
        return None
