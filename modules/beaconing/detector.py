"""Incremental, bounded float-valued connection rhythm analysis."""

import ipaddress
import json
import math
from collections import OrderedDict, deque
from dataclasses import dataclass, field, replace
from statistics import median
from typing import Any

from slips_files.common.anomaly_detection import robust_location_scale
from slips_files.common.flow_direction import tcp_initiator_is_known
from .settings import Settings


@dataclass(frozen=True, slots=True)
class Observation:
    """Original-direction numeric connection summary; epochs remain float64."""

    uid: str
    timestamp: float
    duration: float
    src: str
    dst: str
    port: int
    proto: str
    sent: float
    received: float
    packets_sent: float
    packets_received: float
    answered: bool
    interface: str = "default"
    timewindow: int = 0

    @classmethod
    def from_flow(cls, flow: dict[str, Any]) -> "Observation | None":
        """Adapt a unicast connection; ignore malformed or unsupported records.

        Parameters:
            flow: Slips conn record, without changing its raw state.

        Returns:
            Numeric observation, or None for irrelevant input.
        """
        try:
            if flow.get("type_") != "conn" or str(
                flow.get("proto", "")
            ).lower() not in {"tcp", "udp"}:
                return None
            if not tcp_initiator_is_known(
                str(flow["proto"]), flow.get("history")
            ):
                return None
            addresses = [
                ipaddress.ip_address(flow[k]) for k in ("saddr", "daddr")
            ]
            if addresses[0] == addresses[1] or any(
                a.is_multicast
                or a.is_loopback
                or a.is_unspecified
                or a.is_reserved
                or str(a) == "255.255.255.255"
                for a in addresses
            ):
                return None
            for key in ("smac", "dmac"):
                mac = (
                    str(flow.get(key) or "").replace(":", "").replace("-", "")
                )
                if len(mac) == 12 and int(mac[:2], 16) & 1:
                    return None
            port = int(flow["dport"])
            if not 0 < port <= 65535:
                return None
            uid = flow["uid"]
            if not isinstance(uid, str) or not 0 < len(uid) <= 256:
                return None
            numbers = [
                float(flow.get(k) or 0)
                for k in (
                    "starttime",
                    "dur",
                    "sbytes",
                    "dbytes",
                    "spkts",
                    "dpkts",
                )
            ]
            if (
                not all(math.isfinite(n) and 0 <= n < 1e16 for n in numbers)
                or numbers[0] > 253402300799
            ):
                return None
            timestamp, duration, sent, received, spkts, dpkts = numbers
            state = str(flow.get("state", "")).replace(" ", "").lower()
            answered = dpkts > 0 and (
                str(flow["proto"]).lower() == "udp"
                or state
                in {"sf", "s1", "s2", "s3", "rsto", "rstr", "established"}
            )
            return cls(
                uid,
                timestamp,
                duration,
                str(addresses[0]),
                str(addresses[1]),
                port,
                str(flow["proto"]).lower(),
                sent,
                received,
                spkts,
                dpkts,
                answered,
                str(flow.get("interface") or "default"),
            )
        except (KeyError, ValueError, TypeError, OverflowError):
            return None


def rhythm(gaps: list[float], settings: Settings) -> dict[str, float]:
    """Fit a dominant interval while limiting explanations by missing cycles.

    Parameters:
        gaps: Consecutive start intervals or nonoverlapping idle intervals.
        settings: Period, jitter and missing-callback limits.

    Returns:
        Period in seconds, supported fraction, relative jitter and missed fraction.
    """
    if len(gaps) < settings.min_connections - 1:
        return {}
    positive = sorted(g for g in gaps if g >= settings.min_period_seconds)
    if not positive:
        return {}
    candidates = {median(positive)}
    for q in (0.1, 0.25, 0.75, 0.9):
        candidates.add(
            positive[min(len(positive) - 1, int(q * len(positive)))]
        )
    best: dict[str, float] = {}
    for period in candidates:
        if (
            not settings.min_period_seconds
            <= period
            <= settings.max_period_seconds
        ):
            continue
        multiples = [max(1, round(g / period)) for g in gaps]
        matches = [
            i
            for i, (g, m) in enumerate(zip(gaps, multiples))
            if m <= settings.max_missed + 1
            and abs(g - m * period) <= settings.jitter_tolerance * period
        ]
        direct = sum(multiples[i] == 1 for i in matches) / len(gaps)
        support = len(matches) / len(gaps)
        if direct < 0.5 or support < settings.min_support:
            continue
        adjusted = [gaps[i] / multiples[i] for i in matches]
        center, scale = robust_location_scale(adjusted, 0)
        missed = sum(multiples[i] > 1 for i in matches) / len(gaps)
        result = {
            "period": center,
            "support": support,
            "jitter": scale / max(center, 1e-9),
            "missed": missed,
        }
        if not best or (support - 0.1 * missed, -result["jitter"]) > (
            best["support"] - 0.1 * best["missed"],
            -best["jitter"],
        ):
            best = result
    return best


def features(events: list[Observation], settings: Settings) -> dict[str, Any]:
    """Extract timing, directional size and duration features from a bounded window.

    Parameters:
        events: Unique connections sorted by start time.
        settings: Required support, window and period limits.

    Returns:
        Explained recurring behavior, or an empty dictionary without enough support.
    """
    if (
        len(events) < settings.min_connections
        or events[-1].timestamp - events[0].timestamp
        < settings.min_span_seconds
    ):
        return {}
    starts = [e.timestamp for e in events]
    gaps = [b - a for a, b in zip(starts, starts[1:])]
    idle = [
        max(0.0, b.timestamp - a.timestamp - a.duration)
        for a, b in zip(events, events[1:])
    ]
    fits = [
        (rhythm(gaps, settings), "start-to-start"),
        (rhythm(idle, settings), "after-reply"),
    ]
    # A sequence of short bursts can recur even if individual flow gaps differ.
    ordered = sorted(g for g in gaps if g > 0)
    if len(ordered) >= settings.min_connections:
        cut = max(
            range(1, len(ordered)),
            key=lambda i: ordered[i] / max(ordered[i - 1], 1e-9),
        )
        if ordered[cut] > 4 * ordered[cut - 1]:
            boundary = math.sqrt(ordered[cut] * ordered[cut - 1])
            burst_starts = [starts[0]] + [
                starts[i + 1] for i, gap in enumerate(gaps) if gap > boundary
            ]
            fits.append(
                (
                    rhythm(
                        [
                            b - a
                            for a, b in zip(burst_starts, burst_starts[1:])
                        ],
                        settings,
                    ),
                    "burst-to-burst",
                )
            )
    fits = [(fit, mode) for fit, mode in fits if fit]
    if not fits:
        return {}
    fit, mode = max(
        fits,
        key=lambda item: (
            item[0]["support"] - 0.1 * item[0]["missed"],
            -item[0]["jitter"],
        ),
    )
    result: dict[str, Any] = {
        **fit,
        "mode": mode,
        "count": len(events),
        "span": starts[-1] - starts[0],
        "answered": sum(e.answered for e in events) / len(events),
        "overlap": sum(g == 0 for g in idle) / len(idle),
    }
    for name, values in (
        ("sent", [e.sent for e in events]),
        ("received", [e.received for e in events]),
        ("duration", [e.duration for e in events]),
        ("packets_sent", [e.packets_sent for e in events]),
        ("packets_received", [e.packets_received for e in events]),
    ):
        center, scale = robust_location_scale(values, 0)
        result[name] = center
        result[name + "_variation"] = min(100.0, scale / max(center, 1e-6))
        result[name + "_peak_ratio"] = max(values) / max(center, 1.0)
    return result


@dataclass
class Channel:
    """A bounded recent window, independent of Slips time-window rollover."""

    events: deque[Observation]
    last_seen: float
    pending: int = 0
    last_evaluation: float = -1e30
    last_alert: dict[str, float] = field(default_factory=dict)
    count: int = 0
    matching: bool = False
    reports: dict[str, dict[str, Any]] = field(default_factory=dict)


class Detector:
    """Keep capped channel and UID state with incremental ingest."""

    def __init__(self, settings: Settings) -> None:
        """Initialize bounded state.

        Parameters:
            settings: Validated resource and detection limits.
        """
        settings.validate()
        self.settings = settings
        self.channels: OrderedDict[str, Channel] = OrderedDict()
        self.candidates: OrderedDict[str, Channel] = OrderedDict()
        self.seen: OrderedDict[str, None] = OrderedDict()
        self.dirty: set[str] = set()
        self.deleted: set[str] = set()
        self.watermark = 0.0
        self.evictions = 0
        self.candidate_evictions = 0
        self.late_flows = 0

    def process(
        self, observation: Observation, scope: str, now: float
    ) -> tuple[str, dict[str, Any]] | None:
        """Ingest one connection; evaluate only at the configured cadence.

        Parameters:
            observation: Original-direction unicast flow.
            scope: Packet-time network and client identity scope.
            now: Monotonic processing clock, independent of packet time.

        Returns:
            Channel key and recurring features when evaluated successfully.
        """
        s = self.settings
        o = observation
        key = json.dumps(
            [scope, o.src, o.dst, o.port, o.proto], separators=(",", ":")
        )
        dedup = json.dumps([scope, o.uid], separators=(",", ":"))
        if dedup in self.seen:
            return None
        self.seen[dedup] = None
        while len(self.seen) > min(
            32768, s.max_channels * s.window_connections
        ):
            self.seen.popitem(last=False)
        self.watermark = max(self.watermark, o.timestamp)
        cutoff = self.watermark - s.retention_hours * 3600
        if o.timestamp < cutoff:
            self.late_flows += 1
            return None
        channel = self.channels.get(key) or self.candidates.get(key)
        if channel is None:
            if len(self.candidates) >= s.max_candidates:
                old, evicted = self.candidates.popitem(last=False)
                self._discard(old)
                if evicted.last_seen >= cutoff:
                    self.candidate_evictions += 1
            channel = Channel(deque(maxlen=s.min_connections), o.timestamp)
            self.candidates[key] = channel
            self.deleted.discard(key)
        table = self.channels if key in self.channels else self.candidates
        table.move_to_end(key)
        period = max(
            (report["period"] for report in channel.reports.values()),
            default=0,
        )
        if (
            channel.events
            and period
            and o.timestamp - channel.last_seen
            > max(s.alert_cooldown_seconds, period * (s.max_missed + 2))
        ):
            channel.events.clear()
        while channel.events and channel.events[0].timestamp < cutoff:
            channel.events.popleft()
        if not channel.events:
            channel.count = 0
            channel.pending = 0
            channel.matching = False
            channel.reports.clear()
            channel.last_alert.clear()
            channel.last_evaluation = -1e30
        if any(e.uid == o.uid for e in channel.events):
            return None
        if channel.events and o.timestamp < channel.events[-1].timestamp:
            self.late_flows += 1
            ordered = sorted([*channel.events, o], key=lambda e: e.timestamp)
            channel.events = deque(
                ordered[-channel.events.maxlen :], maxlen=channel.events.maxlen
            )
        else:
            channel.events.append(o)
        channel.last_seen = max(channel.last_seen, o.timestamp)
        channel.count += 1
        channel.pending += 1
        self.dirty.add(key)
        if key in self.candidates and len(channel.events) >= s.min_connections:
            if len(self.channels) >= s.max_channels:
                old, evicted = self.channels.popitem(last=False)
                self._discard(old)
                if evicted.last_seen >= cutoff:
                    self.evictions += 1
            self.candidates.pop(key)
            channel.events = deque(channel.events, maxlen=s.window_connections)
            self.channels[key] = channel
        every = s.evaluate_every
        interval = s.evaluate_interval_seconds
        if channel.matching:
            every = max(every, s.stable_evaluate_every)
            interval = max(interval, s.stable_evaluate_interval_seconds)
        if (
            len(channel.events) < s.min_connections
            or channel.pending < every
            or now - channel.last_evaluation < interval
        ):
            return None
        channel.pending = 0
        channel.last_evaluation = now
        result = features(list(channel.events), s)
        channel.matching = bool(result)
        if not result:
            for report in channel.reports.values():
                report["interrupted"] = True
        return (key, result) if result else None

    def _discard(self, key: str) -> None:
        """Queue removal of an evicted checkpoint without retaining its window.

        Parameters:
            key: Removed channel or candidate identity.
        """
        self.dirty.discard(key)
        self.deleted.add(key)
        if (
            len(self.deleted)
            > self.settings.max_channels + self.settings.max_candidates
        ):
            self.deleted.pop()

    def should_alert(
        self,
        key: str,
        kind: str,
        timestamp: float,
        stats: dict[str, Any] | None = None,
    ) -> bool:
        """Report a new pattern, growth milestone or changed rhythm per category.

        Parameters:
            key: Existing channel key.
            kind: Periodicity or suspected C2 category.
            timestamp: Last connection's packet time.
            stats: Current checked pattern, used to recognize a changed rhythm.

        Returns:
            Whether a fresh checked pattern warrants another evidence.
        """
        channel = self.channels[key]
        previous = channel.reports.get(kind)
        period = float((stats or {}).get("period", 0))
        mode = str((stats or {}).get("mode", ""))
        changed = bool(
            previous
            and period
            and previous["period"]
            and (
                max(period / previous["period"], previous["period"] / period)
                >= 2
                or mode != previous["mode"]
            )
        )
        continuation = bool(
            previous and not changed and not previous.get("interrupted")
        )
        if continuation:
            count = channel.count - previous["origin"]
            if count < previous["next_count"]:
                return False
        else:
            if (
                not changed
                and timestamp - channel.last_alert.get(kind, -1e30)
                < self.settings.alert_cooldown_seconds
            ):
                return False
            count = len(channel.events)
            previous = {
                "origin": channel.count - count,
                "started": channel.events[0].timestamp,
                "period": period,
                "mode": mode,
            }
        next_count = self.settings.report_growth_factor
        while next_count <= count:
            next_count *= self.settings.report_growth_factor
        channel.reports[kind] = {
            **previous,
            "next_count": next_count,
            "count": count,
            "continuation": continuation,
            "interrupted": False,
        }
        channel.last_alert[kind] = timestamp
        self.dirty.add(key)
        return True

    def snapshot(self, key: str) -> dict[str, Any]:
        """Serialize one bounded channel for a checkpoint.

        Parameters:
            key: Existing channel key.

        Returns:
            JSON-compatible recent connections and evidence cooldowns.
        """
        channel = self.channels.get(key) or self.candidates[key]
        endpoint = channel.events[-1]
        return {
            "endpoint": [
                endpoint.src,
                endpoint.dst,
                endpoint.port,
                endpoint.proto,
                endpoint.interface,
            ],
            "events": [
                [
                    e.uid,
                    e.timestamp,
                    e.duration,
                    e.sent,
                    e.received,
                    e.packets_sent,
                    e.packets_received,
                    e.answered,
                    e.timewindow,
                ]
                for e in channel.events
            ],
            "last_alert": channel.last_alert,
            "count": channel.count,
            "reports": channel.reports,
        }

    def restore(self, records: list[tuple[str, dict[str, Any]]]) -> None:
        """Restore recent windows without persisting process-clock deadlines.

        Parameters:
            records: Newest-first, capped checkpoint records.
        """
        limit = self.settings.max_channels + self.settings.max_candidates
        for key, record in reversed(records[:limit]):
            src, dst, port, proto, interface = record["endpoint"]
            events = []
            for (
                uid,
                timestamp,
                duration,
                sent,
                received,
                spkts,
                dpkts,
                answered,
                window,
            ) in record["events"][-self.settings.window_connections :]:
                observation = Observation.from_flow(
                    {
                        "type_": "conn",
                        "uid": uid,
                        "starttime": timestamp,
                        "dur": duration,
                        "saddr": src,
                        "daddr": dst,
                        "dport": port,
                        "proto": proto,
                        "sbytes": sent,
                        "dbytes": received,
                        "spkts": spkts,
                        "dpkts": dpkts,
                        "state": "SF" if answered else "S0",
                        "interface": interface,
                    }
                )
                if observation is not None:
                    observation = replace(observation, timewindow=int(window))
                events.append(observation)
            if not events or any(e is None for e in events):
                continue
            events.sort(key=lambda e: e.timestamp)
            channel = Channel(
                deque(
                    events,
                    maxlen=(
                        self.settings.window_connections
                        if len(events) >= self.settings.min_connections
                        else self.settings.min_connections
                    ),
                ),
                events[-1].timestamp,
                last_alert={
                    k: float(v)
                    for k, v in record.get("last_alert", {}).items()
                    if k in {"periodic", "c2"} and math.isfinite(float(v))
                },
                count=max(len(events), int(record.get("count", len(events)))),
                reports=record.get("reports", {}),
            )
            table = (
                self.channels
                if len(events) >= self.settings.min_connections
                else self.candidates
            )
            table[key] = channel
            capacity = (
                self.settings.max_channels
                if table is self.channels
                else self.settings.max_candidates
            )
            if len(table) > capacity:
                old, _ = table.popitem(last=False)
                self._discard(old)
            self.watermark = max(self.watermark, channel.last_seen)
            scope = json.loads(key)[0]
            for e in events:
                self.seen[
                    json.dumps([scope, e.uid], separators=(",", ":"))
                ] = None
            while len(self.seen) > min(
                32768,
                self.settings.max_channels * self.settings.window_connections,
            ):
                self.seen.popitem(last=False)
