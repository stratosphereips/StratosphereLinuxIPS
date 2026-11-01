"""Bounded client, circular schedule and session-duration baselines."""

import math
import json
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from slips_files.common.anomaly_detection import (
    quantile,
    robust_location_scale,
)

from .models import Observation, Settings


@dataclass
class ClientBaseline:
    """Keep distinct active time slots and a bounded duration sample."""

    count: int = 0
    last_seen: float = 0
    activity: dict[int, int] = field(default_factory=dict)
    durations: list[float] = field(default_factory=list)
    duration_count: int = 0
    addresses: list[str] = field(default_factory=list)
    _time_cache: dict[tuple[int, int], tuple[list[float], int, float]] = field(
        default_factory=dict, repr=False
    )

    def observe(self, observation: Observation, settings: Settings) -> None:
        """Fit one accepted connection without letting bursts dominate time.

        Parameters:
            observation: Accepted connection, possibly incomplete.
            settings: Sampling and retention limits.
        """
        self.count += 1
        self.last_seen = max(self.last_seen, observation.timestamp)
        if observation.client_ip not in self.addresses:
            self.addresses.append(observation.client_ip)
            self.addresses = self.addresses[-8:]
        local = datetime.fromtimestamp(
            observation.timestamp, ZoneInfo(settings.timezone)
        )
        day = local.toordinal()
        slot = local.hour * 2 + local.minute // 30
        bits = self.activity.get(day, 0)
        if not bits & (1 << slot):
            self.activity[day] = bits | (1 << slot)
            cutoff = max(self.activity) - settings.history_days + 1
            self.activity = {
                date: value
                for date, value in self.activity.items()
                if date >= cutoff
            }
            self._time_cache.clear()
        if observation.complete:
            value = math.log1p(observation.duration)
            if len(self.durations) < settings.duration_samples:
                self.durations.append(value)
            else:
                self.durations[self.duration_count % len(self.durations)] = (
                    value
                )
            self.duration_count += 1

    def unusual_time(
        self, timestamp: float, settings: Settings
    ) -> dict | None:
        """Score a smoothed daily cycle only with sufficient regular history.

        Parameters:
            timestamp: Connection start time.
            settings: Coverage, concentration and rarity gates.

        Returns:
            Explained timing anomaly, or None for normal/uncertain schedules.
        """
        local = datetime.fromtimestamp(timestamp, ZoneInfo(settings.timezone))
        day = local.toordinal()
        recent = {
            date: bits
            for date, bits in self.activity.items()
            if day - settings.history_days < date <= day
        }
        if len(recent) < settings.time_min_days:
            return None
        day_type = int(local.weekday() >= 5)
        cache_key = day_type, day
        if cache_key not in self._time_cache:
            counts = [0] * 48
            days = 0
            for date, bits in recent.items():
                if int(datetime.fromordinal(date).weekday() >= 5) != day_type:
                    continue
                days += 1
                for slot in range(48):
                    counts[slot] += bool(bits & (1 << slot))
            smooth = [
                0.2
                + sum(
                    weight * counts[(slot + offset) % 48]
                    for offset, weight in (
                        (-2, 1),
                        (-1, 2),
                        (0, 3),
                        (1, 2),
                        (2, 1),
                    )
                )
                / 9
                for slot in range(48)
            ]
            total = sum(smooth)
            probabilities = [value / total for value in smooth]
            concentration = (sum(sorted(probabilities)[-12:]) - 0.25) / 0.75
            if len(self._time_cache) >= 2:
                self._time_cache.clear()
            self._time_cache[cache_key] = probabilities, days, concentration
        probabilities, days, concentration = self._time_cache[cache_key]
        if (
            days < settings.time_min_matching_days
            or concentration < settings.time_min_concentration
        ):
            return None
        probability = probabilities[local.hour * 2 + local.minute // 30]
        if probability >= settings.time_probability_threshold:
            return None
        return {
            "kind": "unusual_time",
            "local_time": local.isoformat(),
            "probability": round(probability, 6),
            "observed_days": days,
        }

    def unusual_duration(
        self, duration: float, settings: Settings
    ) -> dict | None:
        """Check robust log duration and distance beyond observed tails.

        Parameters:
            duration: Completed connection duration in seconds.
            settings: Minimum sample count and conservative deviation gates.

        Returns:
            Explained short/long anomaly, or None.
        """
        if len(self.durations) < settings.duration_min_samples:
            return None
        samples = sorted(self.durations)
        center, sigma = robust_location_scale(samples, min_scale=0.25)
        value = math.log1p(duration)
        zscore = abs(value - center) / sigma
        low = math.expm1(quantile(samples, 0.01, "lower", presorted=True))
        high = math.expm1(quantile(samples, 0.99, "higher", presorted=True))
        reference = high if duration > high else low
        long = duration > high * settings.duration_ratio
        short = duration * settings.duration_ratio < low
        if (
            not (long or short)
            or zscore < settings.duration_zscore
            or abs(duration - reference)
            < settings.duration_min_difference_seconds
        ):
            return None
        return {
            "kind": "unusual_duration",
            "direction": "long" if long else "short",
            "seconds": duration,
            "usual_low_seconds": round(low, 3),
            "usual_high_seconds": round(high, 3),
            "samples": len(samples),
            "robust_zscore": round(zscore, 3),
        }

    def to_dict(self) -> dict[str, Any]:
        """Return bounded JSON-compatible state for a checkpoint.

        Returns:
            Persistent state without derived scoring caches.
        """
        return {
            "count": self.count,
            "last_seen": self.last_seen,
            "activity": self.activity,
            "durations": self.durations,
            "duration_count": self.duration_count,
            "addresses": self.addresses,
        }

    @classmethod
    def from_dict(cls, data: dict, settings: Settings) -> "ClientBaseline":
        """Restore a client under the current state limits.

        Parameters:
            data: Serialized baseline.
            settings: Current history and sample limits.

        Returns:
            Restored bounded baseline.
        """
        activity = {
            int(day): int(bits) & ((1 << 48) - 1)
            for day, bits in data.get("activity", {}).items()
        }
        latest = max(activity, default=0)
        activity = {
            day: bits
            for day, bits in activity.items()
            if day >= latest - settings.history_days + 1
        }
        durations = [
            float(value)
            for value in data.get("durations", [])[
                -settings.duration_samples :
            ]
        ]
        if any(not math.isfinite(value) or value < 0 for value in durations):
            raise ValueError("Invalid saved duration baseline")
        return cls(
            int(data.get("count", 0)),
            float(data.get("last_seen", 0)),
            activity,
            durations,
            int(data.get("duration_count", len(durations))),
            list(data.get("addresses", []))[-8:],
        )


@dataclass
class ServiceBaseline:
    """Represent a service and independently learned client relationships."""

    first_seen: float
    last_seen: float
    timezone: str
    summary: ClientBaseline = field(default_factory=ClientBaseline)
    clients: dict[str, ClientBaseline] = field(default_factory=dict)
    training_days: set[int] = field(default_factory=set)
    clients_complete: bool = True
    alert_hour: int = -1
    alert_count: int = 0
    recent_alerts: dict[str, float] = field(default_factory=dict)

    def ready(self, timestamp: float, settings: Settings) -> bool:
        """Require elapsed traffic time and support across distinct days.

        Parameters:
            timestamp: Connection start time being evaluated.
            settings: Initial service training requirements.

        Returns:
            Whether client novelty detection has sufficient baseline support.
        """
        return (
            timestamp >= self.first_seen + settings.training_hours * 3600
            and self.summary.count >= settings.min_training_connections
            and len(self.training_days) >= settings.min_training_days
        )

    def to_dict(self) -> dict:
        """Return one service checkpoint.

        Returns:
            Persistent metadata and client models.
        """
        return {
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "timezone": self.timezone,
            "summary": self.summary.to_dict(),
            "clients": {
                key: client.to_dict() for key, client in self.clients.items()
            },
            "training_days": sorted(self.training_days),
            "clients_complete": self.clients_complete,
            "alert_hour": self.alert_hour,
            "alert_count": self.alert_count,
            "recent_alerts": self.recent_alerts,
        }

    @classmethod
    def from_dict(cls, data: dict, settings: Settings) -> "ServiceBaseline":
        """Restore service state without carrying schedules across timezones.

        Parameters:
            data: Serialized service state.
            settings: Current configuration and memory limits.

        Returns:
            Restored service; changed timezones require new timing observations.
        """
        clients = data.get("clients", {})
        selected = sorted(
            clients,
            key=lambda key: clients[key].get("last_seen", 0),
            reverse=True,
        )
        service = cls(
            float(data["first_seen"]),
            float(data["last_seen"]),
            settings.timezone,
        )
        service.summary = ClientBaseline.from_dict(data["summary"], settings)
        service.clients = {
            key: ClientBaseline.from_dict(clients[key], settings)
            for key in selected[: settings.max_clients_per_service]
        }
        service.training_days = set(
            sorted(int(day) for day in data.get("training_days", []))[
                -settings.history_days :
            ]
        )
        service.clients_complete = bool(
            data.get("clients_complete", True)
        ) and len(service.clients) == len(clients)
        service.alert_hour = int(data.get("alert_hour", -1))
        service.alert_count = int(data.get("alert_count", 0))
        service.recent_alerts = dict(
            sorted(
                data.get("recent_alerts", {}).items(), key=lambda item: item[1]
            )[-16:]
        )
        if data.get("timezone") != settings.timezone:
            for client in [service.summary, *service.clients.values()]:
                client.activity.clear()
        return service


class ServiceDetector:
    """Incrementally learn and score normalized observations in bounded RAM."""

    def __init__(self, settings: Settings) -> None:
        """Initialize bounded service, duplicate and alert caches.

        Parameters:
            settings: Validated detector configuration.
        """
        self.settings = settings
        self.services: dict[str, ServiceBaseline] = {}
        self.client_count = 0
        self.seen: OrderedDict[str, None] = OrderedDict()
        self.dirty: set[str] = set()
        self.deleted: set[str] = set()
        self.watermark = 0.0
        self._next_prune = 0.0
        self.capacity_skips = 0

    def restore(self, states: dict[str, ServiceBaseline]) -> None:
        """Load service models while respecting a global client limit.

        Parameters:
            states: Services read from the persistent store.
        """
        for key, service in states.items():
            room = max(0, self.settings.max_clients - self.client_count)
            if len(service.clients) > room:
                service.clients = dict(list(service.clients.items())[:room])
                service.clients_complete = False
            self.services[key] = service
            self.client_count += len(service.clients)
            self.watermark = max(self.watermark, service.last_seen)
            self.dirty.add(key)

    def prune(self, timestamp: float) -> None:
        """Expire inactive models at most once per traffic hour.

        Parameters:
            timestamp: Current traffic-time watermark.
        """
        self.watermark = max(self.watermark, timestamp)
        if self.watermark < self._next_prune:
            return
        self._next_prune = self.watermark + 3600
        cutoff = self.watermark - self.settings.retention_days * 86400
        for key, service in list(self.services.items()):
            if service.last_seen < cutoff:
                self.client_count -= len(service.clients)
                del self.services[key]
                self.dirty.discard(key)
                self.deleted.add(key)
            else:
                stale = [
                    identity
                    for identity, client in service.clients.items()
                    if client.last_seen < cutoff
                ]
                for identity in stale:
                    del service.clients[identity]
                    self.client_count -= 1
                if stale:
                    self.dirty.add(key)

    def process(
        self,
        observation: Observation,
        key: str,
        client_id: str,
        allow_learning: bool = True,
    ) -> list[dict]:
        """Score before fitting; unusual/new clients cannot teach normality.

        Parameters:
            observation: Normalized flow.
            key: Network, server identity, transport and port key.
            client_id: Verified local device identity or scoped IP identity.
            allow_learning: Whether this record is eligible to teach normality.

        Returns:
            Explained anomaly reasons, subject to bounded alert suppression.
        """
        if observation.uid in self.seen:
            return []
        self.seen[observation.uid] = None
        if len(self.seen) > 8192:
            self.seen.popitem(last=False)
        self.prune(observation.timestamp)
        service = self.services.get(key)
        if service is None:
            if not observation.service_reply or self.settings.mode == "detect":
                return []
            if len(self.services) >= self.settings.max_services:
                self.capacity_skips += 1
                return []
            service = ServiceBaseline(
                observation.timestamp,
                observation.timestamp,
                self.settings.timezone,
            )
            self.services[key] = service
            self.dirty.add(key)
            self.deleted.discard(key)
        ready = service.ready(observation.timestamp, self.settings)
        training = self.settings.mode == "train" or not ready
        client = service.clients.get(client_id)
        uncertain_identity = client is None and (
            (
                client_id.startswith("ip:")
                and any(
                    identity.startswith("mac:")
                    and observation.client_ip in known.addresses
                    for identity, known in service.clients.items()
                )
            )
            or (
                client_id.startswith("mac:")
                and f"ip:{observation.client_ip}" in service.clients
            )
        )
        reasons = []
        if not training:
            if (
                client is None
                and service.clients_complete
                and not uncertain_identity
            ):
                reasons.append(
                    {
                        "kind": "new_client",
                        "accepted": observation.accepted,
                        "known_clients": len(service.clients),
                    }
                )
            baseline = client or service.summary
            timing = baseline.unusual_time(
                observation.timestamp, self.settings
            )
            duration = (
                baseline.unusual_duration(observation.duration, self.settings)
                if observation.complete
                else None
            )
            for reason in (timing, duration):
                if reason:
                    reasons.append(
                        {
                            **reason,
                            "baseline": "client" if client else "service",
                        }
                    )
        if observation.service_reply:
            service.last_seen = max(service.last_seen, observation.timestamp)
            self.dirty.add(key)
        if client is not None and observation.accepted:
            client.last_seen = max(client.last_seen, observation.timestamp)
        learn = (
            allow_learning
            and self.settings.mode != "detect"
            and observation.accepted
            and (
                training
                or (
                    client is not None
                    and not reasons
                    and self.settings.adapt_known_clients
                )
            )
        )
        if learn:
            if client is None:
                if (
                    len(service.clients)
                    < self.settings.max_clients_per_service
                    and self.client_count < self.settings.max_clients
                ):
                    client = ClientBaseline()
                    service.clients[client_id] = client
                    self.client_count += 1
                else:
                    service.clients_complete = False
                    self.capacity_skips += 1
            service.summary.observe(observation, self.settings)
            if client:
                client.observe(observation, self.settings)
            service.first_seen = min(service.first_seen, observation.timestamp)
            service.last_seen = max(service.last_seen, observation.timestamp)
            service.training_days.add(int(observation.timestamp // 86400))
            service.training_days = set(
                sorted(service.training_days)[-self.settings.history_days :]
            )
            self.dirty.add(key)
        if reasons and self._allow_alert(
            key, client_id, observation.timestamp, reasons
        ):
            self.dirty.add(key)
            return reasons
        return []

    def _allow_alert(
        self, key: str, client: str, timestamp: float, reasons: list[dict]
    ) -> bool:
        """Apply per-client cooldown and a per-service hourly alert ceiling.

        Parameters:
            key: Service key.
            client: Client identity.
            timestamp: Flow start timestamp.
            reasons: Proposed evidence reasons.

        Returns:
            Whether this event can emit evidence.
        """
        service = self.services[key]
        identity = json.dumps([client, [reason["kind"] for reason in reasons]])
        previous = service.recent_alerts.get(identity)
        if (
            previous is not None
            and timestamp - previous < self.settings.alert_cooldown_seconds
        ):
            return False
        hour = int(timestamp // 3600)
        if hour > service.alert_hour:
            service.alert_hour, service.alert_count = hour, 0
        if service.alert_count >= self.settings.max_alerts_per_service_hour:
            return False
        service.alert_count += 1
        service.recent_alerts.pop(identity, None)
        service.recent_alerts[identity] = timestamp
        while len(service.recent_alerts) > 16:
            service.recent_alerts.pop(next(iter(service.recent_alerts)))
        return True
