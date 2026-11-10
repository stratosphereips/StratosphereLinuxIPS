"""Bounded local-host learning for newly answering services."""

import json
import math
from dataclasses import dataclass, field

from .models import Settings


@dataclass
class HostServices:
    """Remember observed ports independently of their client training."""

    first_seen: float
    last_seen: float
    addresses: list[str] = field(default_factory=list)
    ports: dict[str, dict] = field(default_factory=dict)
    complete: bool = True
    alert_hour: int = -1
    alert_count: int = 0

    def to_dict(self) -> dict:
        """Return bounded state suitable for a checkpoint.

        Returns:
            Host observation times, known ports and warning counters.
        """
        return {
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "addresses": self.addresses,
            "ports": self.ports,
            "complete": self.complete,
            "alert_hour": self.alert_hour,
            "alert_count": self.alert_count,
        }

    @classmethod
    def from_dict(cls, data: dict, settings: Settings) -> "HostServices":
        """Validate saved host state under the current memory limits.

        Parameters:
            data: Saved host record.
            settings: Current host and port limits.

        Returns:
            Restored host without silently forgetting normal ports.
        """
        first, last = float(data["first_seen"]), float(data["last_seen"])
        if first > last or not all(
            math.isfinite(value) and value >= 0 for value in (first, last)
        ):
            raise ValueError("Invalid saved host observation time")
        ports = {}
        for key, item in list(data.get("ports", {}).items())[
            : settings.max_services
        ]:
            proto, port = key.split(":")
            first_reply = float(item["first_reply"])
            last_alert = float(item.get("last_alert", -1))
            last_seen = float(item.get("last_seen", first_reply))
            if (
                proto not in {"tcp", "udp"}
                or not 0 < int(port) <= 65535
                or not math.isfinite(first_reply)
                or first_reply < 0
                or not math.isfinite(last_alert)
                or last_alert < -1
                or not math.isfinite(last_seen)
                or last_seen < first_reply
                or not isinstance(item["normal"], bool)
            ):
                raise ValueError("Invalid saved host service")
            ports[key] = {
                "first_reply": first_reply,
                "last_seen": last_seen,
                "normal": item["normal"],
                "last_alert": last_alert,
            }
        return cls(
            first,
            last,
            list(data.get("addresses", []))[-8:],
            ports,
            bool(data.get("complete", True))
            and len(ports) == len(data.get("ports", {})),
            int(data.get("alert_hour", -1)),
            int(data.get("alert_count", 0)),
        )


class HostInventory:
    """Learn responding local ports without requiring earlier inbound traffic."""

    def __init__(self, settings: Settings) -> None:
        """Initialize bounded host records and derived address lookups.

        Parameters:
            settings: Training, retention and memory limits.
        """
        self.settings = settings
        self.hosts: dict[str, HostServices] = {}
        self.aliases: dict[tuple[str, str], str] = {}
        self.port_count = 0
        self.dirty: set[str] = set()
        self.deleted: dict[str, float] = {}
        self.watermark = 0.0
        self._next_prune = 0.0
        self.capacity_skips = 0

    def restore(self, states: dict[str, HostServices]) -> None:
        """Restore hosts and rebuild bounded, network-scoped IP aliases.

        Parameters:
            states: Validated saved host records.
        """
        for key, host in list(states.items())[: self.settings.max_hosts]:
            if key in self.hosts or len(self.hosts) >= self.settings.max_hosts:
                continue
            room = max(0, self.settings.max_services - self.port_count)
            if len(host.ports) > room:
                host.ports = dict(list(host.ports.items())[:room])
                host.complete = False
            self.hosts[key] = host
            self.port_count += len(host.ports)
            scope, _ = json.loads(key)
            for ip in host.addresses:
                owner = self.aliases.get((scope, ip))
                if (
                    owner is None
                    or host.last_seen >= self.hosts[owner].last_seen
                ):
                    self.aliases[scope, ip] = key
            self.watermark = max(self.watermark, host.last_seen)
            self.dirty.add(key)

    def observe_host(
        self, scope: str, identity: str, ip: str, timestamp: float
    ) -> str | None:
        """Start or resume a local host's clock from any eligible activity.

        Parameters:
            scope: Verified network or isolated run scope.
            identity: Verified MAC or IP fallback.
            ip: Address seen on this network.
            timestamp: Observation time, in the same clock as the flows.

        Returns:
            Host key, or None when memory is full or frozen learning is unknown.
        """
        self.prune(timestamp)
        key = json.dumps([scope, identity], separators=(",", ":"))
        previous = self.aliases.get((scope, ip))
        if key not in self.hosts and previous in self.hosts:
            old_identity = json.loads(previous)[1]
            if identity.startswith("ip:"):
                key = previous
            elif old_identity.startswith("ip:"):
                self.hosts[key] = self.hosts.pop(previous)
                self.dirty.discard(previous)
                self.deleted[previous] = self.hosts[key].last_seen
                for address in self.hosts[key].addresses:
                    self.aliases[scope, address] = key
                self.dirty.add(key)
                self.deleted.pop(key, None)
        if key not in self.hosts:
            if self.settings.mode == "detect":
                return None
            if len(self.hosts) >= self.settings.max_hosts:
                self.capacity_skips += 1
                return None
            self.hosts[key] = HostServices(timestamp, timestamp)
            self.deleted.pop(key, None)
        host = self.hosts[key]
        host.first_seen = min(host.first_seen, timestamp)
        host.last_seen = max(host.last_seen, timestamp)
        if ip and ip not in host.addresses:
            if len(host.addresses) == 8:
                expired = host.addresses.pop(0)
                if self.aliases.get((scope, expired)) == key:
                    self.aliases.pop((scope, expired))
            host.addresses.append(ip)
        owner = self.aliases.get((scope, ip))
        if ip and (
            owner is None or host.last_seen >= self.hosts[owner].last_seen
        ):
            self.aliases[scope, ip] = key
        self.dirty.add(key)
        return key

    def check_service(
        self,
        key: str,
        proto: str,
        port: int,
        timestamp: float,
        allow_learning: bool = True,
        previously_known: bool = False,
    ) -> dict | None:
        """Check an answering port before learning anything from its client.

        Parameters:
            key: Local host key returned by observe_host.
            proto: Answering TCP or UDP transport.
            port: Answering destination port.
            timestamp: Original connection start time.
            allow_learning: Whether this flow can teach a normal service.
            previously_known: Service already present in the older detector.

        Returns:
            New-service reason, or None during training or warning suppression.
        """
        host = self.hosts[key]
        training = (
            timestamp <= host.first_seen + self.settings.training_hours * 3600
        )
        learn = (
            allow_learning
            and self.settings.mode != "detect"
            and (training or self.settings.mode == "train")
        )
        port_key = f"{proto}:{port}"
        item = host.ports.get(port_key)
        if item is None:
            if self.port_count >= self.settings.max_services:
                host.complete = False
                self.dirty.add(key)
                self.capacity_skips += 1
                return None
            if training and not learn:
                return None
            item = {
                "first_reply": timestamp,
                "last_seen": timestamp,
                "normal": learn or previously_known,
                "last_alert": -1.0,
            }
            host.ports[port_key] = item
            self.port_count += 1
        elif learn:
            item["normal"] = True
            item["first_reply"] = min(item["first_reply"], timestamp)
        item["last_seen"] = max(item["last_seen"], timestamp)
        self.dirty.add(key)
        if (
            training
            or self.settings.mode == "train"
            or item["normal"]
            or not host.complete
        ):
            return None
        if (
            item["last_alert"] >= 0
            and timestamp - item["last_alert"]
            < self.settings.alert_cooldown_seconds
        ):
            return None
        hour = int(timestamp // 3600)
        if hour > host.alert_hour:
            host.alert_hour, host.alert_count = hour, 0
        if host.alert_count >= self.settings.max_new_services_per_host_hour:
            return None
        host.alert_count += 1
        item["last_alert"] = timestamp
        return {
            "kind": "new_service",
            "training_hours": self.settings.training_hours,
            "known_services": sum(
                port["normal"] for port in host.ports.values()
            ),
        }

    def prune(self, timestamp: float) -> None:
        """Expire inactive hosts at most once per traffic hour.

        Parameters:
            timestamp: Latest observation time.
        """
        self.watermark = max(self.watermark, timestamp)
        if self.watermark < self._next_prune:
            return
        self._next_prune = self.watermark + 3600
        cutoff = self.watermark - self.settings.retention_days * 86400
        self.deleted = {
            key: timestamp
            for key, timestamp in self.deleted.items()
            if timestamp >= cutoff
        }
        for key, host in list(self.hosts.items()):
            if host.last_seen >= cutoff:
                stale = [
                    port
                    for port, item in host.ports.items()
                    if item["last_seen"] < cutoff
                ]
                for port in stale:
                    del host.ports[port]
                    self.port_count -= 1
                if stale:
                    self.dirty.add(key)
                continue
            scope, _ = json.loads(key)
            for ip in host.addresses:
                if self.aliases.get((scope, ip)) == key:
                    self.aliases.pop((scope, ip))
            self.port_count -= len(host.ports)
            del self.hosts[key]
            self.dirty.discard(key)
            self.deleted[key] = host.last_seen
