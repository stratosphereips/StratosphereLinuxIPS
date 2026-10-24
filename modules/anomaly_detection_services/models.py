"""Validated settings and protocol-neutral observations for service models."""

import ipaddress
import math
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

from modules.supported_module_names import Modules
from slips_files.common.mac import classify_mac


@dataclass
class Settings:
    """Bound training, inference, persistence and memory independently."""

    mode: str = "auto"
    timezone: str = "UTC"
    training_hours: float = 168.0
    detect_new_services: bool = True
    max_hosts: int = 1024
    max_new_services_per_host_hour: int = 10
    min_training_connections: int = 30
    min_training_days: int = 3
    time_min_days: int = 14
    time_min_matching_days: int = 3
    time_probability_threshold: float = 0.01
    time_min_concentration: float = 0.35
    duration_min_samples: int = 50
    duration_samples: int = 128
    duration_zscore: float = 4.5
    duration_ratio: float = 3.0
    duration_min_difference_seconds: float = 30.0
    adapt_known_clients: bool = True
    history_days: int = 56
    retention_days: int = 90
    max_services: int = 1024
    max_clients: int = 4096
    max_clients_per_service: int = 64
    alert_cooldown_seconds: float = 3600.0
    max_alerts_per_service_hour: int = 10
    flush_interval_seconds: float = 30.0

    @classmethod
    def from_config(cls, conf: Any) -> "Settings":
        """Read and validate the module's YAML settings.

        Parameters:
            conf: Slips configuration parser.

        Returns:
            Validated settings with bounded resource limits.
        """
        values = {}
        for field in fields(cls):
            value = conf.read_configuration(
                Modules.ANOMALY_DETECTION_SERVICES.value,
                field.name,
                field.default,
            )
            expected = type(field.default)
            if expected is bool:
                if not isinstance(value, bool):
                    raise ValueError(f"{field.name} must be a boolean")
            elif expected in (int, float):
                if isinstance(value, bool):
                    raise ValueError(f"{field.name} must be numeric")
                number = float(value)
                if not math.isfinite(number) or number < 0:
                    raise ValueError(f"Invalid {field.name}")
                if expected is int and number != int(number):
                    raise ValueError(f"{field.name} must be an integer")
                value = expected(number)
            elif not isinstance(value, str):
                raise ValueError(f"{field.name} must be a string")
            values[field.name] = value
        settings = cls(**values)
        settings.validate()
        return settings

    def validate(self) -> None:
        """Reject unsupported modes and unsafe or inconsistent model limits."""
        if self.mode not in {"auto", "train", "detect"}:
            raise ValueError(
                "Service anomaly mode must be auto, train or detect"
            )
        ZoneInfo(self.timezone)
        bounds = {
            "max_hosts": (1, 16384),
            "max_new_services_per_host_hour": (1, 100),
            "max_services": (1, 16384),
            "max_clients": (1, 16384),
            "max_clients_per_service": (1, 512),
            "duration_samples": (10, 512),
            "history_days": (1, 90),
            "retention_days": (1, 3650),
            "min_training_connections": (1, 1000000),
            "min_training_days": (1, self.history_days),
            "time_min_days": (1, self.history_days),
            "time_min_matching_days": (1, self.history_days),
            "duration_min_samples": (10, self.duration_samples),
            "max_alerts_per_service_hour": (1, 100),
            "flush_interval_seconds": (1, 300),
            "duration_ratio": (1.01, 1000),
            "training_hours": (0, 87600),
            "alert_cooldown_seconds": (0, 2592000),
            "duration_min_difference_seconds": (0, 31536000),
            "duration_zscore": (1, 100),
            "time_probability_threshold": (0.000001, 0.1),
            "time_min_concentration": (0, 1),
        }
        for name, (minimum, maximum) in bounds.items():
            if not minimum <= getattr(self, name) <= maximum:
                raise ValueError(
                    f"{name} must be between {minimum} and {maximum}"
                )


@dataclass(frozen=True)
class Observation:
    """One original-direction connection, independently of its adapter."""

    uid: str
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    proto: str
    timestamp: float
    duration: float
    service_reply: bool
    accepted: bool
    complete: bool
    interface: str

    @classmethod
    def from_zeek(cls, flow: dict[str, Any]) -> "Observation | None":
        """Normalize a unicast Zeek connection, including unanswered attempts.

        Parameters:
            flow: Original-direction conn.log fields from new_flow.

        Returns:
            Observation, or None for irrelevant or malformed records.
        """
        try:
            if flow.get("type_") != "conn" or flow.get("flow_source") not in {
                None,
                "",
                "zeek",
            }:
                return None
            proto = str(flow["proto"]).lower()
            if proto not in {"tcp", "udp"}:
                return None
            client = ipaddress.ip_address(flow["saddr"])
            server = ipaddress.ip_address(flow["daddr"])
            for address in (client, server):
                if (
                    address.is_multicast
                    or address.is_unspecified
                    or address.is_loopback
                    or address.is_reserved
                    or str(address) == "255.255.255.255"
                ):
                    return None
            if client == server or client.version != server.version:
                return None
            if any(
                classify_mac(flow.get(key)) in {"broadcast", "multicast"}
                for key in ("smac", "dmac")
            ):
                return None
            sport, dport = int(flow["sport"]), int(flow["dport"])
            if not 0 < sport <= 65535 or not 0 < dport <= 65535:
                return None
            timestamp, duration = float(flow["starttime"]), float(flow["dur"])
            if not all(
                math.isfinite(value) and value >= 0
                for value in (timestamp, duration)
            ):
                return None
            datetime.fromtimestamp(timestamp, timezone.utc)
            uid = flow["uid"]
            if not isinstance(uid, str) or not 0 < len(uid) <= 256:
                return None
            state = str(flow.get("state", ""))
            history = str(flow.get("history", ""))
            reply = int(flow.get("dpkts", 0) or 0) > 0
            if proto == "tcp":
                established = state in {"SF", "S1", "S2", "S3", "RSTO"}
                established |= (
                    state == "RSTR"
                    and "h" in history
                    and ("A" in history or "D" in history)
                )
                service_reply = established or (
                    "S" in history
                    and "h" in history
                    and state not in {"REJ", "RSTRH", "SHR"}
                )
                if (
                    not service_reply
                    and "S" not in history
                    and state not in {"S0", "REJ", "RSTOS0", "SH"}
                ):
                    return None
                accepted = established and (reply or "h" in history)
                complete = accepted and state == "SF"
            else:
                service_reply = reply and int(flow.get("spkts", 0) or 0) > 0
                accepted = service_reply
                complete = False
            return cls(
                uid,
                str(client),
                str(server),
                sport,
                dport,
                proto,
                timestamp,
                duration,
                service_reply,
                accepted,
                complete,
                str(flow.get("interface") or "default"),
            )
        except (KeyError, ValueError, TypeError, OverflowError):
            return None
