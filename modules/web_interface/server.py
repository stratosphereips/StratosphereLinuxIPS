# SPDX-License-Identifier: GPL-2.0-only
"""Serve the run-scoped Slips web interface."""

import argparse
import base64
import fcntl
import ipaddress
import json
import math
import os
import re
import socket
import sqlite3
import tempfile
import time
import traceback
from datetime import datetime
from collections import Counter, defaultdict
from http import HTTPStatus, cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import parse_qs, unquote, urlparse

import psutil
import redis
import yaml

from managers.network_state import collect_network_state
from slips_files.core.database.sqlite_db.host_profiles import HostProfileStore
from modules.supported_module_names import Modules
from slips_files.core.helpers.whitelist.whitelist_parser import (
    web_whitelist_path,
)
from modules.web_interface.history import (
    BACKEND_DISCONNECTED_KEY,
    BACKEND_HEARTBEAT_KEY,
    connect_history,
    initialize_history,
)
from slips_files.core.database.redis_db.redis_auth import (
    ensure_web_password_matches_redis_password,
    try_connect_with_and_without_password,
    verify_web_password,
)


from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.web_auth import (
    SESSION_COOKIE_NAME,
    SESSION_TTL_SECONDS,
    is_locked_out,
    issue_token,
    login_page_html,
    record_failed_login,
    record_successful_login,
    validate_token,
)

LOOPBACK_ADDRESS = "127.0.0.1"
PROFILE_PREFIX = "profile_"
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 100
MAX_FLOW_LIMIT = 1000
MAX_ZEEK_FALLBACK_BYTES = 32 * 1024 * 1024
ZEEK_FALLBACK_LOGS = (
    "conn",
    "dns",
    "http",
    "ssl",
    "ssh",
    "dhcp",
    "files",
    "notice",
    "quic",
    "arp",
)
MAX_CHART_POINTS = 1200
CLIENT_REQUEST_TIMEOUT_SECONDS = 15
BACKEND_HEARTBEAT_TIMEOUT_SECONDS = 15
P2P_RECENT_ACTIVITY_SECONDS = 15 * 60
INTERNAL_PID_NAMES = {
    "web_interface_history",
    "web_interface_detection_backfill",
}
TIME_RANGES = {
    "live": 60 * 60,
    "1h": 60 * 60,
    "24h": 24 * 60 * 60,
    "7d": 7 * 24 * 60 * 60,
}
METRIC_RANGES = {
    "5m": 5 * 60,
    "15m": 15 * 60,
    "1h": 60 * 60,
    "24h": 24 * 60 * 60,
}
# pragma: allowlist secret
EVIDENCE_MODULE = {
    "ARP_SCAN": Modules.ARP,
    "ARP_OUTSIDE_LOCALNET": Modules.ARP,
    "UNSOLICITED_ARP": Modules.ARP,
    "MITM_ARP_ATTACK": Modules.ARP,
    "PASSWORD_GUESSING": Modules.BRUTE_FORCE_DETECTOR,
    "ANOMALOUS_FLOW": Modules.ANOMALY_DETECTION_HTTPS,
    "SUSPICIOUS_USER_AGENT": Modules.HTTP_ANALYZER,
    "EMPTY_CONNECTIONS": Modules.HTTP_ANALYZER,
    "INCOMPATIBLE_USER_AGENT": Modules.HTTP_ANALYZER,
    "EXECUTABLE_MIME_TYPE": Modules.HTTP_ANALYZER,
    "MULTIPLE_USER_AGENT": Modules.HTTP_ANALYZER,
    "HTTP_TRAFFIC": Modules.HTTP_ANALYZER,
    "MALICIOUS_JARM": Modules.IP_INFO,
    "NETWORK_GPS_LOCATION_LEAKED": Modules.LEAK_DETECTOR,
    "HORIZONTAL_PORT_SCAN": Modules.NETWORK_DISCOVERY,
    "VERTICAL_PORT_SCAN": Modules.NETWORK_DISCOVERY,
    "ICMP_TIMESTAMP_SCAN": Modules.NETWORK_DISCOVERY,
    "ICMP_ADDRESS_SCAN": Modules.NETWORK_DISCOVERY,
    "ICMP_ADDRESS_MASK_SCAN": Modules.NETWORK_DISCOVERY,
    "DHCP_SCAN": Modules.NETWORK_DISCOVERY,
    "COMMAND_AND_CONTROL_CHANNEL": Modules.RNN_CC_DETECTION,
    "MALICIOUS_IP_FROM_P2P_NETWORK": Modules.P2P_TRUST,
    "P2P_REPORT": Modules.P2P_TRUST,
}  # pragma: allowlist secret
MODULE_BY_EVIDENCE_PREFIX = {
    "ARP_": Modules.ARP,
    "HTTP_": Modules.HTTP_ANALYZER,
    "ML_LINEAR_": Modules.ML_LINEAR_MODEL,
    "ML_ONLINE_": Modules.ML_ONLINE_MODEL,
    "PORT_SCAN": Modules.NETWORK_DISCOVERY,
    "VERTICAL_PORT_SCAN": Modules.NETWORK_DISCOVERY,
    "HORIZONTAL_PORT_SCAN": Modules.NETWORK_DISCOVERY,
    "RNN_": Modules.RNN_CC_DETECTION,
    "LEAK": Modules.LEAK_DETECTOR,
    "MALICIOUS_JARM": Modules.IP_INFO,
    "THREAT_INTELLIGENCE": Modules.THREAT_INTELLIGENCE,
}
TI_FIELDS = (
    "geocountry",
    "asn",
    "reverse_dns",
    "threat_level",
    "score",
    "confidence",
    "VirusTotal",
    "threatintelligence",
    "SNI",
)

CONFIG_SECTION_DESCRIPTIONS = {
    "update": "How this Slips installation checks for and selects software updates.",
    "output": "Names and destinations of files produced by this analysis.",
    "parameters": "Core capture, profiling, time-window, and processing behaviour.",
    "Debug": "Diagnostic output controls used while troubleshooting Slips.",
    "detection": "Global scoring, alerting, and enforcement thresholds.",
    "modules": "Which detection and support modules are enabled for this run.",
    "whitelists": "Sources Slips trusts and the traffic or alerts they suppress.",
    "web_interface": "Run-scoped local web server settings.",
    "global_p2p": "Global peer-to-peer threat-intelligence behaviour.",
    "local_p2p": "Local peer-to-peer transport and identity settings.",
}
SENSITIVE_CONFIG_TERMS = (
    "api_key",
    "apikey",
    "password",
    "private_key",
    "secret",
    "token",
)
WHITELIST_TYPES = {
    "IPs": "IP address",
    "domains": "Domain",
    "organizations": "Organization",
    "macs": "MAC address",
}
ARP_EVIDENCE_TYPES = (
    "ARP_SCAN",
    "ARP_OUTSIDE_LOCALNET",
    "UNSOLICITED_ARP",
    "MITM_ARP_ATTACK",
)


class RunMismatchError(RuntimeError):
    """Raised when Redis belongs to a different Slips output directory."""


class RunDataReader:
    """Read bounded live and historical data for exactly one Slips run."""

    def __init__(
        self,
        redis_port: int,
        output_dir: str,
        host_profiles_path: str = "permanent/host_profiles/hosts.sqlite",
    ) -> None:
        """
        Initialize run data sources.

        Parameters:
            redis_port: Redis port assigned to this run.
            output_dir: Output directory assigned to this run.
            host_profiles_path: Shared host profile database path.
        """
        self.redis_port = redis_port
        self.output_dir = Path(output_dir)
        self.sqlite_path = self.output_dir / "databases" / "flows.sqlite"
        self.history_path = (
            self.output_dir / "web_interface" / "history.sqlite"
        )
        self.host_profiles_path = Path(host_profiles_path)
        self.redis = try_connect_with_and_without_password(
            redis.Redis,
            host=LOOPBACK_ADDRESS,
            port=redis_port,
            db=0,
            decode_responses=True,
            socket_timeout=2,
        )
        self.cache = try_connect_with_and_without_password(
            redis.Redis,
            host=LOOPBACK_ADDRESS,
            port=6379,
            db=1,
            decode_responses=True,
            socket_timeout=2,
        )
        self._processes: Dict[int, psutil.Process] = {}
        initialize_history(self.history_path)
        self.score_mode, self.alert_threshold = self._detector_score_settings()

    def _metadata_snapshot(self, suffix: str) -> Optional[Path]:
        """
        Find one immutable input snapshot captured for this run.

        Parameters:
            suffix: File suffix including its leading dot.

        Returns:
            Matching metadata path, or None when metadata was disabled.
        """
        metadata_dir = self.output_dir / "metadata"
        return next(iter(sorted(metadata_dir.glob(f"*{suffix}"))), None)

    def _run_config(self) -> tuple[Dict[str, Any], Optional[Path]]:
        """
        Load the YAML configuration snapshot supplied to this run.

        Returns:
            Parsed top-level configuration and its snapshot path.
        """
        path = self._metadata_snapshot(".yaml")
        if path is None:
            return {}, None
        try:
            with path.open("r", encoding="utf-8") as handle:
                value = yaml.safe_load(handle) or {}
            return (value if isinstance(value, dict) else {}), path
        except (OSError, yaml.YAMLError):
            return {}, path

    @staticmethod
    def _setting_label(name: str) -> str:
        """
        Convert one YAML key into a readable setting name.

        Parameters:
            name: Raw YAML mapping key.

        Returns:
            Human-readable label.
        """
        return str(name).replace("_", " ").strip().capitalize()

    @classmethod
    def _setting_explanation(cls, section: str, path: str) -> str:
        """
        Explain the operational role of one configuration setting.

        Parameters:
            section: Top-level configuration section.
            path: Dot-separated setting path below that section.

        Returns:
            Concise plain-language explanation.
        """
        name = path.rsplit(".", 1)[-1]
        label = cls._setting_label(name).lower()
        explicit = {
            "parameters.time_window_width": (
                "How long evidence is accumulated together before Slips starts "
                "a new analysis time window."
            ),
            "parameters.analysis_direction": (
                "Whether Slips analyses only outbound activity or traffic in "
                "both directions."
            ),
            "detection.evidence_detection_threshold": (
                "Base accumulated-threat threshold used to form alerts in "
                "finite analyses."
            ),
            "detection.risk_accumulated_threat_level": (
                "Risk-adjusted score a live host must reach before Slips forms "
                "an alert."
            ),
            "whitelists.local_whitelist_path": (
                "Whitelist file captured with this run and parsed into the "
                "active local rules."
            ),
            "whitelists.enable_local_whitelist": (
                "Controls whether locally configured IP, domain, organization, "
                "and MAC rules are applied."
            ),
            "whitelists.enable_online_whitelist": (
                "Controls whether the downloaded benign-domain list is used "
                "when evaluating domains."
            ),
            "web_interface.enabled": (
                "Controls whether this run starts its web interface."
            ),
            "web_interface.bind": (
                "Chooses localhost-only access or the monitored interface address."
            ),
            "web_interface.port": "TCP port used by the web server.",
        }
        full_path = f"{section}.{path}"
        if full_path in explicit:
            return explicit[full_path]
        lowered = name.lower()
        if lowered.startswith(("enable_", "use_")):
            feature = label.removeprefix("enable ").removeprefix("use ")
            return f"Turns {feature} on or off."
        if "threshold" in lowered:
            return f"Decision boundary Slips uses for {label}."
        if any(
            term in lowered
            for term in ("timeout", "period", "interval", "width")
        ):
            return f"Time interval controlling {label}."
        if any(
            term in lowered for term in ("path", "file", "directory", "dir")
        ):
            return f"File or directory Slips uses for {label}."
        if lowered.endswith("port"):
            return f"Network port used for {label}."
        component = cls._setting_label(section).lower()
        return f"Value used by the {component} component for {label}."

    @classmethod
    def _flatten_settings(
        cls,
        section: str,
        value: Any,
        prefix: str = "",
    ) -> List[Dict[str, Any]]:
        """
        Flatten a configuration section into displayable leaf settings.

        Parameters:
            section: Top-level configuration section.
            value: Current mapping or leaf value.
            prefix: Dot-separated path accumulated during recursion.

        Returns:
            Ordered setting records for the web interface.
        """
        if isinstance(value, dict):
            settings: List[Dict[str, Any]] = []
            for key, nested in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                settings.extend(cls._flatten_settings(section, nested, path))
            return settings
        lowered_path = prefix.lower()
        sensitive = any(
            term in lowered_path for term in SENSITIVE_CONFIG_TERMS
        )
        return [
            {
                "key": prefix,
                "label": cls._setting_label(prefix.rsplit(".", 1)[-1]),
                "value": (
                    "Configured — hidden" if sensitive and value else value
                ),
                "value_type": type(value).__name__,
                "sensitive": sensitive and bool(value),
                "explanation": cls._setting_explanation(section, prefix),
            }
        ]

    def configuration(self) -> Dict[str, Any]:
        """
        Return the run's captured configuration as explained settings.

        Returns:
            Sectioned configuration snapshot without exposing secret values.
        """
        config, path = self._run_config()
        sections = []
        total = 0
        for name, value in config.items():
            settings = self._flatten_settings(str(name), value)
            total += len(settings)
            sections.append(
                {
                    "key": str(name),
                    "title": self._setting_label(str(name)),
                    "description": CONFIG_SECTION_DESCRIPTIONS.get(
                        str(name),
                        f"Settings used by the {self._setting_label(str(name)).lower()} component.",
                    ),
                    "settings": settings,
                }
            )
        return {
            "source": path.name if path else None,
            "captured": path is not None,
            "total": total,
            "sections": sections,
        }

    @staticmethod
    def _whitelist_effect(direction: str, ignored: str) -> str:
        """
        Describe one parsed whitelist rule's suppression semantics.

        Parameters:
            direction: Source, destination, or both sides of activity.
            ignored: Alerts, flows, or both record classes.

        Returns:
            Human-readable rule effect.
        """
        side = {
            "src": "source side",
            "dst": "destination side",
            "both": "source or destination side",
        }.get(direction, direction)
        target = {
            "alerts": "evidence and alerts",
            "flows": "flows",
            "both": "flows, evidence, and alerts",
        }.get(ignored, ignored)
        return f"Suppresses {target} when this value appears on the {side}."

    def _runtime_whitelist_rules(self) -> List[Dict[str, Any]]:
        """
        Read the local whitelist rules parsed into this run's Redis database.

        Returns:
            Active parsed rule records, falling back to the captured file.
        """
        rules: List[Dict[str, Any]] = []
        try:
            for redis_type, label in WHITELIST_TYPES.items():
                values = self.redis.hgetall(f"whitelist_{redis_type}")
                for value, serialized in values.items():
                    details = self._loads(serialized, {})
                    if not isinstance(details, dict):
                        details = {}
                    direction = str(details.get("from", "both"))
                    ignored = str(details.get("what_to_ignore", "alerts"))
                    rules.append(
                        {
                            "type": label,
                            "value": str(value),
                            "direction": direction,
                            "ignore": ignored,
                            "effect": self._whitelist_effect(
                                direction, ignored
                            ),
                            "source": "Parsed runtime rule",
                        }
                    )
        except (redis.RedisError, TypeError):
            rules = []
        if rules:
            config, _ = self._run_config()
            settings = config.get("whitelists", {})
            if not isinstance(settings, dict):
                settings = {}
            managed_path = web_whitelist_path(
                str(
                    settings.get(
                        "local_whitelist_path", "config/whitelist.conf"
                    )
                )
            )
            try:
                managed = {
                    line.split(",", 3)[1]
                    for line in managed_path.read_text(
                        encoding="utf-8"
                    ).splitlines()
                    if line.startswith("ip,") and len(line.split(",", 3)) == 4
                }
            except OSError:
                managed = set()
            for rule in rules:
                rule["managed"] = (
                    rule["type"] == "IP address" and rule["value"] in managed
                )
                if rule["managed"]:
                    rule["source"] = "Added from web"
            return sorted(
                rules, key=lambda item: (item["type"], item["value"])
            )
        if not hasattr(self, "output_dir"):
            return []
        path = self._metadata_snapshot(".conf")
        if path is None:
            return []
        try:
            for raw in path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith(("#", ";", '"IoCType"')):
                    continue
                parts = [part.strip() for part in line.split(",")]
                if len(parts) < 4:
                    continue
                type_name, value, direction, ignored = parts[:4]
                label = {
                    "ip": "IP address",
                    "domain": "Domain",
                    "organization": "Organization",
                    "mac": "MAC address",
                }.get(type_name.lower(), self._setting_label(type_name))
                rules.append(
                    {
                        "type": label,
                        "value": value,
                        "direction": direction,
                        "ignore": ignored,
                        "effect": self._whitelist_effect(direction, ignored),
                        "source": "Captured local file",
                    }
                )
        except OSError:
            return []
        return rules

    def whitelists(self) -> Dict[str, Any]:
        """
        Return whitelist sources and the exact local rules used by this run.

        Returns:
            Whitelist status, counts, sources, and parsed local rules.
        """
        config, _ = self._run_config()
        settings = config.get("whitelists", {})
        if not isinstance(settings, dict):
            settings = {}
        rules = self._runtime_whitelist_rules()
        counts = dict(Counter(str(rule["type"]) for rule in rules))
        try:
            tranco_count = int(self.cache.zcard("tranco_whitelisted_domains"))
        except (redis.RedisError, TypeError, ValueError):
            tranco_count = 0
        path = self._metadata_snapshot(".conf")
        return {
            "local_enabled": bool(
                settings.get("enable_local_whitelist", True)
            ),
            "online_enabled": bool(
                settings.get("enable_online_whitelist", True)
            ),
            "local_source": (
                path.name if path else settings.get("local_whitelist_path")
            ),
            "online_source": settings.get("online_whitelist"),
            "online_update_period": settings.get(
                "online_whitelist_update_period"
            ),
            "online_domain_limit": settings.get("tranco_top_benign_limit"),
            "online_domains_loaded": tranco_count,
            "counts": counts,
            "total": len(rules),
            "rules": rules,
        }

    @staticmethod
    def _normalize_whitelist_ip(value: Any) -> str:
        """Validate one IP, IP:port, or port-only whitelist value.

        Parameters:
            value: Untrusted value from the browser.

        Returns:
            Canonical rule value accepted by the Slips whitelist parser.
        """
        if not isinstance(value, str) or not value or len(value) > 128:
            raise ValueError("Enter an IP address, IP:port, or *:port")
        candidate = value.strip()
        if not candidate or "%" in candidate:
            raise ValueError("Invalid IP address or port")
        if candidate.startswith("["):
            address, separator, port = candidate[1:].partition("]:")
            if not separator:
                raise ValueError("Use [IPv6]:port for an IPv6 port rule")
            try:
                normalized = str(ipaddress.IPv6Address(address))
            except ValueError as error:
                raise ValueError("Invalid IPv6 address") from error
            prefix = f"[{normalized}]"
        elif candidate.startswith("*:"):
            prefix, port = "*", candidate[2:]
        elif candidate.count(":") == 1:
            address, port = candidate.rsplit(":", 1)
            try:
                prefix = str(ipaddress.IPv4Address(address))
            except ValueError as error:
                raise ValueError("Invalid IPv4 address") from error
        else:
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError as error:
                raise ValueError("Invalid IP address") from error
        if not port.isdecimal() or not 1 <= int(port) <= 65535:
            raise ValueError("Port must be between 1 and 65535")
        return f"{prefix}:{int(port)}"

    def save_whitelist_rule(
        self, action: Any, value: Any, direction: Any, ignored: Any
    ) -> Dict[str, Any]:
        """Persist a web-managed IP rule and update the current run.

        Parameters:
            action: Add or remove the rule.
            value: IP address, IP:port, or port-only value.
            direction: Source, destination, or both sides.
            ignored: Flows, evidence and alerts, or both.

        Returns:
            The saved rule and whether it was added or removed.
        """
        if not isinstance(action, str) or action not in {"add", "remove"}:
            raise ValueError("Invalid whitelist action")
        if not isinstance(direction, str) or direction not in {
            "src",
            "dst",
            "both",
        }:
            raise ValueError("Choose source, destination, or both")
        if not isinstance(ignored, str) or ignored not in {
            "alerts",
            "flows",
            "both",
        }:
            raise ValueError("Choose what the rule suppresses")
        normalized = self._normalize_whitelist_ip(value)
        config, _ = self._run_config()
        settings = config.get("whitelists", {})
        if not isinstance(settings, dict) or not settings.get(
            "enable_local_whitelist", True
        ):
            raise ValueError("Local whitelisting is disabled for this run")
        if not self.response_metadata()["backend_status"]["connected"]:
            raise ValueError("Slips must be running to change whitelist rules")
        source = str(
            settings.get("local_whitelist_path", "config/whitelist.conf")
        )
        path = web_whitelist_path(source)
        if not path.parent.is_dir():
            raise ValueError("The configured whitelist directory is missing")
        lock_path = path.with_name(path.name + ".lock")
        with lock_path.open("a", encoding="utf-8") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            lines = (
                path.read_text(encoding="utf-8").splitlines()
                if path.exists()
                else ["; Rules added through the Slips web interface"]
            )
            existing = {
                parts[1]: line
                for line in lines
                if (parts := line.split(",", 3))
                and len(parts) == 4
                and parts[0] == "ip"
            }
            if action == "add":
                if normalized in existing or self.redis.hexists(
                    "whitelist_IPs", normalized
                ):
                    raise ValueError("This value already has a whitelist rule")
                lines.append(f"ip,{normalized},{direction},{ignored}")
            else:
                if normalized not in existing:
                    raise ValueError(
                        "Only web-managed rules can be removed here"
                    )
                lines = [
                    line for line in lines if line != existing[normalized]
                ]
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=path.parent, delete=False
            ) as temporary:
                temporary.write("\n".join(lines) + "\n")
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary_path = Path(temporary.name)
            try:
                os.replace(temporary_path, path)
            finally:
                temporary_path.unlink(missing_ok=True)
            if action == "add":
                self.redis.hset(
                    "whitelist_IPs",
                    normalized,
                    json.dumps({"from": direction, "what_to_ignore": ignored}),
                )
            else:
                self.redis.hdel("whitelist_IPs", normalized)
        return {
            "action": action,
            "value": normalized,
            "direction": direction,
            "ignore": ignored,
        }

    @staticmethod
    def _direction_matches(entity_direction: Any, rule_direction: str) -> bool:
        """
        Check whether an evidence entity is covered by a whitelist side.

        Parameters:
            entity_direction: Slips SRC or DST entity direction.
            rule_direction: Parsed src, dst, or both rule direction.

        Returns:
            True when the rule applies to the entity's side.
        """
        if rule_direction == "both":
            return True
        normalized = str(entity_direction or "").lower()
        return rule_direction in normalized

    def _whitelist_matches_for_record(
        self,
        record: Dict[str, Any],
        rules: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Reconstruct visible local-rule matches for a whitelisted evidence.

        Parameters:
            record: Parsed durable evidence object.
            rules: Parsed runtime whitelist rules.

        Returns:
            Matching entity and rule details that can be explained in the UI.
        """
        candidates: List[tuple[str, str, str, Any, Any]] = []
        for role in ("attacker", "victim"):
            entity = record.get(role)
            if not isinstance(entity, dict):
                continue
            direction = entity.get("direction")
            value = entity.get("value")
            indicator = str(entity.get("ioc_type") or "").upper()
            if value and indicator == "IP":
                port = (
                    record.get("src_port")
                    if self._direction_matches(direction, "src")
                    else record.get("dst_port")
                )
                candidates.append(
                    (role, "IP address", str(value), direction, port)
                )
            if value and indicator == "DOMAIN":
                candidates.append((role, "Domain", str(value), "dst", None))
            for ip in entity.get("DNS_resolution") or []:
                candidates.append(
                    (role, "IP address", str(ip), direction, None)
                )
            domains = list(entity.get("queries") or [])
            domains.extend(entity.get("CNAME") or [])
            if entity.get("SNI"):
                domains.append(entity["SNI"])
            for domain in domains:
                candidates.append((role, "Domain", str(domain), "dst", None))
        matches = []
        seen = set()
        for role, type_name, value, direction, port in candidates:
            for rule in rules:
                if rule.get("type") != type_name:
                    continue
                rule_value = str(rule.get("value") or "")
                value_matches = value == rule_value
                if type_name == "IP address" and port is not None:
                    address = f"[{value}]" if ":" in value else value
                    value_matches = value_matches or rule_value in {
                        f"{address}:{port}",
                        f"*:{port}",
                    }
                if type_name == "Domain":
                    value_matches = value == rule_value or value.endswith(
                        f".{rule_value}"
                    )
                if not value_matches:
                    continue
                if str(rule.get("ignore")) not in {"alerts", "both"}:
                    continue
                if not self._direction_matches(
                    direction, str(rule.get("direction"))
                ):
                    continue
                identifier = (role, type_name, value, rule_value)
                if identifier in seen:
                    continue
                seen.add(identifier)
                matches.append(
                    {
                        "entity": role,
                        "type": type_name,
                        "value": value,
                        "rule": rule_value,
                        "direction": rule.get("direction"),
                        "ignore": rule.get("ignore"),
                        "effect": rule.get("effect"),
                    }
                )
        return matches

    def _annotate_whitelisted_evidence(
        self, items: List[Dict[str, Any]]
    ) -> None:
        """
        Attach Slips' whitelist decision and matching entities to evidence.

        The whitelist decision is durably persisted in SQLite's
        `evidence.whitelisted` column by Evidence Handler as soon as it
        excludes an evidence, so there's no separate "live" source to
        reconcile here.

        Parameters:
            items: Individual or grouped evidence API records.
        """
        if not items:
            return
        rules = self._runtime_whitelist_rules()
        for item in items:
            grouped_ids = item.pop("_evidence_ids", None)
            if isinstance(grouped_ids, list):
                item["whitelisted"] = (
                    int(item.get("whitelisted_count") or 0) > 0
                )
                continue
            item["whitelisted"] = item.get("whitelisted") in (True, 1, "1")
            item["whitelist_matches"] = (
                self._whitelist_matches_for_record(item, rules)
                if item["whitelisted"]
                else []
            )

    def _annotate_p2p_reporters(self, items: List[Dict[str, Any]]) -> None:
        """Add known reporter peer IDs to P2P evidence on one bounded page.

        Parameters:
            items: Individual or grouped evidence API records.
        """
        relevant = [
            item
            for item in items
            if item.get("evidence_type") == "MALICIOUS_IP_FROM_P2P_NETWORK"
        ]
        if not relevant:
            return
        targets = sorted(
            {
                str(item.get("profile_ip") or "")
                for item in relevant
                if item.get("profile_ip")
            }
        )
        reporters: Dict[str, List[str]] = {}
        trust_path = getattr(
            self,
            "p2p_trust_path",
            Path("permanent") / "p2p_trust_runtime" / "trustdb.db",
        )
        if targets and trust_path.exists():
            try:
                placeholders = ",".join("?" for _ in targets)
                with sqlite3.connect(
                    f"file:{trust_path}?mode=ro", uri=True, timeout=1
                ) as connection:
                    for target, peer_id in connection.execute(
                        "SELECT DISTINCT reported_key, reporter_peerid "
                        "FROM reports WHERE key_type = 'ip' "
                        f"AND reported_key IN ({placeholders}) "
                        "ORDER BY reporter_peerid",
                        targets,
                    ):
                        reporters.setdefault(str(target), []).append(
                            str(peer_id)
                        )
            except sqlite3.Error:
                pass
        for item in relevant:
            item["reporting_peers"] = reporters.get(
                str(item.get("profile_ip") or ""), []
            )

    def _detector_score_settings(self) -> tuple[str, float]:
        """
        Read the run's real Slips alert-score mode and threshold.

        Returns:
            Score field name (ATL or RATL) and configured alert threshold.
        """
        try:
            input_type = str(
                self.redis.hget("analysis", "input_type") or ""
            ).lower()
        except redis.RedisError:
            input_type = ""
        non_stop = input_type in {"interface", "stdin", "cyst"}
        tw_width = 3600.0
        evidence_threshold = 0.25
        ratl_threshold = 5.0
        metadata_dir = self.output_dir / "metadata"
        try:
            config_path = next(iter(sorted(metadata_dir.glob("*.yaml"))))
            with config_path.open("r", encoding="utf-8") as handle:
                config = yaml.safe_load(handle) or {}
            parameters = config.get("parameters", {})
            detection = config.get("detection", {})
            tw_width = float(parameters.get("time_window_width", tw_width))
            evidence_threshold = float(
                detection.get(
                    "evidence_detection_threshold", evidence_threshold
                )
            )
            ratl_threshold = float(
                detection.get("risk_accumulated_threat_level", ratl_threshold)
            )
        except (OSError, StopIteration, TypeError, ValueError, yaml.YAMLError):
            pass
        if non_stop:
            return "ratl", ratl_threshold
        return "atl", evidence_threshold * tw_width / 60

    def _score_fields(
        self,
        accumulated_threat_level: Any,
        accumulated_ratl: Any,
        basis: str,
    ) -> Dict[str, Any]:
        """
        Select the detector value Slips compares with the alert threshold.

        Parameters:
            accumulated_threat_level: Raw Slips ATL value.
            accumulated_ratl: Risk-adjusted Slips RATL value.
            basis: Human-readable point at which the score was captured.

        Returns:
            API fields containing the real score and its threshold context.
        """
        selected = (
            accumulated_ratl
            if getattr(self, "score_mode", "ratl") == "ratl"
            else accumulated_threat_level
        )
        try:
            score = float(selected) if selected is not None else None
        except (TypeError, ValueError):
            score = None
        return {
            "alert_score": score,
            "alert_threshold": getattr(self, "alert_threshold", 5.0),
            "alert_score_mode": getattr(self, "score_mode", "ratl").upper(),
            "alert_score_basis": basis,
        }

    def _detector_score_expression(
        self, connection: sqlite3.Connection, table_name: str
    ) -> str:
        """
        Return a compatible SQL expression for the run's detector score.

        Parameters:
            connection: Read-only current-run SQLite connection.
            table_name: Detection table whose score columns should be checked.

        Returns:
            SQL expression selecting the real score, or NULL before migration.
        """
        columns = {
            str(row[1])
            for row in connection.execute(
                f"PRAGMA table_info({table_name})"
            ).fetchall()
        }
        column_name = (
            "accumulated_ratl"
            if getattr(self, "score_mode", "ratl") == "ratl"
            else "accumulated_threat_level"
        )
        return (
            f"COALESCE({column_name}, 0)" if column_name in columns else "NULL"
        )

    def _attach_current_host_scores(self, items: List[Dict[str, Any]]) -> None:
        """
        Attach current Slips accumulator values to host records in one batch.

        Parameters:
            items: Host records returned by the inventory endpoint.
        """
        if not items:
            return
        try:
            tw_pipeline = self.redis.pipeline(transaction=False)
            for item in items:
                tw_pipeline.zrange(f"twsprofile_{item['ip']}", -1, -1)
            tw_values = tw_pipeline.execute()
            score_pipeline = self.redis.pipeline(transaction=False)
            for item, tw_value in zip(items, tw_values):
                twid = (
                    str(tw_value[0])
                    if tw_value
                    else str(item.get("alert_score_twid") or "")
                )
                item["alert_score_twid"] = twid
                score_pipeline.zscore(
                    "accumulated_threat_levels",
                    f"profile_{item['ip']}_{twid}",
                )
            accumulated_values = score_pipeline.execute()
            risk_weight = float(
                self.redis.hget(
                    "max_risk_weight_of_all_profiles", "risk_weight"
                )
                or 0.32
            )
        except (redis.RedisError, TypeError, ValueError):
            accumulated_values = [None] * len(items)
            risk_weight = 0.32
        for item, accumulated in zip(items, accumulated_values):
            item_risk_weight = float(item.get("risk_weight") or risk_weight)
            raw_score = float(
                accumulated
                if accumulated is not None
                else item.get("accumulated_threat_level") or 0
            )
            item.update(
                self._score_fields(
                    raw_score,
                    raw_score * item_risk_weight,
                    "current host time window",
                )
            )
            item["accumulated_threat_level"] = raw_score
            item["accumulated_ratl"] = raw_score * item_risk_weight
            item["risk_weight"] = item_risk_weight

    @staticmethod
    def _loads(value: Any, default: Any) -> Any:
        """Decode JSON while tolerating missing and already-decoded values."""
        if value is None:
            return default
        if isinstance(value, (dict, list, int, float, bool)):
            return value
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _id_list(value: Any) -> List[str]:
        """Normalize Redis identifier fields into strings."""
        decoded = value
        while isinstance(decoded, str):
            parsed = RunDataReader._loads(decoded, decoded)
            if parsed == decoded:
                break
            decoded = parsed
        if decoded is None:
            return []
        if isinstance(decoded, (list, tuple, set)):
            return [str(item) for item in decoded]
        return [str(decoded)]

    @staticmethod
    def _event_timestamp(value: Any) -> float:
        """
        Normalize numeric, ISO, and Slips timestamps.

        Parameters:
            value: Timestamp from a durable or live record.

        Returns:
            Unix timestamp, or zero for invalid input.
        """
        try:
            return float(value)
        except (TypeError, ValueError):
            pass
        try:
            return datetime.fromisoformat(
                str(value).replace("Z", "+00:00")
            ).timestamp()
        except ValueError:
            pass
        for date_format in (
            "%Y/%m/%d %H:%M:%S.%f%z",
            "%Y/%m/%d %H:%M:%S.%f",
        ):
            try:
                return datetime.strptime(str(value), date_format).timestamp()
            except ValueError:
                continue
        return 0.0

    @staticmethod
    def _backend_status(
        heartbeat_value: Any,
        disconnected_value: Any,
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Determine whether the Slips backend heartbeat is still fresh.

        Parameters:
            heartbeat_value: Last collector heartbeat timestamp.
            disconnected_value: Explicit clean-shutdown timestamp.
            now: Current Unix timestamp, or system time when omitted.

        Returns:
            Backend connectivity, last-seen time, and heartbeat age.
        """
        current_time = time.time() if now is None else float(now)
        try:
            last_seen = float(heartbeat_value or 0)
        except (TypeError, ValueError):
            last_seen = 0.0
        try:
            disconnected_at = float(disconnected_value or 0)
        except (TypeError, ValueError):
            disconnected_at = 0.0
        age = max(0.0, current_time - last_seen) if last_seen else None
        explicitly_disconnected = bool(
            disconnected_at and disconnected_at >= last_seen
        )
        connected = bool(
            last_seen
            and not explicitly_disconnected
            and age is not None
            and age <= BACKEND_HEARTBEAT_TIMEOUT_SECONDS
        )
        return {
            "connected": connected,
            "last_seen": last_seen or None,
            "age_seconds": age,
            "timeout_seconds": BACKEND_HEARTBEAT_TIMEOUT_SECONDS,
        }

    @staticmethod
    def _run_uptime_seconds(
        analysis: Dict[str, Any], now: Optional[float] = None
    ) -> Optional[float]:
        """
        Calculate elapsed wall-clock time for the current Slips run.

        Parameters:
            analysis: Redis analysis metadata with start and optional end time.
            now: Current Unix timestamp used while analysis is still running.

        Returns:
            Elapsed seconds, or None when the start time is unavailable.
        """
        started_at = RunDataReader._event_timestamp(
            analysis.get("analysis_start")
        )
        if not started_at:
            return None
        finished_at = RunDataReader._event_timestamp(
            analysis.get("analysis_end")
        )
        if not finished_at:
            finished_at = time.time() if now is None else now
        return max(0.0, finished_at - started_at)

    @staticmethod
    def _module_for_evidence(evidence_type: str) -> str:
        """Infer the producing module from a canonical evidence type."""
        if evidence_type in EVIDENCE_MODULE:
            return EVIDENCE_MODULE[evidence_type]
        for prefix, module in MODULE_BY_EVIDENCE_PREFIX.items():
            if evidence_type.startswith(prefix):
                return module
        return "flow_alerts"

    @classmethod
    def _evidence_source_module(
        cls, source_module: Any, evidence_type: str
    ) -> str:
        """
        Resolve recorded evidence provenance with a legacy fallback.

        Parameters:
            source_module: Module name stored with the evidence.
            evidence_type: Canonical evidence type used for old records.

        Returns:
            Recorded module name, or the historical type-based inference.
        """
        recorded = str(source_module or "").strip()
        return recorded or cls._module_for_evidence(evidence_type)

    @classmethod
    def _evidence_module_expression(
        cls, connection: sqlite3.Connection, table_alias: str = ""
    ) -> str:
        """
        Build a SQLite expression for evidence module provenance.

        Parameters:
            connection: Active flows database connection.
            table_alias: Optional evidence table alias.

        Returns:
            SQL expression preferring stored provenance when available.
        """
        columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(evidence)")
        }
        prefix = f"{table_alias}." if table_alias else ""
        fallback = f"evidence_module(COALESCE({prefix}evidence_type, ''))"
        if "source_module" not in columns:
            return fallback
        return f"COALESCE(NULLIF(TRIM({prefix}source_module), ''), {fallback})"

    @staticmethod
    def _scope(ip: str) -> str:
        """Classify an IP as local, public, or special."""
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return "special"
        return "local" if address.is_private else "public"

    @staticmethod
    def _encode_cursor(sort_value: Any, stable_id: str) -> str:
        """Encode a stable descending pagination cursor."""
        raw = json.dumps([sort_value, stable_id], separators=(",", ":"))
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    @staticmethod
    def _decode_cursor(value: str) -> Optional[tuple[Any, str]]:
        """Decode a stable pagination cursor."""
        if not value:
            return None
        try:
            padded = value + "=" * (-len(value) % 4)
            sort_value, stable_id = json.loads(
                base64.urlsafe_b64decode(padded).decode()
            )
            return sort_value, str(stable_id)
        except (ValueError, TypeError, json.JSONDecodeError):
            return None

    @staticmethod
    def _query_value(
        query: Dict[str, List[str]], key: str, default: str = ""
    ) -> str:
        """Return the first query-string value."""
        return str(query.get(key, [default])[0])

    @classmethod
    def _limit(
        cls,
        query: Dict[str, List[str]],
        default: int = DEFAULT_PAGE_SIZE,
        maximum: int = MAX_PAGE_SIZE,
    ) -> int:
        """Parse and bound a query page size."""
        try:
            return max(
                1,
                min(
                    int(cls._query_value(query, "limit", str(default))),
                    maximum,
                ),
            )
        except ValueError:
            return default

    def _time_bounds(
        self,
        query: Dict[str, List[str]],
        latest_event: Optional[float] = None,
    ) -> tuple[Optional[float], Optional[float], str]:
        """
        Resolve time bounds against the active run or capture clock.

        Parameters:
            query: Request query-string values.
            latest_event: Newest event timestamp for offline data.

        Returns:
            Start, end, and normalized range name.
        """
        range_name = self._query_value(query, "range", "live")
        now = float(latest_event or time.time())
        try:
            input_type = str(
                getattr(self, "redis", None).hget("analysis", "input_type")
                or ""
            ).lower()
        except (AttributeError, redis.RedisError):
            input_type = ""
        if input_type in {"interface", "stdin", "cyst"}:
            now = time.time()
        if range_name in TIME_RANGES:
            return now - TIME_RANGES[range_name], now, range_name
        if range_name in {"all", "full"}:
            return None, now, "all"
        if range_name == "custom":
            try:
                start = float(self._query_value(query, "from"))
            except ValueError:
                start = None
            try:
                end = float(self._query_value(query, "to"))
            except ValueError:
                end = now
            return start, end, "custom"
        return now - TIME_RANGES["live"], now, "live"

    @classmethod
    def _sort_spec(
        cls,
        query: Dict[str, List[str]],
        allowed: Dict[str, str],
        default: str,
    ) -> tuple[str, str, str]:
        """
        Resolve an allow-listed database sort expression.

        Parameters:
            query: Request query-string values.
            allowed: Public sort keys mapped to trusted SQL expressions.
            default: Sort key used when the request is absent or invalid.

        Returns:
            Public key, trusted SQL expression, and SQL direction.
        """
        key = cls._query_value(query, "sort", default)
        if key not in allowed:
            key = default
        direction = cls._query_value(query, "order", "desc").lower()
        return key, allowed[key], "ASC" if direction == "asc" else "DESC"

    @staticmethod
    def _cursor_clause(
        expression: str,
        stable_id: str,
        direction: str,
    ) -> str:
        """
        Build a stable keyset-pagination predicate.

        Parameters:
            expression: Trusted SQL sort expression.
            stable_id: Stable identifier column.
            direction: SQL ASC or DESC direction.

        Returns:
            Parameterized SQL predicate for the next page.
        """
        operator = ">" if direction == "ASC" else "<"
        return (
            f"({expression} {operator} ? OR "
            f"({expression} = ? AND {stable_id} {operator} ?))"
        )

    def _connect_sqlite(self) -> sqlite3.Connection:
        """Open the current run flow database read-only."""
        connection = sqlite3.connect(
            f"file:{self.sqlite_path}?mode=ro", uri=True, timeout=5
        )
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
        """Check whether a SQLite table exists."""
        row = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        return bool(row)

    @staticmethod
    def _normalized_path(value: str) -> str:
        """Normalize a relative run path for identity comparisons."""
        return Path(value).as_posix().rstrip("/")

    def validate_run_identity(self) -> Dict[str, Any]:
        """
        Ensure Redis and SQLite belong to this configured run.

        Returns:
            Current identity details.

        Raises:
            RunMismatchError: Redis advertises another output directory.
        """
        analysis = self.redis.hgetall("analysis")
        actual = str(analysis.get("output_dir", ""))
        expected = self._normalized_path(str(self.output_dir))
        if not actual:
            raise RunMismatchError(
                f"Web server expects {expected}, but Redis does not advertise "
                "an analysis output directory."
            )
        if self._normalized_path(actual) != expected:
            raise RunMismatchError(
                f"Web server expects {expected}, but Redis serves {actual}."
            )
        return {
            "output_dir": str(self.output_dir),
            "redis_output_dir": actual,
            "redis_port": self.redis_port,
            "name": analysis.get("name", self.output_dir.name),
            "input_type": analysis.get("input_type", ""),
            "analysis_start": analysis.get("analysis_start", ""),
            "analysis_end": analysis.get("analysis_end", ""),
        }

    def identity(self) -> Dict[str, Any]:
        """Return a signed identity response for stale-server detection."""
        return {
            "service": "slips-web-interface",
            "pid": os.getpid(),
            **self.validate_run_identity(),
        }

    def response_metadata(self) -> Dict[str, Any]:
        """Return bounded source freshness and indexing checkpoints."""
        with connect_history(self.history_path, read_only=True) as connection:
            values = {
                str(row["key"]): str(row["value"])
                for row in connection.execute(
                    "SELECT key, value FROM metadata WHERE key IN "
                    "('schema_version', 'flow_last_rowid', "
                    "'flow_index_updated_at', 'alerts_json_offset', "
                    "'error_log_name', 'backend_heartbeat_at', "
                    "'backend_disconnected_at')"
                ).fetchall()
            }
        backend_status = self._backend_status(
            values.get(BACKEND_HEARTBEAT_KEY),
            values.get(BACKEND_DISCONNECTED_KEY),
        )
        return {
            "run_identity": {
                "output_dir": str(self.output_dir),
                "server_pid": os.getpid(),
            },
            "backend_status": backend_status,
            "source_freshness": {
                "flow_index_updated_at": float(
                    values.get("flow_index_updated_at", "0")
                ),
                "error_log": values.get("error_log_name", ""),
            },
            "indexing_status": {
                "schema_version": int(values.get("schema_version", "1")),
                "flow_last_rowid": int(values.get("flow_last_rowid", "0")),
                "alerts_json_offset": int(
                    values.get("alerts_json_offset", "0")
                ),
            },
        }

    def _redis_evidence(self) -> List[Dict[str, Any]]:
        """Read currently retained Redis evidence for compatibility."""
        alert_ids_by_evidence: Dict[str, List[str]] = defaultdict(list)
        for key in self.redis.scan_iter(match="profile_*_timewindow*"):
            if key.endswith("_evidence") or self.redis.type(key) != "hash":
                continue
            alerts = self._loads(self.redis.hget(key, "alerts"), {})
            if not isinstance(alerts, dict):
                continue
            for alert_id, evidence_ids in alerts.items():
                for evidence_id in self._id_list(evidence_ids):
                    alert_ids_by_evidence[evidence_id].append(str(alert_id))
        records: List[Dict[str, Any]] = []
        for key in self.redis.scan_iter(
            match="profile_*_timewindow*_evidence"
        ):
            profile_twid = key[: -len("_evidence")]
            profile_id, separator, twid = profile_twid.rpartition(
                "_timewindow"
            )
            if not separator:
                continue
            for evidence_id, raw in self.redis.hgetall(key).items():
                evidence = self._loads(raw, {})
                if not isinstance(evidence, dict):
                    continue
                canonical_id = str(evidence.get("id") or evidence_id)
                profile = evidence.get("profile", {})
                profile_ip = (
                    str(profile.get("ip", ""))
                    if isinstance(profile, dict)
                    else str(profile).removeprefix(PROFILE_PREFIX)
                )
                evidence_type = str(evidence.get("evidence_type", "unknown"))
                source_module = evidence.get("source_module", "")
                evidence.update(
                    {
                        "id": canonical_id,
                        "profile_ip": profile_ip
                        or profile_id.removeprefix(PROFILE_PREFIX),
                        "twid": f"timewindow{twid}",
                        "module": self._evidence_source_module(
                            source_module, evidence_type
                        ),
                        "alert_ids": alert_ids_by_evidence.get(
                            canonical_id, []
                        ),
                    }
                )
                evidence["flow_count"] = len(
                    self._id_list(evidence.get("uid", []))
                )
                evidence["timestamp"] = self._event_timestamp(
                    evidence.get("timestamp")
                )
                records.append(evidence)
        records.sort(
            key=lambda item: float(item.get("timestamp") or 0),
            reverse=True,
        )
        return records

    def _durable_evidence_row(
        self, connection: sqlite3.Connection, row: sqlite3.Row
    ) -> Dict[str, Any]:
        """Normalize one durable evidence row."""
        record = self._loads(row["data"], {})
        if not isinstance(record, dict):
            record = {}
        evidence_id = str(row["evidence_id"])
        alert_ids = [
            str(item["alert_id"])
            for item in connection.execute(
                "SELECT alert_id FROM alert_evidence "
                "WHERE evidence_id = ? ORDER BY alert_id",
                (evidence_id,),
            ).fetchall()
        ]
        flow_count = connection.execute(
            "SELECT COUNT(*) AS count FROM evidence_flows WHERE evidence_id = ?",
            (evidence_id,),
        ).fetchone()["count"]
        evidence_type = str(row["evidence_type"] or "unknown")
        source_module = (
            row["source_module"] if "source_module" in row.keys() else ""
        ) or record.get("source_module", "")
        record.update(
            {
                "id": evidence_id,
                "timestamp": float(row["evidence_time"] or 0),
                "profile_ip": str(row["profile_ip"] or ""),
                "twid": str(row["timewindow"] or ""),
                "threat_level": str(row["threat_level"] or "info"),
                "evidence_type": evidence_type,
                "description": str(row["description"] or ""),
                "confidence": float(row["confidence"] or 0),
                "module": self._evidence_source_module(
                    source_module, evidence_type
                ),
                "alert_ids": alert_ids,
                "flow_count": int(flow_count),
                "whitelisted": (
                    row["whitelisted"] in (True, 1, "1")
                    if "whitelisted" in row.keys()
                    else False
                ),
            }
        )
        record.update(
            self._score_fields(
                (
                    row["accumulated_threat_level"]
                    if "accumulated_threat_level" in row.keys()
                    else None
                ),
                (
                    row["accumulated_ratl"]
                    if "accumulated_ratl" in row.keys()
                    else None
                ),
                "when this evidence was recorded",
            )
        )
        return record

    @staticmethod
    def _threat_from_rank(rank: Any) -> str:
        """
        Convert a numeric threat rank to its canonical name.

        Parameters:
            rank: Numeric threat rank returned by SQLite.

        Returns:
            Canonical threat-level name.
        """
        levels = ("info", "low", "medium", "high", "critical")
        try:
            return levels[max(0, min(int(rank), len(levels) - 1))]
        except (TypeError, ValueError):
            return "info"

    def _grouped_evidence(self, query: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        Return evidence aggregated by host and evidence type.

        Parameters:
            query: Request filters, sort, range, and cursor values.

        Returns:
            Bounded aggregate page with raw durable total metadata.
        """
        limit = self._limit(query)
        search = self._query_value(query, "search").lower()
        threat = self._query_value(query, "threat").lower()
        association = self._query_value(query, "association")
        profile = self._query_value(query, "profile")
        evidence_type = self._query_value(query, "type")
        cursor = self._decode_cursor(self._query_value(query, "cursor"))
        threat_expression = (
            "CASE LOWER(threat_level) WHEN 'critical' THEN 4 "
            "WHEN 'high' THEN 3 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 1 ELSE 0 END"
        )
        flow_expression = (
            "(SELECT COUNT(*) FROM evidence_flows ef "
            "WHERE ef.evidence_id = evidence.evidence_id)"
        )
        alert_expression = (
            "(SELECT COUNT(*) FROM alert_evidence ae "
            "WHERE ae.evidence_id = evidence.evidence_id)"
        )
        with self._connect_sqlite() as connection:
            connection.execute("BEGIN")
            score_expression = self._detector_score_expression(
                connection, "evidence"
            )
            evidence_columns = {
                str(column[1])
                for column in connection.execute(
                    "PRAGMA table_info(evidence)"
                ).fetchall()
            }
            whitelist_expression = (
                "COALESCE(whitelisted, 0)"
                if "whitelisted" in evidence_columns
                else "0"
            )
            connection.create_function(
                "evidence_module", 1, self._module_for_evidence
            )
            module_expression = self._evidence_module_expression(connection)
            latest_row = connection.execute(
                "SELECT MAX(evidence_time) AS latest FROM evidence"
            ).fetchone()
            latest = float(latest_row["latest"] or 0)
            start, end, range_name = self._time_bounds(query, latest)
            full_total = int(
                connection.execute(
                    "SELECT COUNT(*) AS count FROM evidence"
                ).fetchone()["count"]
            )
            clauses = ["1 = 1"]
            params: List[Any] = []
            if self._query_value(query, "hide_excluded") == "1":
                clauses.append(f"{whitelist_expression} = 0")
            if start is not None:
                clauses.append("evidence_time >= ?")
                params.append(start)
            if end is not None:
                clauses.append("evidence_time <= ?")
                params.append(end)
            if search:
                term = f"%{search}%"
                clauses.append(
                    "(LOWER(description) LIKE ? OR "
                    "LOWER(evidence_type) LIKE ? OR "
                    "LOWER(profile_ip) LIKE ?)"
                )
                params.extend([term, term, term])
            if profile:
                clauses.append("profile_ip = ?")
                params.append(profile)
            if evidence_type:
                clauses.append("evidence_type = ?")
                params.append(evidence_type)
            if threat:
                clauses.append("LOWER(threat_level) = ?")
                params.append(threat)
            if association == "linked":
                clauses.append(
                    "EXISTS (SELECT 1 FROM alert_evidence ae "
                    "WHERE ae.evidence_id = evidence.evidence_id)"
                )
            elif association == "unlinked":
                clauses.append(
                    "NOT EXISTS (SELECT 1 FROM alert_evidence ae "
                    "WHERE ae.evidence_id = evidence.evidence_id)"
                )
            grouped_sql = (
                "SELECT profile_ip, evidence_type, "
                "profile_ip || char(31) || evidence_type AS group_id, "
                "MAX(evidence_time) AS timestamp, "
                "MIN(evidence_time) AS first_timestamp, "
                f"MAX({threat_expression}) AS threat_rank, "
                f"GROUP_CONCAT(DISTINCT {module_expression}) AS module, "
                "COUNT(*) AS evidence_count, "
                "GROUP_CONCAT(evidence_id) AS evidence_ids, "
                f"SUM({whitelist_expression}) AS persisted_whitelisted_count, "
                f"SUM({flow_expression}) AS flow_count, "
                f"SUM({alert_expression}) AS alert_count, "
                f"MAX({score_expression}) AS alert_score "
                f"FROM evidence WHERE {' AND '.join(clauses)} "
                "GROUP BY profile_ip, evidence_type"
            )
            sort_key, sort_expression, direction = self._sort_spec(
                query,
                {
                    "time": "timestamp",
                    "host": "LOWER(profile_ip)",
                    "threat": "threat_rank",
                    "type": "LOWER(evidence_type)",
                    "module": "LOWER(module)",
                    "evidence": "evidence_count",
                    "flows": "flow_count",
                    "alert": "alert_count",
                    "score": "alert_score",
                },
                "time",
            )
            if sort_key == "score":
                # A group displaying Excluded belongs after every numeric
                # score, even if some evidence in that group was scored.
                excluded_value = "1e308" if direction == "ASC" else "-1e308"
                sort_expression = (
                    "CASE WHEN persisted_whitelisted_count > 0 "
                    f"THEN {excluded_value} ELSE COALESCE(alert_score, 0) END"
                )
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) AS count FROM ({grouped_sql})",
                    params,
                ).fetchone()["count"]
            )
            outer_clauses: List[str] = []
            outer_params: List[Any] = []
            if cursor:
                outer_clauses.append(
                    self._cursor_clause(sort_expression, "group_id", direction)
                )
                outer_params.extend([cursor[0], cursor[0], cursor[1]])
            outer_where = (
                f"WHERE {' AND '.join(outer_clauses)}" if outer_clauses else ""
            )
            rows = connection.execute(
                f"SELECT grouped.*, {sort_expression} AS sort_value "
                f"FROM ({grouped_sql}) grouped {outer_where} "
                f"ORDER BY {sort_expression} {direction}, "
                f"group_id {direction} LIMIT ?",
                (*params, *outer_params, limit + 1),
            ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        items = []
        for row in rows:
            item = dict(row)
            item.pop("sort_value", None)
            item["id"] = str(item.pop("group_id"))
            item["threat_level"] = self._threat_from_rank(
                item.pop("threat_rank")
            )
            item["timestamp"] = float(item["timestamp"] or 0)
            item["first_timestamp"] = float(item["first_timestamp"] or 0)
            item["evidence_count"] = int(item["evidence_count"] or 0)
            item["_evidence_ids"] = [
                evidence_id
                for evidence_id in str(item.pop("evidence_ids") or "").split(
                    ","
                )
                if evidence_id
            ]
            item["whitelisted_count"] = int(
                item.pop("persisted_whitelisted_count") or 0
            )
            item["flow_count"] = int(item["flow_count"] or 0)
            item["alert_count"] = int(item["alert_count"] or 0)
            item.update(
                self._score_fields(
                    item["alert_score"],
                    item["alert_score"],
                    "highest score in this evidence group",
                )
            )
            items.append(item)
        self._annotate_detection_networks(
            items, "profile_ip", "timestamp", "first_timestamp"
        )
        self._annotate_whitelisted_evidence(items)
        self._annotate_p2p_reporters(items)
        next_cursor = (
            self._encode_cursor(rows[-1]["sort_value"], str(items[-1]["id"]))
            if has_more and items
            else None
        )
        return {
            "items": items,
            "total": total,
            "full_total": full_total,
            "page_size": len(items),
            "next_cursor": next_cursor,
            "range": range_name,
            "sort": sort_key,
            "order": direction.lower(),
            "group": "host_type",
        }

    def evidence(self, query: Dict[str, List[str]]) -> Dict[str, Any]:
        """Return one filtered, cursor-bounded evidence page."""
        if self._query_value(query, "group") == "host_type":
            return self._grouped_evidence(query)
        limit = self._limit(query)
        search = self._query_value(query, "search").lower()
        threat = self._query_value(query, "threat").lower()
        association = self._query_value(query, "association")
        profiles = [str(value) for value in query.get("profile", []) if value]
        evidence_type = self._query_value(query, "type")
        cursor = self._decode_cursor(self._query_value(query, "cursor"))
        threat_expression = (
            "CASE LOWER(threat_level) WHEN 'critical' THEN 4 "
            "WHEN 'high' THEN 3 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 1 ELSE 0 END"
        )
        flow_expression = (
            "(SELECT COUNT(*) FROM evidence_flows ef "
            "WHERE ef.evidence_id = evidence.evidence_id)"
        )
        alert_expression = (
            "(SELECT COUNT(*) FROM alert_evidence ae "
            "WHERE ae.evidence_id = evidence.evidence_id)"
        )
        sort_key = "time"
        direction = "DESC"
        try:
            with self._connect_sqlite() as connection:
                connection.execute("BEGIN")
                if not self._table_exists(connection, "evidence"):
                    raise sqlite3.OperationalError("no durable evidence")
                score_expression = self._detector_score_expression(
                    connection, "evidence"
                )
                evidence_columns = {
                    str(column[1])
                    for column in connection.execute(
                        "PRAGMA table_info(evidence)"
                    ).fetchall()
                }
                whitelist_expression = (
                    "COALESCE(evidence.whitelisted, 0)"
                    if "whitelisted" in evidence_columns
                    else "0"
                )
                connection.create_function(
                    "evidence_module", 1, self._module_for_evidence
                )
                module_expression = self._evidence_module_expression(
                    connection
                )
                latest_row = connection.execute(
                    "SELECT MAX(evidence_time) AS latest FROM evidence"
                ).fetchone()
                full_total = int(
                    connection.execute(
                        "SELECT COUNT(*) AS count FROM evidence"
                    ).fetchone()["count"]
                )
                latest = float(latest_row["latest"] or 0)
                start, end, range_name = self._time_bounds(query, latest)
                sort_key, sort_expression, direction = self._sort_spec(
                    query,
                    {
                        "time": "evidence_time",
                        "host": "LOWER(COALESCE(profile_ip, ''))",
                        "threat": threat_expression,
                        "type": "LOWER(COALESCE(evidence_type, ''))",
                        "module": f"LOWER({module_expression})",
                        "confidence": "confidence",
                        "flows": flow_expression,
                        "alert": alert_expression,
                        "score": score_expression,
                    },
                    "time",
                )
                if sort_key == "score":
                    excluded_value = (
                        "1e308" if direction == "ASC" else "-1e308"
                    )
                    sort_expression = (
                        f"CASE WHEN {whitelist_expression} > 0 "
                        f"THEN {excluded_value} "
                        f"ELSE COALESCE({score_expression}, 0) END"
                    )
                clauses = ["1 = 1"]
                params: List[Any] = []
                if self._query_value(query, "hide_excluded") == "1":
                    clauses.append(f"{whitelist_expression} = 0")
                if start is not None:
                    clauses.append("evidence_time >= ?")
                    params.append(start)
                if end is not None:
                    clauses.append("evidence_time <= ?")
                    params.append(end)
                if search:
                    clauses.append(
                        "(LOWER(COALESCE(evidence_id, '')) LIKE ? OR "
                        "LOWER(COALESCE(CAST(evidence_time AS TEXT), '')) LIKE ? OR "
                        "LOWER(COALESCE(profile_ip, '')) LIKE ? OR "
                        "LOWER(COALESCE(timewindow, '')) LIKE ? OR "
                        "LOWER(COALESCE(threat_level, '')) LIKE ? OR "
                        "LOWER(COALESCE(evidence_type, '')) LIKE ? OR "
                        "LOWER(COALESCE(description, '')) LIKE ? OR "
                        "LOWER(COALESCE(CAST(confidence AS TEXT), '')) LIKE ? OR "
                        "LOWER(COALESCE(data, '')) LIKE ? OR "
                        f"LOWER(COALESCE({module_expression}, '')) LIKE ? OR "
                        "EXISTS (SELECT 1 FROM evidence_flows ef "
                        "WHERE ef.evidence_id = evidence.evidence_id "
                        "AND LOWER(ef.uid) LIKE ?) OR "
                        "EXISTS (SELECT 1 FROM alert_evidence ae "
                        "WHERE ae.evidence_id = evidence.evidence_id "
                        "AND LOWER(ae.alert_id) LIKE ?))"
                    )
                    term = f"%{search}%"
                    params.extend([term] * 12)
                if profiles:
                    placeholders = ",".join("?" for _ in profiles)
                    clauses.append(f"profile_ip IN ({placeholders})")
                    params.extend(profiles)
                if evidence_type:
                    clauses.append("evidence_type = ?")
                    params.append(evidence_type)
                if threat:
                    clauses.append("LOWER(threat_level) = ?")
                    params.append(threat)
                if association == "linked":
                    clauses.append(
                        "EXISTS (SELECT 1 FROM alert_evidence ae "
                        "WHERE ae.evidence_id = evidence.evidence_id)"
                    )
                elif association == "unlinked":
                    clauses.append(
                        "NOT EXISTS (SELECT 1 FROM alert_evidence ae "
                        "WHERE ae.evidence_id = evidence.evidence_id)"
                    )
                count_where = " AND ".join(clauses)
                count_params = list(params)
                if cursor:
                    clauses.append(
                        self._cursor_clause(
                            sort_expression,
                            "evidence_id",
                            direction,
                        )
                    )
                    params.extend([cursor[0], cursor[0], cursor[1]])
                where = " AND ".join(clauses)
                total = connection.execute(
                    f"SELECT COUNT(*) AS count FROM evidence WHERE {count_where}",
                    count_params,
                ).fetchone()["count"]
                rows = connection.execute(
                    f"SELECT evidence.*, {sort_expression} AS sort_value "
                    f"FROM evidence WHERE {where} ORDER BY "
                    f"{sort_expression} {direction}, evidence_id {direction} LIMIT ?",
                    (*params, limit + 1),
                ).fetchall()
                has_more = len(rows) > limit
                rows = rows[:limit]
                items = [
                    self._durable_evidence_row(connection, row) for row in rows
                ]
                sort_values = [row["sort_value"] for row in rows]
        except sqlite3.Error:
            records = self._redis_evidence()
            full_total = len(records)
            if self._query_value(query, "hide_excluded") == "1":
                records = [
                    item for item in records if not item.get("whitelisted")
                ]
            latest = max(
                (float(item.get("timestamp") or 0) for item in records),
                default=0,
            )
            start, end, range_name = self._time_bounds(query, latest)
            if start is not None:
                records = [
                    item
                    for item in records
                    if float(item.get("timestamp") or 0) >= start
                ]
            if end is not None:
                records = [
                    item
                    for item in records
                    if float(item.get("timestamp") or 0) <= end
                ]
            if search:
                records = [
                    item
                    for item in records
                    if search
                    in json.dumps(item, sort_keys=True, default=str).lower()
                ]
            profile_set = set(profiles)
            if profile_set:
                records = [
                    item
                    for item in records
                    if str(item.get("profile_ip", "")) in profile_set
                ]
            if evidence_type:
                records = [
                    item
                    for item in records
                    if str(item.get("evidence_type", "")) == evidence_type
                ]
            if threat:
                records = [
                    item
                    for item in records
                    if str(item.get("threat_level", "")).lower() == threat
                ]
            if association:
                records = [
                    item
                    for item in records
                    if bool(item.get("alert_ids")) == (association == "linked")
                ]
            if cursor:
                records = [
                    item
                    for item in records
                    if (
                        float(item.get("timestamp") or 0),
                        str(item.get("id", "")),
                    )
                    < cursor
                ]
            records.sort(
                key=lambda item: (
                    float(item.get("timestamp") or 0),
                    str(item.get("id", "")),
                ),
                reverse=direction == "DESC",
            )
            total = len(records)
            items = records[:limit]
            sort_values = [float(item.get("timestamp") or 0) for item in items]
            has_more = len(records) > limit
        self._annotate_detection_networks(items, "profile_ip", "timestamp")
        self._annotate_whitelisted_evidence(items)
        self._annotate_p2p_reporters(items)
        next_cursor = (
            self._encode_cursor(
                sort_values[-1],
                str(items[-1]["id"]),
            )
            if has_more and items
            else None
        )
        return {
            "items": items,
            "total": int(total),
            "full_total": int(full_total),
            "page_size": len(items),
            "next_cursor": next_cursor,
            "range": range_name,
            "sort": sort_key,
            "order": direction.lower(),
        }

    def _alert_evidence(
        self,
        connection: sqlite3.Connection,
        alert: Dict[str, Any],
        maximum: int = 100,
    ) -> List[Dict[str, Any]]:
        """Load bounded durable or live evidence for one alert."""
        alert_id = str(alert["alert_id"])
        rows: List[sqlite3.Row] = []
        if self._table_exists(connection, "alert_evidence"):
            rows = connection.execute(
                "SELECT e.* FROM evidence e JOIN alert_evidence ae "
                "ON ae.evidence_id = e.evidence_id "
                "WHERE ae.alert_id = ? "
                "ORDER BY e.evidence_time DESC "
                "LIMIT ?",
                (alert_id, maximum),
            ).fetchall()
        if rows:
            items = [
                self._durable_evidence_row(connection, row) for row in rows
            ]
            self._annotate_detection_networks(items, "profile_ip", "timestamp")
            self._annotate_whitelisted_evidence(items)
            return items
        profile_id = f"profile_{alert.get('ip_alerted', '')}"
        twid = str(alert.get("timewindow", ""))
        alert_map = self._loads(
            self.redis.hget(f"{profile_id}_{twid}", "alerts"), {}
        )
        ids = (
            self._id_list(alert_map.get(alert_id, []))
            if isinstance(alert_map, dict)
            else []
        )
        by_id = {item["id"]: item for item in self._redis_evidence()}
        items = [by_id[item] for item in ids if item in by_id][:maximum]
        self._annotate_detection_networks(items, "profile_ip", "timestamp")
        self._annotate_whitelisted_evidence(items)
        return items

    @staticmethod
    def _highest_threat(levels: Sequence[str]) -> str:
        """Select the highest canonical threat level."""
        rank = {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        return max(levels or ["info"], key=lambda item: rank.get(item, 0))

    def _grouped_alerts(self, query: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        Return alerts aggregated by affected host.

        Parameters:
            query: Request filters, sort, range, and cursor values.

        Returns:
            Bounded host aggregate page with raw durable alert total.
        """
        limit = self._limit(query)
        search = self._query_value(query, "search").lower()
        threat = self._query_value(query, "threat").lower()
        profile = self._query_value(query, "profile")
        cursor = self._decode_cursor(self._query_value(query, "cursor"))
        threat_expression = (
            "COALESCE((SELECT MAX(CASE LOWER(e.threat_level) "
            "WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) "
            "FROM alert_evidence ae JOIN evidence e "
            "ON e.evidence_id = ae.evidence_id "
            "WHERE ae.alert_id = alerts.alert_id), 0)"
        )
        evidence_expression = (
            "(SELECT COUNT(*) FROM alert_evidence ae "
            "WHERE ae.alert_id = alerts.alert_id)"
        )
        with self._connect_sqlite() as connection:
            connection.execute("BEGIN")
            score_expression = self._detector_score_expression(
                connection, "alerts"
            )
            latest_row = connection.execute(
                "SELECT MAX(CAST(alert_time AS REAL)) AS latest FROM alerts"
            ).fetchone()
            latest = float(latest_row["latest"] or 0)
            start, end, range_name = self._time_bounds(query, latest)
            full_total = int(
                connection.execute(
                    "SELECT COUNT(*) AS count FROM alerts"
                ).fetchone()["count"]
            )
            clauses = ["1 = 1"]
            params: List[Any] = []
            if start is not None:
                clauses.append("CAST(alert_time AS REAL) >= ?")
                params.append(start)
            if end is not None:
                clauses.append("CAST(alert_time AS REAL) <= ?")
                params.append(end)
            if search:
                clauses.append(
                    "(LOWER(alert_id) LIKE ? OR LOWER(ip_alerted) LIKE ? "
                    "OR LOWER(label) LIKE ?)"
                )
                term = f"%{search}%"
                params.extend([term, term, term])
            if profile:
                clauses.append("ip_alerted = ?")
                params.append(profile)
            if threat:
                threat_rank = {
                    "info": 0,
                    "low": 1,
                    "medium": 2,
                    "high": 3,
                    "critical": 4,
                }.get(threat)
                if threat_rank is not None:
                    clauses.append(f"{threat_expression} = ?")
                    params.append(threat_rank)
            grouped_sql = (
                "SELECT ip_alerted, ip_alerted AS group_id, "
                "MAX(CAST(alert_time AS REAL)) AS alert_time, "
                "MIN(CAST(alert_time AS REAL)) AS first_alert_time, "
                f"MAX({threat_expression}) AS threat_rank, "
                "COUNT(*) AS alert_count, "
                f"SUM({evidence_expression}) AS evidence_count, "
                f"MAX({score_expression}) AS alert_score, "
                "GROUP_CONCAT(DISTINCT COALESCE(label, '')) AS labels "
                f"FROM alerts WHERE {' AND '.join(clauses)} GROUP BY ip_alerted"
            )
            sort_key, sort_expression, direction = self._sort_spec(
                query,
                {
                    "time": "alert_time",
                    "host": "LOWER(ip_alerted)",
                    "threat": "threat_rank",
                    "label": "LOWER(labels)",
                    "alerts": "alert_count",
                    "evidence": "evidence_count",
                    "score": "alert_score",
                },
                "time",
            )
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) AS count FROM ({grouped_sql})",
                    params,
                ).fetchone()["count"]
            )
            outer_clauses: List[str] = []
            outer_params: List[Any] = []
            if cursor:
                outer_clauses.append(
                    self._cursor_clause(sort_expression, "group_id", direction)
                )
                outer_params.extend([cursor[0], cursor[0], cursor[1]])
            outer_where = (
                f"WHERE {' AND '.join(outer_clauses)}" if outer_clauses else ""
            )
            rows = connection.execute(
                f"SELECT grouped.*, {sort_expression} AS sort_value "
                f"FROM ({grouped_sql}) grouped {outer_where} "
                f"ORDER BY {sort_expression} {direction}, "
                f"group_id {direction} LIMIT ?",
                (*params, *outer_params, limit + 1),
            ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        items = []
        for row in rows:
            item = dict(row)
            item.pop("sort_value", None)
            item["id"] = str(item.pop("group_id"))
            item["threat_level"] = self._threat_from_rank(
                item.pop("threat_rank")
            )
            item["alert_time"] = float(item["alert_time"] or 0)
            item["first_alert_time"] = float(item["first_alert_time"] or 0)
            item["alert_count"] = int(item["alert_count"] or 0)
            item["evidence_count"] = int(item["evidence_count"] or 0)
            item["label"] = str(item.pop("labels") or "")
            item.update(
                self._score_fields(
                    item["alert_score"],
                    item["alert_score"],
                    "highest threshold-crossing score for this host",
                )
            )
            item.update(self._ip_context_for_ip(str(item["ip_alerted"])))
            items.append(item)
        self._annotate_detection_networks(
            items, "ip_alerted", "alert_time", "first_alert_time"
        )
        next_cursor = (
            self._encode_cursor(rows[-1]["sort_value"], str(items[-1]["id"]))
            if has_more and items
            else None
        )
        return {
            "items": items,
            "total": total,
            "full_total": full_total,
            "page_size": len(items),
            "next_cursor": next_cursor,
            "range": range_name,
            "sort": sort_key,
            "order": direction.lower(),
            "group": "host",
        }

    def alerts(self, query: Dict[str, List[str]]) -> Dict[str, Any]:
        """Return one filtered, cursor-bounded alert page."""
        if self._query_value(query, "group") == "host":
            return self._grouped_alerts(query)
        limit = self._limit(query)
        search = self._query_value(query, "search").lower()
        threat = self._query_value(query, "threat").lower()
        profile = self._query_value(query, "profile")
        include_details = (
            self._query_value(query, "details").lower() != "false"
        )
        cursor = self._decode_cursor(self._query_value(query, "cursor"))
        threat_expression = (
            "COALESCE((SELECT MAX(CASE LOWER(e.threat_level) "
            "WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) "
            "FROM alert_evidence ae JOIN evidence e "
            "ON e.evidence_id = ae.evidence_id "
            "WHERE ae.alert_id = alerts.alert_id), 0)"
        )
        evidence_expression = (
            "(SELECT COUNT(*) FROM alert_evidence ae "
            "WHERE ae.alert_id = alerts.alert_id)"
        )
        with self._connect_sqlite() as connection:
            connection.execute("BEGIN")
            score_expression = self._detector_score_expression(
                connection, "alerts"
            )
            latest_row = connection.execute(
                "SELECT MAX(CAST(alert_time AS REAL)) AS latest FROM alerts"
            ).fetchone()
            full_total = int(
                connection.execute(
                    "SELECT COUNT(*) AS count FROM alerts"
                ).fetchone()["count"]
            )
            latest = float(latest_row["latest"] or 0)
            start, end, range_name = self._time_bounds(query, latest)
            sort_key, sort_expression, direction = self._sort_spec(
                query,
                {
                    "time": "CAST(alert_time AS REAL)",
                    "host": "LOWER(COALESCE(ip_alerted, ''))",
                    "threat": threat_expression,
                    "tw": "LOWER(COALESCE(timewindow, ''))",
                    "tw_start": "COALESCE(tw_start, '')",
                    "tw_end": "COALESCE(tw_end, '')",
                    "label": "LOWER(COALESCE(label, ''))",
                    "evidence": evidence_expression,
                    "score": score_expression,
                    "id": "LOWER(alert_id)",
                },
                "time",
            )
            clauses = ["1 = 1"]
            params: List[Any] = []
            if start is not None:
                clauses.append("CAST(alert_time AS REAL) >= ?")
                params.append(start)
            if end is not None:
                clauses.append("CAST(alert_time AS REAL) <= ?")
                params.append(end)
            if search:
                clauses.append(
                    "(LOWER(alert_id) LIKE ? OR LOWER(ip_alerted) LIKE ? "
                    "OR LOWER(label) LIKE ?)"
                )
                term = f"%{search}%"
                params.extend([term, term, term])
            if profile:
                clauses.append("ip_alerted = ?")
                params.append(profile)
            if threat:
                threat_rank = {
                    "info": 0,
                    "low": 1,
                    "medium": 2,
                    "high": 3,
                    "critical": 4,
                }.get(threat)
                if threat_rank is not None:
                    clauses.append(f"{threat_expression} = ?")
                    params.append(threat_rank)
            count_where = " AND ".join(clauses)
            count_params = list(params)
            if cursor:
                clauses.append(
                    self._cursor_clause(sort_expression, "alert_id", direction)
                )
                params.extend([cursor[0], cursor[0], cursor[1]])
            where = " AND ".join(clauses)
            total = connection.execute(
                f"SELECT COUNT(*) AS count FROM alerts WHERE {count_where}",
                count_params,
            ).fetchone()["count"]
            rows = connection.execute(
                f"SELECT alerts.*, {sort_expression} AS sort_value, "
                f"{threat_expression} AS threat_rank, "
                f"{evidence_expression} AS evidence_count "
                f"FROM alerts WHERE {where} ORDER BY "
                f"{sort_expression} {direction}, alert_id {direction} LIMIT ?",
                (*params, limit + 1),
            ).fetchall()
            has_more = len(rows) > limit
            items: List[Dict[str, Any]] = []
            sort_values: List[Any] = []
            for row in rows[:limit]:
                alert = dict(row)
                sort_values.append(alert.pop("sort_value"))
                threat_rank = alert.pop("threat_rank")
                evidence_count = int(alert.pop("evidence_count") or 0)
                alert["alert_time"] = float(alert["alert_time"] or 0)
                alert["evidence_count"] = evidence_count
                alert["threat_level"] = self._threat_from_rank(threat_rank)
                alert.update(
                    self._score_fields(
                        alert.get("accumulated_threat_level"),
                        alert.get("accumulated_ratl"),
                        "when this alert crossed the threshold",
                    )
                )
                if include_details:
                    related = self._alert_evidence(connection, alert)
                    alert["evidence"] = related
                    alert["evidence_count"] = len(related)
                    alert["threat_level"] = self._highest_threat(
                        [
                            str(item.get("threat_level", "info")).lower()
                            for item in related
                        ]
                    )
                alert.update(self._ip_context_for_ip(str(alert["ip_alerted"])))
                items.append(alert)
            self._annotate_detection_networks(
                items, "ip_alerted", "alert_time"
            )
        next_cursor = (
            self._encode_cursor(
                sort_values[-1],
                str(items[-1]["alert_id"]),
            )
            if has_more and items
            else None
        )
        return {
            "items": items,
            "total": int(total),
            "full_total": full_total,
            "page_size": len(items),
            "next_cursor": next_cursor,
            "range": range_name,
            "sort": sort_key,
            "order": direction.lower(),
        }

    def _flow_uids_for_evidence(self, evidence_id: str) -> List[str]:
        """Read durable triggering flow IDs with a Redis fallback."""
        try:
            with self._connect_sqlite() as connection:
                if self._table_exists(connection, "evidence_flows"):
                    rows = connection.execute(
                        "SELECT uid FROM evidence_flows "
                        "WHERE evidence_id = ? ORDER BY uid LIMIT 1000",
                        (evidence_id,),
                    ).fetchall()
                    if rows:
                        return [str(row["uid"]).strip() for row in rows]
        except sqlite3.Error:
            pass
        return self._id_list(
            self.redis.hget("flows_causing_evidence", evidence_id)
        )

    def _recover_zeek_flows(self, grouped: Dict[str, Dict[str, Any]]) -> int:
        """Recover pruned flow details from bounded Zeek JSON logs.

        Parameters:
            grouped: Linked UIDs and any raw SQLite records already found.

        Returns:
            Number of linked UIDs recovered from Zeek logs.
        """
        output_dir = getattr(self, "output_dir", None)
        if output_dir is None:
            return 0
        log_dirs = (
            Path(output_dir) / "web_interface" / "zeek_recovery",
            Path(output_dir) / "zeek_files",
        )
        remaining = MAX_ZEEK_FALLBACK_BYTES
        recovered: set[str] = set()
        for log_type in ZEEK_FALLBACK_LOGS:
            for log_dir in log_dirs:
                path = log_dir / f"{log_type}.log"
                try:
                    size = path.stat().st_size
                    if not size or remaining <= 0:
                        continue
                    start = max(0, size - remaining)
                    with path.open("rb") as stream:
                        stream.seek(start)
                        if start:
                            remaining -= len(stream.readline())
                        while remaining > 0:
                            raw = stream.readline()
                            if not raw:
                                break
                            remaining -= len(raw)
                            try:
                                flow = json.loads(raw)
                            except (TypeError, ValueError):
                                continue
                            if not isinstance(flow, dict):
                                continue
                            uid = str(flow.get("uid") or "").strip()
                            if uid not in grouped:
                                continue
                            group = grouped[uid]
                            record = {
                                "uid": uid,
                                "flow": flow,
                                "table": (
                                    "flows"
                                    if log_type == "conn"
                                    else "altflows"
                                ),
                                "flow_type": log_type,
                                "source": "zeek_log",
                                "event_time": flow.get("ts"),
                            }
                            if log_type == "conn":
                                if group["network_flow"] is None:
                                    group["network_flow"] = record
                                    recovered.add(uid)
                            elif not any(
                                item.get("flow_type") == log_type
                                for item in group["protocol_flows"]
                            ):
                                group["protocol_flows"].append(record)
                                recovered.add(uid)
                except OSError:
                    continue
        return len(recovered)

    def flows_for_evidence(self, evidence_id: str) -> Dict[str, Any]:
        """Return triggering network flows grouped with protocol activity."""
        uids = self._flow_uids_for_evidence(evidence_id)
        if not uids:
            for item in self._redis_evidence():
                if item["id"] == evidence_id:
                    uids = self._id_list(item.get("uid", []))
                    break
        if not uids:
            return {
                "items": [],
                "total": 0,
                "linked_uid_count": 0,
                "unavailable_flow_count": 0,
                "network_flow_total": 0,
                "protocol_flow_total": 0,
                "recovered_flow_count": 0,
                "page_size": 0,
            }
        bounded_uids = list(
            dict.fromkeys(str(uid).strip() for uid in uids if str(uid).strip())
        )[:MAX_FLOW_LIMIT]
        placeholders = ",".join("?" for _ in bounded_uids)
        grouped: Dict[str, Dict[str, Any]] = {
            uid: {"uid": uid, "network_flow": None, "protocol_flows": []}
            for uid in bounded_uids
        }
        with self._connect_sqlite() as connection:
            for table in ("flows", "altflows"):
                rows = connection.execute(
                    f"SELECT * FROM {table} WHERE uid IN ({placeholders}) LIMIT 1000",
                    tuple(bounded_uids),
                ).fetchall()
                for row in rows:
                    record = dict(row)
                    record["flow"] = self._loads(record.get("flow"), {})
                    record["table"] = table
                    uid = str(record.get("uid", ""))
                    item = grouped.setdefault(
                        uid,
                        {
                            "uid": uid,
                            "network_flow": None,
                            "protocol_flows": [],
                        },
                    )
                    if table == "flows":
                        item["network_flow"] = record
                    else:
                        item["protocol_flows"].append(record)
        recovered_flow_count = 0
        if any(
            not group["network_flow"] and not group["protocol_flows"]
            for group in grouped.values()
        ):
            recovered_flow_count = self._recover_zeek_flows(grouped)
        items = [
            grouped[uid]
            for uid in bounded_uids
            if uid in grouped
            and (
                grouped[uid]["network_flow"] or grouped[uid]["protocol_flows"]
            )
        ]
        network_flow_total = sum(bool(item["network_flow"]) for item in items)
        protocol_flow_total = sum(
            len(item["protocol_flows"]) for item in items
        )
        return {
            "items": items,
            "total": len(items),
            "linked_uid_count": len(bounded_uids),
            "unavailable_flow_count": len(bounded_uids) - len(items),
            "network_flow_total": network_flow_total,
            "protocol_flow_total": protocol_flow_total,
            "recovered_flow_count": recovered_flow_count,
            "page_size": len(items),
        }

    def _snapshot(self, ip: str) -> Dict[str, Any]:
        """Read last-known host identity from the history database."""
        with connect_history(self.history_path, read_only=True) as connection:
            row = connection.execute(
                "SELECT observed_at, data FROM host_snapshots WHERE ip = ?",
                (ip,),
            ).fetchone()
        if not row:
            return {"ip": ip, "scope": self._scope(ip)}
        result = self._loads(row["data"], {})
        result["observed_at"] = float(row["observed_at"])
        return result

    def _live_host(self, ip: str) -> Dict[str, Any]:
        """Merge current Redis identity into a host snapshot."""
        result = self._snapshot(ip)
        profile_id = f"profile_{ip}"
        fields = self.redis.hgetall(profile_id)
        if not fields:
            result["live"] = False
            return result
        result.update(
            {
                "ip": ip,
                "scope": self._scope(ip),
                "hostname": fields.get("host_name", ""),
                "mac": fields.get("MAC", ""),
                "mac_vendor": fields.get("MAC_vendor", ""),
                "threat_level": fields.get("threat_level", "info"),
                "max_threat_level": fields.get("max_threat_level", "info"),
                "dns": self._loads(self.redis.hget("DNSresolution", ip), {}),
                "live": True,
            }
        )
        return result

    def host_names(self, query: Dict[str, List[str]]) -> Dict[str, Any]:
        """Resolve a bounded set of displayed IPs to stored host names.

        Parameters:
            query: Repeated ``ip`` query values from the current view.

        Returns:
            Name and provenance for each valid requested address.
        """
        requested: Dict[str, str] = {}
        for value in query.get("ip", [])[:MAX_PAGE_SIZE]:
            try:
                ip = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            requested[value] = ip
        ips = list(dict.fromkeys(requested.values()))
        if not ips:
            return {"names": {}}
        annotations = HostProfileStore.annotations_for_ips(
            getattr(
                self,
                "host_profiles_path",
                Path("permanent/host_profiles/hosts.sqlite"),
            ),
            ips,
        )

        snapshots: Dict[str, Dict[str, Any]] = {}
        try:
            placeholders = ", ".join("?" for _ in ips)
            with connect_history(
                self.history_path, read_only=True
            ) as connection:
                rows = connection.execute(
                    f"SELECT ip, data FROM host_snapshots WHERE ip IN ({placeholders})",
                    ips,
                ).fetchall()
            snapshots = {
                str(row["ip"]): self._loads(row["data"], {}) for row in rows
            }
        except (OSError, sqlite3.Error):
            pass

        live_identity: List[Any] = []
        try:
            pipeline = self.redis.pipeline(transaction=False)
            for ip in ips:
                pipeline.hget(f"profile_{ip}", "host_name")
                pipeline.hget("DNSresolution", ip)
                pipeline.hget(f"profile_{ip}", "MAC_vendor")
            live_identity = pipeline.execute()
        except (AttributeError, redis.RedisError):
            live_identity = []

        names: Dict[str, Dict[str, str]] = {}
        for index, ip in enumerate(ips):
            snapshot = snapshots.get(ip, {})
            annotation = annotations.get(ip, {})
            live_name = (
                live_identity[index * 3]
                if index * 3 < len(live_identity)
                else ""
            )
            name = str(annotation.get("name") or "")
            source = "User name" if name else ""
            if not name:
                name = str(live_name or snapshot.get("hostname") or "")
                source = "Hostname" if name else ""
            if not name:
                live_dns = (
                    live_identity[index * 3 + 1]
                    if index * 3 + 1 < len(live_identity)
                    else None
                )
                dns = self._loads(live_dns, {}) or snapshot.get("dns") or {}
                domains = (
                    dns.get("domains", []) if isinstance(dns, dict) else []
                )
                if isinstance(domains, list) and domains:
                    name = str(domains[0])
                    source = "DNS"
            if not name and getattr(self, "cache", None) is not None:
                try:
                    reverse_dns = self.cache.hget("IPsInfo:reverse_dns", ip)
                except (AttributeError, redis.RedisError):
                    reverse_dns = None
                reverse_dns = self._loads(reverse_dns, reverse_dns)
                if isinstance(reverse_dns, (list, tuple)):
                    reverse_dns = reverse_dns[0] if reverse_dns else ""
                if reverse_dns:
                    name = str(reverse_dns)
                    source = "rDNS"
            if not name:
                vendor = (
                    live_identity[index * 3 + 2]
                    if index * 3 + 2 < len(live_identity)
                    else ""
                ) or snapshot.get("mac_vendor")
                if vendor:
                    name = f"{str(vendor).strip()} device"
                    source = "MAC vendor"
            names[ip] = {"name": name, "source": source}
        return {"names": {value: names[ip] for value, ip in requested.items()}}

    def _current_profile_threats(self) -> Dict[str, str]:
        """
        Read current maximum threat levels for live Redis profiles in one batch.

        Returns:
            Live profile IPs mapped to canonical lowercase threat levels.
        """
        try:
            profiles = self.redis.zrange("profiles", 0, -1)
            if not isinstance(profiles, (list, tuple)):
                return {}
            pipeline = self.redis.pipeline(transaction=False)
            for profile_id in profiles:
                pipeline.hget(str(profile_id), "max_threat_level")
            values = pipeline.execute()
        except (redis.RedisError, TypeError):
            return {}
        result: Dict[str, str] = {}
        for profile_id, value in zip(profiles, values):
            decoded = self._loads(value, value)
            result[str(profile_id).removeprefix(PROFILE_PREFIX)] = str(
                decoded or "info"
            ).lower()
        return result

    def _host_ips(self, ip: str) -> List[str]:
        """Return only the selected Slips profile IP.

        Parameters:
            ip: Profile IP selected in the host workspace.

        Returns:
            A single-item list suitable for parameterized SQL predicates.
        """
        return [ip]

    def _host_load(self, ip: str) -> Dict[str, Any]:
        """Read compact all-time traffic totals for the exact profile IP."""
        ips = self._host_ips(ip)
        predicate, params = self._ip_predicate(ips)
        placeholders = ",".join("?" for _ in ips)
        src_in = f"src_ip IN ({placeholders})"
        dst_in = f"dst_ip IN ({placeholders})"
        with connect_history(self.history_path, read_only=True) as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS flows, COALESCE(SUM(bytes), 0) AS bytes, "
                "COALESCE(SUM(packets), 0) AS packets, "
                f"COALESCE(SUM(CASE WHEN {dst_in} AND NOT {src_in} "
                "THEN 1 ELSE 0 END), 0) AS inbound_flows, "
                f"COALESCE(SUM(CASE WHEN {src_in} AND NOT {dst_in} "
                "THEN 1 ELSE 0 END), 0) AS outbound_flows, "
                f"COALESCE(SUM(CASE WHEN {dst_in} AND NOT {src_in} "
                "THEN bytes ELSE 0 END), 0) AS inbound_bytes, "
                f"COALESCE(SUM(CASE WHEN {src_in} AND NOT {dst_in} "
                "THEN bytes ELSE 0 END), 0) AS outbound_bytes, "
                "COALESCE(MAX(event_time), 0) AS last_seen "
                f"FROM flow_index WHERE {predicate}",
                (
                    *ips,
                    *ips,
                    *ips,
                    *ips,
                    *ips,
                    *ips,
                    *ips,
                    *ips,
                    *params,
                ),
            ).fetchone()
        return (
            dict(row)
            if row
            else {
                "flows": 0,
                "bytes": 0,
                "packets": 0,
                "inbound_flows": 0,
                "outbound_flows": 0,
                "inbound_bytes": 0,
                "outbound_bytes": 0,
                "last_seen": 0,
            }
        )

    def _host_page_loads(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """Aggregate page traffic in one indexed history query.

        Parameters:
            ips: IPs in the requested Hosts page.

        Returns:
            Traffic totals keyed by IP.
        """
        if not ips:
            return {}
        placeholders = ",".join("?" for _ in ips)
        with connect_history(self.history_path, read_only=True) as connection:
            rows = connection.execute(
                "SELECT ip, COUNT(*) AS flows, SUM(bytes) AS bytes, "
                "SUM(packets) AS packets, "
                "SUM(inbound_flows) AS inbound_flows, "
                "SUM(outbound_flows) AS outbound_flows, "
                "SUM(inbound_bytes) AS inbound_bytes, "
                "SUM(outbound_bytes) AS outbound_bytes, "
                "MAX(event_time) AS last_seen FROM ("
                "SELECT src_ip AS ip, bytes, packets, event_time, "
                "0 AS inbound_flows, "
                "CASE WHEN src_ip != dst_ip THEN 1 ELSE 0 END "
                "AS outbound_flows, 0 AS inbound_bytes, "
                "CASE WHEN src_ip != dst_ip THEN bytes ELSE 0 END "
                "AS outbound_bytes FROM flow_index "
                f"WHERE src_ip IN ({placeholders}) UNION ALL "
                "SELECT dst_ip AS ip, bytes, packets, event_time, "
                "1 AS inbound_flows, 0 AS outbound_flows, "
                "bytes AS inbound_bytes, 0 AS outbound_bytes "
                f"FROM flow_index WHERE dst_ip IN ({placeholders}) "
                "AND src_ip != dst_ip) GROUP BY ip",
                (*ips, *ips),
            ).fetchall()
        return {str(row["ip"]): dict(row) for row in rows}

    def _host_page_counts(self, ips: List[str]) -> Dict[str, Dict[str, int]]:
        """Count evidence and alerts for a page with two indexed queries.

        Parameters:
            ips: IPs in the requested Hosts page.

        Returns:
            Evidence and alert counts keyed by IP.
        """
        counts = {ip: {"evidence": 0, "alerts": 0} for ip in ips}
        if not ips:
            return counts
        placeholders = ",".join("?" for _ in ips)
        try:
            with self._connect_sqlite() as connection:
                for table, column, field in (
                    ("evidence", "profile_ip", "evidence"),
                    ("alerts", "ip_alerted", "alerts"),
                ):
                    rows = connection.execute(
                        f"SELECT {column} AS ip, COUNT(*) AS count "
                        f"FROM {table} WHERE {column} IN ({placeholders}) "
                        f"GROUP BY {column}",
                        ips,
                    ).fetchall()
                    for row in rows:
                        counts[str(row["ip"])][field] = int(row["count"])
        except sqlite3.Error:
            pass
        return counts

    def _host_page_identity(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """Fetch live names, DNS, and threat context with two pipelines.

        Parameters:
            ips: IPs in the requested Hosts page.

        Returns:
            Identity records keyed by IP.
        """
        if not ips:
            return {}
        context_fields = ("reverse_dns", "threatintelligence")
        profile_pipe = self.redis.pipeline(transaction=False)
        cache_pipe = self.cache.pipeline(transaction=False)
        for ip in ips:
            profile_pipe.hgetall(f"profile_{ip}")
            profile_pipe.hget("DNSresolution", ip)
            for field in context_fields:
                cache_pipe.hget(f"IPsInfo:{field}", ip)
        try:
            profile_values = profile_pipe.execute()
            cache_values = cache_pipe.execute()
        except redis.RedisError:
            return {}
        result: Dict[str, Dict[str, Any]] = {}
        for index, ip in enumerate(ips):
            fields = profile_values[index * 2] or {}
            dns = self._loads(profile_values[index * 2 + 1], {})
            ti = {}
            for offset, field in enumerate(context_fields):
                raw = cache_values[index * len(context_fields) + offset]
                ti[field] = self._loads(raw, raw)
            rdns = ti.get("reverse_dns") or ""
            if isinstance(rdns, (list, tuple)):
                rdns = rdns[0] if rdns else ""
            domains = dns.get("domains", []) if isinstance(dns, dict) else []
            if not isinstance(domains, (list, tuple)):
                domains = [domains]
            ti_record = ti.get("threatintelligence") or {}
            sources = (
                ti_record.get("source", [])
                if isinstance(ti_record, dict)
                else []
            )
            if not isinstance(sources, (list, tuple)):
                sources = [sources]
            result[ip] = {
                "fields": fields,
                "dns": dns,
                "dns_name": str(rdns or (domains[0] if domains else "")),
                "dns_name_source": (
                    "rDNS" if rdns else ("DNS" if domains else "")
                ),
                "ti_feeds": [str(source) for source in sources if source],
            }
        return result

    def hosts(self, query: Dict[str, List[str]]) -> Dict[str, Any]:
        """Return one filtered, cursor-bounded historical host page."""
        limit = self._limit(query)
        search = self._query_value(query, "search").lower()
        scope = self._query_value(query, "scope")
        threat = self._query_value(query, "threat").lower()
        current_threats = self._current_profile_threats() if threat else {}
        cursor = self._decode_cursor(self._query_value(query, "cursor"))
        with connect_history(self.history_path, read_only=True) as connection:
            connection.execute("BEGIN")
            connection.execute(
                "ATTACH DATABASE ? AS run_db", (str(self.sqlite_path),)
            )
            latest_row = connection.execute(
                "SELECT MAX(event_time) AS latest FROM flow_index"
            ).fetchone()
            latest = float(latest_row["latest"] or 0)
            if not latest:
                latest_row = connection.execute(
                    "SELECT MAX(observed_at) AS latest FROM host_snapshots"
                ).fetchone()
                latest = float(latest_row["latest"] or 0)
            full_total = int(
                connection.execute(
                    "SELECT COUNT(*) AS count FROM host_snapshots"
                ).fetchone()["count"]
            )
            evidence_columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA run_db.table_info(evidence)"
                ).fetchall()
            }
            start, end, range_name = self._time_bounds(query, latest)
            flow_expression = (
                "(SELECT COUNT(*) FROM flow_index fi "
                "WHERE fi.src_ip = hs.ip OR fi.dst_ip = hs.ip)"
            )
            byte_expression = (
                "(SELECT COALESCE(SUM(bytes), 0) FROM flow_index fi "
                "WHERE fi.src_ip = hs.ip OR fi.dst_ip = hs.ip)"
            )
            evidence_expression = "(SELECT COUNT(*) FROM run_db.evidence e WHERE e.profile_ip = hs.ip)"
            alert_expression = "(SELECT COUNT(*) FROM run_db.alerts a WHERE a.ip_alerted = hs.ip)"
            last_seen_expression = (
                "COALESCE((SELECT MAX(event_time) FROM flow_index fi "
                "WHERE fi.src_ip = hs.ip OR fi.dst_ip = hs.ip), hs.observed_at)"
            )
            threat_expression = (
                "CASE LOWER(COALESCE(json_extract(hs.data, '$.max_threat_level'), "
                "'info')) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
                "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"
            )
            score_field = (
                "accumulated_ratl"
                if getattr(self, "score_mode", "ratl") == "ratl"
                else "accumulated_threat_level"
            )
            score_expression = (
                f"COALESCE(json_extract(hs.data, '$.{score_field}'), 0)"
            )
            peak_score_expression = (
                f"(SELECT MAX(e.{score_field}) FROM run_db.evidence e "
                "WHERE e.profile_ip = hs.ip)"
                if score_field in evidence_columns
                else "NULL"
            )
            peak_score_sort_expression = (
                f"COALESCE({peak_score_expression}, 0)"
            )
            sort_key, sort_expression, direction = self._sort_spec(
                query,
                {
                    "ip": "LOWER(hs.ip)",
                    "scope": "LOWER(COALESCE(json_extract(hs.data, '$.scope'), ''))",
                    "hostname": (
                        "LOWER(COALESCE(json_extract(hs.data, '$.hostname'), ''))"
                    ),
                    "mac": "LOWER(COALESCE(json_extract(hs.data, '$.mac'), ''))",
                    "threat": threat_expression,
                    "flows": flow_expression,
                    "bytes": byte_expression,
                    "evidence": evidence_expression,
                    "alerts": alert_expression,
                    "score": score_expression,
                    "peak_score": peak_score_sort_expression,
                    "last_seen": last_seen_expression,
                },
                "last_seen",
            )
            clauses = ["1 = 1"]
            params: List[Any] = []
            if range_name != "all" and start is not None:
                clauses.append(f"{last_seen_expression} >= ?")
                params.append(start)
            if range_name != "all" and end is not None:
                clauses.append(f"{last_seen_expression} <= ?")
                params.append(end)
            if search:
                clauses.append("LOWER(hs.data) LIKE ?")
                params.append(f"%{search}%")
            if scope:
                clauses.append("json_extract(hs.data, '$.scope') = ?")
                params.append(scope)
            if threat:
                snapshot_threat = (
                    "LOWER(COALESCE(json_extract("
                    "hs.data, '$.max_threat_level'), 'info')) = ?"
                )
                if current_threats:
                    live_ips = list(current_threats)
                    matching_ips = [
                        ip
                        for ip, level in current_threats.items()
                        if level == threat
                    ]
                    live_placeholders = ",".join("?" for _ in live_ips)
                    if matching_ips:
                        matching_placeholders = ",".join(
                            "?" for _ in matching_ips
                        )
                        clauses.append(
                            f"(hs.ip IN ({matching_placeholders}) OR "
                            f"(hs.ip NOT IN ({live_placeholders}) AND "
                            f"{snapshot_threat}))"
                        )
                        params.extend([*matching_ips, *live_ips, threat])
                    else:
                        clauses.append(
                            f"(hs.ip NOT IN ({live_placeholders}) AND "
                            f"{snapshot_threat})"
                        )
                        params.extend([*live_ips, threat])
                else:
                    clauses.append(snapshot_threat)
                    params.append(threat)
            count_where = " AND ".join(clauses)
            count_params = list(params)
            if cursor:
                clauses.append(
                    self._cursor_clause(sort_expression, "hs.ip", direction)
                )
                params.extend([cursor[0], cursor[0], cursor[1]])
            where = " AND ".join(clauses)
            total = connection.execute(
                f"SELECT COUNT(*) AS count FROM host_snapshots hs WHERE {count_where}",
                count_params,
            ).fetchone()["count"]
            rows = connection.execute(
                f"SELECT hs.ip, hs.observed_at, hs.data, "
                f"{peak_score_expression} AS peak_alert_score, "
                f"{sort_expression} AS sort_value FROM host_snapshots hs "
                f"WHERE {where} ORDER BY {sort_expression} {direction}, "
                f"hs.ip {direction} LIMIT ?",
                (*params, limit + 1),
            ).fetchall()
        has_more = len(rows) > limit
        page_rows = rows[:limit]
        page_ips = [str(row["ip"]) for row in page_rows]
        fast_page = getattr(self, "cache", None) is not None
        if fast_page:
            loads = self._host_page_loads(page_ips)
            counts = self._host_page_counts(page_ips)
            identities = self._host_page_identity(page_ips)
        items: List[Dict[str, Any]] = []
        annotations = HostProfileStore.annotations_for_ips(
            getattr(
                self,
                "host_profiles_path",
                Path("permanent/host_profiles/hosts.sqlite"),
            ),
            page_ips,
        )
        for row in page_rows:
            ip = str(row["ip"])
            if fast_page:
                host = self._loads(row["data"], {})
                identity = identities.get(ip, {})
                fields = identity.get("fields") or {}
                host.update({"ip": ip, "live": bool(fields)})
                if fields:
                    host.update(
                        {
                            "scope": self._scope(ip),
                            "hostname": fields.get("host_name", ""),
                            "mac": fields.get("MAC", ""),
                            "mac_vendor": fields.get("MAC_vendor", ""),
                            "threat_level": fields.get("threat_level", "info"),
                            "max_threat_level": fields.get(
                                "max_threat_level", "info"
                            ),
                            "dns": identity.get("dns", {}),
                        }
                    )
            else:
                host = self._live_host(ip)
            host["observed_at"] = float(row["observed_at"])
            host["peak_alert_score"] = (
                float(row["peak_alert_score"])
                if row["peak_alert_score"] is not None
                else None
            )
            if fast_page:
                host["load"] = loads.get(
                    ip,
                    {
                        "flows": 0,
                        "bytes": 0,
                        "packets": 0,
                        "inbound_flows": 0,
                        "outbound_flows": 0,
                        "inbound_bytes": 0,
                        "outbound_bytes": 0,
                        "last_seen": 0,
                    },
                )
                dns_name = identities.get(ip, {}).get("dns_name", "")
                dns_source = identities.get(ip, {}).get("dns_name_source", "")
                if not dns_name:
                    saved_dns = host.get("dns") or {}
                    domains = (
                        saved_dns.get("domains", [])
                        if isinstance(saved_dns, dict)
                        else []
                    )
                    if isinstance(domains, (list, tuple)) and domains:
                        dns_name = str(domains[0])
                        dns_source = "DNS"
                host.update(
                    {
                        "dns_name": dns_name,
                        "dns_name_source": dns_source,
                        "ti_feeds": identities.get(ip, {}).get("ti_feeds", []),
                    }
                )
                host["evidence_count"] = counts[ip]["evidence"]
                host["alert_count"] = counts[ip]["alerts"]
            else:
                host["load"] = self._host_load(ip)
                host.update(self._ip_context_for_ip(ip, host.get("dns")))
                host["evidence_count"] = self._profile_evidence_count(ip)
                host["alert_count"] = self._profile_alert_count(ip)
            annotation = annotations.get(ip, {})
            host["user_name"] = annotation.get("name", "")
            host["user_note"] = annotation.get("note", "")
            items.append(host)
        self._attach_current_host_scores(items)
        next_cursor = (
            self._encode_cursor(
                rows[min(limit, len(rows)) - 1]["sort_value"],
                str(items[-1]["ip"]),
            )
            if has_more and items
            else None
        )
        return {
            "items": items,
            "total": int(total),
            "full_total": full_total,
            "page_size": len(items),
            "next_cursor": next_cursor,
            "range": range_name,
            "sort": sort_key,
            "order": direction.lower(),
        }

    def _profile_evidence_count(self, ip: str) -> int:
        """Count durable evidence for the exact profile IP."""
        ips = self._host_ips(ip)
        placeholders = ",".join("?" for _ in ips)
        try:
            with self._connect_sqlite() as connection:
                if not self._table_exists(connection, "evidence"):
                    return sum(
                        item.get("profile_ip") in ips
                        for item in self._redis_evidence()
                    )
                return int(
                    connection.execute(
                        "SELECT COUNT(*) AS count FROM evidence "
                        f"WHERE profile_ip IN ({placeholders}) ",
                        ips,
                    ).fetchone()["count"]
                )
        except sqlite3.Error:
            return 0

    def _profile_alert_count(self, ip: str) -> int:
        """Count durable alerts for the exact profile IP."""
        ips = self._host_ips(ip)
        placeholders = ",".join("?" for _ in ips)
        try:
            with self._connect_sqlite() as connection:
                return int(
                    connection.execute(
                        "SELECT COUNT(*) AS count FROM alerts "
                        f"WHERE ip_alerted IN ({placeholders})",
                        ips,
                    ).fetchone()["count"]
                )
        except sqlite3.Error:
            return 0

    def _ti_for_ip(self, ip: str) -> Dict[str, Any]:
        """Read cached threat-intelligence fields for an IP."""
        result: Dict[str, Any] = {}
        try:
            for field in TI_FIELDS:
                value = self.cache.hget(f"IPsInfo:{field}", ip)
                if value is not None:
                    result[field] = self._loads(value, value)
        except (AttributeError, redis.RedisError):
            pass
        return result

    def _ip_context_for_ip(
        self, ip: str, dns: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Build compact DNS and threat-intelligence context for an IP.

        Parameters:
            ip: IP address whose cached context should be read.
            dns: Optional already-loaded DNS-resolution record for the IP.

        Returns:
            A display-ready name, its source, and matching TI feed names.
        """
        ti = self._ti_for_ip(ip)
        rdns_value = ti.get("reverse_dns", "")
        if isinstance(rdns_value, (list, tuple)):
            rdns_value = rdns_value[0] if rdns_value else ""
        rdns = str(rdns_value or "")
        if dns is None:
            try:
                dns = self._loads(self.redis.hget("DNSresolution", ip), {})
            except (AttributeError, redis.RedisError):
                dns = {}
        domains_value = dns.get("domains", []) if isinstance(dns, dict) else []
        if not isinstance(domains_value, (list, tuple)):
            domains_value = [domains_value]
        domains = [str(domain) for domain in domains_value if domain]
        ti_record = ti.get("threatintelligence", {})
        source_value = (
            ti_record.get("source", []) if isinstance(ti_record, dict) else []
        )
        if not isinstance(source_value, (list, tuple)):
            source_value = [source_value]
        ti_feeds = [str(source) for source in source_value if source]
        return {
            "dns_name": rdns or (domains[0] if domains else ""),
            "dns_name_source": "rDNS" if rdns else ("DNS" if domains else ""),
            "ti_feeds": ti_feeds,
        }

    def _network_context_at(
        self,
        path: Path,
        ip: str,
        observed_at: Any,
        states: Dict[str, List[Dict[str, Any]]],
        names: Dict[str, str],
        run_name: str,
    ) -> Dict[str, str]:
        """Find an event's network from interface history or host sightings.

        Parameters:
            path: Permanent host profile database path.
            ip: Address associated with the detection.
            observed_at: Detection time as a Unix timestamp.
            states: Saved network states grouped by monitored interface.
            names: User names indexed by network identity.
            run_name: Current run identifier for routerless networks.

        Returns:
            Network identity, name, and display label.
        """
        saved = HostProfileStore.network_for_observation(path, ip, observed_at)
        try:
            address = ipaddress.ip_address(ip)
            timestamp = float(observed_at)
        except (TypeError, ValueError):
            return saved
        if address.is_global:
            return saved
        matches: Dict[str, Dict[str, Any]] = {}
        for snapshots in states.values():
            previous = [
                state
                for state in snapshots
                if state.get("changed_at")
                and float(state["changed_at"]) <= timestamp
            ]
            if not previous:
                continue
            state = max(previous, key=lambda item: float(item["changed_at"]))
            if not state.get("connected"):
                continue
            if address.version == 4:
                try:
                    is_local = address in ipaddress.ip_network(
                        state.get("local_network", ""), strict=False
                    )
                except ValueError:
                    is_local = False
            elif address.is_link_local:
                is_local = True
            else:
                is_local = False
                for item in state.get("addresses", []):
                    try:
                        if address in ipaddress.ip_network(
                            item.get("network", ""), strict=False
                        ):
                            is_local = True
                            break
                    except ValueError:
                        continue
            if is_local:
                network_id = HostProfileStore.network_id_for_state(
                    state, run_name
                )
                if network_id:
                    matches[network_id] = state
        if len(matches) != 1:
            return saved
        network_id, state = next(iter(matches.items()))
        gateway_mac = str(state.get("gateway_mac") or "").lower()
        default_label = (
            f"{state.get('local_network') or 'Local network'} · router {gateway_mac}"
            if gateway_mac
            else f"Unidentified network · {run_name}"
        )
        network_name = names.get(network_id, "")
        return {
            "network_id": network_id,
            "network_name": network_name,
            "network_label": network_name or default_label,
        }

    def _annotate_detection_networks(
        self,
        items: List[Dict[str, Any]],
        ip_field: str,
        time_field: str,
        start_field: str = "",
    ) -> None:
        """Attach the saved network identity for each detection timestamp.

        Parameters:
            items: Detection rows returned to the web interface.
            ip_field: Row field containing the affected host IP.
            time_field: Row field containing the detection timestamp.
            start_field: Optional first timestamp for grouped detections.
        """
        host_profiles_path = getattr(
            self,
            "host_profiles_path",
            Path("permanent") / "host_profiles" / "hosts.sqlite",
        )
        states: Dict[str, List[Dict[str, Any]]] = {}
        if getattr(self, "redis", None) is not None:
            try:
                raw_states = self.redis.hgetall("network_states")
            except redis.RedisError:
                raw_states = {}
            if not isinstance(raw_states, dict):
                raw_states = {}
            for interface, raw in raw_states.items():
                state = self._loads(raw, {})
                if not isinstance(state, dict):
                    continue
                history = state.get("history", [])
                snapshots = (
                    [item for item in history if isinstance(item, dict)]
                    if isinstance(history, list)
                    else []
                )
                states[interface] = [*snapshots, state]
        run_name = self._network_run_name() if states else ""
        names = HostProfileStore.network_names(
            host_profiles_path,
            (
                HostProfileStore.network_id_for_state(state, run_name)
                for snapshots in states.values()
                for state in snapshots
            ),
        )
        for item in items:
            context = self._network_context_at(
                host_profiles_path,
                str(item.get(ip_field) or ""),
                item.get(time_field) or 0,
                states,
                names,
                run_name,
            )
            if start_field and item.get(start_field):
                first_context = self._network_context_at(
                    host_profiles_path,
                    str(item.get(ip_field) or ""),
                    item[start_field],
                    states,
                    names,
                    run_name,
                )
                if (
                    first_context["network_id"]
                    and context["network_id"]
                    and first_context["network_id"] != context["network_id"]
                ):
                    context = {
                        "network_id": ",".join(
                            sorted(
                                {
                                    first_context["network_id"],
                                    context["network_id"],
                                }
                            )
                        ),
                        "network_name": "",
                        "network_label": "Multiple networks",
                    }
            item.update(context)

    def _current_network_profile_first(
        self, ip: str, profiles: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Show an address's current network identity before older runs.

        Parameters:
            ip: Host address being opened.
            profiles: Permanent profiles ordered by last sighting.

        Returns:
            Profiles with the matching current network first, if known.
        """
        if len(profiles) < 2:
            return profiles
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return profiles
        current_ids = set()
        run_name = self._network_run_name()
        for raw in self.redis.hgetall("network_states").values():
            state = self._loads(raw, {})
            if not isinstance(state, dict) or not state.get("connected"):
                continue
            try:
                network = ipaddress.ip_network(
                    state.get("local_network", ""), strict=False
                )
            except ValueError:
                continue
            if address in network:
                current_ids.add(
                    HostProfileStore.network_id_for_state(state, run_name)
                )
        if not current_ids:
            return profiles
        return sorted(
            profiles,
            key=lambda profile: profile.get("network_id") not in current_ids,
        )

    def host(self, ip: str) -> Dict[str, Any]:
        """Return complete bounded context for one current or historical host."""
        host = self._live_host(ip)
        if not host.get("observed_at") and not host.get("live"):
            raise KeyError(ip)
        self._attach_current_host_scores([host])
        host_ips = self._host_ips(ip)
        host["all_ips"] = host_ips
        host["load"] = self._host_load(ip)
        host["ti"] = self._ti_for_ip(ip)
        host["permanent_profiles"] = HostProfileStore.read(
            getattr(
                self,
                "host_profiles_path",
                Path("permanent/host_profiles/hosts.sqlite"),
            ),
            ip,
        )
        host["permanent_profiles"] = self._current_network_profile_first(
            ip, host["permanent_profiles"]
        )
        if host["permanent_profiles"]:
            host["user_name"] = host["permanent_profiles"][0]["user_name"]
            host["user_note"] = host["permanent_profiles"][0]["user_note"]
        else:
            host["user_name"] = ""
            host["user_note"] = ""
        alerts_by_id: Dict[str, Dict[str, Any]] = {}
        alert_total = 0
        for address in host_ips:
            alert_page = self.alerts(
                {
                    "range": ["all"],
                    "profile": [address],
                    "limit": ["100"],
                    "details": ["false"],
                }
            )
            alert_total += int(alert_page["total"])
            alerts_by_id.update(
                {str(item["alert_id"]): item for item in alert_page["items"]}
            )
        host["alerts"] = sorted(
            alerts_by_id.values(),
            key=lambda item: (
                float(item.get("alert_time") or 0),
                str(item.get("alert_id", "")),
            ),
            reverse=True,
        )[:MAX_PAGE_SIZE]
        host["alert_count"] = alert_total
        host["evidence"] = []
        host["evidence_count"] = self._profile_evidence_count(ip)
        return host

    def evidence_for_host(
        self, ip: str, query: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """
        Return one bounded evidence page for the exact profile IP.

        Parameters:
            ip: Primary host address.
            query: Request filters, sorting, time range, and cursor values.

        Returns:
            One evidence page with durable totals and pagination metadata.
        """
        host_query = dict(query)
        host_query["profile"] = self._host_ips(ip)
        host_query.pop("group", None)
        return self.evidence(host_query)

    @staticmethod
    def _ip_predicate(ips: Sequence[str]) -> tuple[str, List[Any]]:
        """Build a parameterized bidirectional host predicate."""
        placeholders = ",".join("?" for _ in ips)
        return (
            f"(src_ip IN ({placeholders}) OR dst_ip IN ({placeholders}))",
            [*ips, *ips],
        )

    def flows_for_host(
        self, ip: str, query: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """Return a bounded bidirectional host flow page."""
        try:
            requested = int(self._query_value(query, "limit", "100"))
        except ValueError:
            requested = 100
        limit = max(1, min(requested, MAX_FLOW_LIMIT))
        cursor = self._decode_cursor(self._query_value(query, "cursor"))
        ips = self._host_ips(ip)
        predicate, params = self._ip_predicate(ips)
        with connect_history(self.history_path, read_only=True) as history:
            latest_row = history.execute(
                "SELECT MAX(event_time) AS latest FROM flow_index"
            ).fetchone()
        latest = float(latest_row["latest"] or 0)
        start, end, range_name = self._time_bounds(query, latest)
        clauses = [predicate]
        if start is not None:
            clauses.append("event_time >= ?")
            params.append(start)
        if end is not None:
            clauses.append("event_time <= ?")
            params.append(end)
        with connect_history(self.history_path, read_only=True) as history:
            if self._query_value(query, "hide_excluded") == "1":
                history.execute(
                    "ATTACH DATABASE ? AS run_db",
                    (f"file:{self.sqlite_path}?mode=ro",),
                )
                evidence_columns = {
                    str(column[1])
                    for column in history.execute(
                        "PRAGMA run_db.table_info(evidence)"
                    ).fetchall()
                }
                if "whitelisted" in evidence_columns:
                    clauses.append(
                        "(NOT EXISTS (SELECT 1 FROM run_db.evidence_flows ef "
                        "JOIN run_db.evidence e ON e.evidence_id = ef.evidence_id "
                        "WHERE ef.uid = flow_index.uid AND e.whitelisted = 1) "
                        "OR EXISTS (SELECT 1 FROM run_db.evidence_flows ef "
                        "JOIN run_db.evidence e ON e.evidence_id = ef.evidence_id "
                        "WHERE ef.uid = flow_index.uid "
                        "AND COALESCE(e.whitelisted, 0) = 0))"
                    )
            count_clauses = list(clauses)
            count_params = list(params)
            if cursor:
                clauses.append(
                    "(event_time < ? OR (event_time = ? AND uid < ?))"
                )
                params.extend([cursor[0], cursor[0], cursor[1]])
            where = " AND ".join(clauses)
            total = history.execute(
                f"SELECT COUNT(*) AS count FROM flow_index WHERE "
                f"{' AND '.join(count_clauses)}",
                count_params,
            ).fetchone()["count"]
            index_rows = history.execute(
                f"SELECT * FROM flow_index WHERE {where} "
                "ORDER BY event_time DESC, uid DESC LIMIT ?",
                (*params, limit + 1),
            ).fetchall()
        has_more = len(index_rows) > limit
        index_rows = index_rows[:limit]
        raw_by_uid: Dict[str, Dict[str, Any]] = {}
        if index_rows:
            uids = [str(row["uid"]) for row in index_rows]
            placeholders = ",".join("?" for _ in uids)
            with self._connect_sqlite() as connection:
                rows = connection.execute(
                    f"SELECT uid, flow, label FROM flows WHERE uid IN ({placeholders})",
                    uids,
                ).fetchall()
            raw_by_uid = {
                str(row["uid"]): self._loads(row["flow"], {}) for row in rows
            }
        host_ips = set(ips)
        items: List[Dict[str, Any]] = []
        for row in index_rows:
            raw = raw_by_uid.get(str(row["uid"]), {})
            src = str(row["src_ip"])
            dst = str(row["dst_ip"])
            if src in host_ips and dst in host_ips:
                direction = "internal"
                peer = dst
            elif src in host_ips:
                direction = "outbound"
                peer = dst
            else:
                direction = "inbound"
                peer = src
            items.append(
                {
                    "uid": str(row["uid"]),
                    "event_time": float(row["event_time"]),
                    "direction": direction,
                    "peer": peer,
                    "src_ip": src,
                    "dst_ip": dst,
                    "src_port": raw.get("sport"),
                    "dst_port": raw.get("dport"),
                    "proto": str(row["proto"] or ""),
                    "app_proto": str(row["app_proto"] or ""),
                    "state": raw.get("state", ""),
                    "duration": raw.get("dur", 0),
                    "packets": int(row["packets"] or 0),
                    "bytes": int(row["bytes"] or 0),
                    "label": str(row["label"] or ""),
                    "raw": raw,
                }
            )
        next_cursor = (
            self._encode_cursor(
                float(items[-1]["event_time"]), str(items[-1]["uid"])
            )
            if has_more and items
            else None
        )
        return {
            "items": items,
            "total": int(total),
            "page_size": len(items),
            "next_cursor": next_cursor,
            "range": range_name,
            "host_ips": ips,
        }

    def traffic_summary(
        self, ip: str, query: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """Return bounded server-side host traffic plot aggregates."""
        try:
            max_points = int(self._query_value(query, "max_points", "300"))
        except ValueError:
            max_points = 300
        max_points = max(10, min(max_points, MAX_CHART_POINTS))
        ips = self._host_ips(ip)
        predicate, params = self._ip_predicate(ips)
        with connect_history(self.history_path, read_only=True) as connection:
            latest_row = connection.execute(
                "SELECT MAX(event_time) AS latest FROM flow_index"
            ).fetchone()
        latest = float(latest_row["latest"] or 0)
        start, end, range_name = self._time_bounds(query, latest)
        clauses = [predicate]
        if start is not None:
            clauses.append("event_time >= ?")
            params.append(start)
        if end is not None:
            clauses.append("event_time <= ?")
            params.append(end)
        where = " AND ".join(clauses)
        with connect_history(self.history_path, read_only=True) as connection:
            bounds = connection.execute(
                f"SELECT MIN(event_time) AS first, MAX(event_time) AS last "
                f"FROM flow_index WHERE {where}",
                params,
            ).fetchone()
            first = float(bounds["first"] or 0)
            last = float(bounds["last"] or 0)
            bucket = max(math.ceil(max(last - first, 1) / max_points), 1)
            placeholders = ",".join("?" for _ in ips)
            timeline = connection.execute(
                f"SELECT CAST(event_time / ? AS INTEGER) * ? AS ts, "
                f"SUM(CASE WHEN src_ip IN ({placeholders}) THEN 1 ELSE 0 END) "
                "AS outbound_flows, "
                f"SUM(CASE WHEN src_ip NOT IN ({placeholders}) THEN 1 ELSE 0 END) "
                "AS inbound_flows, "
                f"SUM(CASE WHEN src_ip IN ({placeholders}) THEN bytes ELSE 0 END) "
                "AS outbound_bytes, "
                f"SUM(CASE WHEN src_ip NOT IN ({placeholders}) THEN bytes ELSE 0 END) "
                "AS inbound_bytes FROM flow_index "
                f"WHERE {where} GROUP BY ts ORDER BY ts",
                (
                    bucket,
                    bucket,
                    *ips,
                    *ips,
                    *ips,
                    *ips,
                    *params,
                ),
            ).fetchall()
            protocol = connection.execute(
                f"SELECT COALESCE(NULLIF(app_proto, ''), proto) AS name, "
                f"COUNT(*) AS value FROM flow_index WHERE {where} "
                "GROUP BY name ORDER BY value DESC LIMIT 12",
                params,
            ).fetchall()
            peer_expression = f"CASE WHEN src_ip IN ({placeholders}) THEN dst_ip ELSE src_ip END"
            peers = connection.execute(
                f"SELECT {peer_expression} AS name, COUNT(*) AS value "
                f"FROM flow_index WHERE {where} GROUP BY name "
                "ORDER BY value DESC LIMIT 12",
                (*ips, *params),
            ).fetchall()
        return {
            "timeline": [dict(row) for row in timeline],
            "protocols": [dict(row) for row in protocol],
            "peers": [dict(row) for row in peers],
            "range": range_name,
            "bucket_seconds": bucket if first else 0,
        }

    def score_history(
        self, ip: str, query: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """
        Return bounded real Slips score samples for one profile IP.

        Parameters:
            ip: Primary host address.
            query: Time range and maximum chart-point parameters.

        Returns:
            Score timeline, threshold, reset hints, and persistence coverage.
        """
        try:
            max_points = int(self._query_value(query, "max_points", "600"))
        except ValueError:
            max_points = 600
        max_points = max(10, min(max_points, MAX_CHART_POINTS))
        # Slips accumulators are profile/IP-specific. MAC-derived aliases can
        # include unrelated public IPs that share a gateway MAC, so combining
        # their scores would fabricate a value that Slips never calculated.
        ips = [ip]
        placeholders = ",".join("?" for _ in ips)
        score_column = (
            "accumulated_ratl"
            if getattr(self, "score_mode", "ratl") == "ratl"
            else "accumulated_threat_level"
        )
        with self._connect_sqlite() as connection:
            columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(evidence)"
                ).fetchall()
            }
            latest_row = connection.execute(
                "SELECT MAX(evidence_time) AS latest FROM evidence"
            ).fetchone()
            latest = float(latest_row["latest"] or 0)
            start, end, range_name = self._time_bounds(query, latest)
            clauses = [f"profile_ip IN ({placeholders})"]
            params: List[Any] = list(ips)
            if start is not None:
                clauses.append("evidence_time >= ?")
                params.append(start)
            if end is not None:
                clauses.append("evidence_time <= ?")
                params.append(end)
            where = " AND ".join(clauses)
            evidence_total = int(
                connection.execute(
                    f"SELECT COUNT(*) AS count FROM evidence WHERE {where}",
                    params,
                ).fetchone()["count"]
            )
            if score_column not in columns:
                scored_evidence = 0
                timeline: List[Dict[str, Any]] = []
                bucket = 0
            else:
                scored_evidence = int(
                    connection.execute(
                        f"SELECT COUNT({score_column}) AS count FROM evidence "
                        f"WHERE {where}",
                        params,
                    ).fetchone()["count"]
                )
                bounds = connection.execute(
                    f"SELECT MIN(evidence_time) AS first, "
                    f"MAX(evidence_time) AS last FROM evidence WHERE {where} "
                    f"AND {score_column} IS NOT NULL",
                    params,
                ).fetchone()
                first = float(bounds["first"] or 0)
                last = float(bounds["last"] or 0)
                bucket = max(math.ceil(max(last - first, 1) / max_points), 1)
                rows = connection.execute(
                    "WITH samples AS ("
                    "SELECT evidence_id, evidence_time, timewindow, "
                    f"{score_column} AS score, "
                    "CAST(evidence_time / ? AS INTEGER) AS bucket_id "
                    f"FROM evidence WHERE {where} AND {score_column} IS NOT NULL"
                    "), ranked AS ("
                    "SELECT evidence_time AS ts, timewindow, score, bucket_id, "
                    "ROW_NUMBER() OVER (PARTITION BY timewindow, bucket_id "
                    "ORDER BY evidence_time DESC, evidence_id DESC) AS latest_rank, "
                    "MAX(score) OVER (PARTITION BY timewindow, bucket_id) "
                    "AS peak_score, "
                    "MIN(score) OVER (PARTITION BY timewindow, bucket_id) "
                    "AS minimum_score, "
                    "COUNT(*) OVER (PARTITION BY timewindow, bucket_id) "
                    "AS sample_count FROM samples) "
                    "SELECT ts, timewindow, score, peak_score, minimum_score, "
                    "sample_count FROM ranked WHERE latest_rank = 1 ORDER BY ts",
                    (bucket, *params),
                ).fetchall()
                timeline = [dict(row) for row in rows]

        current_host = self._live_host(ip)
        current_wall_time = time.time()
        current_in_range = (start is None or current_wall_time >= start) and (
            range_name != "custom" or end is None or current_wall_time <= end
        )
        if current_host.get("live") and current_in_range:
            self._attach_current_host_scores([current_host])
            current_score = current_host.get("alert_score")
            if current_score is not None:
                current_ts = max(latest, current_wall_time)
                if timeline and current_ts <= float(timeline[-1]["ts"]):
                    current_ts = float(timeline[-1]["ts"]) + 0.001
                timeline.append(
                    {
                        "ts": current_ts,
                        "timewindow": current_host.get("alert_score_twid", ""),
                        "score": float(current_score),
                        "peak_score": float(current_score),
                        "minimum_score": float(current_score),
                        "sample_count": 1,
                        "current": True,
                    }
                )

        resets = 0
        previous: Optional[Dict[str, Any]] = None
        peak_score = 0.0
        for point in timeline:
            point["threshold"] = self.alert_threshold
            peak_score = max(peak_score, float(point.get("peak_score") or 0))
            reset_reason = ""
            if previous:
                if point.get("timewindow") != previous.get("timewindow"):
                    reset_reason = "time window changed"
                elif float(point.get("score") or 0) < float(
                    previous.get("score") or 0
                ):
                    # A lower persisted sample is consistent with Slips
                    # resetting the score, but the chart cannot prove why it
                    # dropped (for example, whether an alert caused it).
                    reset_reason = "score decreased (possible reset)"
            point["reset_reason"] = reset_reason
            if reset_reason:
                resets += 1
            previous = point
        return {
            "timeline": timeline,
            "threshold": getattr(self, "alert_threshold", 5.0),
            "mode": getattr(self, "score_mode", "ratl").upper(),
            "peak_score": peak_score,
            "evidence_total": evidence_total,
            "scored_evidence": scored_evidence,
            "coverage": (
                scored_evidence / evidence_total if evidence_total else 1.0
            ),
            "reset_count": resets,
            "range": range_name,
            "bucket_seconds": bucket,
            "host_ips": ips,
        }

    def metrics(self, query: Dict[str, List[str]]) -> Dict[str, Any]:
        """Return bounded mixed-resolution runtime history."""
        range_name = self._query_value(query, "range", "15m")
        now = time.time()
        start = (
            now - METRIC_RANGES[range_name]
            if range_name in METRIC_RANGES
            else None
        )
        try:
            max_points = int(self._query_value(query, "max_points", "600"))
        except ValueError:
            max_points = 600
        max_points = max(10, min(max_points, MAX_CHART_POINTS))
        with connect_history(self.history_path, read_only=True) as connection:
            if start is None:
                first_rows = [
                    connection.execute(
                        "SELECT MIN(ts) AS first FROM runtime_metrics_1s"
                    ).fetchone()["first"],
                    connection.execute(
                        "SELECT MIN(bucket_ts) AS first FROM runtime_metrics_1m"
                    ).fetchone()["first"],
                ]
                available = [float(value) for value in first_rows if value]
                start = min(available) if available else now
            bucket = max(math.ceil(max(now - start, 1) / max_points), 1)
            recent = connection.execute(
                "SELECT CAST(ts / ? AS INTEGER) * ? AS ts, "
                "AVG(cpu_percent) AS cpu, MAX(cpu_percent) AS cpu_max, "
                "AVG(memory_mb) AS memory, MAX(memory_mb) AS memory_max, "
                "AVG(flows_per_second) AS fps, "
                "MAX(flows_per_second) AS fps_max "
                "FROM runtime_metrics_1s WHERE ts >= ? "
                "GROUP BY CAST(ts / ? AS INTEGER) ORDER BY ts",
                (bucket, bucket, start, bucket),
            ).fetchall()
            older_bucket = max(bucket, 60)
            older = connection.execute(
                "SELECT CAST(bucket_ts / ? AS INTEGER) * ? AS ts, "
                "AVG(cpu_avg) AS cpu, MAX(cpu_max) AS cpu_max, "
                "AVG(memory_avg) AS memory, MAX(memory_max) AS memory_max, "
                "AVG(fps_avg) AS fps, MAX(fps_max) AS fps_max "
                "FROM runtime_metrics_1m WHERE bucket_ts >= ? "
                "GROUP BY CAST(bucket_ts / ? AS INTEGER) ORDER BY ts",
                (older_bucket, older_bucket, start, older_bucket),
            ).fetchall()
        merged = {float(row["ts"]): dict(row) for row in older}
        merged.update({float(row["ts"]): dict(row) for row in recent})
        points = [merged[key] for key in sorted(merged)][-max_points:]
        return {
            "items": points,
            "page_size": len(points),
            "range": range_name,
            "max_points": max_points,
            "raw_retention_seconds": 24 * 60 * 60,
        }

    def _module_rows(
        self,
        evidence_counts: Optional[Counter[str]],
        error_counts: Dict[str, int],
        analysis_complete: bool,
    ) -> List[Dict[str, Any]]:
        """Build bounded process health rows for current module PIDs.

        Parameters:
            evidence_counts: Optional exact evidence totals by module. ``None``
                keeps expensive historical attribution out of the fast path.
            error_counts: Parsed runtime-error totals by module.
            analysis_complete: Whether the monitored analysis has finished.

        Returns:
            Bounded process-health rows for display.
        """
        modules: List[Dict[str, Any]] = []
        flow_modules = set(self.redis.smembers("flows_per_minute_modules"))
        now_bucket = int(time.time() // 60 * 60)
        total_memory = max(psutil.virtual_memory().total, 1)
        for name, raw_pid in self.redis.hgetall("PIDs").items():
            # utils.start_thread() stores native thread IDs in the same Redis
            # hash used for processes. They are implementation details of
            # their owning module, not standalone Slips modules.
            normalized_name = name.lower().replace(" ", "_")
            if (
                "thread" in normalized_name
                or normalized_name in INTERNAL_PID_NAMES
            ):
                continue
            try:
                pid = int(raw_pid)
                process = self._processes.get(pid)
                if process is None:
                    process = psutil.Process(pid)
                    self._processes[pid] = process
                running = process.is_running()
                status = process.status() if running else "stopped"
                memory_mb = (
                    round(process.memory_info().rss / 1024 / 1024, 1)
                    if running
                    else 0
                )
                memory_percent = (
                    process.memory_info().rss / total_memory * 100
                    if running
                    else 0
                )
                cpu = process.cpu_percent(interval=None) if running else 0
            except (ValueError, psutil.Error):
                pid = int(raw_pid) if str(raw_pid).isdigit() else 0
                running = False
                memory_percent = 0
                status = "completed" if analysis_complete else "stopped"
                memory_mb = 0
                cpu = 0
            flow_rate = 0
            if name in flow_modules:
                flow_rate = int(
                    self.redis.hget(f"flows_per_minute:{name}", now_bucket)
                    or 0
                )
            modules.append(
                {
                    "name": name,
                    "pid": pid,
                    "memory_percent": memory_percent,
                    "state": status,
                    "running": running,
                    "cpu_percent": cpu,
                    "memory_mb": memory_mb,
                    "flows_per_minute": flow_rate,
                    "evidence_count": (
                        evidence_counts.get(name, 0)
                        if evidence_counts is not None
                        else None
                    ),
                    "error_count": error_counts.get(name, 0),
                }
            )
        modules.sort(key=lambda item: item["name"].lower())
        return modules[:MAX_PAGE_SIZE]

    def _durable_evidence_counts(
        self, connection: sqlite3.Connection
    ) -> Counter[str]:
        """
        Count evidence by producing module from durable history.

        Parameters:
            connection: Short-lived read-only flows database connection.

        Returns:
            Evidence counts keyed by module name.
        """
        if not self._table_exists(connection, "evidence"):
            return Counter()
        connection.create_function(
            "evidence_module", 1, self._module_for_evidence
        )
        module_expression = self._evidence_module_expression(connection)
        rows = connection.execute(
            f"SELECT {module_expression} AS module, COUNT(*) AS count "
            f"FROM evidence GROUP BY {module_expression}"
        ).fetchall()
        counts: Counter[str] = Counter()
        for row in rows:
            module = str(row["module"] or "flow_alerts")
            counts[module] += int(row["count"])
        return counts

    def _run_metadata(self) -> Dict[str, str]:
        """
        Parse bounded run facts written by Slips.

        Returns:
            Metadata labels and values from metadata/info.txt.
        """
        path = self.output_dir / "metadata" / "info.txt"
        try:
            content = path.read_text(encoding="utf-8", errors="replace")[
                :65536
            ]
        except OSError:
            return {}
        metadata: Dict[str, str] = {}
        for line in content.splitlines():
            label, separator, value = line.partition(":")
            if separator and label.strip():
                metadata[label.strip()] = value.strip()
        return metadata

    def _firewall_overview(self) -> Dict[str, Any]:
        """Summarize current and historical firewall enforcement.

        Returns:
            Active IP count, block and unblock totals, and impact estimates.
        """
        try:
            blocked_rows = self.redis.zrange(
                "blocked_ips", 0, -1, withscores=True
            )
            schedule_rows = self.redis.hgetall("firewall_blocks")
        except redis.RedisError:
            blocked_rows, schedule_rows = [], {}
        active_blocks: Dict[str, float] = {}
        if isinstance(blocked_rows, (list, tuple)):
            for row in blocked_rows:
                try:
                    ip, blocked_at = row
                    active_blocks[str(ip)] = float(blocked_at)
                except (TypeError, ValueError):
                    continue
        scheduled_ips = (
            {str(ip) for ip in schedule_rows}
            if isinstance(schedule_rows, dict)
            else set()
        )
        history = self._firewall_history()
        return {
            "current": len(set(active_blocks) | scheduled_ips),
            "added": sum(item.get("action") == "blocked" for item in history),
            "discarded": sum(
                item.get("action") == "unblocked" for item in history
            ),
            "impact": self._firewall_attack_estimate(history, active_blocks),
        }

    def metadata(self) -> Dict[str, Any]:
        """Return the bounded metadata snapshot for this run.

        Returns:
            Parsed run metadata and its response timestamp.
        """
        return {"items": self._run_metadata(), "updated_at": time.time()}

    def logs(self) -> Dict[str, Any]:
        """Return the latest parsed runtime messages.

        Returns:
            Total parsed message count and the newest bounded records.
        """
        with connect_history(self.history_path, read_only=True) as history:
            total = int(
                history.execute(
                    "SELECT COUNT(*) AS count FROM error_events"
                ).fetchone()["count"]
            )
            items = [
                dict(row)
                for row in history.execute(
                    "SELECT event_time, module, message, line "
                    "FROM error_events ORDER BY event_time DESC, id DESC "
                    "LIMIT 100"
                ).fetchall()
            ]
        return {"items": items, "total": total, "updated_at": time.time()}

    @staticmethod
    def _interface_addresses(interface_names: str) -> Dict[str, List[str]]:
        """
        Return non-loopback IPv4 and IPv6 addresses for monitored interfaces.

        Parameters:
            interface_names: Comma- or whitespace-separated interface names.

        Returns:
            Address lists grouped under ``ipv4`` and ``ipv6``.
        """
        result: Dict[str, List[str]] = {"ipv4": [], "ipv6": []}
        names = [
            name
            for name in re.split(r"[,\s]+", interface_names.strip())
            if name
        ]
        if not names:
            return result
        try:
            interface_addresses = psutil.net_if_addrs()
        except psutil.Error:
            return result
        for interface_name in names:
            for address in interface_addresses.get(interface_name, []):
                if address.family not in (socket.AF_INET, socket.AF_INET6):
                    continue
                raw_address = str(address.address).split("%", 1)[0]
                try:
                    candidate = ipaddress.ip_address(raw_address)
                except ValueError:
                    continue
                if candidate.is_loopback or candidate.is_unspecified:
                    continue
                family = "ipv4" if candidate.version == 4 else "ipv6"
                normalized = str(candidate)
                if normalized not in result[family]:
                    result[family].append(normalized)
        return result

    @staticmethod
    def _current_network_states(
        analysis: Dict[str, str],
        saved_states: List[Dict[str, Any]],
        host_addresses: Dict[str, List[str]],
    ) -> List[Dict[str, Any]]:
        """Show live interface settings if the stored snapshot has fallen behind.

        Parameters:
            analysis: Run input metadata.
            saved_states: Network settings last saved by Slips.
            host_addresses: Current operating-system interface addresses.

        Returns:
            Saved states with any outdated live interface replaced for display.
        """
        if analysis.get("input_type") != "interface" or analysis.get(
            "analysis_end"
        ):
            return saved_states
        interface_names = {
            name.strip()
            for name in str(analysis.get("interface", "")).split(",")
            if name.strip()
        }
        result = []
        for saved in saved_states:
            if saved.get("interface") not in interface_names:
                result.append(saved)
                continue
            interface_addresses = (
                host_addresses
                if len(interface_names) == 1
                else RunDataReader._interface_addresses(saved["interface"])
            )
            live_addresses = set(interface_addresses.get("ipv4", [])) | set(
                interface_addresses.get("ipv6", [])
            )
            stored_addresses = {
                item.get("ip") for item in saved.get("addresses", [])
            }
            if not stored_addresses and saved.get("host_ip"):
                stored_addresses.add(saved["host_ip"])
            if live_addresses == stored_addresses:
                result.append(saved)
                continue
            current = collect_network_state(
                saved["interface"], len(interface_names)
            )
            current["live_reading"] = True
            current["observed_at"] = time.time()
            current["saved_changed_at"] = saved.get("changed_at")
            result.append(current)
        return result

    def _network_run_name(self) -> str:
        """Return the same run identifier used by the host profile module.

        Returns:
            Output directory and main-process PID, if known.
        """
        main_pid = self.redis.hget("PIDs", "main")
        if not isinstance(main_pid, (str, int)) or not str(main_pid).isdigit():
            return ""
        return f"{self.output_dir}:{main_pid}"

    def _named_network_states(
        self, states: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Attach permanent user names to current network cards.

        Parameters:
            states: Current interface settings.

        Returns:
            Settings with network identity and saved display name.
        """
        if not states:
            return []
        run_name = self._network_run_name()
        result = [
            {
                **state,
                "network_id": HostProfileStore.network_id_for_state(
                    state, run_name
                ),
            }
            for state in states
        ]
        names = HostProfileStore.network_names(
            getattr(
                self,
                "host_profiles_path",
                Path("permanent/host_profiles/hosts.sqlite"),
            ),
            (state["network_id"] for state in result),
        )
        for state in result:
            state["name"] = names.get(state["network_id"], "")
            state["name_scope"] = (
                "network" if state.get("gateway_mac") else "run"
            )
        return result

    def save_network_name(
        self, interface: str, network_id: str, name: str
    ) -> Dict[str, str]:
        """Name the currently monitored network in permanent storage.

        Parameters:
            interface: Interface selected in the Overview panel.
            network_id: Identity displayed when the editor was opened.
            name: New display name, or empty to clear it.

        Returns:
            Saved name and network identity.

        Raises:
            ValueError: The input or current network is invalid or changed.
        """
        if not all(
            isinstance(value, str) for value in (interface, network_id)
        ):
            raise ValueError("Network name request must contain text values")
        name = self._validated_network_name(name)
        analysis = self.redis.hgetall("analysis")
        interfaces = [
            item.strip()
            for item in str(analysis.get("interface", "")).split(",")
            if item.strip()
        ]
        if (
            analysis.get("input_type") != "interface"
            or analysis.get("analysis_end")
            or interface not in interfaces
        ):
            raise ValueError("Select a currently monitored interface")
        current = collect_network_state(interface, len(interfaces))
        if not current.get("connected"):
            raise ValueError("The selected interface is disconnected")
        run_name = self._network_run_name()
        expected_id = HostProfileStore.network_id_for_state(current, run_name)
        if not expected_id or expected_id != network_id:
            raise ValueError(
                "The network changed; refresh the page and try again"
            )
        HostProfileStore.set_network_name(
            self.host_profiles_path, expected_id, name
        )
        saved = self._loads(self.redis.hget("network_states", interface), {})
        if (
            current.get("gateway_mac")
            and not saved.get("history")
            and str(saved.get("gateway_mac") or "").lower()
            == str(current["gateway_mac"]).lower()
            and run_name
        ):
            HostProfileStore.set_network_name(
                self.host_profiles_path,
                HostProfileStore.network_id_for_state({}, run_name),
                name,
            )
        return {"network_id": expected_id, "name": name}

    @staticmethod
    def _validated_network_name(name: str) -> str:
        """Normalize a printable network name before persisting it.

        Parameters:
            name: User-provided network display name.

        Returns:
            Trimmed name, or an empty string to clear a saved name.

        Raises:
            ValueError: The value is not printable bounded text.
        """
        if not isinstance(name, str):
            raise ValueError("Network name must be text")
        name = name.strip()
        if len(name) > 80 or any(
            ord(char) < 32 or ord(char) == 127 for char in name
        ):
            raise ValueError(
                "Network name must be at most 80 printable characters"
            )
        return name

    def save_profile_network_name(
        self, ip: str, network_id: str, name: str
    ) -> Dict[str, str]:
        """Name a historical network shown in one permanent host profile.

        Parameters:
            ip: Host whose network profile is visible in the page.
            network_id: Exact stored network identity for that profile.
            name: New display name, or empty to clear it.

        Returns:
            Saved name and network identity.

        Raises:
            ValueError: The profile or proposed name is invalid.
        """
        if not isinstance(ip, str) or not isinstance(network_id, str):
            raise ValueError("Select a visible host network profile")
        name = self._validated_network_name(name)
        if not HostProfileStore.has_network_profile(
            self.host_profiles_path, ip, network_id
        ):
            raise ValueError(
                "The selected host network profile is unavailable"
            )
        HostProfileStore.set_network_name(
            self.host_profiles_path, network_id, name
        )
        return {"network_id": network_id, "name": name}

    def save_host_annotation(
        self, ip: str, network_id: str, name: str, note: str
    ) -> Dict[str, str]:
        """Save a user name and note for an exact permanent host profile.

        Parameters:
            ip: Selected host IP.
            network_id: Network identity shown in the Host tab.
            name: User-provided host name, or empty to clear it.
            note: User-provided note, or empty to clear it.

        Returns:
            The saved host annotation.
        """
        if not all(
            isinstance(value, str) for value in (ip, network_id, name, note)
        ):
            raise ValueError("Host annotation must contain text values")
        name = name.strip()
        note = note.strip()
        if len(name) > 80 or any(
            ord(char) < 32 or ord(char) == 127 for char in name
        ):
            raise ValueError(
                "Host name must be at most 80 printable characters"
            )
        if len(note) > 1000 or any(
            (ord(char) < 32 and char not in "\n\t") or ord(char) == 127
            for char in note
        ):
            raise ValueError(
                "Host note must be at most 1000 printable characters"
            )
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError as error:
            raise ValueError("Select a valid host IP") from error
        if not HostProfileStore.has_network_profile(
            self.host_profiles_path, ip, network_id
        ):
            raise ValueError("The selected host profile is unavailable")
        HostProfileStore.set_host_annotation(
            self.host_profiles_path, ip, network_id, name, note
        )
        return {"ip": ip, "network_id": network_id, "name": name, "note": note}

    def overview(self) -> Dict[str, Any]:
        """Build a bounded current-run operational overview."""
        analysis = self.redis.hgetall("analysis")
        run_metadata = self._run_metadata()
        complete = bool(analysis.get("analysis_end"))
        now = time.time()
        try:
            with self._connect_sqlite() as connection:
                alert_count = int(
                    connection.execute(
                        "SELECT COUNT(*) AS count FROM alerts"
                    ).fetchone()["count"]
                )
                durable_evidence = (
                    int(
                        connection.execute(
                            "SELECT COUNT(*) AS count FROM evidence"
                        ).fetchone()["count"]
                    )
                    if self._table_exists(connection, "evidence")
                    else 0
                )
        except sqlite3.Error:
            alert_count = 0
            durable_evidence = 0
        try:
            redis_evidence_count = int(
                self.redis.get("number_of_evidence") or 0
            )
        except (TypeError, ValueError, redis.RedisError):
            redis_evidence_count = 0
        evidence_count = durable_evidence or redis_evidence_count
        with connect_history(self.history_path, read_only=True) as history:
            error_rows = history.execute(
                "SELECT module, COUNT(*) AS count FROM error_events GROUP BY module"
            ).fetchall()
            error_counts = {
                str(row["module"]): int(row["count"]) for row in error_rows
            }
            recent_errors = [
                dict(row)
                for row in history.execute(
                    "SELECT event_time, module, message, line "
                    "FROM error_events ORDER BY event_time DESC, id DESC "
                    "LIMIT 20"
                ).fetchall()
            ]
            host_count = int(
                history.execute(
                    "SELECT COUNT(*) AS count FROM host_snapshots"
                ).fetchone()["count"]
            )
            metadata = {
                str(row["key"]): str(row["value"])
                for row in history.execute(
                    "SELECT key, value FROM metadata"
                ).fetchall()
            }
        try:
            redis_alert_count = int(self.redis.get("number_of_alerts") or 0)
        except ValueError:
            redis_alert_count = 0
        try:
            processed_flows = int(
                self.redis.get("processed_flows_by_profiler_so_far") or 0
            )
        except ValueError:
            processed_flows = 0
        disk = psutil.disk_usage(self.output_dir)
        db_size = (
            self.sqlite_path.stat().st_size if self.sqlite_path.exists() else 0
        )
        growth = float(metadata.get("storage_growth_bps", "0"))
        if disk.percent >= 95 or disk.free < 5 * 1024**3:
            disk_warning = "critical"
        elif disk.percent >= 90 or disk.free < 10 * 1024**3:
            disk_warning = "warning"
        else:
            disk_warning = ""
        estimated_seconds_remaining = (
            disk.free / growth if growth > 0 else None
        )
        backend_status = self._backend_status(
            metadata.get(BACKEND_HEARTBEAT_KEY),
            metadata.get(BACKEND_DISCONNECTED_KEY),
            now,
        )
        try:
            computer_interfaces = ",".join(psutil.net_if_addrs())
        except psutil.Error:
            computer_interfaces = ""
        uptime_reference = (
            now
            if backend_status["connected"]
            else backend_status["last_seen"] or now
        )
        firewall = self._firewall_overview()
        host_addresses = self._interface_addresses(
            str(analysis.get("interface") or run_metadata.get("File", ""))
        )
        saved_network_states = [
            json.loads(value)
            for _, value in sorted(
                self.redis.hgetall("network_states").items()
            )
        ]
        current_network_states = self._named_network_states(
            self._current_network_states(
                analysis, saved_network_states, host_addresses
            )
        )
        return {
            "run": {
                **analysis,
                "state": (
                    "complete"
                    if complete
                    else (
                        "running"
                        if backend_status["connected"]
                        else "disconnected"
                    )
                ),
                "redis_port": self.redis_port,
                "output_dir": str(self.output_dir),
                "uptime_seconds": self._run_uptime_seconds(
                    analysis, uptime_reference
                ),
            },
            "backend_status": backend_status,
            "run_metadata": run_metadata,
            "host_addresses": host_addresses,
            "computer_addresses": self._interface_addresses(
                computer_interfaces
            ),
            "computer_name": socket.gethostname(),
            "network_states": current_network_states,
            "sources": {
                "redis": True,
                "sqlite": self.sqlite_path.exists(),
                "history": self.history_path.exists(),
                "error_log": metadata.get("error_log_name", ""),
                "flow_index_updated_at": float(
                    metadata.get("flow_index_updated_at", "0")
                ),
            },
            "system": {
                "cpu_percent": psutil.cpu_percent(interval=None),
                "memory_percent": psutil.virtual_memory().percent,
                "load_average": list(os.getloadavg()),
                "output_disk_percent": disk.percent,
                "output_disk_free": disk.free,
                "flows_db_size": db_size,
                "flows_db_growth_bps": growth,
                "disk_warning": disk_warning,
                "estimated_seconds_remaining": estimated_seconds_remaining,
            },
            "counts": {
                "alerts": alert_count,
                "evidence": evidence_count,
                "hosts": host_count,
                "processed_flows": processed_flows,
                "module_errors": sum(error_counts.values()),
            },
            "firewall": {
                "current": firewall["current"],
                "added": firewall["added"],
                "discarded": firewall["discarded"],
            },
            "firewall_impact": firewall["impact"],
            "diagnostics": {
                "redis_alert_count": redis_alert_count,
                "alert_count_mismatch": redis_alert_count != alert_count,
            },
            "modules": self._module_rows(None, error_counts, complete),
            "evidence_details_loaded": False,
            "recent_errors": recent_errors,
            "updated_at": now,
        }

    def overview_evidence_counts(self) -> Dict[str, Any]:
        """Load exact evidence totals omitted from the fast Overview response.

        Returns:
            Exact overall and per-module evidence counts from durable storage,
            or from the retained Redis compatibility data when necessary.
        """
        durable_evidence = 0
        evidence_counts: Counter[str] = Counter()
        try:
            with self._connect_sqlite() as connection:
                if self._table_exists(connection, "evidence"):
                    durable_evidence = int(
                        connection.execute(
                            "SELECT COUNT(*) AS count FROM evidence"
                        ).fetchone()["count"]
                    )
                    if durable_evidence:
                        evidence_counts = self._durable_evidence_counts(
                            connection
                        )
        except sqlite3.Error:
            durable_evidence = 0
        if durable_evidence:
            evidence_count = durable_evidence
            source = "sqlite"
        else:
            redis_evidence = self._redis_evidence()
            evidence_count = len(redis_evidence)
            evidence_counts = Counter(
                str(item.get("module", "unknown")) for item in redis_evidence
            )
            source = "redis"
        return {
            "evidence": evidence_count,
            "modules": dict(evidence_counts),
            "source": source,
            "updated_at": time.time(),
        }

    def _firewall_intervals(
        self,
        history: Optional[List[Dict[str, Any]]] = None,
        active_blocks: Optional[Dict[str, float]] = None,
        now: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """
        Build non-overlapping blocked intervals from durable transitions.

        Parameters:
            history: Parsed block and unblock transitions for this run.
            active_blocks: Current Redis block timestamps keyed by IP.
            now: Upper boundary for intervals that remain active.

        Returns:
            Chronological blocked intervals with their active state.
        """
        transitions = (
            history if history is not None else self._firewall_history()
        )
        if active_blocks is None:
            try:
                active_blocks = {
                    str(ip): float(blocked_at)
                    for ip, blocked_at in self.redis.zrange(
                        "blocked_ips", 0, -1, withscores=True
                    )
                }
            except (redis.RedisError, TypeError, ValueError):
                active_blocks = {}
        current_time = time.time() if now is None else now
        opened: Dict[str, float] = {}
        intervals: List[Dict[str, Any]] = []
        for event in sorted(
            transitions,
            key=lambda item: (float(item.get("timestamp") or 0), item["ip"]),
        ):
            ip = str(event.get("ip") or "")
            timestamp = float(event.get("timestamp") or 0)
            if not ip or not timestamp:
                continue
            if event.get("action") == "blocked":
                opened.setdefault(ip, timestamp)
            elif event.get("action") == "unblocked" and ip in opened:
                start = opened.pop(ip)
                if timestamp > start:
                    intervals.append(
                        {
                            "ip": ip,
                            "start": start,
                            "end": timestamp,
                            "active": False,
                        }
                    )
        for ip, blocked_at in active_blocks.items():
            opened.setdefault(ip, float(blocked_at))
        for ip, start in opened.items():
            if current_time > start:
                intervals.append(
                    {
                        "ip": ip,
                        "start": start,
                        "end": current_time,
                        "active": ip in active_blocks,
                    }
                )
        intervals.sort(key=lambda item: (item["start"], item["ip"]))
        return intervals

    def _arp_poisoning_events(self) -> Dict[str, List[Dict[str, Any]]]:
        """Parse ARP poison, schedule, extension, and release transitions.

        Returns:
            Host state and newest-first transition records for this run.
        """
        log_path = (
            self.output_dir / Modules.ARP_POISONER.value / "arp_poisoning.log"
        )
        try:
            lines = log_path.read_text(errors="replace").splitlines()
        except OSError:
            lines = []
        hosts: Dict[str, Dict[str, Any]] = {}
        events: List[Dict[str, Any]] = []
        schedule_pattern = re.compile(
            r"^Current TW: (?P<current_tw>[^.]+)\. Registered a request "
            r"to stop poisoning (?P<ip>\S+) at the end of: "
            r"(?P<release_tw>timewindow\d+)\. IP will be poisoned for "
            r"(?P<extra_tws>\d+) more timewindows\. Timestamp to stop "
            r"poisoning: (?P<unblock_at>.+?)\)\s*$"
        )
        release_pattern = re.compile(
            r"^Done poisoning (?P<ip>\S+)\. The poisoning lasted "
            r"(?P<duration_tws>\d+) timewindows\. "
            r"\((?P<duration_hours>[\d.]+)hrs - From "
            r"(?P<started_at>.+?) to (?P<released_at>.+?)\)\.\s*$"
        )
        poison_pattern = re.compile(
            r"^Poisoned (?P<ip>\S+) at (?P<mac>\S+)\.\s*$"
        )
        for line in lines:
            timestamp_text, separator, message = line.partition(" - ")
            if not separator:
                continue
            timestamp = self._event_timestamp(timestamp_text)
            if not timestamp:
                continue
            if match := poison_pattern.match(message):
                values = match.groupdict()
                ip = values["ip"]
                host = hosts.setdefault(ip, {"ip": ip})
                host.update(
                    {
                        "status": "poisoned",
                        "poisoned_at": timestamp,
                        "released_at": None,
                        "mac": values["mac"],
                    }
                )
                events.append(
                    {
                        "timestamp": timestamp,
                        "ip": ip,
                        "action": "poisoned",
                        "current_tw": None,
                        "release_tw": None,
                        "unblock_at": None,
                        "extra_timewindows": None,
                        "details": f"target MAC {values['mac']}",
                    }
                )
                continue
            if match := schedule_pattern.match(message):
                values = match.groupdict()
                ip = values["ip"]
                host = hosts.setdefault(ip, {"ip": ip})
                action = "extended" if host.get("unblock_at") else "scheduled"
                unblock_at = self._event_timestamp(values["unblock_at"])
                extra_tws = int(values["extra_tws"])
                host.update(
                    {
                        "status": "poisoned",
                        "poisoned_at": host.get("poisoned_at") or timestamp,
                        "released_at": None,
                        "current_tw": values["current_tw"],
                        "release_tw": values["release_tw"],
                        "unblock_at": unblock_at or None,
                        "extra_timewindows": extra_tws,
                    }
                )
                events.append(
                    {
                        "timestamp": timestamp,
                        "ip": ip,
                        "action": action,
                        "current_tw": values["current_tw"],
                        "release_tw": values["release_tw"],
                        "unblock_at": unblock_at or None,
                        "extra_timewindows": extra_tws,
                        "details": "release schedule updated",
                    }
                )
                continue
            if match := release_pattern.match(message):
                values = match.groupdict()
                ip = values["ip"]
                released_at = (
                    self._event_timestamp(values["released_at"]) or timestamp
                )
                started_at = self._event_timestamp(values["started_at"])
                host = hosts.setdefault(ip, {"ip": ip})
                host.update(
                    {
                        "status": "released",
                        "poisoned_at": started_at
                        or host.get("poisoned_at")
                        or timestamp,
                        "released_at": released_at,
                        "extra_timewindows": 0,
                    }
                )
                events.append(
                    {
                        "timestamp": released_at,
                        "ip": ip,
                        "action": "released",
                        "current_tw": host.get("current_tw"),
                        "release_tw": host.get("release_tw"),
                        "unblock_at": released_at,
                        "extra_timewindows": 0,
                        "details": (
                            f"{values['duration_tws']} timewindows · "
                            f"{values['duration_hours']} hours"
                        ),
                    }
                )
        now = time.time()
        for host in hosts.values():
            unblock_at = float(host.get("unblock_at") or 0)
            if host.get("status") == "poisoned" and unblock_at:
                host["remaining_seconds"] = max(0.0, unblock_at - now)
                if now >= unblock_at:
                    host["status"] = "release due"
            else:
                host["remaining_seconds"] = None
        return {
            "hosts": sorted(hosts.values(), key=lambda item: item["ip"]),
            "events": sorted(
                events,
                key=lambda item: (item["timestamp"], item["ip"]),
                reverse=True,
            ),
        }

    def _arp_evidence(self, hide_excluded: bool = False) -> Dict[str, Any]:
        """Return bounded durable evidence generated by the ARP detector.

        Parameters:
            hide_excluded: Omit evidence excluded by a whitelist rule.

        Returns:
            Latest ARP evidence, full total, and counts by evidence type.
        """
        placeholders = ",".join("?" for _ in ARP_EVIDENCE_TYPES)
        records: List[Dict[str, Any]] = []
        counts: Dict[str, int] = {}
        total = 0
        try:
            with self._connect_sqlite() as connection:
                if not self._table_exists(connection, "evidence"):
                    raise sqlite3.OperationalError("no durable evidence")
                columns = {
                    str(column[1])
                    for column in connection.execute(
                        "PRAGMA table_info(evidence)"
                    ).fetchall()
                }
                where = f"evidence_type IN ({placeholders})"
                if hide_excluded and "whitelisted" in columns:
                    where += " AND COALESCE(whitelisted, 0) = 0"
                rows = connection.execute(
                    f"SELECT evidence.*, "
                    f"(SELECT COUNT(*) FROM evidence_flows ef WHERE "
                    f"ef.evidence_id = evidence.evidence_id) AS flow_count, "
                    f"(SELECT COUNT(*) FROM alert_evidence ae WHERE "
                    f"ae.evidence_id = evidence.evidence_id) AS alert_count "
                    f"FROM evidence WHERE {where} "
                    f"ORDER BY evidence_time DESC, evidence_id DESC LIMIT ?",
                    (*ARP_EVIDENCE_TYPES, MAX_PAGE_SIZE),
                ).fetchall()
                records = [
                    {
                        "timestamp": float(row["evidence_time"] or 0),
                        "profile_ip": str(row["profile_ip"] or ""),
                        "threat_level": str(row["threat_level"] or "info"),
                        "evidence_type": str(
                            row["evidence_type"] or "unknown"
                        ),
                        "description": str(row["description"] or ""),
                        "confidence": float(row["confidence"] or 0),
                        "flow_count": int(row["flow_count"] or 0),
                        "alert_count": int(row["alert_count"] or 0),
                    }
                    for row in rows
                ]
                count_rows = connection.execute(
                    f"SELECT evidence_type, COUNT(*) AS count FROM evidence "
                    f"WHERE {where} "
                    f"GROUP BY evidence_type",
                    ARP_EVIDENCE_TYPES,
                ).fetchall()
                counts = {
                    str(row["evidence_type"]): int(row["count"])
                    for row in count_rows
                }
                total = sum(counts.values())
        except sqlite3.Error:
            records = [
                item
                for item in self._redis_evidence()
                if str(item.get("evidence_type")) in ARP_EVIDENCE_TYPES
                and (
                    not hide_excluded
                    or item.get("whitelisted") not in (True, 1, "1")
                )
            ][:MAX_PAGE_SIZE]
            counts = dict(Counter(item["evidence_type"] for item in records))
            total = len(records)
        return {"items": records, "total": total, "counts": counts}

    def arp_poisoning(
        self, query: Optional[Dict[str, List[str]]] = None
    ) -> Dict[str, Any]:
        """Return ARP isolation state, transitions, and detector evidence.

        Parameters:
            query: Optional visibility filter for excluded evidence.

        Returns:
            Bounded run-scoped ARP poisoner and detector information.
        """
        parsed = self._arp_poisoning_events()
        evidence = self._arp_evidence(
            hide_excluded=self._query_value(query or {}, "hide_excluded")
            == "1"
        )
        try:
            raw_pid = self.redis.hget("PIDs", Modules.ARP_POISONER)
            analysis_complete = bool(
                self.redis.hget("analysis", "analysis_end")
            )
        except redis.RedisError:
            raw_pid = None
            analysis_complete = False
        log_exists = (
            self.output_dir / Modules.ARP_POISONER.value / "arp_poisoning.log"
        ).exists()
        module_state = "not started"
        pid = int(raw_pid) if str(raw_pid or "").isdigit() else None
        if pid:
            try:
                process = self._processes.get(pid)
                if process is None:
                    process = psutil.Process(pid)
                    self._processes[pid] = process
                module_state = (
                    process.status() if process.is_running() else "stopped"
                )
            except psutil.Error:
                module_state = "completed" if analysis_complete else "stopped"
        elif log_exists:
            module_state = "completed" if analysis_complete else "stopped"
        hosts = parsed["hosts"]
        active = sum(
            item.get("status") in {"poisoned", "release due"} for item in hosts
        )
        return {
            "module": {
                "enabled": bool(raw_pid),
                "state": module_state,
                "pid": pid,
            },
            "counts": {
                "active": active,
                "released": sum(
                    item.get("status") == "released" for item in hosts
                ),
                "hosts": len(hosts),
                "transitions": len(parsed["events"]),
                "evidence": evidence["total"],
            },
            "hosts": hosts[:MAX_PAGE_SIZE],
            "events": parsed["events"][:MAX_PAGE_SIZE],
            "evidence": evidence["items"],
            "evidence_counts": evidence["counts"],
            "updated_at": time.time(),
        }

    def _firewall_attack_estimate(
        self,
        history: Optional[List[Dict[str, Any]]] = None,
        active_blocks: Optional[Dict[str, float]] = None,
    ) -> Dict[str, Any]:
        """
        Estimate traffic attempted by IPs while firewall rules were active.

        Parameters:
            history: Parsed block and unblock transitions for this run.
            active_blocks: Current Redis block timestamps keyed by IP.

        Returns:
            Run totals and per-IP packet, flow, and evidence estimates.
        """
        intervals = self._firewall_intervals(history, active_blocks)
        by_ip: Dict[str, Dict[str, int]] = {}
        for interval in intervals:
            by_ip.setdefault(
                interval["ip"],
                {"packets": 0, "flows": 0, "evidence": 0},
            )
        history_path = getattr(self, "history_path", None)
        if history_path and Path(history_path).exists():
            try:
                with connect_history(
                    Path(history_path), read_only=True
                ) as connection:
                    for interval in intervals:
                        row = connection.execute(
                            "SELECT COUNT(*) AS flows, "
                            "COALESCE(SUM(source_packets), 0) AS packets "
                            "FROM flow_index WHERE src_ip = ? "
                            "AND event_time >= ? AND event_time < ?",
                            (
                                interval["ip"],
                                interval["start"],
                                interval["end"],
                            ),
                        ).fetchone()
                        impact = by_ip[interval["ip"]]
                        impact["flows"] += int(row["flows"] or 0)
                        impact["packets"] += int(row["packets"] or 0)
            except sqlite3.Error:
                pass
        sqlite_path = getattr(self, "sqlite_path", None)
        if sqlite_path and Path(sqlite_path).exists():
            try:
                with self._connect_sqlite() as connection:
                    if self._table_exists(connection, "evidence"):
                        for interval in intervals:
                            row = connection.execute(
                                "SELECT COUNT(*) AS evidence FROM evidence "
                                "WHERE profile_ip = ? AND evidence_time >= ? "
                                "AND evidence_time < ?",
                                (
                                    interval["ip"],
                                    interval["start"],
                                    interval["end"],
                                ),
                            ).fetchone()
                            by_ip[interval["ip"]]["evidence"] += int(
                                row["evidence"] or 0
                            )
            except sqlite3.Error:
                pass
        totals = {
            name: sum(item[name] for item in by_ip.values())
            for name in ("packets", "flows", "evidence")
        }
        return {
            **totals,
            "estimated": True,
            "blocked_ips": len(by_ip),
            "blocked_intervals": len(intervals),
            "by_ip": by_ip,
        }

    def firewall(self, query: Dict[str, List[str]]) -> Dict[str, Any]:
        """Return active Slips firewall blocks and their probation schedules."""
        try:
            blocked = self.redis.zrange("blocked_ips", 0, -1, withscores=True)
            schedules = {
                ip: self._loads(raw, {})
                for ip, raw in self.redis.hgetall("firewall_blocks").items()
            }
        except redis.RedisError:
            blocked, schedules = [], {}
        blocked_at_by_ip = {
            str(ip): float(blocked_at) for ip, blocked_at in blocked
        }
        all_history = self._firewall_history()
        impact = self._firewall_attack_estimate(all_history, blocked_at_by_ip)
        records: List[Dict[str, Any]] = []
        now = time.time()
        for ip in set(blocked_at_by_ip) | set(schedules):
            schedule = schedules.get(ip, {})
            ip_impact = impact["by_ip"].get(
                ip, {"packets": 0, "flows": 0, "evidence": 0}
            )
            deadline = self._event_timestamp(schedule.get("unblock_at"))
            remaining_windows = schedule.get("remaining_timewindows")
            recovery_status = str(schedule.get("recovery_status") or "")
            recovered = schedule.get("recovered") is True
            if recovery_status in {"legacy metadata", "invalid metadata"}:
                status = "stale"
            elif deadline and now >= deadline:
                status = "overdue"
            elif remaining_windows == 0:
                status = "probation"
            else:
                status = "blocked"
            records.append(
                {
                    "ip": ip,
                    "status": status,
                    "blocked_at": blocked_at_by_ip.get(ip),
                    "unblock_at": deadline or None,
                    "remaining_seconds": (
                        max(0, deadline - now) if deadline else None
                    ),
                    "remaining_timewindows": remaining_windows,
                    "recovered": recovered,
                    "recovery_status": recovery_status or None,
                    "origin_run": schedule.get("origin_run"),
                    "rule_comment": schedule.get("rule_comment"),
                    "evidence_count": self._profile_evidence_count(ip),
                    "alert_count": self._profile_alert_count(ip),
                    "stopped_packets": ip_impact["packets"],
                    "stopped_flows": ip_impact["flows"],
                    "evidence_while_blocked": ip_impact["evidence"],
                },
            )
        search = self._query_value(query, "search").lower()
        if search:
            records = [
                item
                for item in records
                if search
                in " ".join(
                    (
                        item["ip"],
                        item["status"],
                        str(item.get("recovery_status") or ""),
                        str(item.get("origin_run") or ""),
                    )
                ).lower()
            ]
        records.sort(key=lambda item: (item["unblock_at"] or 0, item["ip"]))
        history = all_history
        if search:
            history = [
                item
                for item in history
                if search
                in " ".join(
                    (item["ip"], item["action"], item["details"])
                ).lower()
            ]
        try:
            history_offset = max(
                0, int(self._query_value(query, "history_offset") or 0)
            )
        except ValueError:
            history_offset = 0
        history_page = history[history_offset : history_offset + MAX_PAGE_SIZE]
        history_next = history_offset + len(history_page)
        return {
            "enabled": bool(self.redis.hget("PIDs", Modules.BLOCKING)),
            "items": records[:MAX_PAGE_SIZE],
            "total": len(records),
            "full_total": len(records),
            "page_size": min(len(records), MAX_PAGE_SIZE),
            "history": history_page,
            "history_total": len(history),
            "history_next_cursor": (
                str(history_next) if history_next < len(history) else None
            ),
            "impact": impact,
        }

    def _firewall_history(self, search: str = "") -> List[Dict[str, Any]]:
        """Parse durable block and unblock transitions from blocking.log.

        Parameters:
            search: Optional case-insensitive IP, action, or detail filter.

        Returns:
            Newest-first firewall transition records for this run.
        """
        log_path = self.output_dir / Modules.BLOCKING.value / "blocking.log"
        try:
            lines = log_path.read_text(errors="replace").splitlines()
        except OSError:
            return []
        events: Dict[tuple[str, str, int], Dict[str, Any]] = {}
        for line in lines:
            timestamp_text, separator, message = line.partition(" - ")
            if not separator:
                continue
            timestamp = self._event_timestamp(timestamp_text)
            if not timestamp:
                continue
            action = ""
            ip = ""
            details = ""
            block_match = re.match(
                r"^Blocked all traffic (from|to):\s+(\S+)$", message
            )
            unblock_match = re.match(
                r"^IP (\S+) is unblocked(?: in ([^.]+))?\.$", message
            )
            failure_match = re.match(
                r"^An err+or occured\. Unable to unblock (\S+)$", message
            )
            if block_match:
                action = "blocked"
                direction, ip = block_match.groups()
                key = (action, ip, int(timestamp))
                if key in events:
                    previous = events[key]["details"].removeprefix("traffic ")
                    directions = sorted(
                        set(previous.split(" + ") + [direction])
                    )
                    events[key][
                        "details"
                    ] = f"traffic {' + '.join(directions)}"
                    continue
                details = f"traffic {direction}"
            elif unblock_match:
                action = "unblocked"
                ip, timewindow = unblock_match.groups()
                details = (
                    f"rules removed in {timewindow}"
                    if timewindow
                    else "rules removed"
                )
            elif failure_match:
                action = "unblock failed"
                ip = failure_match.group(1)
                details = "firewall rules could not be removed"
            else:
                continue
            key = (action, ip, int(timestamp))
            events[key] = {
                "timestamp": timestamp,
                "ip": ip,
                "action": action,
                "details": details,
            }
        history = sorted(
            events.values(),
            key=lambda item: (item["timestamp"], item["ip"]),
            reverse=True,
        )
        if not search:
            return history
        return [
            item
            for item in history
            if search
            in " ".join((item["ip"], item["action"], item["details"])).lower()
        ]

    def _live_p2p_connections(self) -> List[Dict[str, Any]]:
        """Return unexpired authenticated P2P tuples from live Redis state.

        Returns:
            Authenticated connection records whose individual TTL keys exist.
        """
        connections = []
        index = "p2p:active_connections"
        prefix = "p2p:active_connection:"
        try:
            members = self.redis.smembers(index)
            if not isinstance(members, (set, list, tuple)):
                return []
            for connection_id in members:
                raw = self.redis.get(f"{prefix}{connection_id}")
                if raw is None:
                    self.redis.srem(index, connection_id)
                    continue
                connection = self._loads(raw, {})
                if (
                    isinstance(connection, dict)
                    and connection.get("authenticated") is True
                    and connection.get("connected") is True
                ):
                    connections.append(connection)
        except redis.RedisError:
            return []
        return connections

    def _legacy_connected_p2p_peers(
        self, peer_info: Dict[str, Dict[str, Any]]
    ) -> set[str]:
        """Read connected peers reported by legacy Pigeon binaries.

        Parameters:
            peer_info: Decoded peer state indexed by peer ID.

        Returns:
            Peer IDs that both legacy connectivity records mark connected.
        """
        raw_connected = self._loads(self.redis.get("connected_peers"), [])
        if not isinstance(raw_connected, (list, tuple, set)):
            return set()
        connected = {str(peer_id) for peer_id in raw_connected}
        now = time.time()
        active_peers = set()
        for peer_id in connected:
            state = peer_info.get(peer_id, {})
            timestamp = self._event_timestamp(
                state.get("last_activity", state.get("timestamp"))
            )
            if state.get("connected") is True and (
                timestamp == 0
                or now - timestamp <= P2P_RECENT_ACTIVITY_SECONDS
            ):
                active_peers.add(peer_id)
        return active_peers

    def p2p(
        self, query: Optional[Dict[str, List[str]]] = None
    ) -> Dict[str, Any]:
        """Return live P2P connectivity, report activity, and trust history."""
        query = query or {"range": ["all"]}
        live_connections = self._live_p2p_connections()
        connected = {
            str(connection.get("peer_id"))
            for connection in live_connections
            if connection.get("peer_id")
        }
        peer_info = {
            peer_id: self._loads(raw, {})
            for peer_id, raw in self.redis.hgetall("peer_info").items()
        }
        connected.update(self._legacy_connected_p2p_peers(peer_info))
        peer_trust = self.redis.hgetall("peer_trust")
        peer_seen = dict(
            self.redis.zrange("peers_strust", 0, -1, withscores=True)
        )
        current_tw = self.redis.get("current_timewindow") or "1"
        counts = {
            key: int(value)
            for key, value in self.redis.hgetall(
                f"p2p_message_counts_{current_tw}"
            ).items()
        }
        activity = [
            self._loads(raw, {})
            for raw in self.redis.lrange("p2p_message_history", 0, 199)
        ]
        analysis = self.redis.hgetall("analysis")
        run_start = self._event_timestamp(analysis.get("analysis_start"))
        recent_activity_cutoff = max(
            time.time() - P2P_RECENT_ACTIVITY_SECONDS,
            run_start or 0,
        )
        for peer_id, info in peer_info.items():
            last_activity = self._event_timestamp(info.get("last_activity"))
            if (
                info.get("connected") is True
                and last_activity
                and last_activity >= recent_activity_cutoff
            ):
                connected.add(peer_id)
        trust_path = Path("permanent") / "p2p_trust_runtime" / "trustdb.db"
        trust_range = "all"
        trust_history: List[Dict[str, Any]] = []
        latest_reliability: Dict[str, Dict[str, Any]] = {}
        reports: List[Dict[str, Any]] = []
        reports_received = 0
        report_counts: Counter[str] = Counter()
        peer_ips: Dict[str, Dict[str, Any]] = {}
        if trust_path.exists():
            try:
                with sqlite3.connect(
                    f"file:{trust_path}?mode=ro", uri=True, timeout=5
                ) as connection:
                    connection.row_factory = sqlite3.Row
                    latest_reliability_row = connection.execute(
                        "SELECT MAX(update_time) AS latest FROM go_reliability"
                    ).fetchone()
                    latest_reliability_time = self._event_timestamp(
                        latest_reliability_row["latest"]
                    )
                    trust_start, trust_end, trust_range = self._time_bounds(
                        query, latest_reliability_time
                    )
                    trust_clauses = ["1 = 1"]
                    trust_params: List[Any] = []
                    if trust_start is not None:
                        trust_clauses.append("update_time >= ?")
                        trust_params.append(trust_start)
                    if trust_end is not None:
                        trust_clauses.append("update_time <= ?")
                        trust_params.append(trust_end)
                    trust_where = " AND ".join(trust_clauses)
                    for row in connection.execute(
                        "SELECT peerid, reliability, update_time "
                        f"FROM go_reliability WHERE {trust_where} "
                        "ORDER BY update_time DESC LIMIT 2000",
                        trust_params,
                    ):
                        trust_history.append(
                            {
                                "peer_id": str(row["peerid"]),
                                "reliability": float(row["reliability"]),
                                "timestamp": self._event_timestamp(
                                    row["update_time"]
                                ),
                            }
                        )
                    for row in connection.execute(
                        "SELECT peerid, reliability, update_time "
                        "FROM go_reliability ORDER BY update_time DESC"
                    ):
                        latest_reliability.setdefault(
                            str(row["peerid"]),
                            {
                                "peer_id": str(row["peerid"]),
                                "reliability": float(row["reliability"]),
                                "timestamp": self._event_timestamp(
                                    row["update_time"]
                                ),
                            },
                        )
                    for row in connection.execute(
                        "SELECT peerid, ipaddress, update_time FROM peer_ips "
                        "ORDER BY update_time DESC LIMIT 1000"
                    ):
                        peer_ips.setdefault(
                            str(row["peerid"]),
                            {
                                "ip": str(row["ipaddress"]),
                                "timestamp": self._event_timestamp(
                                    row["update_time"]
                                ),
                            },
                        )
                    for row in connection.execute(
                        "SELECT reporter_peerid, reported_key, score, confidence, "
                        "update_time FROM reports ORDER BY update_time DESC LIMIT 500"
                    ):
                        timestamp = self._event_timestamp(row["update_time"])
                        reports.append(
                            {
                                "peer_id": str(row["reporter_peerid"]),
                                "target": str(row["reported_key"]),
                                "score": float(row["score"]),
                                "confidence": float(row["confidence"]),
                                "timestamp": timestamp,
                                "this_run": not run_start
                                or timestamp >= run_start,
                            }
                        )
                    report_where = (
                        "WHERE update_time >= ?" if run_start else ""
                    )
                    report_params = (run_start,) if run_start else ()
                    for row in connection.execute(
                        "SELECT reporter_peerid, COUNT(*) AS total "
                        f"FROM reports {report_where} "
                        "GROUP BY reporter_peerid",
                        report_params,
                    ):
                        count = int(row["total"])
                        report_counts[str(row["reporter_peerid"])] = count
                        reports_received += count
            except sqlite3.Error:
                pass
        peer_ids = (
            set(peer_info)
            | set(peer_ips)
            | set(latest_reliability)
            | set(report_counts)
            | connected
        )
        peers = []
        for peer_id in peer_ids:
            info = peer_info.get(peer_id, {})
            pairing = peer_ips.get(peer_id, {})
            ip = str(
                info.get("ip")
                or info.get("ipaddress")
                or pairing.get("ip")
                or ""
            )
            reliability = latest_reliability.get(peer_id, {})
            reliability_value = reliability.get("reliability")
            if reliability_value is None:
                try:
                    reliability_value = float(info["reliability"])
                except (KeyError, TypeError, ValueError):
                    reliability_value = None
            peers.append(
                {
                    "peer_id": peer_id,
                    "ip": ip,
                    "connected": peer_id in connected,
                    "trust": (
                        float(peer_trust[ip]) if ip in peer_trust else None
                    ),
                    "reliability": reliability_value,
                    "last_seen": max(
                        float(peer_seen.get(peer_id, 0)),
                        self._event_timestamp(info.get("timestamp")),
                        self._event_timestamp(info.get("last_activity")),
                        float(pairing.get("timestamp") or 0),
                        float(reliability.get("timestamp") or 0),
                    ),
                    "reports_received": report_counts[peer_id],
                    "connections": [
                        connection
                        for connection in live_connections
                        if str(connection.get("peer_id")) == peer_id
                    ],
                }
            )
        peers.sort(
            key=lambda item: (
                not item["connected"],
                -item["last_seen"],
                item["peer_id"],
            )
        )
        p2p_log = self.output_dir / Modules.P2P_TRUST.value / "p2p.log"
        listener = ""
        local_peer_id = ""
        multiaddress = str(self.redis.get("multiAddress") or "").strip()
        matches = re.findall(
            r"(/(?:ip4|ip6)/[^\s]+/p2p/([^\s/]+))", multiaddress
        )
        if matches:
            listener, local_peer_id = matches[-1]
        else:
            try:
                log_tail = p2p_log.read_text(
                    encoding="utf-8", errors="replace"
                )[-65536:]
                matches = re.findall(
                    r"(/(?:ip4|ip6)/[^\s]+/p2p/([^\s/]+))", log_tail
                )
                if matches:
                    listener, local_peer_id = matches[-1]
            except OSError:
                pass
        current_reports = [item for item in reports if item["this_run"]]
        return {
            "enabled": bool(self.redis.hget("PIDs", Modules.P2P_TRUST)),
            "listener": listener,
            "local_peer_id": local_peer_id,
            "peers": peers,
            "trust_history": trust_history,
            "trust_range": trust_range,
            "reports": current_reports[:200],
            "activity": [item for item in activity if isinstance(item, dict)],
            "counts": {
                "connected": len(connected),
                "known": len(peers),
                "reports_sent": counts.get("sent:report", 0)
                + counts.get("sent:blame", 0),
                "reports_received": reports_received,
                "requests_sent": counts.get("sent:request", 0),
                "requests_received": counts.get("received:request", 0),
            },
        }


class SlipsHTTPServer(ThreadingHTTPServer):
    """Concurrent HTTP server carrying the fixed run data reader."""

    daemon_threads = True
    request_queue_size = 128

    def __init__(
        self,
        server_address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        reader: RunDataReader,
    ) -> None:
        """Attach the run reader to the HTTP server."""
        super().__init__(server_address, handler)
        self.reader = reader

    def get_request(self) -> tuple[socket.socket, Any]:
        """
        Accept a client without letting an idle connection occupy a worker forever.

        Returns:
            Connected client socket and its address.
        """
        connection, address = super().get_request()
        connection.settimeout(CLIENT_REQUEST_TIMEOUT_SECONDS)
        return connection, address


class RequestHandler(BaseHTTPRequestHandler):
    """Serve run data and bounded, local network-name edits."""

    server: SlipsHTTPServer

    def log_message(self, format_string: str, *args: object) -> None:
        """Write access records to the module server log."""
        print(
            f"{self.address_string()} [{self.log_date_time_string()}] "
            f"{format_string % args}",
            flush=True,
        )

    def _send_json(
        self, payload: Any, status: HTTPStatus = HTTPStatus.OK
    ) -> None:
        """Send a JSON response with local-interface security headers."""
        self.send_response(status)
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'",
        )
        try:
            self.end_headers()
            self.wfile.write(body)
        except ConnectionError:
            # Browsers may cancel an in-flight request when refreshing data.
            return

    def _send_html(
        self, body_str: str, status: HTTPStatus = HTTPStatus.OK, headers=None
    ) -> None:
        """Send a small HTML response (login form, redirects)."""
        body = body_str.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _session_ok(self) -> bool:
        """Checks the request's session cookie against the shared password."""
        header = self.headers.get("Cookie")
        if not header:
            return False
        jar = cookies.SimpleCookie()
        jar.load(header)
        morsel = jar.get(SESSION_COOKIE_NAME)
        return bool(morsel) and validate_token(morsel.value)

    def _send_asset(self, filename: str | Path, content_type: str) -> None:
        """Send one allow-listed interface asset.

        Parameters:
            filename: Sibling filename or explicit repository asset path.
            content_type: HTTP media type returned for the asset.
        """
        path = (
            filename
            if isinstance(filename, Path)
            else Path(__file__).with_name(filename)
        )
        try:
            body = path.read_bytes()
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _api_response(self, path: str, query: Dict[str, List[str]]) -> Any:
        """Route one bounded API request and attach indexing metadata."""
        reader = self.server.reader
        reader.validate_run_identity()
        if path == "/api/identity":
            payload = reader.identity()
        elif path == "/api/overview":
            payload = reader.overview()
        elif path == "/api/overview/evidence-counts":
            payload = reader.overview_evidence_counts()
        elif path == "/api/metadata":
            payload = reader.metadata()
        elif path == "/api/logs":
            payload = reader.logs()
        elif path == "/api/metrics":
            payload = reader.metrics(query)
        elif path == "/api/alerts":
            payload = reader.alerts(query)
        elif path == "/api/evidence":
            payload = reader.evidence(query)
        elif path == "/api/hosts":
            payload = reader.hosts(query)
        elif path == "/api/host-names":
            payload = reader.host_names(query)
        elif path == "/api/firewall":
            payload = reader.firewall(query)
        elif path == "/api/arp-poisoning":
            payload = reader.arp_poisoning(query)
        elif path == "/api/p2p":
            payload = reader.p2p(query)
        elif path == "/api/configuration":
            payload = reader.configuration()
        elif path == "/api/whitelists":
            payload = reader.whitelists()
        elif path.startswith("/api/evidence/") and path.endswith("/flows"):
            evidence_id = unquote(path[len("/api/evidence/") : -len("/flows")])
            payload = reader.flows_for_evidence(evidence_id)
        elif path.startswith("/api/hosts/") and path.endswith(
            "/score-history"
        ):
            ip = unquote(path[len("/api/hosts/") : -len("/score-history")])
            payload = reader.score_history(ip, query)
        elif path.startswith("/api/hosts/") and path.endswith(
            "/traffic-summary"
        ):
            ip = unquote(path[len("/api/hosts/") : -len("/traffic-summary")])
            payload = reader.traffic_summary(ip, query)
        elif path.startswith("/api/hosts/") and path.endswith("/evidence"):
            ip = unquote(path[len("/api/hosts/") : -len("/evidence")])
            payload = reader.evidence_for_host(ip, query)
        elif path.startswith("/api/hosts/") and path.endswith("/flows"):
            ip = unquote(path[len("/api/hosts/") : -len("/flows")])
            payload = reader.flows_for_host(ip, query)
        elif path.startswith("/api/hosts/"):
            ip = unquote(path[len("/api/hosts/") :])
            payload = reader.host(ip)
        else:
            raise KeyError(path)
        if isinstance(payload, dict):
            payload.update(reader.response_metadata())
        return payload

    UNAUTHENTICATED_PATHS = {
        "/login",
        "/style.css",
        "/favicon.svg",
        "/slips-logo.png",
    }

    def _require_password(self) -> bool:
        return ConfigParser().web_interface_require_password()

    def do_GET(self) -> None:
        """Serve an allow-listed static asset or API response."""
        parsed = urlparse(self.path)

        if parsed.path == "/login":
            self._send_html(login_page_html(None))
            return

        if (
            self._require_password()
            and parsed.path not in self.UNAUTHENTICATED_PATHS
            and not self._session_ok()
        ):
            if parsed.path.startswith("/api/"):
                self._send_json(
                    {"error": "login required"}, HTTPStatus.UNAUTHORIZED
                )
            else:
                self._send_html(
                    "", HTTPStatus.FOUND, headers={"Location": "/login"}
                )
            return

        assets = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "/style.css": ("style.css", "text/css; charset=utf-8"),
            "/favicon.svg": (
                Path(__file__).with_name("favicon.svg"),
                "image/svg+xml",
            ),
            "/slips-logo.png": (
                Path(__file__).with_name("slips-logo.png"),
                "image/png",
            ),
        }
        if parsed.path in assets:
            self._send_asset(*assets[parsed.path])
            return
        if not parsed.path.startswith("/api/"):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            payload = self._api_response(parsed.path, parse_qs(parsed.query))
            self._send_json(payload)
        except RunMismatchError as error:
            self._send_json(
                {"error": "Run mismatch", "detail": str(error)},
                HTTPStatus.CONFLICT,
            )
        except KeyError:
            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
        except (
            redis.RedisError,
            sqlite3.Error,
            OSError,
            psutil.Error,
        ) as error:
            traceback.print_exc()
            self._send_json(
                {
                    "error": "The run data source is unavailable",
                    "detail": str(error),
                },
                HTTPStatus.SERVICE_UNAVAILABLE,
            )
        except Exception as error:
            traceback.print_exc()
            self._send_json(
                {
                    "error": "Unable to build the response",
                    "detail": str(error),
                },
                HTTPStatus.INTERNAL_SERVER_ERROR,
            )

    MAX_LOGIN_BODY_BYTES = 1024

    def do_POST(self) -> None:
        """Handle login and authenticated API changes."""
        parsed = urlparse(self.path)
        if parsed.path != "/login":
            self._post_annotation(parsed.path)
            return

        ensure_web_password_matches_redis_password()
        client_ip = self.client_address[0]

        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = -1
        if length < 0 or length > self.MAX_LOGIN_BODY_BYTES:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        body = self.rfile.read(length).decode("utf-8", errors="replace")

        if is_locked_out(client_ip):
            self._send_html(
                login_page_html("Too many attempts, try again shortly."),
                HTTPStatus.TOO_MANY_REQUESTS,
            )
            return

        password = parse_qs(body).get("password", [""])[0]
        if not verify_web_password(password):
            record_failed_login(client_ip)
            self._send_html(
                login_page_html("Incorrect password."),
                HTTPStatus.UNAUTHORIZED,
            )
            return

        record_successful_login(client_ip)
        cookie_header = (
            f"{SESSION_COOKIE_NAME}={issue_token()}; HttpOnly; "
            f"SameSite=Strict; Max-Age={SESSION_TTL_SECONDS}; Path=/"
        )
        self._send_html(
            "",
            HTTPStatus.FOUND,
            headers={"Location": "/", "Set-Cookie": cookie_header},
        )

    def _post_annotation(self, path: str) -> None:
        """Save an authenticated annotation, network name, or whitelist rule.

        Parameters:
            path: Requested API path.
        """
        if self._require_password() and not self._session_ok():
            self._send_json(
                {"error": "login required"}, HTTPStatus.UNAUTHORIZED
            )
            return
        if path not in {
            "/api/network-name",
            "/api/host-annotation",
            "/api/whitelists",
        }:
            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
            return
        if (
            path == "/api/whitelists"
            and not ipaddress.ip_address(self.client_address[0]).is_loopback
        ):
            self._send_json(
                {"error": "Whitelist changes require a local connection"},
                HTTPStatus.FORBIDDEN,
            )
            return
        origin = self.headers.get("Origin", "")
        if origin and urlparse(origin).netloc != self.headers.get("Host", ""):
            self._send_json({"error": "Invalid origin"}, HTTPStatus.FORBIDDEN)
            return
        if (
            self.headers.get("Content-Type", "")
            .split(";", 1)[0]
            .strip()
            .lower()
            != "application/json"
        ):
            self._send_json(
                {"error": "Expected a JSON request"},
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            )
            return
        try:
            size = int(self.headers.get("Content-Length", ""))
        except ValueError:
            size = 0
        if size < 1 or size > 8192:
            self._send_json(
                {"error": "Invalid request size"},
                HTTPStatus.BAD_REQUEST,
            )
            return
        try:
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict):
                raise ValueError("Expected an object")
            self.server.reader.validate_run_identity()
            if path == "/api/whitelists":
                saved = self.server.reader.save_whitelist_rule(
                    payload.get("action"),
                    payload.get("value"),
                    payload.get("direction"),
                    payload.get("ignore"),
                )
            elif path == "/api/host-annotation":
                saved = self.server.reader.save_host_annotation(
                    payload.get("ip"),
                    payload.get("network_id"),
                    payload.get("name"),
                    payload.get("note"),
                )
            elif "ip" in payload:
                saved = self.server.reader.save_profile_network_name(
                    payload.get("ip"),
                    payload.get("network_id"),
                    payload.get("name"),
                )
            else:
                saved = self.server.reader.save_network_name(
                    payload.get("interface"),
                    payload.get("network_id"),
                    payload.get("name"),
                )
            self._send_json(saved)
        except ValueError as error:
            self._send_json(
                {"error": "Invalid value", "detail": str(error)},
                HTTPStatus.BAD_REQUEST,
            )
        except RunMismatchError as error:
            self._send_json(
                {"error": "Run mismatch", "detail": str(error)},
                HTTPStatus.CONFLICT,
            )
        except (redis.RedisError, sqlite3.Error, OSError) as error:
            traceback.print_exc()
            self._send_json(
                {
                    "error": "Unable to save the requested change",
                    "detail": str(error),
                },
                HTTPStatus.SERVICE_UNAVAILABLE,
            )


def ipv4_address(value: str) -> str:
    """Validate one IPv4 bind address from the server command line.

    Parameters:
        value: Address supplied to ``--bind-address``.

    Returns:
        Normalized IPv4 address.

    Raises:
        argparse.ArgumentTypeError: When the value is not an IPv4 address.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    if not isinstance(address, ipaddress.IPv4Address):
        raise argparse.ArgumentTypeError("bind address must be IPv4")
    if address.is_unspecified:
        raise argparse.ArgumentTypeError(
            "bind address must identify one exact interface"
        )
    return str(address)


def parse_arguments() -> argparse.Namespace:
    """Parse run-specific server arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bind-address",
        type=ipv4_address,
        default=LOOPBACK_ADDRESS,
    )
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--redis-port", type=int, required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument(
        "--host-profiles-path",
        default="permanent/host_profiles/hosts.sqlite",
    )
    return parser.parse_args()


def main() -> None:
    """Start the single-run server on the configured IPv4 address."""
    args = parse_arguments()
    reader = RunDataReader(
        args.redis_port, args.output_dir, args.host_profiles_path
    )
    reader.validate_run_identity()
    server = SlipsHTTPServer(
        (args.bind_address, args.port), RequestHandler, reader
    )
    display_host = (
        "localhost"
        if args.bind_address == LOOPBACK_ADDRESS
        else args.bind_address
    )
    print(
        f"Serving {args.output_dir} at http://{display_host}:{args.port}/",
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
