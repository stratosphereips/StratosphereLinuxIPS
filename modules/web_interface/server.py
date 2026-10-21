# SPDX-License-Identifier: GPL-2.0-only
"""Serve the run-scoped Slips web interface."""

import argparse
import copy
import base64
import csv
import fcntl
import io
import ipaddress
import json
import math
import os
import re
import socket
import sys
import sqlite3
import tempfile
import time
import traceback
from datetime import datetime
from collections import Counter, defaultdict
from http import HTTPStatus, cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence
from urllib.parse import parse_qs, unquote, urlparse

import psutil
import redis
import yaml

from slips_files.common.mac import classify_mac
from slips_files.common.log_rotation import RotatingTextLog

from managers.network_state import collect_network_state
from slips_files.core.database.sqlite_db.host_profiles import HostProfileStore
from slips_files.core.database.sqlite_db.detection_queries import (
    detection_total,
    hourly_evidence_source,
)
from slips_files.core.database.sqlite_db.detection_history import (
    ARCHIVE_GLOB,
    ARCHIVE_NAME,
)
from slips_files.core.structures.evidence import EvidenceType
from modules.supported_module_names import Modules
from modules.p2p_trust.trust.base_model import (
    RELIABILITY_WEIGHT,
    local_maliciousness_to_thesis_score,
)
from modules.p2p_trust.trust.report_validation import (
    ReportValidator,
    observation_record,
    queue_review_event,
)
from slips_files.core.helpers.whitelist.whitelist_parser import (
    backup_local_whitelist,
    ensure_local_whitelist,
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
WEB_RULES_START = "; Begin rules added from the Slips web interface"
WEB_RULES_END = "; End rules added from the Slips web interface"
EVIDENCE_THREAT_RANKS = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
PROFILE_PREFIX = "profile_"
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 100
MISSING_CONFIG_DEFAULT = object()
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
    "5m": 5 * 60,
    "15m": 15 * 60,
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
    "detection_history": "Active detection limits, monthly archives, log rotation, and maintenance budgets.",
    "global_p2p": "Global peer-to-peer threat-intelligence behaviour.",
    "local_p2p": "Local peer-to-peer transport and identity settings.",
}
SENSITIVE_CONFIG_TERMS = (
    "api_key",
    "apikey",
    "password",
    "private_key",
    "secret",
    "credential",
)
WHITELIST_TYPES = {
    "IPs": "IP address",
    "domains": "Domain",
    "organizations": "Organization",
    "macs": "MAC address",
    "uris": "Request URI",
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

    @staticmethod
    def _is_sensitive_config_path(path: str) -> bool:
        """Identify secret-bearing YAML keys without hiding token-count limits.

        Parameters:
            path: Dot-separated YAML key path.

        Returns:
            Whether the setting value must be hidden from the browser.
        """
        lowered = path.lower()
        leaf = lowered.rsplit(".", 1)[-1]
        return any(term in lowered for term in SENSITIVE_CONFIG_TERMS) or (
            leaf == "token" or leaf.endswith("_token")
        )

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
            "detection.popup_alerts": (
                "Show a desktop notification when Slips raises an alert."
            ),
            "detection.low_risk_weight": (
                "Multiplier applied to low-threat evidence in the host score."
            ),
            "detection.medium_risk_weight": (
                "Multiplier applied to medium-threat evidence in the host score."
            ),
            "detection.high_risk_weight": (
                "Multiplier applied to high-threat evidence in the host score."
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
        default_value: Any = MISSING_CONFIG_DEFAULT,
    ) -> List[Dict[str, Any]]:
        """
        Flatten a configuration section into displayable leaf settings.

        Parameters:
            section: Top-level configuration section.
            value: Current mapping or leaf value.
            prefix: Dot-separated path accumulated during recursion.
            default_value: Value in the shipped configuration, if present.

        Returns:
            Ordered setting records for the web interface.
        """
        if isinstance(value, dict):
            settings: List[Dict[str, Any]] = []
            for key, nested in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                default_nested = (
                    default_value.get(key, MISSING_CONFIG_DEFAULT)
                    if isinstance(default_value, dict)
                    else MISSING_CONFIG_DEFAULT
                )
                settings.extend(
                    cls._flatten_settings(
                        section, nested, path, default_nested
                    )
                )
            return settings
        sensitive = cls._is_sensitive_config_path(prefix)
        has_default = default_value is not MISSING_CONFIG_DEFAULT
        return [
            {
                "key": prefix,
                "label": (
                    "Alert threshold"
                    if section == "detection"
                    and prefix == "risk_accumulated_threat_level"
                    else cls._setting_label(prefix.rsplit(".", 1)[-1])
                ),
                "value": (
                    "Configured — hidden" if sensitive and value else value
                ),
                "value_type": type(value).__name__,
                "sensitive": sensitive and bool(value),
                "changed": has_default and value != default_value,
                "has_default": has_default,
                "default": (
                    cls._redact_config(default_value, f"{section}.{prefix}")
                    if has_default
                    else None
                ),
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
        try:
            with Path("config/slips.yaml").open(encoding="utf-8") as handle:
                defaults = yaml.safe_load(handle) or {}
            if not isinstance(defaults, dict):
                defaults = {}
        except (OSError, yaml.YAMLError):
            defaults = {}
        sections = []
        total = 0
        changed_total = 0
        secret_total = 0
        for name, value in config.items():
            settings = self._flatten_settings(
                str(name),
                value,
                default_value=defaults.get(name, MISSING_CONFIG_DEFAULT),
            )
            total += len(settings)
            changed_count = sum(
                bool(setting["changed"]) for setting in settings
            )
            secret_count = sum(
                bool(setting["sensitive"]) for setting in settings
            )
            changed_total += changed_count
            secret_total += secret_count
            sections.append(
                {
                    "key": str(name),
                    "title": self._setting_label(str(name)),
                    "description": CONFIG_SECTION_DESCRIPTIONS.get(
                        str(name),
                        f"Settings used by the {self._setting_label(str(name)).lower()} component.",
                    ),
                    "settings": settings,
                    "changed_count": changed_count,
                    "secret_count": secret_count,
                }
            )
        return {
            "source": path.name if path else None,
            "captured": path is not None,
            "total": total,
            "changed_total": changed_total,
            "secret_total": secret_total,
            "sections": sections,
            "redacted_yaml": yaml.safe_dump(
                self._redact_config(config),
                sort_keys=False,
                allow_unicode=True,
            ),
        }

    @classmethod
    def _redact_config(cls, value: Any, path: str = "") -> Any:
        """Hide secret values before returning the run YAML to the browser.

        Parameters:
            value: Parsed YAML subtree.
            path: Dot-separated keys above this subtree.

        Returns:
            A copy safe to display in the web interface.
        """
        if cls._is_sensitive_config_path(path):
            return "Configured — hidden" if value else value
        if isinstance(value, dict):
            return {
                key: cls._redact_config(
                    nested, f"{path}.{key}" if path else str(key)
                )
                for key, nested in value.items()
            }
        if isinstance(value, list):
            return [cls._redact_config(item, path) for item in value]
        return value

    @staticmethod
    def _whitelist_effect(
        direction: str, ignored: str, rule_type: str = "ip"
    ) -> str:
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
        if rule_type == "uri":
            return "Suppresses matching request flows and their detections."
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
                    evidence_type = str(details.get("evidence_type") or "")
                    visible_value = (
                        str(value)
                        if label == "Request URI"
                        else str(value).split("|", 1)[0]
                    )
                    rules.append(
                        {
                            "type": label,
                            "value": visible_value,
                            "direction": direction,
                            "ignore": ignored,
                            "evidence_type": evidence_type,
                            "effect": self._whitelist_effect(
                                direction,
                                ignored,
                                "uri" if label == "Request URI" else "ip",
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
            managed_path = Path(
                str(
                    settings.get(
                        "local_whitelist_path", "config/whitelist.conf"
                    )
                )
            )
            try:
                content = managed_path.read_text(encoding="utf-8")
                managed_lines = (
                    content.split(WEB_RULES_START, 1)[1]
                    .split(WEB_RULES_END, 1)[0]
                    .splitlines()
                    if WEB_RULES_START in content
                    else []
                )
                legacy_path = web_whitelist_path(str(managed_path))
                if legacy_path.exists():
                    managed_lines.extend(
                        legacy_path.read_text(encoding="utf-8").splitlines()
                    )
                managed = {
                    (parts[0], parts[1], parts[4] if len(parts) > 4 else "")
                    for line in managed_lines
                    if (parts := line.split(","))
                    and parts[0] in {"ip", "uri"}
                    and len(parts) >= 4
                }
            except OSError:
                managed = set()
            for rule in rules:
                rule["managed"] = (
                    rule["type"] in {"IP address", "Request URI"}
                    and (
                        "uri" if rule["type"] == "Request URI" else "ip",
                        rule["value"],
                        rule["evidence_type"],
                    )
                    in managed
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
                evidence_type = parts[4] if len(parts) > 4 else ""
                label = {
                    "ip": "IP address",
                    "domain": "Domain",
                    "organization": "Organization",
                    "mac": "MAC address",
                    "uri": "Request URI",
                }.get(type_name.lower(), self._setting_label(type_name))
                rules.append(
                    {
                        "type": label,
                        "value": value,
                        "direction": direction,
                        "ignore": ignored,
                        "evidence_type": evidence_type,
                        "effect": self._whitelist_effect(
                            direction, ignored, type_name.lower()
                        ),
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
            "evidence_types": [item.name for item in EvidenceType],
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

    @staticmethod
    def _normalize_whitelist_uri(value: Any) -> str:
        """Validate a literal request URI for a flow rule.

        Parameters:
            value: Request URI from the browser.

        Returns:
            Validated URI.
        """
        if (
            not isinstance(value, str)
            or not value.startswith("/")
            or len(value) > 256
            or any(character in value for character in ("\r", "\n", ","))
        ):
            raise ValueError(
                "Enter a request URI beginning with / (up to 256 characters)"
            )
        return value

    def save_whitelist_rule(
        self,
        action: Any,
        value: Any,
        direction: Any,
        ignored: Any,
        evidence_type: Any = None,
        rule_type: Any = "ip",
    ) -> Dict[str, Any]:
        """Persist a web-managed IP or request URI rule and update the run.

        Parameters:
            action: Add or remove the rule.
            value: IP address, IP:port, or port-only value.
            direction: Source, destination, or both sides.
            ignored: Flows, evidence and alerts, or both.
            evidence_type: Optional evidence type for alert-only rules.
            rule_type: IP or URI rule.

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
        if evidence_type in (None, ""):
            evidence_type = ""
        elif (
            not isinstance(evidence_type, str)
            or evidence_type.upper() not in EvidenceType.__members__
        ):
            raise ValueError("Choose a valid evidence type")
        else:
            evidence_type = evidence_type.upper()
        if evidence_type and ignored != "alerts":
            raise ValueError("Evidence type rules must suppress alerts only")
        if rule_type not in {"ip", "uri"}:
            raise ValueError("Choose an IP or request URI rule")
        if rule_type == "uri" and (
            direction != "both" or ignored != "flows" or evidence_type
        ):
            raise ValueError(
                "Request URI rules must suppress flows on both sides"
            )
        normalized = (
            self._normalize_whitelist_uri(value)
            if rule_type == "uri"
            else self._normalize_whitelist_ip(value)
        )
        redis_value = (
            f"{normalized}|{evidence_type}" if evidence_type else normalized
        )
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
        path = Path(source)
        if not path.parent.is_dir():
            raise ValueError("The configured whitelist directory is missing")
        ensure_local_whitelist(source)
        lock_path = path.with_name(path.name + ".lock")
        with lock_path.open("a", encoding="utf-8") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if not path.is_file():
                raise FileNotFoundError(
                    f"Configured whitelist {path} is missing. "
                    "Restore it before changing web rules."
                )
            lines = path.read_text(encoding="utf-8").splitlines()
            backup_local_whitelist(path)
            if WEB_RULES_START in lines and WEB_RULES_END in lines:
                start = lines.index(WEB_RULES_START)
                end = lines.index(WEB_RULES_END, start)
                base_lines = lines[:start] + lines[end + 1 :]
                managed_lines = lines[start + 1 : end]
            else:
                base_lines = lines
                managed_lines = []
            legacy_path = web_whitelist_path(source)
            if legacy_path.exists():
                managed_lines.extend(
                    legacy_path.read_text(encoding="utf-8").splitlines()
                )
            existing = {
                (parts[0], parts[1], parts[4] if len(parts) > 4 else ""): line
                for line in managed_lines
                if (parts := line.split(","))
                and len(parts) >= 4
                and parts[0] in {"ip", "uri"}
            }
            if action == "add":
                if (
                    rule_type,
                    normalized,
                    evidence_type,
                ) in existing or self.redis.hexists(
                    (
                        "whitelist_uris"
                        if rule_type == "uri"
                        else "whitelist_IPs"
                    ),
                    redis_value,
                ):
                    raise ValueError("This value already has a whitelist rule")
                suffix = f",{evidence_type}" if evidence_type else ""
                managed_lines.append(
                    f"{rule_type},{normalized},{direction},{ignored}{suffix}"
                )
            else:
                if (rule_type, normalized, evidence_type) not in existing:
                    raise ValueError(
                        "Only web-managed rules can be removed here"
                    )
                managed_lines = [
                    line
                    for line in managed_lines
                    if line != existing[(rule_type, normalized, evidence_type)]
                ]
            lines = (
                base_lines
                + [WEB_RULES_START]
                + managed_lines
                + [WEB_RULES_END]
            )
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=path.parent, delete=False
            ) as temporary:
                temporary.write("\n".join(lines) + "\n")
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary_path = Path(temporary.name)
            try:
                if path.exists():
                    os.chmod(temporary_path, path.stat().st_mode & 0o777)
                os.replace(temporary_path, path)
                backup_local_whitelist(path)
                legacy_path.unlink(missing_ok=True)
            finally:
                temporary_path.unlink(missing_ok=True)
            if action == "add":
                self.redis.hset(
                    (
                        "whitelist_uris"
                        if rule_type == "uri"
                        else "whitelist_IPs"
                    ),
                    redis_value,
                    json.dumps(
                        {
                            "from": direction,
                            "what_to_ignore": ignored,
                            **(
                                {"evidence_type": evidence_type}
                                if evidence_type
                                else {}
                            ),
                        }
                    ),
                )
            else:
                self.redis.hdel(
                    (
                        "whitelist_uris"
                        if rule_type == "uri"
                        else "whitelist_IPs"
                    ),
                    redis_value,
                )
        return {
            "action": action,
            "value": normalized,
            "direction": direction,
            "ignore": ignored,
            "evidence_type": evidence_type,
            "rule_type": rule_type,
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
                if rule.get("evidence_type") and rule[
                    "evidence_type"
                ] != record.get("evidence_type"):
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
                        **(
                            {"evidence_type": rule["evidence_type"]}
                            if rule.get("evidence_type")
                            else {}
                        ),
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
        rules = (
            []
            if all(item.get("_grouped_evidence") for item in items)
            else self._runtime_whitelist_rules()
        )
        for item in items:
            grouped_ids = item.pop("_evidence_ids", None)
            if item.pop("_grouped_evidence", False) or isinstance(
                grouped_ids, list
            ):
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
        """Use each finding's recorded replies for its reporting peer list.

        Parameters:
            items: Individual or grouped evidence API records.
        """
        for item in items:
            if item.get("evidence_type") != "MALICIOUS_IP_FROM_P2P_NETWORK":
                continue
            description = str(item.get("description") or "")
            match = re.search(
                r"Replied to this lookup, peers?: (.*?)(?:\.(?:\s|$)|$)",
                description,
            )
            item["reporting_peers"] = (
                [label.split(" (")[0] for label in match.group(1).split(", ")]
                if match
                else []
            )
            if "Reported by peer" in description:
                item["description"] = re.sub(
                    r"Reported by peers?:",
                    "Historical reports from peers (possibly offline):",
                    description,
                    count=1,
                )

    @staticmethod
    def _clarify_legacy_p2p_report(item: Dict[str, Any]) -> None:
        """Explain an older P2P report without inventing an attack victim.

        Parameters:
            item: Evidence API record, updated in place when its description
                uses the former ambiguous P2P wording.
        """
        if item.get("evidence_type") != "P2P_REPORT":
            return
        description = str(item.get("description") or "")
        match = re.match(
            r"^attacking another peer:\s*(?:(?P<address>\S+)\s+)?"
            r"\((?P<peer_id>[^)]+)\)\.\s*confidence:\s*"
            r"(?P<confidence>\S+)",
            description,
        )
        if not match:
            return
        peer_id = match.group("peer_id")
        address = match.group("address")
        reporter_label = (
            f"{address} ({peer_id})"
            if address
            else f"{peer_id} (IP unavailable)"
        )
        item["description"] = (
            f"Received from P2P peer {reporter_label}: reputation report "
            f"about IP {item.get('profile_ip') or 'unknown'}; confidence "
            f"{match.group('confidence')}. No victim or attack details "
            "were provided."
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
        if input_type in {"interface", "stdin", "cyst"} and not getattr(
            self, "archive_mode", False
        ):
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
        if getattr(self, "archive_context", False):
            paths = [self.output_dir / "databases" / "flows.sqlite"]
            paths.extend(
                sorted(
                    (
                        path
                        for path in (
                            self.output_dir / "databases" / "archives"
                        ).glob(ARCHIVE_GLOB)
                        if ARCHIVE_NAME.fullmatch(path.name)
                        and not path.is_symlink()
                    ),
                    key=lambda path: abs(
                        int(path.stem[11:15]) * 12
                        + int(path.stem[16:18])
                        - int(self.sqlite_path.stem[11:15]) * 12
                        - int(self.sqlite_path.stem[16:18])
                    ),
                )
            )
            evidence_id = getattr(self, "archive_evidence_id", "")
            if evidence_id:
                matching = []
                for path in paths[1:]:
                    try:
                        with sqlite3.connect(
                            f"file:{path}?mode=ro", uri=True, timeout=1
                        ) as archive:
                            if archive.execute(
                                "SELECT 1 FROM evidence_flows WHERE evidence_id=? LIMIT 1",
                                (evidence_id,),
                            ).fetchone():
                                matching.append(path)
                    except sqlite3.OperationalError:
                        continue
                paths = (
                    paths[:1]
                    + matching
                    + [path for path in paths[1:] if path not in matching]
                )
            databases = ["main"]
            for path in paths:
                if (
                    path == self.sqlite_path
                    or not path.is_file()
                    or len(databases) >= 10
                ):
                    continue
                alias = f"context{len(databases)}"
                connection.execute(
                    f"ATTACH DATABASE ? AS {alias}", (f"file:{path}?mode=ro",)
                )
                databases.append(alias)
            for table, keys in (
                ("evidence", ("evidence_id",)),
                ("evidence_flows", ("evidence_id", "uid")),
                ("flows", ("uid",)),
                ("altflows", ("uid",)),
            ):
                columns = [
                    str(row[1])
                    for row in connection.execute(
                        f"PRAGMA main.table_info({table})"
                    )
                ]
                if table in {"flows", "altflows"}:
                    columns.insert(0, "rowid")
                sources = []
                for index, database in enumerate(databases):
                    exists = connection.execute(
                        f"SELECT 1 FROM {database}.sqlite_master WHERE name=?",
                        (table,),
                    ).fetchone()
                    if not exists:
                        continue
                    missing = " AND ".join(
                        f"NOT EXISTS (SELECT 1 FROM {previous}.{table} prior WHERE "
                        + " AND ".join(
                            f"prior.{key}=current.{key}" for key in keys
                        )
                        + ")"
                        for previous in databases[:index]
                    )
                    sources.append(
                        f"SELECT {','.join('current.' + column for column in columns)} "
                        f"FROM {database}.{table} current"
                        + (f" WHERE {missing}" if missing else "")
                    )
                connection.execute(
                    f"CREATE TEMP VIEW {table} AS "
                    + " UNION ALL ".join(sources)
                )
        return connection

    def archives(self) -> Dict[str, Any]:
        """List monthly archives without loading their detection records.

        Returns:
            Archive filenames, sizes and current maintenance health.
        """
        directory = self.output_dir / "databases" / "archives"
        items = []
        for path in sorted(directory.glob(ARCHIVE_GLOB), reverse=True):
            if not ARCHIVE_NAME.fullmatch(path.name) or path.is_symlink():
                continue
            try:
                with sqlite3.connect(
                    f"file:{path}?mode=ro", uri=True, timeout=0.1
                ) as archive:
                    ready = archive.execute(
                        "SELECT value FROM archive_metadata WHERE key='ready'"
                    ).fetchone()
            except (OSError, sqlite3.Error):
                continue
            if ready and ready[0] == "1":
                items.append(
                    {
                        "id": path.name,
                        "label": path.stem.removeprefix("detections-"),
                        "size_bytes": path.stat().st_size,
                        "updated_at": path.stat().st_mtime,
                    }
                )
        maintenance = {}
        with self._connect_sqlite() as connection:
            if self._table_exists(connection, "history_state"):
                row = connection.execute(
                    "SELECT value FROM history_state WHERE key='maintenance'"
                ).fetchone()
                if row:
                    maintenance = self._loads(row[0], {})
        return {
            "items": items,
            "maintenance": maintenance,
            "archive_size_bytes": sum(item["size_bytes"] for item in items),
        }

    def with_archive(
        self, filename: str, context: bool = False
    ) -> "RunDataReader":
        """Select an archive explicitly while preserving the live run identity.

        Parameters:
            filename: Allow-listed archive basename returned by archives().
            context: Resolve related evidence from other retained databases.

        Returns:
            Request-local reader using the selected read-only archive.
        """
        if not ARCHIVE_NAME.fullmatch(filename):
            raise KeyError("Unknown archive")
        path = self.output_dir / "databases" / "archives" / filename
        if not path.is_file() or path.is_symlink():
            raise KeyError("Archive expired or does not exist")
        reader = copy.copy(self)
        reader.sqlite_path = path
        reader.archive_mode = True
        reader.archive_context = context
        return reader

    def iter_reviewed_flows(self) -> Iterator[Dict[str, Any]]:
        """Stream retained flow rows with a separate analyst label.

        Returns:
            Flow dictionaries whose human_review is blank, benign, malicious,
            or conflict when linked decisions disagree.
        """
        with self._connect_sqlite() as connection:
            evidence_reviews = self._table_exists(
                connection, "evidence_reviews"
            )
            alert_reviews = self._table_exists(connection, "alert_reviews")
            alert_verdicts = alert_reviews and any(
                row[1] == "verdict"
                for row in connection.execute(
                    "PRAGMA table_info(alert_reviews)"
                )
            )
            for table in ("flows", "altflows"):
                if not self._table_exists(connection, table):
                    continue
                last_rowid = 0
                maximum = connection.execute(
                    f"SELECT COALESCE(MAX(rowid), 0) FROM {table}"
                ).fetchone()[0]
                while last_rowid < maximum:
                    rows = connection.execute(
                        f"SELECT rowid, uid, flow, label, profileid, twid, "
                        f"{'aid' if table == 'flows' else 'NULL AS aid'}, "
                        "event_time, retention_class "
                        f"FROM {table} WHERE rowid > ? AND rowid <= ? "
                        "ORDER BY rowid LIMIT 400",
                        (last_rowid, maximum),
                    ).fetchall()
                    if not rows:
                        break
                    last_rowid = rows[-1]["rowid"]
                    uids = [row["uid"] for row in rows]
                    placeholders = ",".join("?" for _ in uids)
                    decisions: Dict[str, set[str]] = defaultdict(set)
                    if evidence_reviews:
                        for decision in connection.execute(
                            "SELECT ef.uid, er.status FROM evidence_flows ef "
                            "JOIN evidence_reviews er ON er.evidence_id = ef.evidence_id "
                            f"WHERE ef.uid IN ({placeholders}) AND er.status IN "
                            "('true_positive', 'false_positive', 'expected_behavior')",
                            uids,
                        ):
                            decisions[decision["uid"]].add(decision["status"])
                    if alert_verdicts:
                        for decision in connection.execute(
                            "SELECT ef.uid, ar.verdict FROM evidence_flows ef "
                            "JOIN alert_evidence ae ON ae.evidence_id = ef.evidence_id "
                            "JOIN alert_reviews ar ON ar.alert_id = ae.alert_id "
                            f"WHERE ef.uid IN ({placeholders}) AND ar.verdict IN "
                            "('true_positive', 'false_positive', 'expected_behavior')",
                            uids,
                        ):
                            decisions[decision["uid"]].add(decision["verdict"])
                    for row in rows:
                        verdicts = decisions[row["uid"]]
                        positive = "true_positive" in verdicts
                        negative = bool(
                            verdicts & {"false_positive", "expected_behavior"}
                        )
                        if positive and negative:
                            human_review = "conflict"
                        elif positive:
                            human_review = "malicious"
                        elif negative:
                            human_review = "benign"
                        else:
                            human_review = ""
                        item = dict(row)
                        item.pop("rowid")
                        item["human_review"] = human_review
                        yield item

    @staticmethod
    def _review_clause(
        connection: sqlite3.Connection, entity: str, status: str, alias: str
    ) -> str:
        """Build a review filter for both old and migrated run databases.

        Parameters:
            connection: Current run database connection.
            entity: Either alert or evidence.
            status: Requested review state.
            alias: SQL alias of the outer record.

        Returns:
            A trusted SQL predicate without user supplied SQL.
        """
        table = f"{entity}_reviews"
        key = f"{entity}_id"
        if status == "all":
            return "1 = 1"
        if not RunDataReader._table_exists(connection, table):
            return (
                "1 = 1"
                if status in {"open", "active", "unreviewed"}
                else "0 = 1"
            )
        if entity == "alert" and status == "open":
            return (
                f"NOT EXISTS (SELECT 1 FROM {table} review "
                f"WHERE review.{key} = {alias}.{key} "
                "AND review.status = 'resolved')"
            )
        default = "active" if entity == "alert" else "unreviewed"
        return (
            f"COALESCE((SELECT review.status FROM {table} review "
            f"WHERE review.{key} = {alias}.{key}), '{default}') = '{status}'"
        )

    def _report_validation_path(self) -> Path:
        """Locate shared P2P feedback using this run's configured permanent path.

        Returns:
            Persistent validation database, or isolated storage for test readers.
        """
        if not hasattr(self, "output_dir"):
            return self.sqlite_path.parent / "report_validation.sqlite"
        config, _ = self._run_config()
        directory = config.get("parameters", {}).get(
            "permanent_dir", "permanent"
        )
        return (
            Path(directory) / "p2p_trust_runtime" / "report_validation.sqlite"
        )

    def _review_feedback_records(
        self,
        connection: sqlite3.Connection,
        entity: str,
        identifier: str,
    ) -> List[Dict[str, Any]]:
        """Snapshot reviewed evidence before deletion or later flow retention.

        Parameters:
            connection: Review write transaction.
            entity: Alert or evidence.
            identifier: Reviewed record ID.

        Returns:
            Local or typed peer observations suitable for validation.
        """
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(evidence)")
        }
        if "data" not in columns:
            return []
        condition = (
            "evidence_id = ?"
            if entity == "evidence"
            else "evidence_id IN (SELECT evidence_id FROM alert_evidence WHERE alert_id = ?)"
        )
        records = []
        for row in connection.execute(
            f"SELECT evidence_id, data FROM evidence WHERE {condition}",
            (identifier,),
        ):
            raw = self._loads(row["data"], {})
            if not isinstance(raw, dict):
                continue
            raw.setdefault("id", row["evidence_id"])
            observed = observation_record(
                raw, f"run:{getattr(self, 'output_dir', self.sqlite_path)}"
            )
            if observed:
                if (
                    not raw.get("detection_provenance")
                    and not raw.get("peer_report")
                    and hasattr(self, "output_dir")
                ):
                    temporary = {
                        "profile_ip": observed["target"],
                        "evidence_time": observed["observed_at"],
                    }
                    self._annotate_detection_networks(
                        [temporary], "profile_ip", "evidence_time"
                    )
                    network = temporary.get("network_id")
                    if network:
                        observed["network_id"] = network
                        observed["target_key"] = (
                            f"{network}|{observed['target']}"
                        )
                records.append(observed)
        return records

    def save_review(
        self, entity: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Persist a review state or remove selected linked records atomically.

        Parameters:
            entity: Alert or evidence requested by the API route.
            payload: Identifier, action, status or depth, and analyst note.

        Returns:
            Saved state or counts of deleted and protected shared records.
        """
        if getattr(self, "archive_mode", False):
            raise ValueError("Detection archives are read-only")
        if entity not in {"alert", "evidence"}:
            raise ValueError("Unknown review entity")
        identifier = payload.get("id")
        action = payload.get("action")
        note = payload.get("note", "")
        if not isinstance(identifier, str) or not 1 <= len(identifier) <= 160:
            raise ValueError("Select a valid record")
        if (
            not isinstance(note, str)
            or len(note) > 2000
            or any(
                (ord(char) < 32 and char not in "\n\t") or ord(char) == 127
                for char in note
            )
        ):
            raise ValueError(
                "Review note must be at most 2000 printable characters"
            )
        note = note.strip()
        if action == "review":
            status = payload.get("status")
            verdict = payload.get("verdict", "") if entity == "alert" else ""
            if entity == "alert" and verdict not in {
                "",
                "true_positive",
                "false_positive",
                "expected_behavior",
                "inconclusive",
            }:
                raise ValueError("Unknown alert verdict")
            allowed = (
                {"active", "in_review", "resolved"}
                if entity == "alert"
                else {
                    "unreviewed",
                    "in_review",
                    "true_positive",
                    "false_positive",
                    "expected_behavior",
                    "inconclusive",
                }
            )
            if status not in allowed:
                raise ValueError("Unknown review status")
            if entity == "alert" and status == "resolved" and not note:
                raise ValueError("Add a note before resolving an alert")
        elif action == "delete":
            depth = payload.get("depth")
            allowed = (
                {"alert", "evidence", "flows"}
                if entity == "alert"
                else {"evidence", "flows"}
            )
            if depth not in allowed:
                raise ValueError("Unknown deletion depth")
            if not note:
                raise ValueError("Add a reason before deleting")
        else:
            raise ValueError("Unknown review action")
        table = "alerts" if entity == "alert" else "evidence"
        key = f"{entity}_id"
        connection = sqlite3.connect(str(self.sqlite_path), timeout=15)
        connection.row_factory = sqlite3.Row
        try:
            history_path = getattr(self, "history_path", None)
            history_attached = bool(
                history_path and Path(history_path).exists()
            )
            if history_attached:
                connection.execute(
                    "ATTACH DATABASE ? AS web_history", (str(history_path),)
                )
            connection.execute("BEGIN IMMEDIATE")
            if not connection.execute(
                f"SELECT 1 FROM {table} WHERE {key} = ?", (identifier,)
            ).fetchone():
                raise ValueError("Record no longer exists")
            feedback_records = self._review_feedback_records(
                connection, entity, identifier
            )
            deleted_evidence_ids = []
            connection.execute(
                "CREATE TABLE IF NOT EXISTS alert_reviews ("
                "alert_id TEXT PRIMARY KEY, status TEXT NOT NULL, "
                "note TEXT NOT NULL DEFAULT '', updated_at REAL NOT NULL, "
                "verdict TEXT NOT NULL DEFAULT '')"
            )
            if not any(
                row[1] == "verdict"
                for row in connection.execute(
                    "PRAGMA table_info(alert_reviews)"
                )
            ):
                connection.execute(
                    "ALTER TABLE alert_reviews ADD COLUMN verdict TEXT NOT NULL DEFAULT ''"
                )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS evidence_reviews ("
                "evidence_id TEXT PRIMARY KEY, status TEXT NOT NULL, "
                "note TEXT NOT NULL DEFAULT '', updated_at REAL NOT NULL)"
            )
            if action == "review":
                if entity == "alert":
                    connection.execute(
                        "INSERT INTO alert_reviews "
                        "(alert_id, status, note, updated_at, verdict) "
                        "VALUES (?, ?, ?, ?, ?) ON CONFLICT(alert_id) DO UPDATE SET "
                        "status = excluded.status, note = excluded.note, "
                        "updated_at = excluded.updated_at, verdict = excluded.verdict",
                        (identifier, status, note, time.time(), verdict),
                    )
                else:
                    connection.execute(
                        "INSERT INTO evidence_reviews "
                        "(evidence_id, status, note, updated_at) VALUES (?, ?, ?, ?) "
                        "ON CONFLICT(evidence_id) DO UPDATE SET "
                        "status = excluded.status, note = excluded.note, "
                        "updated_at = excluded.updated_at",
                        (identifier, status, note, time.time()),
                    )
                result = {"id": identifier, "status": status, "note": note}
                if entity == "alert":
                    result["verdict"] = verdict
            else:
                evidence_ids = (
                    [
                        str(row[0])
                        for row in connection.execute(
                            "SELECT evidence_id FROM alert_evidence WHERE alert_id = ?",
                            (identifier,),
                        ).fetchall()
                    ]
                    if entity == "alert"
                    else [identifier]
                )
                if entity == "alert":
                    connection.execute(
                        "DELETE FROM alert_evidence WHERE alert_id = ?",
                        (identifier,),
                    )
                    connection.execute(
                        "DELETE FROM alerts WHERE alert_id = ?", (identifier,)
                    )
                    connection.execute(
                        "DELETE FROM alert_reviews WHERE alert_id = ?",
                        (identifier,),
                    )
                else:
                    connection.execute(
                        "DELETE FROM alert_evidence WHERE evidence_id = ?",
                        (identifier,),
                    )
                removed_evidence = 0
                removed_flows = 0
                protected = 0
                if depth != "alert":
                    for evidence_id in evidence_ids:
                        if connection.execute(
                            "SELECT 1 FROM alert_evidence WHERE evidence_id = ? LIMIT 1",
                            (evidence_id,),
                        ).fetchone():
                            protected += 1
                            continue
                        uids = [
                            str(row[0])
                            for row in connection.execute(
                                "SELECT uid FROM evidence_flows WHERE evidence_id = ?",
                                (evidence_id,),
                            ).fetchall()
                        ]
                        connection.execute(
                            "DELETE FROM evidence_flows WHERE evidence_id = ?",
                            (evidence_id,),
                        )
                        connection.execute(
                            "DELETE FROM evidence WHERE evidence_id = ?",
                            (evidence_id,),
                        )
                        connection.execute(
                            "DELETE FROM evidence_reviews WHERE evidence_id = ?",
                            (evidence_id,),
                        )
                        removed_evidence += 1
                        deleted_evidence_ids.append(evidence_id)
                        if depth == "flows":
                            for uid in uids:
                                if connection.execute(
                                    "SELECT 1 FROM evidence_flows WHERE uid = ? LIMIT 1",
                                    (uid,),
                                ).fetchone():
                                    continue
                                for flow_table in ("flows", "altflows"):
                                    removed_flows += connection.execute(
                                        f"DELETE FROM {flow_table} WHERE uid = ?",
                                        (uid,),
                                    ).rowcount
                                if history_attached:
                                    connection.execute(
                                        "DELETE FROM web_history.flow_index "
                                        "WHERE uid = ?",
                                        (uid,),
                                    )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS review_deletions ("
                    "entity TEXT NOT NULL, record_id TEXT NOT NULL, "
                    "depth TEXT NOT NULL, note TEXT NOT NULL, deleted_at REAL NOT NULL, "
                    "evidence_removed INTEGER NOT NULL, flows_removed INTEGER NOT NULL, "
                    "shared_preserved INTEGER NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO review_deletions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        entity,
                        identifier,
                        depth,
                        note,
                        time.time(),
                        removed_evidence,
                        removed_flows,
                        protected,
                    ),
                )
                result = {
                    "id": identifier,
                    "deleted": True,
                    "depth": depth,
                    "evidence_removed": removed_evidence,
                    "flows_removed": removed_flows,
                    "shared_preserved": protected,
                }
            feedback_verdict = (
                (verdict if entity == "alert" else status)
                if action == "review"
                else ""
            )
            if entity == "alert" and feedback_verdict == "true_positive":
                types = {
                    record["evidence_type"] for record in feedback_records
                }
                if len(types) > 1:
                    feedback_verdict = "inconclusive"
            queue_review_event(
                connection,
                f"{entity}:{identifier}",
                feedback_verdict,
                feedback_records if action == "review" else [],
                deleted_evidence_ids,
            )
            connection.commit()
            if feedback_records:
                try:
                    validator = ReportValidator(self._report_validation_path())
                    validator.drain_reviews(self.sqlite_path)
                    result["p2p_feedback"] = "applied"
                    if (
                        feedback_verdict == "inconclusive"
                        and entity == "alert"
                        and verdict == "true_positive"
                    ):
                        result["p2p_feedback_note"] = (
                            "Review saved. This alert contains several evidence types; review individual evidence to confirm each detector for P2P learning."
                        )
                except (sqlite3.Error, OSError):
                    result["p2p_feedback"] = "pending"
            if action == "delete" and depth == "flows":
                connection.execute("PRAGMA incremental_vacuum(1000)")
            return result
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

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

    def _current_network_start(self) -> Optional[float]:
        """Find the start of the current continuous monitored connection.

        Returns:
            Earliest retained timestamp on the current network, if connected.
        """
        analysis = self.redis.hgetall("analysis")
        if analysis.get("input_type") != "interface" or analysis.get(
            "analysis_end"
        ):
            return None
        interface = (
            str(analysis.get("interface") or "").split(",", 1)[0].strip()
        )
        state = self._loads(self.redis.hget("network_states", interface), {})
        if not isinstance(state, dict) or not state.get("connected"):
            return None
        try:
            start = float(state["changed_at"])
        except (KeyError, TypeError, ValueError):
            return None
        if not math.isfinite(start):
            return None
        gateway_mac = str(state.get("gateway_mac") or "").lower()
        if gateway_mac:
            for previous in reversed(state.get("history", [])):
                if not isinstance(previous, dict) or not previous.get(
                    "connected"
                ):
                    break
                if (
                    str(previous.get("gateway_mac") or "").lower()
                    != gateway_mac
                ):
                    break
                try:
                    previous_start = float(previous["changed_at"])
                except (KeyError, TypeError, ValueError):
                    break
                if not math.isfinite(previous_start):
                    break
                start = previous_start
        return start

    def _scoped_start(
        self, query: Dict[str, List[str]], start: Optional[float]
    ) -> Optional[float]:
        """Limit a requested time range to the current connection.

        Parameters:
            query: Request filters, including the optional network scope.
            start: Lower bound from the selected time range.

        Returns:
            Effective lower bound, or infinity when no network is connected.
        """
        if (
            getattr(self, "archive_mode", False)
            or self._query_value(query, "network") != "current"
        ):
            return start
        network_start = self._current_network_start()
        if network_start is None:
            return float("inf")
        return max(start or 0.0, network_start)

    def identity(self) -> Dict[str, Any]:
        """Return a signed identity response for stale-server detection."""
        return {
            "service": "slips-web-interface",
            "pid": os.getpid(),
            "review_actions": True,
            "network_filter_supported": True,
            "device_view_supported": True,
            "current_network_start": self._current_network_start(),
            "current_network": self._current_header_network(),
            **self.validate_run_identity(),
        }

    def _current_header_network(self) -> Dict[str, Any]:
        """Return the named live network for the shared page header.

        Returns:
            Current monitored interface, connection, name and all its IPs.
        """
        analysis = self.redis.hgetall("analysis")
        if analysis.get("input_type") != "interface" or analysis.get(
            "analysis_end"
        ):
            return {}
        interfaces = str(analysis.get("interface") or "")
        interface = interfaces.split(",", 1)[0]
        if not interface:
            return {}
        state = self._loads(self.redis.hget("network_states", interface), {})
        if not isinstance(state, dict):
            return {}
        addresses = self._interface_addresses(interfaces)
        if not state.get("connected"):
            return {
                "interface": interface,
                "connected": False,
                "host_addresses": addresses,
            }
        try:
            network = self._named_network_states([state])[0]
        except sqlite3.Error:
            network = state
        return {
            "interface": interface,
            "connected": True,
            "name": network.get("name") or "",
            "network_id": network.get("network_id") or "",
            "host_ip": network.get("host_ip") or "",
            "host_addresses": addresses,
        }

    def live_counts(
        self, query: Optional[Dict[str, List[str]]] = None
    ) -> Dict[str, int]:
        """Count alerts and hosts in the lists' rolling live range.

        Returns:
            Alert and host totals for the same one-hour window used by
            the live Alerts and Hosts filters.
        """
        live_query = {"range": ["live"]}
        if self._query_value(query or {}, "network") == "current":
            live_query["network"] = ["current"]
        with self._connect_sqlite() as connection:
            latest_alert = connection.execute(
                "SELECT MAX(CAST(alert_time AS REAL)) FROM alerts"
            ).fetchone()[0]
            alert_start, alert_end, _ = self._time_bounds(
                live_query, latest_alert
            )
            alert_start = self._scoped_start(live_query, alert_start)
            alerts = int(
                connection.execute(
                    "SELECT COUNT(*) FROM alerts "
                    "WHERE CAST(alert_time AS REAL) BETWEEN ? AND ? AND "
                    + self._review_clause(
                        connection, "alert", "open", "alerts"
                    ),
                    (alert_start, alert_end),
                ).fetchone()[0]
            )
        with connect_history(self.history_path, read_only=True) as history:
            latest_host = history.execute(
                "SELECT MAX(event_time) FROM flow_index"
            ).fetchone()[0]
            if not latest_host:
                latest_host = history.execute(
                    "SELECT MAX(observed_at) FROM host_snapshots"
                ).fetchone()[0]
            host_start, host_end, _ = self._time_bounds(
                live_query, latest_host
            )
            device_view = self._query_value(query or {}, "device") == "1"
            host_start = self._scoped_start(live_query, host_start)
            scoped = self._query_value(live_query, "network") == "current"
            if scoped:
                history.execute(
                    "ATTACH DATABASE ? AS run_db", (str(self.sqlite_path),)
                )
            seen = self._host_last_seen_expression(history, scoped)
            host_rows = history.execute(
                f"SELECT hs.ip FROM host_snapshots hs WHERE {seen} BETWEEN ? AND ?",
                (host_start, host_end),
            ).fetchall()
            if device_view:
                device_keys = self._device_key_map()
                hosts = len(
                    {
                        device_keys.get(str(row["ip"]), str(row["ip"]))
                        for row in host_rows
                    }
                )
            else:
                hosts = len(host_rows)
        return {"alerts": alerts, "hosts": hosts}

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
                self._clarify_legacy_p2p_report(evidence)
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
            "SELECT COUNT(*) AS count FROM evidence_flows "
            "WHERE evidence_id = ? AND uid <> ''",
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
        if self._table_exists(connection, "evidence_reviews"):
            review = connection.execute(
                "SELECT status, note, updated_at FROM evidence_reviews "
                "WHERE evidence_id = ?",
                (evidence_id,),
            ).fetchone()
            if review:
                record.update(
                    {
                        "review_status": review["status"],
                        "review_note": review["note"],
                        "review_updated_at": review["updated_at"],
                    }
                )
        record.setdefault("review_status", "unreviewed")
        self._clarify_legacy_p2p_report(record)
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

    @staticmethod
    def _type_alert_counts_from_stream(
        connection: sqlite3.Connection,
        page_ids: set[str],
        hide_excluded: bool,
        end: Optional[float],
        start: Optional[float] = None,
        group_expression: str = "evidence_type",
    ) -> Dict[str, int]:
        """Count grouped alert links by merging two ordered covering indexes.

        Parameters:
            connection: Current flows database connection.
            page_ids: Evidence types visible on the requested page.
            hide_excluded: Whether excluded evidence is filtered out.
            end: Upper bound of the selected run clock.
            start: Optional lower bound of the selected time range.
            group_expression: Trusted SQL expression identifying each group.

        Returns:
            Alert-link counts for the requested groups.
        """
        evidence_rows = connection.execute(
            f"SELECT evidence_id, {group_expression} AS evidence_type, "
            "evidence_time, whitelisted "
            "FROM evidence INDEXED BY evidence_alert_group_idx "
            "ORDER BY evidence_id"
        )
        linked_rows = iter(
            connection.execute(
                "SELECT evidence_id, COUNT(*) AS link_count "
                "FROM alert_evidence INDEXED BY alert_evidence_evidence_idx "
                "GROUP BY evidence_id"
            )
        )
        linked = next(linked_rows, None)
        counts: Counter[str] = Counter()
        for evidence in evidence_rows:
            evidence_id = str(evidence["evidence_id"])
            while linked and str(linked["evidence_id"]) < evidence_id:
                linked = next(linked_rows, None)
            if not linked or str(linked["evidence_id"]) != evidence_id:
                continue
            evidence_type = str(evidence["evidence_type"] or "")
            if evidence_type not in page_ids:
                continue
            if hide_excluded and evidence["whitelisted"] not in (None, 0, "0"):
                continue
            if (
                start is not None
                and float(evidence["evidence_time"] or 0) < start
            ):
                continue
            if end is not None and float(evidence["evidence_time"] or 0) > end:
                continue
            counts[evidence_type] += int(linked["link_count"])
        return dict(counts)

    def _grouped_evidence(self, query: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        Return evidence aggregated by host, type, or their combination.

        Parameters:
            query: Request filters, sort, range, and cursor values.

        Returns:
            Bounded aggregate page with raw durable total metadata.
        """
        limit = self._limit(query)
        group_mode = self._query_value(query, "group", "host_type")
        device_view = self._query_value(query, "device") == "1"
        host_group = "device_key(profile_ip)" if device_view else "profile_ip"
        if group_mode == "type":
            group_fields = ("'' AS profile_ip, evidence_type", "evidence_type")
            group_id = "evidence_type"
        elif group_mode == "host":
            group_fields = (
                "MIN(profile_ip) AS profile_ip, '' AS evidence_type",
                host_group,
            )
            group_id = host_group
        else:
            group_fields = (
                "MIN(profile_ip) AS profile_ip, evidence_type",
                f"{host_group}, evidence_type",
            )
            group_id = f"{host_group} || char(31) || evidence_type"
        search = self._query_value(query, "search").lower()
        threat = self._query_value(query, "threat").lower()
        association = self._query_value(query, "association")
        profile = self._query_value(query, "profile")
        evidence_type = self._query_value(query, "type")
        compact_groups = self._query_value(
            query, "compact"
        ) == "1" and self._query_value(query, "sort") not in {"flows", "alert"}
        cursor = self._decode_cursor(self._query_value(query, "cursor"))
        threat_expression = (
            "CASE LOWER(threat_level) WHEN 'critical' THEN 4 "
            "WHEN 'high' THEN 3 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 1 ELSE 0 END"
        )
        flow_expression = (
            "(SELECT COUNT(*) FROM evidence_flows ef "
            "WHERE ef.evidence_id = evidence.evidence_id AND ef.uid <> '')"
        )
        alert_expression = (
            "(SELECT COUNT(*) FROM alert_evidence ae "
            "WHERE ae.evidence_id = evidence.evidence_id)"
        )
        with self._connect_sqlite() as connection:
            connection.execute("BEGIN")
            self._register_device_key(connection, device_view)
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
            start = self._scoped_start(query, start)
            full_total = detection_total(connection, "evidence")
            clauses = ["1 = 1"]
            params: List[Any] = []
            review_status = self._query_value(query, "review", "all")
            if review_status in {
                "unreviewed",
                "in_review",
                "true_positive",
                "false_positive",
                "expected_behavior",
                "inconclusive",
            }:
                clauses.append(
                    self._review_clause(
                        connection, "evidence", review_status, "evidence"
                    )
                )
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
                clauses.append(
                    "device_key(profile_ip) = ?"
                    if device_view
                    else "profile_ip = ?"
                )
                params.append(profile)
            if evidence_type:
                clauses.append("evidence_type = ?")
                params.append(evidence_type)
            if threat:
                minimum = threat.removesuffix("_or_more")
                if (
                    threat.endswith("_or_more")
                    and minimum in EVIDENCE_THREAT_RANKS
                ):
                    clauses.append(f"{threat_expression} >= ?")
                    params.append(EVIDENCE_THREAT_RANKS[minimum])
                else:
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
            if self._query_value(query, "scored_only") == "1":
                clauses.append(f"COALESCE({score_expression}, 0) > 0")
            type_cover_index_available = bool(
                group_mode == "type"
                and connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'index' "
                    "AND name = 'evidence_type_group_cover_idx'"
                ).fetchone()
            )
            cover_index_available = bool(
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'index' "
                    "AND name = 'evidence_group_cover_idx'"
                ).fetchone()
            )
            covered_groups = bool(
                compact_groups
                and not search
                and not association
                and review_status == "all"
            )
            group_source = (
                "evidence INDEXED BY evidence_type_group_cover_idx"
                if covered_groups and type_cover_index_available
                else (
                    "evidence INDEXED BY evidence_group_cover_idx"
                    if covered_groups and cover_index_available
                    else "evidence"
                )
            )
            time_cover = bool(
                start is not None
                and connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE name='evidence_time_cover_idx'"
                ).fetchone()
            )
            if covered_groups and time_cover:
                group_source = "evidence INDEXED BY evidence_time_cover_idx"
            summary_source = (
                hourly_evidence_source(connection, start, end)
                if covered_groups
                and self._query_value(query, "scored_only") != "1"
                else None
            )
            if summary_source:
                group_source = summary_source
            record_count = "SUM(weight)" if summary_source else "COUNT(*)"
            first_time = "first_time" if summary_source else "evidence_time"
            matching_total = int(
                connection.execute(
                    f"SELECT COALESCE({record_count},0) FROM {group_source} "
                    f"WHERE {' AND '.join(clauses)}",
                    params,
                ).fetchone()[0]
            )
            device_ips_expression = (
                "GROUP_CONCAT(DISTINCT profile_ip)"
                if device_view and group_mode != "type"
                else "''"
            )
            grouped_sql = (
                f"SELECT {group_fields[0]}, "
                f"{group_id} AS group_id, "
                f"{device_ips_expression} AS device_ips, "
                "MAX(evidence_time) AS timestamp, "
                f"MIN({first_time}) AS first_timestamp, "
                f"MAX({threat_expression}) AS threat_rank, "
                f"GROUP_CONCAT(DISTINCT {module_expression}) AS module, "
                f"{record_count} AS evidence_count, "
                f"SUM({whitelist_expression}{' * weight' if summary_source else ''}) AS persisted_whitelisted_count, "
                f"{('0' if compact_groups else f'SUM({flow_expression})')} "
                "AS flow_count, "
                f"{('SUM(summarized_alerts)' if summary_source else '0' if compact_groups else f'SUM({alert_expression})')} AS alert_count, "
                f"MAX({score_expression}) AS alert_score "
                f"FROM {group_source} WHERE {' AND '.join(clauses)} "
                f"GROUP BY {group_fields[1]}"
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
            total = None
            if cursor:
                total = int(
                    connection.execute(
                        "SELECT COUNT(*) AS count FROM (SELECT 1 FROM "
                        f"{group_source} WHERE {' AND '.join(clauses)} "
                        f"GROUP BY {group_fields[1]})",
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
                "SELECT grouped.*, COUNT(*) OVER () AS total_groups, "
                f"{sort_expression} AS sort_value "
                f"FROM ({grouped_sql}) grouped {outer_where} "
                f"ORDER BY {sort_expression} {direction}, "
                f"group_id {direction} LIMIT ?",
                (*params, *outer_params, limit + 1),
            ).fetchall()
            alert_counts: Dict[str, int] = {}
            if (
                compact_groups
                and rows
                and association != "unlinked"
                and not summary_source
            ):
                page_ids = [str(row["group_id"]) for row in rows[:limit]]
                page_has_null = any(
                    row["group_id"] is None for row in rows[:limit]
                )
                page_marks = ",".join("?" for _ in page_ids)
                time_index = bool(
                    start is not None
                    and connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type = 'index' "
                        "AND name = 'evidence_time_idx'"
                    ).fetchone()
                )
                alert_cover_index = bool(
                    connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type = 'index' "
                        "AND name = 'evidence_alert_group_idx'"
                    ).fetchone()
                )
                stream_counts = bool(
                    alert_cover_index
                    and not page_has_null
                    and not time_cover
                    and not search
                    and not threat
                    and not association
                    and review_status == "all"
                    and not profile
                    and self._query_value(query, "scored_only") != "1"
                    and connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type = 'index' "
                        "AND name = 'alert_evidence_evidence_idx'"
                    ).fetchone()
                )
                if stream_counts:
                    alert_counts = self._type_alert_counts_from_stream(
                        connection,
                        set(page_ids),
                        self._query_value(query, "hide_excluded") == "1",
                        end,
                        start,
                        group_id,
                    )
                else:
                    if time_cover:
                        alert_source = "evidence INDEXED BY evidence_time_cover_idx CROSS JOIN alert_evidence ae"
                    elif alert_cover_index:
                        alert_source = (
                            "alert_evidence ae CROSS JOIN evidence "
                            "INDEXED BY evidence_alert_group_idx"
                        )
                    else:
                        index_hint = (
                            " INDEXED BY evidence_time_idx"
                            if time_index
                            else ""
                        )
                        alert_source = f"evidence{index_hint} CROSS JOIN alert_evidence ae"
                    alert_counts = {
                        str(row["group_id"]): int(row["alert_count"])
                        for row in connection.execute(
                            f"SELECT {group_id} AS group_id, "
                            "COUNT(*) AS alert_count "
                            f"FROM {alert_source} "
                            f"WHERE {' AND '.join(clauses)} "
                            "AND ae.evidence_id = evidence.evidence_id "
                            f"AND ({group_id} IN ({page_marks})"
                            + (
                                f" OR {group_id} IS NULL"
                                if page_has_null
                                else ""
                            )
                            + ") "
                            f"GROUP BY {group_id}",
                            (*params, *page_ids),
                        )
                    }
        if total is None:
            total = int(rows[0]["total_groups"] or 0) if rows else 0
        has_more = len(rows) > limit
        rows = rows[:limit]
        items = []
        for row in rows:
            item = dict(row)
            item.pop("sort_value", None)
            item.pop("total_groups", None)
            item["id"] = str(item.pop("group_id"))
            if device_view and group_mode != "type":
                item["device_id"] = item["id"].split("\x1f", 1)[0]
                item["device_ips"] = sorted(
                    str(item.get("device_ips") or "").split(",")
                )
            item["threat_level"] = self._threat_from_rank(
                item.pop("threat_rank")
            )
            item["timestamp"] = float(item["timestamp"] or 0)
            item["first_timestamp"] = float(item["first_timestamp"] or 0)
            item["evidence_count"] = int(item["evidence_count"] or 0)
            item["_grouped_evidence"] = True
            item["whitelisted_count"] = int(
                item.pop("persisted_whitelisted_count") or 0
            )
            item["flow_count"] = (
                None if compact_groups else int(item["flow_count"] or 0)
            )
            item["alert_count"] = (
                alert_counts.get(item["id"], 0)
                if compact_groups and not summary_source
                else int(item["alert_count"] or 0)
            )
            item.update(
                self._score_fields(
                    item["alert_score"],
                    item["alert_score"],
                    "highest score in this evidence group",
                )
            )
            items.append(item)
        if group_mode != "type":
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
            "matching_total": matching_total,
            "full_total": full_total,
            "page_size": len(items),
            "next_cursor": next_cursor,
            "range": range_name,
            "sort": sort_key,
            "order": direction.lower(),
            "group": group_mode,
        }

    def evidence(self, query: Dict[str, List[str]]) -> Dict[str, Any]:
        """Return one filtered, cursor-bounded evidence page."""
        if self._query_value(query, "group") in {"host_type", "type", "host"}:
            return self._grouped_evidence(query)
        limit = self._limit(query)
        search = self._query_value(query, "search").lower()
        threat = self._query_value(query, "threat").lower()
        association = self._query_value(query, "association")
        profiles = [str(value) for value in query.get("profile", []) if value]
        device_id = self._query_value(query, "device_id")
        evidence_type = self._query_value(query, "type")
        cursor = self._decode_cursor(self._query_value(query, "cursor"))
        threat_expression = (
            "CASE LOWER(threat_level) WHEN 'critical' THEN 4 "
            "WHEN 'high' THEN 3 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 1 ELSE 0 END"
        )
        flow_expression = (
            "(SELECT COUNT(*) FROM evidence_flows ef "
            "WHERE ef.evidence_id = evidence.evidence_id AND ef.uid <> '')"
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
                self._register_device_key(connection, bool(device_id))
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
                reporter_expression = (
                    "LOWER(CASE WHEN INSTR(description, 'peers: ') > 0 "
                    "THEN SUBSTR(description, INSTR(description, 'peers: ') + 7) "
                    "WHEN INSTR(description, 'peer: ') > 0 "
                    "THEN SUBSTR(description, INSTR(description, 'peer: ') + 6) "
                    "ELSE '' END)"
                )
                latest_row = connection.execute(
                    "SELECT MAX(evidence_time) AS latest FROM evidence"
                ).fetchone()
                full_total = detection_total(connection, "evidence")
                latest = float(latest_row["latest"] or 0)
                start, end, range_name = self._time_bounds(query, latest)
                start = self._scoped_start(query, start)
                sort_key, sort_expression, direction = self._sort_spec(
                    query,
                    {
                        "time": "evidence_time",
                        "host": "LOWER(COALESCE(profile_ip, ''))",
                        "threat": threat_expression,
                        "type": "LOWER(COALESCE(evidence_type, ''))",
                        "module": f"LOWER({module_expression})",
                        "reporters": reporter_expression,
                        "handling": whitelist_expression,
                        "description": "LOWER(COALESCE(description, ''))",
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
                review_status = self._query_value(query, "review", "all")
                if review_status in {
                    "unreviewed",
                    "in_review",
                    "true_positive",
                    "false_positive",
                    "expected_behavior",
                    "inconclusive",
                }:
                    clauses.append(
                        self._review_clause(
                            connection, "evidence", review_status, "evidence"
                        )
                    )
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
                        "LOWER(COALESCE(strftime('%d/%m/%Y, %H:%M:%S', "
                        "evidence_time, 'unixepoch'), '')) LIKE ? OR "
                        "LOWER(COALESCE(profile_ip, '')) LIKE ? OR "
                        "LOWER(COALESCE(timewindow, '')) LIKE ? OR "
                        "LOWER(COALESCE(threat_level, '')) LIKE ? OR "
                        "LOWER(COALESCE(evidence_type, '')) LIKE ? OR "
                        "LOWER(REPLACE(COALESCE(evidence_type, ''), '_', ' ')) LIKE ? OR "
                        "LOWER(COALESCE(description, '')) LIKE ? OR "
                        "LOWER(COALESCE(CAST(confidence AS TEXT), '')) LIKE ? OR "
                        "LOWER(printf('%d%%', CAST(ROUND(confidence * 100) AS INTEGER))) LIKE ? OR "
                        "LOWER(COALESCE(data, '')) LIKE ? OR "
                        f"LOWER(COALESCE({module_expression}, '')) LIKE ? OR "
                        f"LOWER(CASE WHEN {whitelist_expression} > 0 "
                        "THEN 'excluded' ELSE 'scored' END) LIKE ? OR "
                        f"CAST({flow_expression} AS TEXT) LIKE ? OR "
                        f"CAST({alert_expression} AS TEXT) LIKE ? OR "
                        f"LOWER(CASE WHEN {alert_expression} = 0 "
                        "THEN 'none' ELSE 'linked' END) LIKE ? OR "
                        "EXISTS (SELECT 1 FROM evidence_flows ef "
                        "WHERE ef.evidence_id = evidence.evidence_id "
                        "AND LOWER(ef.uid) LIKE ?) OR "
                        "EXISTS (SELECT 1 FROM alert_evidence ae "
                        "WHERE ae.evidence_id = evidence.evidence_id "
                        "AND LOWER(ae.alert_id) LIKE ?))"
                    )
                    term = f"%{search}%"
                    params.extend([term] * 19)
                if profiles:
                    placeholders = ",".join("?" for _ in profiles)
                    clauses.append(f"profile_ip IN ({placeholders})")
                    params.extend(profiles)
                if device_id:
                    clauses.append("device_key(profile_ip) = ?")
                    params.append(device_id)
                if evidence_type:
                    clauses.append("evidence_type = ?")
                    params.append(evidence_type)
                if threat:
                    minimum = threat.removesuffix("_or_more")
                    if (
                        threat.endswith("_or_more")
                        and minimum in EVIDENCE_THREAT_RANKS
                    ):
                        clauses.append(f"{threat_expression} >= ?")
                        params.append(EVIDENCE_THREAT_RANKS[minimum])
                    else:
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
                if self._query_value(query, "scored_only") == "1":
                    clauses.append(f"COALESCE({score_expression}, 0) > 0")
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
                minimum = threat.removesuffix("_or_more")
                if (
                    threat.endswith("_or_more")
                    and minimum in EVIDENCE_THREAT_RANKS
                ):
                    records = [
                        item
                        for item in records
                        if EVIDENCE_THREAT_RANKS.get(
                            str(item.get("threat_level", "")).lower(), 0
                        )
                        >= EVIDENCE_THREAT_RANKS[minimum]
                    ]
                else:
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
        if self._query_value(query, "device") == "1":
            self._annotate_devices(items, "profile_ip")
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
        if getattr(self, "archive_mode", False):
            return self._archive_alert_evidence(alert_id, maximum)
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

    def _archive_alert_evidence(
        self, alert_id: str, maximum: int
    ) -> List[Dict[str, Any]]:
        """Resolve an archived alert across all retained segments in bounded pages.

        Parameters:
            alert_id: Alert in the selected archive.
            maximum: Maximum evidence records returned.

        Returns:
            Newest linked evidence available in retained storage.
        """
        paths = [
            self.sqlite_path,
            self.output_dir / "databases" / "flows.sqlite",
        ]
        paths.extend(
            path
            for path in (self.output_dir / "databases" / "archives").glob(
                ARCHIVE_GLOB
            )
            if ARCHIVE_NAME.fullmatch(path.name)
            and path != self.sqlite_path
            and not path.is_symlink()
        )
        found: Dict[str, Dict[str, Any]] = {}
        for path in paths:
            if not path.is_file():
                continue
            try:
                with sqlite3.connect(
                    f"file:{path}?mode=ro", uri=True, timeout=1
                ) as source:
                    source.row_factory = sqlite3.Row
                    source.execute(
                        "ATTACH DATABASE ? AS selected",
                        (f"file:{self.sqlite_path}?mode=ro",),
                    )
                    rows = source.execute(
                        "SELECT e.* FROM main.evidence e JOIN selected.alert_evidence ae "
                        "ON ae.evidence_id=e.evidence_id WHERE ae.alert_id=? "
                        "ORDER BY e.evidence_time DESC,e.evidence_id DESC LIMIT ?",
                        (alert_id, maximum),
                    ).fetchall()
                    for row in rows:
                        if row["evidence_id"] not in found:
                            item = self._durable_evidence_row(source, row)
                            found[item["id"]] = item
                    found = dict(
                        sorted(
                            found.items(),
                            key=lambda entry: (
                                entry[1]["timestamp"],
                                entry[0],
                            ),
                            reverse=True,
                        )[:maximum]
                    )
            except (FileNotFoundError, sqlite3.OperationalError):
                continue
        items = list(found.values())
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

    def _grouped_alerts_fast(
        self, query: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """Group hosts before looking up linked severity in indexed batches.

        Parameters:
            query: Alert filters, sort order, and cursor.

        Returns:
            One page of host aggregates and its pagination metadata.
        """
        limit = self._limit(query)
        search = self._query_value(query, "search").lower()
        profile = self._query_value(query, "profile")
        cursor = self._decode_cursor(self._query_value(query, "cursor"))
        sort_key, _, direction = self._sort_spec(
            query,
            {
                key: key
                for key in (
                    "time",
                    "host",
                    "threat",
                    "label",
                    "alerts",
                    "evidence",
                    "score",
                )
            },
            "time",
        )
        with self._connect_sqlite() as connection:
            connection.execute("BEGIN")
            score = self._detector_score_expression(connection, "alerts")
            latest = float(
                connection.execute(
                    "SELECT MAX(CAST(alert_time AS REAL)) FROM alerts"
                ).fetchone()[0]
                or 0
            )
            start, end, range_name = self._time_bounds(query, latest)
            start = self._scoped_start(query, start)
            full_total = detection_total(connection, "alerts")
            open_total = full_total - (
                int(
                    connection.execute(
                        "SELECT COUNT(*) FROM alert_reviews WHERE status = 'resolved'"
                    ).fetchone()[0]
                )
                if self._table_exists(connection, "alert_reviews")
                else 0
            )
            clauses = ["1 = 1"]
            params: List[Any] = []
            review_status = self._query_value(query, "review", "open")
            if review_status not in {
                "open",
                "active",
                "in_review",
                "resolved",
                "all",
            }:
                review_status = "open"
            if review_status != "all":
                clauses.append(
                    self._review_clause(
                        connection, "alert", review_status, "a"
                    )
                )
            if start is not None:
                clauses.append("CAST(a.alert_time AS REAL) >= ?")
                params.append(start)
            if end is not None:
                clauses.append("CAST(a.alert_time AS REAL) <= ?")
                params.append(end)
            if search:
                clauses.append(
                    "(LOWER(a.alert_id) LIKE ? OR LOWER(a.ip_alerted) "
                    "LIKE ? OR LOWER(a.label) LIKE ?)"
                )
                params.extend([f"%{search}%"] * 3)
            if profile:
                clauses.append("a.ip_alerted = ?")
                params.append(profile)
            where = " AND ".join(clauses)
            rows = [
                dict(row)
                for row in connection.execute(
                    "SELECT a.ip_alerted, a.ip_alerted AS group_id, "
                    "MAX(CAST(a.alert_time AS REAL)) AS alert_time, "
                    "MIN(CAST(a.alert_time AS REAL)) AS first_alert_time, "
                    "COUNT(*) AS alert_count, "
                    "SUM((SELECT COUNT(*) FROM alert_evidence ae "
                    "WHERE ae.alert_id = a.alert_id)) AS evidence_count, "
                    f"MAX({score}) AS alert_score, "
                    "GROUP_CONCAT(DISTINCT COALESCE(a.label, '')) AS labels "
                    f"FROM alerts a WHERE {where} GROUP BY a.ip_alerted",
                    params,
                ).fetchall()
            ]
            ranks: Dict[str, int] = {}
            if rows:
                upper_levels = [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT DISTINCT threat_level FROM evidence "
                        "WHERE threat_level IS NOT NULL"
                    ).fetchall()
                    if str(row[0]).lower() in {"critical", "high", "medium"}
                ]
                if upper_levels:
                    placeholders = ",".join("?" for _ in upper_levels)
                    upper_rows = connection.execute(
                        "SELECT a.ip_alerted, MAX(CASE LOWER(e.threat_level) "
                        "WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
                        "WHEN 'medium' THEN 2 ELSE 0 END) AS threat_rank "
                        "FROM evidence e JOIN alert_evidence ae "
                        "ON ae.evidence_id = e.evidence_id JOIN alerts a "
                        "ON a.alert_id = ae.alert_id "
                        f"WHERE e.threat_level IN ({placeholders}) "
                        f"AND {where} GROUP BY a.ip_alerted",
                        (*upper_levels, *params),
                    ).fetchall()
                    ranks.update(
                        {
                            str(row["ip_alerted"]): int(row["threat_rank"])
                            for row in upper_rows
                        }
                    )
                remaining = [
                    str(row["ip_alerted"])
                    for row in rows
                    if str(row["ip_alerted"]) not in ranks
                ]
                if remaining:
                    placeholders = ",".join("?" for _ in remaining)
                    lower_rows = connection.execute(
                        "SELECT a.ip_alerted, MAX(CASE LOWER(e.threat_level) "
                        "WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
                        "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 "
                        "ELSE 0 END) AS threat_rank "
                        "FROM alerts a JOIN alert_evidence ae "
                        "ON ae.alert_id = a.alert_id JOIN evidence e "
                        "ON e.evidence_id = ae.evidence_id "
                        f"WHERE {where} AND a.ip_alerted IN "
                        f"({placeholders}) GROUP BY a.ip_alerted",
                        (*params, *remaining),
                    ).fetchall()
                    ranks.update(
                        {
                            str(row["ip_alerted"]): int(row["threat_rank"])
                            for row in lower_rows
                        }
                    )
        for row in rows:
            row["threat_rank"] = ranks.get(str(row["ip_alerted"]), 0)

        def sort_value(row: Dict[str, Any]) -> Any:
            """Return the selected sort value for a grouped host.

            Parameters:
                row: One grouped alert host.

            Returns:
                Comparable number or normalized text.
            """
            field = {
                "time": "alert_time",
                "host": "ip_alerted",
                "threat": "threat_rank",
                "label": "labels",
                "alerts": "alert_count",
                "evidence": "evidence_count",
                "score": "alert_score",
            }[sort_key]
            value = row[field]
            return (
                str(value or "").lower()
                if sort_key in {"host", "label"}
                else float(value or 0)
            )

        rows.sort(
            key=lambda row: (sort_value(row), str(row["group_id"])),
            reverse=direction == "DESC",
        )
        total = len(rows)
        matching_total = sum(int(row["alert_count"] or 0) for row in rows)
        if cursor:
            rows = [
                row
                for row in rows
                if (
                    (sort_value(row), str(row["group_id"]))
                    > (cursor[0], cursor[1])
                    if direction == "ASC"
                    else (sort_value(row), str(row["group_id"]))
                    < (cursor[0], cursor[1])
                )
            ]
        page = rows[:limit]
        items = []
        for row in page:
            item = dict(row)
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
            self._encode_cursor(
                sort_value(page[-1]), str(page[-1]["group_id"])
            )
            if len(rows) > limit and page
            else None
        )
        return {
            "items": items,
            "total": total,
            "matching_total": matching_total,
            "full_total": full_total,
            "open_total": open_total,
            "page_size": len(items),
            "next_cursor": next_cursor,
            "range": range_name,
            "sort": sort_key,
            "order": direction.lower(),
            "group": "host",
            "latest_alert_time": latest,
        }

    def _grouped_alerts(self, query: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        Return alerts aggregated by affected host.

        Parameters:
            query: Request filters, sort, range, and cursor values.

        Returns:
            Bounded host aggregate page with raw durable alert total.
        """
        device_view = self._query_value(query, "device") == "1"
        if not device_view and self._query_value(query, "threat").lower() in {
            "",
            "info_or_more",
        }:
            return self._grouped_alerts_fast(query)
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
            self._register_device_key(connection, device_view)
            score_expression = self._detector_score_expression(
                connection, "alerts"
            )
            latest_row = connection.execute(
                "SELECT MAX(CAST(alert_time AS REAL)) AS latest FROM alerts"
            ).fetchone()
            latest = float(latest_row["latest"] or 0)
            start, end, range_name = self._time_bounds(query, latest)
            start = self._scoped_start(query, start)
            full_total = detection_total(connection, "alerts")
            open_total = full_total - (
                int(
                    connection.execute(
                        "SELECT COUNT(*) FROM alert_reviews WHERE status = 'resolved'"
                    ).fetchone()[0]
                )
                if self._table_exists(connection, "alert_reviews")
                else 0
            )
            clauses = ["1 = 1"]
            params: List[Any] = []
            review_status = self._query_value(query, "review", "open")
            if review_status not in {
                "open",
                "active",
                "in_review",
                "resolved",
                "all",
            }:
                review_status = "open"
            if review_status != "all":
                clauses.append(
                    self._review_clause(
                        connection, "alert", review_status, "alerts"
                    )
                )
            if start is not None:
                clauses.append("CAST(alert_time AS REAL) >= ?")
                params.append(start)
            if end is not None:
                clauses.append("CAST(alert_time AS REAL) <= ?")
                params.append(end)
            if search:
                clauses.append(
                    "(LOWER(alert_id) LIKE ? OR LOWER(ip_alerted) LIKE ? "
                    "OR LOWER(label) LIKE ? OR "
                    "EXISTS (SELECT 1 FROM alert_evidence ae JOIN evidence e "
                    "ON e.evidence_id = ae.evidence_id "
                    "WHERE ae.alert_id = alerts.alert_id AND "
                    "(LOWER(e.evidence_type) LIKE ? OR "
                    "LOWER(REPLACE(e.evidence_type, '_', ' ')) LIKE ? OR "
                    "LOWER(e.description) LIKE ?)))"
                )
                term = f"%{search}%"
                params.extend([term] * 6)
            if profile:
                clauses.append(
                    "device_key(ip_alerted) = ?"
                    if device_view
                    else "ip_alerted = ?"
                )
                params.append(profile)
            if threat:
                minimum = threat.removesuffix("_or_more")
                threat_rank = {
                    "info": 0,
                    "low": 1,
                    "medium": 2,
                    "high": 3,
                    "critical": 4,
                }.get(minimum)
                if threat_rank is not None:
                    operator = ">=" if threat.endswith("_or_more") else "="
                    clauses.append(f"{threat_expression} {operator} ?")
                    params.append(threat_rank)
            host_group = (
                "device_key(ip_alerted)" if device_view else "ip_alerted"
            )
            grouped_sql = (
                f"SELECT MIN(ip_alerted) AS ip_alerted, {host_group} AS group_id, "
                "GROUP_CONCAT(DISTINCT ip_alerted) AS device_ips, "
                "MAX(CAST(alert_time AS REAL)) AS alert_time, "
                "MIN(CAST(alert_time AS REAL)) AS first_alert_time, "
                f"MAX({threat_expression}) AS threat_rank, "
                "COUNT(*) AS alert_count, "
                f"SUM({evidence_expression}) AS evidence_count, "
                f"MAX({score_expression}) AS alert_score, "
                "GROUP_CONCAT(DISTINCT COALESCE(label, '')) AS labels "
                f"FROM alerts WHERE {' AND '.join(clauses)} GROUP BY {host_group}"
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
            totals = connection.execute(
                "SELECT COUNT(*) AS count, "
                "COALESCE(SUM(alert_count), 0) AS matching_total "
                f"FROM ({grouped_sql})",
                params,
            ).fetchone()
            total = int(totals["count"])
            matching_total = int(totals["matching_total"])
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
            if device_view:
                item["device_id"] = item["id"]
                item["device_ips"] = str(item.get("device_ips") or "").split(
                    ","
                )
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
            "matching_total": matching_total,
            "full_total": full_total,
            "open_total": open_total,
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
        alert_id = self._query_value(query, "alert_id")
        if (
            not alert_id
            and self._query_value(query, "range") == "all"
            and self._query_value(query, "review") == "all"
            and self._query_value(query, "limit") == "1"
            and self._query_value(query, "details").lower() != "false"
            and re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                r"[0-9a-f]{4}-[0-9a-f]{12}",
                search,
            )
        ):
            alert_id = search
            search = ""
        threat = self._query_value(query, "threat").lower()
        profile = self._query_value(query, "profile")
        device_id = self._query_value(query, "device_id")
        include_details = (
            self._query_value(query, "details").lower() != "false"
        )
        include_summary = self._query_value(query, "summary") == "1"
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
            self._register_device_key(connection, bool(device_id))
            score_expression = self._detector_score_expression(
                connection, "alerts"
            )
            latest_row = connection.execute(
                "SELECT MAX(CAST(alert_time AS REAL)) AS latest FROM alerts"
            ).fetchone()
            full_total = detection_total(connection, "alerts")
            open_total = full_total - (
                int(
                    connection.execute(
                        "SELECT COUNT(*) FROM alert_reviews WHERE status = 'resolved'"
                    ).fetchone()[0]
                )
                if self._table_exists(connection, "alert_reviews")
                else 0
            )
            latest = float(latest_row["latest"] or 0)
            start, end, range_name = self._time_bounds(query, latest)
            start = self._scoped_start(query, start)
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
            if alert_id:
                clauses.append("alert_id = ?")
                params.append(alert_id)
            review_status = self._query_value(query, "review", "open")
            if review_status not in {
                "open",
                "active",
                "in_review",
                "resolved",
                "all",
            }:
                review_status = "open"
            if review_status != "all":
                clauses.append(
                    self._review_clause(
                        connection, "alert", review_status, "alerts"
                    )
                )
            if start is not None:
                clauses.append("CAST(alert_time AS REAL) >= ?")
                params.append(start)
            if end is not None:
                clauses.append("CAST(alert_time AS REAL) <= ?")
                params.append(end)
            if search:
                clauses.append(
                    "(LOWER(alert_id) LIKE ? OR LOWER(ip_alerted) LIKE ? "
                    "OR LOWER(label) LIKE ? OR "
                    "EXISTS (SELECT 1 FROM alert_evidence ae JOIN evidence e "
                    "ON e.evidence_id = ae.evidence_id "
                    "WHERE ae.alert_id = alerts.alert_id AND "
                    "(LOWER(e.evidence_type) LIKE ? OR "
                    "LOWER(REPLACE(e.evidence_type, '_', ' ')) LIKE ? OR "
                    "LOWER(e.description) LIKE ?)))"
                )
                term = f"%{search}%"
                params.extend([term] * 6)
            if profile:
                clauses.append("ip_alerted = ?")
                params.append(profile)
            if device_id:
                clauses.append("device_key(ip_alerted) = ?")
                params.append(device_id)
            if threat:
                minimum = threat.removesuffix("_or_more")
                threat_rank = {
                    "info": 0,
                    "low": 1,
                    "medium": 2,
                    "high": 3,
                    "critical": 4,
                }.get(minimum)
                if threat_rank is not None:
                    operator = ">=" if threat.endswith("_or_more") else "="
                    clauses.append(f"{threat_expression} {operator} ?")
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
                if self._table_exists(connection, "alert_reviews"):
                    review = connection.execute(
                        "SELECT * FROM alert_reviews WHERE alert_id = ?",
                        (alert["alert_id"],),
                    ).fetchone()
                    if review:
                        alert.update(
                            {
                                "review_status": review["status"],
                                "review_note": review["note"],
                                "review_updated_at": review["updated_at"],
                                "review_verdict": (
                                    review["verdict"]
                                    if "verdict" in review.keys()
                                    else ""
                                ),
                            }
                        )
                alert.setdefault("review_status", "active")
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
                elif include_summary:
                    summary = connection.execute(
                        "SELECT e.evidence_type, e.description "
                        "FROM alert_evidence ae JOIN evidence e "
                        "ON e.evidence_id = ae.evidence_id "
                        "WHERE ae.alert_id = ? "
                        "ORDER BY e.evidence_time DESC LIMIT 1",
                        (alert["alert_id"],),
                    ).fetchone()
                    alert["evidence_type"] = (
                        str(summary["evidence_type"] or "") if summary else ""
                    )
                    alert["summary"] = (
                        str(summary["description"] or "")[:240]
                        if summary
                        else ""
                    )
                alert.update(self._ip_context_for_ip(str(alert["ip_alerted"])))
                items.append(alert)
            if include_summary and items:
                alert_ids = [str(item["alert_id"]) for item in items]
                placeholders = ",".join("?" for _ in alert_ids)
                types_by_alert: Dict[str, List[Dict[str, Any]]] = defaultdict(
                    list
                )
                for type_row in connection.execute(
                    "SELECT ae.alert_id, COALESCE(e.evidence_type, '') "
                    "AS evidence_type, COUNT(*) AS type_count "
                    "FROM alert_evidence ae JOIN evidence e "
                    "ON e.evidence_id = ae.evidence_id "
                    f"WHERE ae.alert_id IN ({placeholders}) "
                    "GROUP BY ae.alert_id, e.evidence_type "
                    "ORDER BY type_count DESC, evidence_type",
                    alert_ids,
                ):
                    types_by_alert[str(type_row["alert_id"])].append(
                        {
                            "type": str(
                                type_row["evidence_type"] or "UNKNOWN"
                            ),
                            "count": int(type_row["type_count"]),
                        }
                    )
                for alert in items:
                    alert["evidence_types"] = types_by_alert[
                        str(alert["alert_id"])
                    ]
                if self._query_value(query, "modules") == "1":
                    evidence_columns = {
                        str(column[1])
                        for column in connection.execute(
                            "PRAGMA table_info(evidence)"
                        )
                    }
                    source_column = (
                        "e.source_module"
                        if "source_module" in evidence_columns
                        else "''"
                    )
                    modules_by_alert: Dict[str, set[str]] = defaultdict(set)
                    for module_row in connection.execute(
                        "SELECT DISTINCT ae.alert_id, e.evidence_type, "
                        f"{source_column} AS source_module "
                        "FROM alert_evidence ae JOIN evidence e "
                        "ON e.evidence_id = ae.evidence_id "
                        f"WHERE ae.alert_id IN ({placeholders})",
                        alert_ids,
                    ):
                        modules_by_alert[str(module_row["alert_id"])].add(
                            self._evidence_source_module(
                                module_row["source_module"],
                                str(module_row["evidence_type"] or ""),
                            )
                        )
                    for alert in items:
                        alert["evidence_modules"] = [
                            {"module": module}
                            for module in sorted(
                                modules_by_alert[str(alert["alert_id"])]
                            )
                        ]
            self._annotate_detection_networks(
                items, "ip_alerted", "alert_time"
            )
            if self._query_value(query, "device") == "1":
                self._annotate_devices(items, "ip_alerted")
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
            "open_total": open_total,
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
                        return [
                            str(row["uid"]).strip()
                            for row in rows
                            if str(row["uid"]).strip()
                        ]
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

    def flow_details(
        self, uid: str, query: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """Read one connection and a bounded page of its protocol records.

        Parameters:
            uid: Exact flow UID selected in the host table.
            query: Optional protocol page limit and last row-ID cursor.

        Returns:
            Flow group with protocol pagination and the retained record count.
        """
        try:
            limit = max(
                1, min(int(self._query_value(query, "limit") or 20), 100)
            )
            after = max(0, int(self._query_value(query, "cursor") or 0))
        except ValueError:
            limit, after = 20, 0
        result = {
            "uid": uid,
            "network_flow": None,
            "protocol_flows": [],
            "protocol_flow_total": 0,
            "next_cursor": None,
        }
        with self._connect_sqlite() as connection:
            if self._table_exists(connection, "flows"):
                row = connection.execute(
                    "SELECT * FROM flows WHERE uid=? LIMIT 1", (uid,)
                ).fetchone()
                if row:
                    record = dict(row)
                    record["flow"] = self._loads(record.get("flow"), {})
                    record["table"] = "flows"
                    result["network_flow"] = record
            if self._table_exists(connection, "altflows"):
                result["protocol_flow_total"] = connection.execute(
                    "SELECT COUNT(*) FROM altflows WHERE uid=?", (uid,)
                ).fetchone()[0]
                rows = connection.execute(
                    "SELECT rowid AS protocol_rowid, * FROM altflows "
                    "WHERE uid=? AND rowid>? ORDER BY rowid LIMIT ?",
                    (uid, after, limit + 1),
                ).fetchall()
                if len(rows) > limit:
                    result["next_cursor"] = str(
                        rows[limit - 1]["protocol_rowid"]
                    )
                for row in rows[:limit]:
                    record = dict(row)
                    record.pop("protocol_rowid", None)
                    record["flow"] = self._loads(record.get("flow"), {})
                    record["table"] = "altflows"
                    result["protocol_flows"].append(record)
        return result

    def flows_for_evidence(
        self, evidence_id: str, query: Optional[Dict[str, List[str]]] = None
    ) -> Dict[str, Any]:
        """Return a bounded page of triggering flows and related protocols.

        Parameters:
            evidence_id: Durable evidence identifier.
            query: Optional page limit and last UID cursor.

        Returns:
            Linked flow groups, counts, and the next UID cursor.
        """
        query = query or {}
        try:
            limit = max(
                1, min(int(self._query_value(query, "limit") or 20), 100)
            )
        except ValueError:
            limit = 20
        after = self._query_value(query, "cursor")[:256]
        total_uids = 0
        durable_found = False
        uids = []
        with self._connect_sqlite() as connection:
            if self._table_exists(connection, "evidence_flows"):
                total_uids = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM evidence_flows WHERE evidence_id=? AND TRIM(uid) <> ''",
                        (evidence_id,),
                    ).fetchone()[0]
                )
                uids = [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT uid FROM evidence_flows WHERE evidence_id=? "
                        "AND uid > ? AND TRIM(uid) <> '' ORDER BY uid LIMIT ?",
                        (evidence_id, after, limit + 1),
                    )
                ]
            if not total_uids and self._table_exists(connection, "evidence"):
                row = connection.execute(
                    "SELECT data FROM evidence WHERE evidence_id=?",
                    (evidence_id,),
                ).fetchone()
                if row:
                    durable_found = True
                    uids = self._id_list(
                        self._loads(row[0], {}).get("uid", [])
                    )
        if not total_uids:
            if not uids and not durable_found:
                uids = self._flow_uids_for_evidence(evidence_id)
            if not uids and not durable_found:
                for item in self._redis_evidence():
                    if item["id"] == evidence_id:
                        uids = self._id_list(item.get("uid", []))
                        break
            uids = sorted(
                {str(uid).strip() for uid in uids if str(uid).strip()}
            )
            total_uids = len(uids)
            uids = [uid for uid in uids if uid > after][: limit + 1]
        has_more = len(uids) > limit
        page_uids = uids[:limit]
        next_cursor = page_uids[-1] if has_more else None
        bounded_uids = list(
            dict.fromkeys(uid.strip() for uid in page_uids if uid.strip())
        )
        if not bounded_uids:
            return {
                "items": [],
                "total": 0,
                "linked_uid_count": total_uids,
                "unavailable_flow_count": 0,
                "network_flow_total": 0,
                "protocol_flow_total": 0,
                "recovered_flow_count": 0,
                "page_size": 0,
                "next_cursor": None,
            }
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
            "linked_uid_count": total_uids,
            "unavailable_flow_count": len(bounded_uids) - len(items),
            "network_flow_total": network_flow_total,
            "protocol_flow_total": protocol_flow_total,
            "recovered_flow_count": recovered_flow_count,
            "page_size": len(items),
            "next_cursor": next_cursor,
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
                "hostname": fields.get("host_name")
                or result.get("hostname", ""),
                "mac": fields.get("MAC") or result.get("mac", ""),
                "mac_vendor": fields.get("MAC_vendor")
                or result.get("mac_vendor", ""),
                "threat_level": fields.get("threat_level", "info"),
                "max_threat_level": fields.get("max_threat_level", "info"),
                "dns": self._loads(self.redis.hget("DNSresolution", ip), {}),
                "live": True,
            }
        )
        return result

    def _restore_host_identities(
        self,
        hosts: List[Dict[str, Any]],
        query: Dict[str, List[str]],
        live_identity: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        """Restore durable identity after transient Redis fields expire.

        Parameters:
            hosts: Host records being displayed or exported.
            query: Selected capture network and view filters.
            live_identity: Optional freshly read profile fields to verify MACs.
        """
        stored = HostProfileStore.identities_for_ips(
            getattr(
                self,
                "host_profiles_path",
                Path("permanent/host_profiles/hosts.sqlite"),
            ),
            [host["ip"] for host in hosts],
            self._annotation_networks(query),
            {
                ip: (record.get("fields") or {}).get("MAC", "")
                for ip, record in (live_identity or {}).items()
            },
        )
        for host in hosts:
            identity = stored.get(host["ip"], {})
            fields = (live_identity or {}).get(host["ip"], {}).get(
                "fields"
            ) or {}
            if identity.get("identity_changed") or (
                identity.get("mac")
                and host.get("mac")
                and identity["mac"]
                != HostProfileStore._usable_mac(host["mac"])
            ):
                host["hostname"] = fields.get("host_name", "")
                host["dns_name"] = ""
                host["dns_name_source"] = ""
            if identity.get("name"):
                host["hostname"] = identity["name"]
                host["hostname_source"] = identity["source"]
            if identity.get("mac"):
                host["mac"] = identity["mac"]
            host["mac_address_type"] = classify_mac(host.get("mac"))

    def _annotation_networks(self, query: Dict[str, List[str]]) -> List[str]:
        """Use the selected capture network when resolving saved private host names.

        Parameters:
            query: Current pane's network filter.

        Returns:
            Selected private-network keys, or an empty list for all history.
        """
        if self._query_value(query, "network") != "current":
            return []
        network_id = self._current_header_network().get("network_id", "")
        return [network_id] if network_id else []

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
            self._annotation_networks(query),
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
                pipeline.hget(f"profile_{ip}", "MAC")
            live_identity = pipeline.execute()
        except (AttributeError, redis.RedisError):
            live_identity = []

        stored = HostProfileStore.identities_for_ips(
            getattr(
                self,
                "host_profiles_path",
                Path("permanent/host_profiles/hosts.sqlite"),
            ),
            ips,
            self._annotation_networks(query),
            {
                ip: live_identity[index * 4 + 3]
                for index, ip in enumerate(ips)
                if index * 4 + 3 < len(live_identity)
            },
        )
        names: Dict[str, Dict[str, str]] = {}
        for index, ip in enumerate(ips):
            snapshot = snapshots.get(ip, {})
            identity_changed = bool(
                stored.get(ip, {}).get("identity_changed")
            ) or bool(
                stored.get(ip, {}).get("mac")
                and snapshot.get("mac")
                and stored[ip]["mac"]
                != HostProfileStore._usable_mac(snapshot["mac"])
            )
            if identity_changed:
                snapshot = {}
            annotation = annotations.get(ip, {})
            live_name = (
                live_identity[index * 4]
                if index * 4 < len(live_identity)
                else ""
            )
            if identity_changed:
                live_name = ""
            name = str(annotation.get("name") or "")
            source = "User name" if name else ""
            if not name and stored.get(ip, {}).get("name"):
                name = stored[ip]["name"]
                source = stored[ip]["source"]
            if not name:
                name = str(live_name or snapshot.get("hostname") or "")
                source = "Hostname" if name else ""
            if not name and not identity_changed:
                live_dns = (
                    live_identity[index * 4 + 1]
                    if index * 4 + 1 < len(live_identity)
                    else None
                )
                dns = self._loads(live_dns, {}) or snapshot.get("dns") or {}
                domains = (
                    dns.get("domains", []) if isinstance(dns, dict) else []
                )
                if isinstance(domains, list) and domains:
                    name = str(domains[0])
                    source = "DNS"
            if (
                not name
                and not identity_changed
                and getattr(self, "cache", None) is not None
            ):
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
                    live_identity[index * 4 + 2]
                    if index * 4 + 2 < len(live_identity)
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

    def _host_ips(
        self, ip: str, query: Optional[Dict[str, List[str]]] = None
    ) -> List[str]:
        """Return this profile or the local MAC-matched device profiles.

        Parameters:
            ip: Profile IP selected in the host workspace.
            query: Optional request that enables verified device grouping.

        Returns:
            IPs suitable for parameterized SQL predicates.
        """
        if self._query_value(query or {}, "device") == "1":
            keys = self._device_key_map()
            key = keys.get(ip)
            if key:
                members = [
                    ip,
                    *sorted(
                        address
                        for address, device in keys.items()
                        if device == key and address != ip
                    ),
                ]
                network_start = self._scoped_start(query or {}, None)
                if network_start is not None:
                    activity = self._host_activity_times(members)
                    members = [
                        address
                        for address in members
                        if activity.get(address, 0) >= network_start
                    ]
                return members or [ip]
        return [ip]

    def _device_key_map(self) -> Dict[str, str]:
        """Map local profiles and OS-verified own addresses to a MAC identity.

        Returns:
            Profile IPs mapped to a device key; ambiguous MACs stay separate.
        """
        try:
            with connect_history(
                self.history_path, read_only=True
            ) as connection:
                rows = connection.execute(
                    "SELECT ip, json_extract(data, '$.mac') AS mac, "
                    "json_extract(data, '$.scope') AS scope FROM host_snapshots"
                ).fetchall()
        except (OSError, sqlite3.Error):
            return {}
        candidates: Dict[str, List[str]] = defaultdict(list)
        for row in rows:
            ip = str(row["ip"] or "")
            mac = str(row["mac"] or "").lower().replace("-", ":")
            if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                continue
            if mac in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
                continue
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if not (address.is_private or address.is_link_local):
                continue
            if address.is_multicast or address.is_unspecified:
                continue
            if str(row["scope"] or "local") != "local":
                continue
            candidates[mac].append(ip)
        keys = {
            ip: f"mac:{mac}"
            for mac, ips in candidates.items()
            if 1 < len(ips) <= 16
            for ip in ips
        }
        try:
            analysis = self.redis.hgetall("analysis")
            if analysis.get("input_type") != "interface" or analysis.get(
                "analysis_end"
            ):
                return keys
            known_ips = {str(row["ip"]) for row in rows}
            interfaces = psutil.net_if_addrs()
            for name in str(analysis.get("interface") or "").split(","):
                addresses = interfaces.get(name.strip(), [])
                mac = next(
                    (
                        HostProfileStore._usable_mac(entry.address)
                        for entry in addresses
                        if entry.family == psutil.AF_LINK
                    ),
                    "",
                )
                if not mac:
                    continue
                for entry in addresses:
                    if entry.family not in (socket.AF_INET, socket.AF_INET6):
                        continue
                    ip = str(
                        ipaddress.ip_address(entry.address.split("%", 1)[0])
                    )
                    if ip in known_ips:
                        keys[ip] = f"mac:{mac}"
        except (AttributeError, OSError, ValueError, redis.RedisError):
            pass
        return keys

    def _register_device_key(
        self, connection: sqlite3.Connection, enabled: bool
    ) -> Dict[str, str]:
        """Expose verified MAC grouping to one SQLite request.

        Parameters:
            connection: SQLite connection used for the request.
            enabled: Whether this request uses device grouping.

        Returns:
            Profile IPs mapped to their device keys.
        """
        keys = self._device_key_map() if enabled else {}
        connection.create_function(
            "device_key",
            1,
            lambda ip: keys.get(str(ip), str(ip)),
            deterministic=True,
        )
        return keys

    def _annotate_devices(
        self, items: List[Dict[str, Any]], ip_field: str
    ) -> None:
        """Attach a page record's device key and member addresses.

        Parameters:
            items: One bounded alert or evidence page.
            ip_field: Field holding the original profile IP.
        """
        keys = self._device_key_map()
        members: Dict[str, List[str]] = defaultdict(list)
        for ip, key in keys.items():
            members[key].append(ip)
        for item in items:
            ip = str(item.get(ip_field) or "")
            key = keys.get(ip, ip)
            item["device_id"] = key
            item["device_ips"] = sorted(members.get(key, [ip]))

    def _host_last_seen_expression(
        self, connection: sqlite3.Connection, current_network: bool
    ) -> str:
        """Use actual host activity as evidence of a current-network observation.

        Parameters:
            connection: History connection with the run database attached as run_db.
            current_network: Whether cache refreshes must be excluded as proof.

        Returns:
            SQL activity timestamp for a host_snapshots row aliased as hs.
        """
        missing = "-1e300"
        flow_seen = (
            "MAX(COALESCE((SELECT MAX(event_time) FROM flow_index fi "
            f"WHERE fi.src_ip=hs.ip), {missing}), "
            "COALESCE((SELECT MAX(event_time) FROM flow_index fi "
            f"WHERE fi.dst_ip=hs.ip), {missing}))"
        )
        if not current_network:
            return f"COALESCE(NULLIF({flow_seen}, {missing}), hs.observed_at)"
        capture = self._current_header_network()
        run_name = (
            self._network_run_name() if getattr(self, "redis", None) else ""
        )
        sightings = HostProfileStore.observation_times(
            getattr(
                self,
                "host_profiles_path",
                Path("permanent/host_profiles/hosts.sqlite"),
            ),
            [
                capture.get("network_id", ""),
                f"run:{run_name}" if run_name else "",
            ],
        )
        connection.create_function(
            "host_observed_at", 1, lambda ip: sightings.get(ip)
        )
        expressions = [
            flow_seen,
            f"COALESCE(host_observed_at(hs.ip), {missing})",
        ]
        for table, ip_column, time_column in (
            ("evidence", "profile_ip", "evidence_time"),
            ("alerts", "ip_alerted", "alert_time"),
        ):
            columns = {
                str(row[1])
                for row in connection.execute(
                    f"PRAGMA run_db.table_info({table})"
                )
            }
            if {ip_column, time_column} <= columns:
                observed_time = (
                    time_column
                    if table == "evidence"
                    else f"CAST({time_column} AS REAL)"
                )
                expressions.append(
                    f"COALESCE((SELECT MAX({observed_time}) FROM run_db.{table} "
                    f"WHERE {ip_column}=hs.ip), {missing})"
                )
        return f"NULLIF(MAX({', '.join(expressions)}), {missing})"

    def _host_activity_times(self, ips: Sequence[str]) -> Dict[str, float]:
        """Read actual observations for a bounded set of host or device addresses.

        Parameters:
            ips: Selected addresses from the current inventory.

        Returns:
            Actual latest observation times, excluding Redis metadata refreshes.
        """
        if not ips:
            return {}
        with connect_history(self.history_path, read_only=True) as connection:
            connection.execute(
                "ATTACH DATABASE ? AS run_db", (str(self.sqlite_path),)
            )
            seen = self._host_last_seen_expression(connection, True)
            marks = ",".join("?" for _ in ips)
            return {
                str(row["ip"]): float(row["seen"] or 0)
                for row in connection.execute(
                    f"SELECT hs.ip, {seen} AS seen FROM host_snapshots hs WHERE hs.ip IN ({marks})",
                    ips,
                )
            }

    def _host_load(
        self, ip: str, query: Optional[Dict[str, List[str]]] = None
    ) -> Dict[str, Any]:
        """Read traffic totals for the selected identity and network scope."""
        ips = self._host_ips(ip, query)
        predicate, params = self._ip_predicate(ips)
        network_start = self._scoped_start(query or {}, None)
        if network_start is not None:
            predicate += " AND event_time >= ?"
            params.append(network_start)
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

    def _host_page_loads(
        self, ips: List[str], network_start: Optional[float] = None
    ) -> Dict[str, Dict[str, Any]]:
        """Aggregate page traffic in one indexed history query.

        Parameters:
            ips: IPs in the requested Hosts page.
            network_start: Optional earliest observation on this connection.

        Returns:
            Traffic totals keyed by IP.
        """
        if not ips:
            return {}
        placeholders = ",".join("?" for _ in ips)
        scope = " AND event_time >= ?" if network_start is not None else ""
        scoped_ips = [
            *ips,
            *([network_start] if network_start is not None else []),
        ]
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
                f"WHERE src_ip IN ({placeholders}){scope} UNION ALL "
                "SELECT dst_ip AS ip, bytes, packets, event_time, "
                "1 AS inbound_flows, 0 AS outbound_flows, "
                "bytes AS inbound_bytes, 0 AS outbound_bytes "
                f"FROM flow_index WHERE dst_ip IN ({placeholders}){scope} "
                "AND src_ip != dst_ip) GROUP BY ip",
                (*scoped_ips, *scoped_ips),
            ).fetchall()
        return {str(row["ip"]): dict(row) for row in rows}

    def _host_page_counts(
        self,
        ips: List[str],
        network_start: Optional[float] = None,
        query: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, Dict[str, int]]:
        """Count scoped evidence and alerts with batched indexed queries.

        Parameters:
            ips: IPs in the requested Hosts page.
            network_start: Optional earliest event in the current connection.
            query: Optional activity time, network and exclusion selections.

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
                    time_column = (
                        "evidence_time"
                        if table == "evidence"
                        else "CAST(alert_time AS REAL)"
                    )
                    start, end = network_start, None
                    columns = {
                        str(row[1])
                        for row in connection.execute(
                            f"PRAGMA table_info({table})"
                        )
                    }
                    if (
                        query is not None
                        and (
                            "evidence_time"
                            if table == "evidence"
                            else "alert_time"
                        )
                        in columns
                    ):
                        latest = connection.execute(
                            f"SELECT MAX({time_column}) FROM {table}"
                        ).fetchone()[0]
                        start, end, _ = self._time_bounds(query, latest)
                        start = self._scoped_start(query, start)
                    scope = (
                        f" AND {time_column} >= ?" if start is not None else ""
                    )
                    arguments = [*ips]
                    if start is not None:
                        arguments.append(start)
                    if end is not None:
                        scope += f" AND {time_column} <= ?"
                        arguments.append(end)
                    if (
                        table == "evidence"
                        and self._query_value(query or {}, "hide_excluded")
                        == "1"
                        and "whitelisted" in columns
                    ):
                        scope += " AND COALESCE(whitelisted, 0)=0"
                    evidence_hint = (
                        self._host_evidence_index_hint(
                            connection, start is not None
                        )
                        if table == "evidence"
                        else ""
                    )
                    reviews = (
                        " AND NOT EXISTS (SELECT 1 FROM alert_reviews ar "
                        "WHERE ar.alert_id=alerts.alert_id AND ar.status='resolved')"
                        if table == "alerts"
                        and self._table_exists(connection, "alert_reviews")
                        else ""
                    )
                    rows = connection.execute(
                        f"SELECT {column} AS ip, COUNT(*) AS count "
                        f"FROM {table}{evidence_hint} "
                        f"WHERE {column} IN ({placeholders})"
                        f"{scope}{reviews} "
                        f"GROUP BY {column}",
                        arguments,
                    ).fetchall()
                    for row in rows:
                        counts[str(row["ip"])][field] = int(row["count"])
        except sqlite3.Error:
            pass
        return counts

    @staticmethod
    def _host_evidence_index_hint(
        connection: sqlite3.Connection,
        bounded: bool = False,
    ) -> str:
        """Choose existing time or covering indexes for host finding aggregates.

        Parameters:
            connection: Read-only run database connection.
            bounded: Whether the request has an earliest evidence timestamp.

        Returns:
            An index hint, or an empty string for older database schemas.
        """
        indexes = {
            str(row[1])
            for row in connection.execute("PRAGMA index_list(evidence)")
        }
        preferred = (
            "evidence_time_cover_idx"
            if bounded and "evidence_time_cover_idx" in indexes
            else "evidence_group_cover_idx"
        )
        if preferred not in indexes and bounded:
            preferred = "evidence_profile_time_idx"
        return f" INDEXED BY {preferred}" if preferred in indexes else ""

    def _host_finding_stats(
        self,
        ips: List[str],
        query: Dict[str, List[str]],
    ) -> Dict[str, Dict[str, Any]]:
        """Summarize visible evidence using the detail table's range and scope.

        Parameters:
            ips: Host or MAC-matched device addresses.
            query: Time, network and exclusion selections.

        Returns:
            Evidence count, peak score and maximum threat rank for each IP.
        """
        result = {
            ip: {"evidence": 0, "peak": None, "threat_rank": -1} for ip in ips
        }
        if not ips:
            return result
        try:
            with self._connect_sqlite() as connection:
                columns = {
                    str(row[1])
                    for row in connection.execute(
                        "PRAGMA table_info(evidence)"
                    )
                }
                if "profile_ip" not in columns:
                    return result
                latest = (
                    connection.execute(
                        "SELECT MAX(evidence_time) FROM evidence"
                    ).fetchone()[0]
                    if "evidence_time" in columns
                    else 0
                )
                start, end, _ = self._time_bounds(
                    {"range": ["all"], **query}, latest
                )
                start = self._scoped_start(query, start)
                evidence_hint = self._host_evidence_index_hint(
                    connection, start is not None
                )
                scope = ""
                values = []
                if "evidence_time" in columns:
                    if start is not None:
                        scope += " AND evidence_time >= ?"
                        values.append(start)
                    if end is not None:
                        scope += " AND evidence_time <= ?"
                        values.append(end)
                if (
                    self._query_value(query, "hide_excluded") == "1"
                    and "whitelisted" in columns
                ):
                    scope += " AND COALESCE(whitelisted,0)=0"
                score = (
                    "accumulated_ratl"
                    if getattr(self, "score_mode", "ratl") == "ratl"
                    else "accumulated_threat_level"
                )
                score = score if score in columns else "NULL"
                threat = (
                    "CASE LOWER(threat_level) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
                    "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 WHEN 'info' THEN 0 ELSE -1 END"
                    if "threat_level" in columns
                    else "-1"
                )
                for offset in range(0, len(ips), 300):
                    batch = ips[offset : offset + 300]
                    marks = ",".join("?" for _ in batch)
                    for row in connection.execute(
                        f"SELECT profile_ip, COUNT(*) AS count, MAX({score}) AS peak, MAX({threat}) AS rank "
                        f"FROM evidence{evidence_hint} WHERE profile_ip IN ({marks}){scope} GROUP BY profile_ip",
                        (*batch, *values),
                    ):
                        result[str(row[0])] = {
                            "evidence": int(row[1]),
                            "peak": row[2],
                            "threat_rank": int(row[3]),
                        }
        except (OSError, sqlite3.Error):
            pass
        return result

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
        if self._query_value(query, "device") == "1":
            return self._devices(query)
        limit = self._limit(query)
        search = self._query_value(query, "search").lower()
        scope = self._query_value(query, "scope")
        threat = self._query_value(query, "threat").lower()
        alerts_only = self._query_value(query, "alerts_only") == "1"
        hide_excluded = self._query_value(query, "hide_excluded") == "1"
        network_start = self._scoped_start(query, None)
        annotation_networks = self._annotation_networks(query)
        network_start_sql = (
            str(min(network_start, 1e300)) if network_start is not None else ""
        )
        current_threats = (
            self._current_profile_threats()
            if threat and threat != "info_or_more"
            else {}
        )
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
            start = self._scoped_start(query, start)
            alert_network_clause = ""
            if "evidence_time" in evidence_columns:
                finding_latest = connection.execute(
                    "SELECT MAX(CAST(alert_time AS REAL)) FROM run_db.alerts"
                ).fetchone()[0]
                finding_start, finding_end, _ = self._time_bounds(
                    query, finding_latest
                )
                finding_start = self._scoped_start(query, finding_start)
                if finding_start is not None:
                    lower = min(finding_start, 1e300)
                    alert_network_clause += (
                        f" AND CAST(a.alert_time AS REAL) >= {lower}"
                    )
                if finding_end is not None:
                    alert_network_clause += (
                        f" AND CAST(a.alert_time AS REAL) <= {finding_end}"
                    )
            flow_network_clause = (
                f" AND fi.event_time >= {network_start_sql}"
                if network_start is not None
                else ""
            )
            flow_expression = (
                "(SELECT COUNT(*) FROM flow_index fi "
                "WHERE (fi.src_ip = hs.ip OR fi.dst_ip = hs.ip)"
                + flow_network_clause
                + ")"
            )
            byte_expression = (
                "(SELECT COALESCE(SUM(bytes), 0) FROM flow_index fi "
                "WHERE (fi.src_ip = hs.ip OR fi.dst_ip = hs.ip)"
                + flow_network_clause
                + ")"
            )
            candidate_ips = [
                str(row[0])
                for row in connection.execute("SELECT ip FROM host_snapshots")
            ]
            findings = self._host_finding_stats(
                candidate_ips,
                {
                    "range": [self._query_value(query, "range", "live")],
                    **query,
                },
            )
            connection.create_function(
                "host_evidence_count",
                1,
                lambda ip: findings[ip]["evidence"],
            )
            connection.create_function(
                "host_evidence_peak", 1, lambda ip: findings[ip]["peak"]
            )
            connection.create_function(
                "host_evidence_threat",
                1,
                lambda ip: findings[ip]["threat_rank"],
            )
            evidence_expression = "host_evidence_count(hs.ip)"
            has_alert_reviews = bool(
                connection.execute(
                    "SELECT 1 FROM run_db.sqlite_master WHERE type = 'table' "
                    "AND name = 'alert_reviews'"
                ).fetchone()
            )
            alert_expression = (
                "(SELECT COUNT(*) FROM run_db.alerts a WHERE a.ip_alerted = hs.ip "
                + alert_network_clause
                + (
                    " AND NOT EXISTS (SELECT 1 FROM run_db.alert_reviews ar "
                    "WHERE ar.alert_id = a.alert_id AND ar.status = 'resolved')"
                    if has_alert_reviews
                    else ""
                )
                + ")"
            )
            last_seen_expression = self._host_last_seen_expression(
                connection, network_start is not None
            )
            threat_expression = (
                "host_evidence_threat(hs.ip)"
                if "threat_level" in evidence_columns
                else "CASE LOWER(COALESCE(json_extract(hs.data, '$.max_threat_level'), "
                "'info')) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
                "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"
            )
            if "threat_level" in evidence_columns:
                current_threats = {}
            profile_path = getattr(
                self,
                "host_profiles_path",
                Path("permanent/host_profiles/hosts.sqlite"),
            )
            triage = HostProfileStore.triage_for_ips(
                profile_path, candidate_ips
            )
            saved_annotations = (
                HostProfileStore.annotations_for_ips(
                    profile_path, candidate_ips, annotation_networks
                )
                if search
                else {}
            )
            saved_identities = (
                HostProfileStore.identities_for_ips(
                    profile_path, candidate_ips, annotation_networks
                )
                if search
                else {}
            )
            connection.create_function(
                "host_status",
                1,
                lambda ip: triage.get(ip, {}).get("status", ""),
            )
            connection.create_function(
                "host_labels",
                1,
                lambda ip: ", ".join(triage.get(ip, {}).get("labels", [])),
            )
            connection.create_function(
                "host_annotation_search",
                1,
                lambda ip: json.dumps(
                    [
                        triage.get(ip, {}),
                        saved_annotations.get(ip, {}),
                        saved_identities.get(ip, {}),
                    ],
                    ensure_ascii=False,
                ).lower(),
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
                "host_evidence_peak(hs.ip)"
                if score_field in evidence_columns
                else "NULL"
            )
            peak_score_sort_expression = (
                f"COALESCE({peak_score_expression}, 0)"
            )
            ti_sort_values: Dict[str, str] = {}
            if (
                self._query_value(query, "sort") == "ti"
                and getattr(self, "cache", None) is not None
            ):
                candidate_ips = [
                    str(row["ip"])
                    for row in connection.execute(
                        "SELECT ip FROM host_snapshots"
                    ).fetchall()
                ]
                cache_pipe = self.cache.pipeline(transaction=False)
                for ip in candidate_ips:
                    cache_pipe.hget("IPsInfo:threatintelligence", ip)
                try:
                    cached = cache_pipe.execute()
                except redis.RedisError:
                    cached = []
                for ip, raw in zip(candidate_ips, cached):
                    record = self._loads(raw, {})
                    sources = (
                        record.get("source", [])
                        if isinstance(record, dict)
                        else []
                    )
                    if not isinstance(sources, (list, tuple)):
                        sources = [sources]
                    ti_sort_values[ip] = ", ".join(
                        sorted(
                            str(source).lower() for source in sources if source
                        )
                    )

            def ti_feed_sort(ip: str) -> str:
                """Return cached feed names for a host during SQL sorting.

                Parameters:
                    ip: Host address in the current history database.

                Returns:
                    Normalized feed names, or an empty string.
                """
                return ti_sort_values.get(str(ip), "")

            connection.create_function("ti_feed_sort", 1, ti_feed_sort)
            sort_key, sort_expression, direction = self._sort_spec(
                query,
                {
                    "ip": "LOWER(hs.ip)",
                    "review": "host_status(hs.ip)",
                    "labels": "LOWER(host_labels(hs.ip))",
                    "scope": "LOWER(COALESCE(json_extract(hs.data, '$.scope'), ''))",
                    "hostname": (
                        "LOWER(COALESCE(json_extract(hs.data, '$.hostname'), ''))"
                    ),
                    "ti": "ti_feed_sort(hs.ip)",
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
            if start is not None:
                clauses.append(f"{last_seen_expression} >= ?")
                params.append(start)
            if (
                range_name != "all" or network_start is not None
            ) and end is not None:
                clauses.append(f"{last_seen_expression} <= ?")
                params.append(end)
            if search:
                connection.create_function("mac_type", 1, classify_mac)
                clauses.append(
                    "(LOWER(hs.data) LIKE ? OR host_annotation_search(hs.ip) LIKE ? "
                    "OR REPLACE(mac_type(json_extract(hs.data, '$.mac')), '_', ' ') LIKE ?)"
                )
                params.extend([f"%{search}%"] * 3)
            review = self._query_value(query, "review")
            if review:
                clauses.append("host_status(hs.ip) = ?")
                params.append("" if review == "unmarked" else review)
            if scope:
                clauses.append("json_extract(hs.data, '$.scope') = ?")
                params.append(scope)
            if alerts_only:
                clauses.append(f"{alert_expression} > 0")
            if threat:
                levels = {
                    "info": 0,
                    "low": 1,
                    "medium": 2,
                    "high": 3,
                    "critical": 4,
                }
                minimum = levels.get(threat.removesuffix("_or_more"))
                operator = ">=" if threat.endswith("_or_more") else "="
                snapshot_threat = f"{threat_expression} {operator} ?"
                if current_threats:
                    live_ips = list(current_threats)
                    matching_ips = [
                        ip
                        for ip, level in current_threats.items()
                        if minimum is not None
                        and (
                            levels.get(level, 0) >= minimum
                            if operator == ">="
                            else levels.get(level, 0) == minimum
                        )
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
                        params.extend([*matching_ips, *live_ips, minimum])
                    else:
                        clauses.append(
                            f"(hs.ip NOT IN ({live_placeholders}) AND "
                            f"{snapshot_threat})"
                        )
                        params.extend([*live_ips, minimum])
                else:
                    clauses.append(snapshot_threat)
                    params.append(minimum)
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
                f"{last_seen_expression} AS activity_time, "
                f"{threat_expression} AS displayed_threat_rank, "
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
            loads = (
                self._host_page_loads(page_ips, network_start)
                if network_start is not None
                else self._host_page_loads(page_ips)
            )
            counts = self._host_page_counts(page_ips, query=query)
            identities = self._host_page_identity(page_ips)
        items: List[Dict[str, Any]] = []
        annotations = HostProfileStore.annotations_for_ips(
            getattr(
                self,
                "host_profiles_path",
                Path("permanent/host_profiles/hosts.sqlite"),
            ),
            page_ips,
            annotation_networks,
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
                            "hostname": fields.get("host_name")
                            or host.get("hostname", ""),
                            "mac": fields.get("MAC") or host.get("mac", ""),
                            "mac_vendor": fields.get("MAC_vendor")
                            or host.get("mac_vendor", ""),
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
            host["last_seen"] = float(row["activity_time"] or 0)
            if "threat_level" in evidence_columns:
                host["has_findings"] = row["displayed_threat_rank"] >= 0
                host["max_threat_level"] = (
                    self._threat_from_rank(row["displayed_threat_rank"])
                    if host["has_findings"]
                    else ""
                )
            host["user_status"] = triage.get(ip, {}).get("status", "")
            host["user_labels"] = triage.get(ip, {}).get("labels", [])
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
                host["load"] = (
                    self._host_load(ip, query)
                    if network_start is not None
                    else self._host_load(ip)
                )
                host.update(self._ip_context_for_ip(ip, host.get("dns")))
                if (
                    range_name == "all"
                    and network_start is None
                    and not hide_excluded
                ):
                    host["evidence_count"] = self._profile_evidence_count(ip)
                    host["alert_count"] = self._profile_alert_count(ip)
                else:
                    scoped_counts = self._host_page_counts([ip], query=query)
                    host["evidence_count"] = scoped_counts[ip]["evidence"]
                    host["alert_count"] = scoped_counts[ip]["alerts"]
            annotation = annotations.get(ip, {})
            host["user_name"] = annotation.get("name", "")
            host["user_note"] = annotation.get("note", "")
            host["mac_address_type"] = classify_mac(host.get("mac"))
            items.append(host)
        self._restore_host_identities(
            items, query, identities if fast_page else {}
        )
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

    def _devices(self, query: Dict[str, List[str]]) -> Dict[str, Any]:
        """Group local host profiles by verified MAC before filtering and paging.

        Parameters:
            query: Hosts filters, time range, sort, and cursor.

        Returns:
            A bounded page of device aggregates and their member addresses.
        """
        keys = self._device_key_map()
        network_start = self._scoped_start(query, None)
        annotation_networks = self._annotation_networks(query)
        with connect_history(self.history_path, read_only=True) as connection:
            full_total = len(
                {
                    keys.get(str(row[0]), str(row[0]))
                    for row in connection.execute(
                        "SELECT ip FROM host_snapshots"
                    )
                }
            )
            if network_start is not None:
                connection.execute(
                    "ATTACH DATABASE ? AS run_db", (str(self.sqlite_path),)
                )
                seen = self._host_last_seen_expression(connection, True)
                snapshots = connection.execute(
                    f"SELECT hs.ip, {seen} AS observed_at, hs.data FROM host_snapshots hs "
                    f"WHERE {seen} >= ?",
                    (network_start,),
                ).fetchall()
            else:
                snapshots = connection.execute(
                    "SELECT ip, observed_at, data FROM host_snapshots"
                ).fetchall()
        ips = [str(row["ip"]) for row in snapshots]
        loads: Dict[str, Dict[str, Any]] = {}
        counts: Dict[str, Dict[str, int]] = {}
        for offset in range(0, len(ips), 300):
            batch = ips[offset : offset + 300]
            loads.update(
                self._host_page_loads(batch, network_start)
                if network_start is not None
                else self._host_page_loads(batch)
            )
            counts.update(self._host_page_counts(batch, query=query))
        finding_stats = self._host_finding_stats(ips, query)
        has_threat_column = False
        profile_path = getattr(
            self,
            "host_profiles_path",
            Path("permanent/host_profiles/hosts.sqlite"),
        )
        triage = HostProfileStore.triage_for_ips(profile_path, ips)
        saved_annotations = HostProfileStore.annotations_for_ips(
            profile_path, ips, annotation_networks
        )
        try:
            with self._connect_sqlite() as connection:
                evidence_columns = {
                    str(column[1])
                    for column in connection.execute(
                        "PRAGMA table_info(evidence)"
                    ).fetchall()
                }
                has_threat_column = "threat_level" in evidence_columns
        except (AttributeError, sqlite3.Error):
            pass
        groups: Dict[str, Dict[str, Any]] = {}
        for snapshot in snapshots:
            ip = str(snapshot["ip"])
            data = self._loads(snapshot["data"], {})
            if not isinstance(data, dict):
                data = {}
            key = keys.get(ip, ip)
            group = groups.setdefault(
                key,
                {
                    "id": key,
                    "members": [],
                    "last_seen": 0.0,
                    "flows": 0,
                    "bytes": 0,
                    "evidence": 0,
                    "alerts": 0,
                    "peak_score": None,
                    "threat_rank": -1,
                    "user_status": "",
                    "user_labels": [],
                },
            )
            load = loads.get(ip, {})
            count = counts.get(ip, {})
            findings = finding_stats[ip]
            group["members"].append((ip, data, float(snapshot["observed_at"])))
            group["last_seen"] = max(
                group["last_seen"],
                float(load.get("last_seen") or 0),
                float(snapshot["observed_at"]),
            )
            for field, source in (
                ("flows", load),
                ("bytes", load),
                ("evidence", count),
                ("alerts", count),
            ):
                group[field] += int(source.get(field) or 0)
            if findings["peak"] is not None:
                group["peak_score"] = max(
                    group["peak_score"] or 0, findings["peak"]
                )
            group["threat_rank"] = max(
                group["threat_rank"],
                (
                    findings["threat_rank"]
                    if has_threat_column
                    else EVIDENCE_THREAT_RANKS.get(
                        str(data.get("max_threat_level") or "info").lower(), 0
                    )
                ),
            )
            if ip in triage:
                group["user_status"] = triage[ip].get("status", "")
                group["user_labels"] = list(
                    dict.fromkeys(
                        [*group["user_labels"], *triage[ip].get("labels", [])]
                    )
                )
        with connect_history(self.history_path, read_only=True) as connection:
            for group in groups.values():
                addresses = [member[0] for member in group["members"]]
                if len(addresses) < 2:
                    continue
                marks = ",".join("?" for _ in addresses)
                internal = connection.execute(
                    "SELECT COUNT(*) AS flows, COALESCE(SUM(bytes), 0) AS bytes "
                    f"FROM flow_index WHERE src_ip IN ({marks}) "
                    f"AND dst_ip IN ({marks}) AND src_ip != dst_ip"
                    + (
                        " AND event_time >= ?"
                        if network_start is not None
                        else ""
                    ),
                    (
                        *addresses,
                        *addresses,
                        *(
                            [network_start]
                            if network_start is not None
                            else []
                        ),
                    ),
                ).fetchone()
                group["flows"] -= int(internal["flows"] or 0)
                group["bytes"] -= int(internal["bytes"] or 0)
        latest = max(
            (group["last_seen"] for group in groups.values()), default=0
        )
        start, end, range_name = self._time_bounds(query, latest)
        start = self._scoped_start(query, start)
        search = self._query_value(query, "search").lower()
        scope = self._query_value(query, "scope")
        threat = self._query_value(query, "threat").lower()
        alerts_only = self._query_value(query, "alerts_only") == "1"
        saved_identities = (
            HostProfileStore.identities_for_ips(
                profile_path, ips, annotation_networks
            )
            if search
            else {}
        )
        filtered: List[Dict[str, Any]] = []
        for group in groups.values():
            members = group["members"]
            if start is not None and group["last_seen"] < start:
                continue
            if end is not None and group["last_seen"] > end:
                continue
            if search and not any(
                search
                in (
                    ip
                    + " "
                    + json.dumps(
                        [
                            data,
                            triage.get(ip, {}),
                            saved_annotations.get(ip, {}),
                            saved_identities.get(ip, {}),
                            classify_mac(data.get("mac")).replace("_", " "),
                        ],
                        ensure_ascii=False,
                    )
                ).lower()
                for ip, data, _ in members
            ):
                continue
            if scope and not any(
                data.get("scope") == scope for _, data, _ in members
            ):
                continue
            if alerts_only and not group["alerts"]:
                continue
            review = self._query_value(query, "review")
            if review and group["user_status"] != (
                "" if review == "unmarked" else review
            ):
                continue
            if threat:
                threshold = EVIDENCE_THREAT_RANKS.get(
                    threat.removesuffix("_or_more")
                )
                if threshold is None or (
                    group["threat_rank"] < threshold
                    if threat.endswith("_or_more")
                    else group["threat_rank"] != threshold
                ):
                    continue
            filtered.append(group)
        sort_key, _, direction = self._sort_spec(
            query,
            {
                key: key
                for key in (
                    "ip",
                    "scope",
                    "hostname",
                    "ti",
                    "mac",
                    "threat",
                    "flows",
                    "bytes",
                    "evidence",
                    "alerts",
                    "score",
                    "peak_score",
                    "last_seen",
                    "review",
                    "labels",
                )
            },
            "last_seen",
        )

        def sort_value(group: Dict[str, Any]) -> Any:
            """Return a stable value for the chosen device table column.

            Parameters:
                group: One merged device.

            Returns:
                Comparable text or numeric value.
            """
            representative = max(group["members"], key=lambda item: item[2])
            data = representative[1]
            values = {
                "ip": representative[0],
                "review": group["user_status"],
                "labels": ", ".join(group["user_labels"]),
                "scope": data.get("scope", ""),
                "hostname": data.get("hostname", ""),
                "ti": "",
                "mac": data.get("mac", ""),
                "threat": group["threat_rank"],
                "flows": group["flows"],
                "bytes": group["bytes"],
                "evidence": group["evidence"],
                "alerts": group["alerts"],
                "score": group["peak_score"],
                "peak_score": group["peak_score"],
                "last_seen": group["last_seen"],
            }
            value = values[sort_key]
            return (
                str(value or "").lower()
                if sort_key
                in {"ip", "scope", "hostname", "ti", "mac", "review", "labels"}
                else float(value or 0)
            )

        filtered.sort(
            key=lambda group: (sort_value(group), group["id"]),
            reverse=direction == "DESC",
        )
        total = len(filtered)
        cursor = self._decode_cursor(self._query_value(query, "cursor"))
        if cursor:
            filtered = [
                group
                for group in filtered
                if (
                    (sort_value(group), group["id"]) > (cursor[0], cursor[1])
                    if direction == "ASC"
                    else (sort_value(group), group["id"])
                    < (cursor[0], cursor[1])
                )
            ]
        limit = self._limit(query)
        page = filtered[:limit]
        page_ips = [ip for group in page for ip, _, _ in group["members"]]
        annotations = HostProfileStore.annotations_for_ips(
            getattr(
                self,
                "host_profiles_path",
                Path("permanent/host_profiles/hosts.sqlite"),
            ),
            page_ips,
            annotation_networks,
        )
        identities = (
            self._host_page_identity(page_ips)
            if getattr(self, "cache", None)
            else {}
        )
        items: List[Dict[str, Any]] = []
        for group in page:
            members = sorted(
                group["members"], key=lambda item: item[2], reverse=True
            )
            ip, snapshot, observed = members[0]
            host = dict(snapshot)
            host.update(
                {
                    "ip": ip,
                    "device_id": group["id"],
                    "device_ips": [member[0] for member in members],
                    "observed_at": observed,
                    "last_seen": group["last_seen"],
                    "peak_alert_score": group["peak_score"],
                    "alert_count": group["alerts"],
                    "evidence_count": group["evidence"],
                    "max_threat_level": (
                        self._threat_from_rank(group["threat_rank"])
                        if group["threat_rank"] >= 0
                        else ""
                    ),
                    "has_findings": group["threat_rank"] >= 0,
                    "user_status": group["user_status"],
                    "user_labels": group["user_labels"],
                    "load": {
                        "flows": group["flows"],
                        "bytes": group["bytes"],
                        "last_seen": group["last_seen"],
                    },
                    "user_name": annotations.get(ip, {}).get("name", ""),
                    "user_note": annotations.get(ip, {}).get("note", ""),
                    "dns_name": identities.get(ip, {}).get("dns_name", ""),
                    "dns_name_source": identities.get(ip, {}).get(
                        "dns_name_source", ""
                    ),
                    "ti_feeds": identities.get(ip, {}).get("ti_feeds", []),
                }
            )
            host["mac_address_type"] = classify_mac(host.get("mac"))
            items.append(host)
        self._restore_host_identities(items, query, identities)
        self._attach_current_host_scores(items)
        next_cursor = (
            self._encode_cursor(sort_value(page[-1]), page[-1]["id"])
            if len(filtered) > limit and page
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
            "view": "device",
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
                        f"WHERE ip_alerted IN ({placeholders}) AND "
                        + self._review_clause(
                            connection, "alert", "open", "alerts"
                        ),
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

    def _host_annotation_profile(
        self, ip: str, host: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Offer an isolated annotation target for an observed legacy host.

        Parameters:
            ip: Address already present in the run inventory.
            host: Optional identity already read for the host workspace.

        Returns:
            A profile with an explicitly unidentified network, or an empty map.
        """
        if host is None:
            try:
                host = self._live_host(ip)
            except (AttributeError, OSError, sqlite3.Error):
                return {}
        if not host.get("observed_at") and not host.get("live"):
            return {}
        run_name = (
            self._network_run_name() if getattr(self, "redis", None) else ""
        )
        run_name = run_name or str(getattr(self, "output_dir", ""))
        public = ipaddress.ip_address(ip).is_global
        if not public and not run_name:
            return {}
        return {
            "ip": ip,
            "network_id": "public" if public else f"run:{run_name}",
            "network_label": (
                "Public internet" if public else "Unidentified network"
            ),
            "network_name": "",
            "user_name": "",
            "user_note": "",
            "first_seen": float(host.get("observed_at") or time.time()),
            "last_seen": float(host.get("observed_at") or time.time()),
            "facts": [],
        }

    def host(
        self, ip: str, query: Optional[Dict[str, List[str]]] = None
    ) -> Dict[str, Any]:
        """Return complete bounded context for one current or historical host."""
        network_start = self._scoped_start(query or {}, None)
        host = self._live_host(ip)
        if not host.get("observed_at") and not host.get("live"):
            raise KeyError(ip)
        self._attach_current_host_scores([host])
        host_ips = self._host_ips(ip, query)
        host["all_ips"] = host_ips
        if self._query_value(query or {}, "device") == "1":
            host["device_id"] = self._device_key_map().get(ip, ip)
            host["device_ips"] = host_ips
        host["load"] = self._host_load(ip, query)
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
        if network_start is not None:
            capture = self._current_header_network()
            run_name = (
                self._network_run_name()
                if getattr(self, "redis", None)
                else ""
            )
            network_ids = {
                capture.get("network_id", ""),
                f"run:{run_name}" if run_name else "",
            }
            if ipaddress.ip_address(ip).is_global:
                network_ids.add("public")
            host["current_network_profiles"] = [
                profile
                for profile in host["permanent_profiles"]
                if profile.get("network_id") in network_ids
                and float(profile.get("last_seen") or 0) >= network_start
            ]
            activity = self._host_activity_times(host_ips)
            host["last_seen"] = max(activity.values(), default=0)
            host["seen_on_current_network"] = (
                host["last_seen"] >= network_start
            )
            host["capture_network"] = capture
        host["annotation_profile"] = (
            {}
            if host["permanent_profiles"]
            else self._host_annotation_profile(ip, host)
        )
        identity_profiles = host.get(
            "current_network_profiles", host["permanent_profiles"]
        )
        if identity_profiles:
            host["user_name"] = identity_profiles[0]["user_name"]
            host["user_note"] = identity_profiles[0]["user_note"]
        else:
            host["user_name"] = ""
            host["user_note"] = ""
        for field, kind in (
            ("mac", "mac"),
            ("mac_vendor", "mac_vendor"),
            ("hostname", "hostname"),
        ):
            if not host.get(field):
                host[field] = next(
                    (
                        fact["value"]
                        for profile in identity_profiles
                        for fact in profile.get("facts", [])
                        if fact["kind"] == kind
                    ),
                    "",
                )
        self._restore_host_identities([host], query or {})
        analysis = (
            self.redis.hgetall("analysis")
            if getattr(self, "redis", None)
            else {}
        )
        if (
            isinstance(analysis, dict)
            and analysis.get("input_type") == "interface"
            and not analysis.get("analysis_end")
        ):
            for interface in str(analysis.get("interface") or "").split(","):
                interface = interface.strip()
                if not interface:
                    continue
                addresses = psutil.net_if_addrs().get(interface, [])
                own_ips = {
                    entry.address.split("%", 1)[0]
                    for entry in addresses
                    if entry.family in (socket.AF_INET, socket.AF_INET6)
                }
                if ip in own_ips:
                    mac = next(
                        (
                            HostProfileStore._usable_mac(entry.address)
                            for entry in addresses
                            if entry.family == psutil.AF_LINK
                        ),
                        "",
                    )
                    if mac:
                        host["mac"] = mac
                        host["mac_source"] = f"Monitored interface {interface}"
        triage = HostProfileStore.triage_for_profiles(
            getattr(
                self,
                "host_profiles_path",
                Path("permanent/host_profiles/hosts.sqlite"),
            ),
            host_ips,
        )
        for profile in host["permanent_profiles"]:
            mark = triage.get((profile["network_id"], ip), {})
            profile["user_status"] = mark.get("status", "")
            profile["user_labels"] = mark.get("labels", [])
        current_profile = next(iter(identity_profiles), {})
        host["user_status"] = current_profile.get("user_status", "")
        host["user_labels"] = current_profile.get("user_labels", [])
        alerts_by_id: Dict[str, Dict[str, Any]] = {}
        alert_total = 0
        for address in host_ips:
            alert_query = {
                "range": [self._query_value(query or {}, "range", "all")],
                "profile": [address],
                "limit": ["100"],
                "details": ["false"],
            }
            for key in ("from", "to"):
                if key in (query or {}):
                    alert_query[key] = query[key]
            if network_start is not None:
                alert_query["network"] = ["current"]
            alert_page = self.alerts(alert_query)
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
        finding_query = {"range": ["all"], **(query or {})}
        findings = list(
            self._host_finding_stats(host_ips, finding_query).values()
        )
        host["evidence_count"] = sum(item["evidence"] for item in findings)
        scores = [
            item["peak"] for item in findings if item["peak"] is not None
        ]
        host["peak_alert_score"] = max(scores, default=None)
        threat_rank = max(
            (item["threat_rank"] for item in findings), default=-1
        )
        host["has_findings"] = threat_rank >= 0
        host["max_threat_level"] = (
            self._threat_from_rank(threat_rank) if threat_rank >= 0 else ""
        )
        host["findings_range"] = self._query_value(
            finding_query, "range", "all"
        )
        host["mac_address_type"] = classify_mac(host.get("mac"))
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
        host_query["profile"] = self._host_ips(ip, query)
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
        ips = self._host_ips(ip, query)
        host_ips = set(ips)

        def direction_sort(src: str, dst: str) -> str:
            """Return the displayed direction for an indexed flow.

            Parameters:
                src: Source address.
                dst: Destination address.

            Returns:
                Direction relative to this host.
            """
            if src in host_ips and dst in host_ips:
                return "internal"
            return "outbound" if src in host_ips else "inbound"

        def peer_sort(src: str, dst: str) -> str:
            """Return the displayed peer for an indexed flow.

            Parameters:
                src: Source address.
                dst: Destination address.

            Returns:
                Address at the opposite end of this host's flow.
            """
            return dst if src in host_ips else src

        predicate, params = self._ip_predicate(ips)
        with connect_history(self.history_path, read_only=True) as history:
            latest_row = history.execute(
                "SELECT MAX(event_time) AS latest FROM flow_index"
            ).fetchone()
        latest = float(latest_row["latest"] or 0)
        start, end, range_name = self._time_bounds(query, latest)
        start = self._scoped_start(query, start)
        clauses = [predicate]
        if start is not None:
            clauses.append("event_time >= ?")
            params.append(start)
        if end is not None:
            clauses.append("event_time <= ?")
            params.append(end)
        with connect_history(self.history_path, read_only=True) as history:
            history.create_function("flow_direction_sort", 2, direction_sort)
            history.create_function("flow_peer_sort", 2, peer_sort)
            raw_sort_keys = {"ports", "state", "duration"}
            requested_sort = self._query_value(query, "sort", "event_time")
            threat = self._query_value(query, "threat").lower()
            if (
                self._query_value(query, "hide_excluded") == "1"
                or requested_sort in raw_sort_keys
                or requested_sort == "threat"
                or threat
            ):
                history.execute(
                    "ATTACH DATABASE ? AS run_db",
                    (f"file:{self.sqlite_path}?mode=ro",),
                )
            linked_threat_available = False
            linked_threat_exclusion = ""
            if requested_sort == "threat" or threat:
                evidence_columns = {
                    str(column[1])
                    for column in history.execute(
                        "PRAGMA run_db.table_info(evidence)"
                    )
                }
                linked_threat_available = "threat_level" in evidence_columns
                if (
                    self._query_value(query, "hide_excluded") == "1"
                    and "whitelisted" in evidence_columns
                ):
                    linked_threat_exclusion = (
                        " AND COALESCE(e.whitelisted, 0) = 0"
                    )
            raw_flow = (
                "(SELECT flow FROM run_db.flows f "
                "WHERE f.uid = flow_index.uid)"
            )
            raw_value = (
                f"CASE WHEN json_valid({raw_flow}) "
                f"THEN {raw_flow} ELSE '{{}}' END"
            )
            linked_threat_rank = (
                (
                    "(SELECT MAX(CASE LOWER(e.threat_level) "
                    "WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
                    "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) "
                    "FROM run_db.evidence_flows ef JOIN run_db.evidence e "
                    "ON e.evidence_id = ef.evidence_id "
                    f"WHERE ef.uid = flow_index.uid{linked_threat_exclusion})"
                )
                if linked_threat_available
                else "NULL"
            )
            sort_key, sort_expression, sort_direction = self._sort_spec(
                query,
                {
                    "event_time": "event_time",
                    "direction": "flow_direction_sort(src_ip, dst_ip)",
                    "peer": "LOWER(flow_peer_sort(src_ip, dst_ip))",
                    "protocol": "LOWER(COALESCE(proto, '') || '/' || COALESCE(app_proto, ''))",
                    "ports": (
                        f"printf('%05d:%05d', CAST(json_extract({raw_value}, '$.sport') AS INTEGER), "
                        f"CAST(json_extract({raw_value}, '$.dport') AS INTEGER))"
                    ),
                    "state": f"LOWER(COALESCE(json_extract({raw_value}, '$.state'), ''))",
                    "packets": "packets",
                    "bytes": "bytes",
                    "duration": f"COALESCE(CAST(json_extract({raw_value}, '$.dur') AS REAL), 0)",
                    "label": "LOWER(COALESCE(label, ''))",
                    "threat": linked_threat_rank,
                },
                "event_time",
            )
            if threat:
                minimum = threat.removesuffix("_or_more")
                rank = EVIDENCE_THREAT_RANKS.get(minimum)
                if rank is not None:
                    operator = ">=" if threat.endswith("_or_more") else "="
                    clauses.append(f"{linked_threat_rank} {operator} ?")
                    params.append(rank)
            if self._query_value(query, "hide_excluded") == "1":
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
                    self._cursor_clause(sort_expression, "uid", sort_direction)
                )
                params.extend([cursor[0], cursor[0], cursor[1]])
            where = " AND ".join(clauses)
            total = history.execute(
                f"SELECT COUNT(*) AS count FROM flow_index WHERE "
                f"{' AND '.join(count_clauses)}",
                count_params,
            ).fetchone()["count"]
            index_rows = history.execute(
                f"SELECT *, {sort_expression} AS sort_value FROM flow_index WHERE {where} "
                f"ORDER BY {sort_expression} {sort_direction}, uid {sort_direction} LIMIT ?",
                (*params, limit + 1),
            ).fetchall()
        has_more = len(index_rows) > limit
        index_rows = index_rows[:limit]
        raw_by_uid: Dict[str, Dict[str, Any]] = {}
        threat_by_uid: Dict[str, str] = {}
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
            with self._connect_sqlite() as connection:
                if self._table_exists(
                    connection, "evidence_flows"
                ) and self._table_exists(connection, "evidence"):
                    evidence_columns = {
                        str(column[1])
                        for column in connection.execute(
                            "PRAGMA table_info(evidence)"
                        )
                    }
                    if "threat_level" in evidence_columns:
                        exclusion = (
                            " AND COALESCE(e.whitelisted, 0) = 0"
                            if self._query_value(query, "hide_excluded") == "1"
                            and "whitelisted" in evidence_columns
                            else ""
                        )
                        threat_rows = connection.execute(
                            "SELECT ef.uid, MAX(CASE LOWER(e.threat_level) "
                            "WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
                            "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) "
                            "AS threat_rank FROM evidence_flows ef JOIN evidence e "
                            "ON e.evidence_id = ef.evidence_id "
                            f"WHERE ef.uid IN ({placeholders}){exclusion} "
                            "GROUP BY ef.uid",
                            uids,
                        ).fetchall()
                        threat_by_uid = {
                            str(item["uid"]): self._threat_from_rank(
                                item["threat_rank"]
                            )
                            for item in threat_rows
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
                    "linked_threat_level": threat_by_uid.get(str(row["uid"])),
                    "threat": EVIDENCE_THREAT_RANKS.get(
                        threat_by_uid.get(str(row["uid"]), ""), -1
                    ),
                    "raw": raw,
                }
            )
        next_cursor = (
            self._encode_cursor(
                index_rows[-1]["sort_value"], str(items[-1]["uid"])
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
        ips = self._host_ips(ip, query)
        predicate, params = self._ip_predicate(ips)
        with connect_history(self.history_path, read_only=True) as connection:
            latest_row = connection.execute(
                "SELECT MAX(event_time) AS latest FROM flow_index"
            ).fetchone()
        latest = float(latest_row["latest"] or 0)
        start, end, range_name = self._time_bounds(query, latest)
        start = self._scoped_start(query, start)
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
            start = self._scoped_start(query, start)
            clauses = [f"profile_ip IN ({placeholders})"]
            params: List[Any] = list(ips)
            if (
                self._query_value(query, "hide_excluded") == "1"
                and "whitelisted" in columns
            ):
                clauses.append("COALESCE(whitelisted,0)=0")
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
        if self._query_value(query, "network") == "current":
            current_in_range = current_in_range and self._host_activity_times(
                ips
            ).get(ip, 0) >= (start or float("inf"))
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
        self,
        connection: sqlite3.Connection,
        network_start: Optional[float] = None,
    ) -> Counter[str]:
        """
        Count evidence by producing module from durable history.

        Parameters:
            connection: Short-lived read-only flows database connection.
            network_start: Optional earliest event in the current connection.

        Returns:
            Evidence counts keyed by module name.
        """
        if not self._table_exists(connection, "evidence"):
            return Counter()
        connection.create_function(
            "evidence_module", 1, self._module_for_evidence
        )
        module_expression = self._evidence_module_expression(connection)
        scope = "WHERE evidence_time >= ?" if network_start is not None else ""
        rows = connection.execute(
            f"SELECT {module_expression} AS module, COUNT(*) AS count "
            f"FROM evidence {scope} GROUP BY {module_expression}",
            (network_start,) if network_start is not None else (),
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

    def logs(
        self, query: Optional[Dict[str, List[str]]] = None
    ) -> Dict[str, Any]:
        """Return sortable parsed runtime messages.

        Parameters:
            query: Optional sort key and direction.

        Returns:
            Total parsed message count and one bounded sorted page.
        """
        query = query or {}
        with connect_history(self.history_path, read_only=True) as history:

            def log_level(message: str, line: str) -> str:
                """Classify a stored log using the visible level labels.

                Parameters:
                    message: Parsed summary.
                    line: Raw source line.

                Returns:
                    Severity label used by the browser.
                """
                content = f"{message or ''} {line or ''}".lower()
                for level, pattern in (
                    (
                        "critical",
                        r"\b(critical|fatal|panic|traceback|exception)\b",
                    ),
                    ("warning", r"\b(warning|warn)\b"),
                    ("debug", r"\bdebug\b"),
                    ("info", r"\b(info|notice)\b"),
                ):
                    if re.search(pattern, content):
                        return level
                return "error"

            history.create_function("log_level", 2, log_level)
            _, sort_expression, direction = self._sort_spec(
                query,
                {
                    "event_time": "event_time",
                    "level": "log_level(message, line)",
                    "module": "LOWER(module)",
                    "message": "LOWER(message)",
                },
                "event_time",
            )
            total = int(
                history.execute(
                    "SELECT COUNT(*) AS count FROM error_events"
                ).fetchone()["count"]
            )
            items = [
                dict(row)
                for row in history.execute(
                    "SELECT event_time, module, message, line "
                    f"FROM error_events ORDER BY {sort_expression} {direction}, id {direction} "
                    "LIMIT 100"
                ).fetchall()
            ]
        for item in items:
            if not str(item["message"]).startswith("Traceback"):
                continue
            for line in reversed(str(item["line"]).splitlines()):
                cause = line.strip()
                if re.match(
                    r"^(?:[A-Za-z_][\w.]*)(?:Error|Exception|Interrupt):",
                    cause,
                ):
                    item["message"] = f"{item['message']} — {cause[:240]}"
                    break
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
        self,
        ip: str,
        network_id: str,
        name: str,
        note: str,
        status: Optional[str] = None,
        labels: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Save a user name and note for an exact permanent host profile.

        Parameters:
            ip: Selected host IP.
            network_id: Network identity shown in the Host tab.
            name: User-provided host name, or empty to clear it.
            note: User-provided note, or empty to clear it.
            status: Optional review workflow mark.
            labels: Optional user-defined labels.

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
        if status is not None or labels is not None:
            if status not in {"", "to_analyze", "in_review", "reviewed"}:
                raise ValueError("Choose a valid host review mark")
            if (
                not isinstance(labels, list)
                or len(labels) > 10
                or any(
                    not isinstance(label, str)
                    or not label.strip()
                    or len(label) > 40
                    or any(
                        ord(char) < 32 or ord(char) == 127 for char in label
                    )
                    for label in labels
                )
            ):
                raise ValueError(
                    "Use at most 10 labels of 40 printable characters"
                )
            labels = list(dict.fromkeys(label.strip() for label in labels))
        if not HostProfileStore.has_network_profile(
            self.host_profiles_path, ip, network_id
        ):
            fallback = self._host_annotation_profile(ip)
            if not fallback or fallback["network_id"] != network_id:
                raise ValueError("The selected host profile is unavailable")
            run_name = network_id.removeprefix("run:")
            store = HostProfileStore(
                self.host_profiles_path, run_name, lambda _: {}, []
            )
            store._save(ip, "", fallback["last_seen"], [])
        HostProfileStore.set_host_annotation(
            self.host_profiles_path,
            ip,
            network_id,
            name,
            note,
            **(
                {"status": status, "labels": labels}
                if status is not None
                else {}
            ),
        )
        result = {
            "ip": ip,
            "network_id": network_id,
            "name": name,
            "note": note,
        }
        if status is not None:
            result.update({"status": status, "labels": labels})
        return result

    def overview(
        self, query: Optional[Dict[str, List[str]]] = None
    ) -> Dict[str, Any]:
        """Build a bounded current-run operational overview."""
        scoped_start = self._scoped_start(query or {}, None)
        alert_scope = (
            " AND CAST(alert_time AS REAL) >= ?"
            if scoped_start is not None
            else ""
        )
        evidence_scope = (
            " WHERE evidence_time >= ?" if scoped_start is not None else ""
        )
        scope_params = (scoped_start,) if scoped_start is not None else ()
        analysis = self.redis.hgetall("analysis")
        run_metadata = self._run_metadata()
        complete = bool(analysis.get("analysis_end"))
        now = time.time()
        try:
            with self._connect_sqlite() as connection:
                alert_count = int(
                    connection.execute(
                        "SELECT COUNT(*) AS count FROM alerts WHERE "
                        + self._review_clause(
                            connection, "alert", "open", "alerts"
                        )
                        + alert_scope,
                        scope_params,
                    ).fetchone()["count"]
                )
                durable_evidence = (
                    int(
                        connection.execute(
                            "SELECT COUNT(*) AS count FROM evidence"
                            + evidence_scope,
                            scope_params,
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
        evidence_count = (
            durable_evidence
            if scoped_start is not None
            else durable_evidence or redis_evidence_count
        )
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
        highest_score = None
        if not alert_count:
            score_field = (
                "accumulated_ratl"
                if getattr(self, "score_mode", "ratl") == "ratl"
                else "accumulated_threat_level"
            )
            with connect_history(self.history_path, read_only=True) as history:
                row = history.execute(
                    "SELECT ip, CAST(json_extract(data, ?) AS REAL) AS score "
                    "FROM host_snapshots ORDER BY score DESC LIMIT 1",
                    (f"$.{score_field}",),
                ).fetchone()
                if row:
                    highest_score = {"ip": row["ip"], "score": row["score"]}
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
            "highest_score": highest_score,
            "alert_threshold": getattr(self, "alert_threshold", 5.0),
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

    def overview_evidence_counts(
        self, query: Optional[Dict[str, List[str]]] = None
    ) -> Dict[str, Any]:
        """Load exact evidence totals omitted from the fast Overview response.

        Returns:
            Exact overall and per-module evidence counts from durable storage,
            or from the retained Redis compatibility data when necessary.
        """
        network_start = self._scoped_start(query or {}, None)
        durable_evidence = 0
        evidence_counts: Counter[str] = Counter()
        try:
            with self._connect_sqlite() as connection:
                if self._table_exists(connection, "evidence"):
                    durable_evidence = int(
                        connection.execute(
                            "SELECT COUNT(*) AS count FROM evidence"
                            + (
                                " WHERE evidence_time >= ?"
                                if network_start is not None
                                else ""
                            ),
                            (
                                (network_start,)
                                if network_start is not None
                                else ()
                            ),
                        ).fetchone()["count"]
                    )
                    if durable_evidence:
                        evidence_counts = self._durable_evidence_counts(
                            connection, network_start
                        )
        except sqlite3.Error:
            durable_evidence = 0
        if durable_evidence:
            evidence_count = durable_evidence
            source = "sqlite"
        elif network_start is None:
            redis_evidence = self._redis_evidence()
            evidence_count = len(redis_evidence)
            evidence_counts = Counter(
                str(item.get("module", "unknown")) for item in redis_evidence
            )
            source = "redis"
        else:
            evidence_count = 0
            source = "sqlite"
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
                    f"ORDER BY evidence_time DESC LIMIT ?",
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
        rule_key = self._query_value(query, "sort", "unblock_at")
        numeric_rule_keys = {
            "blocked_at",
            "unblock_at",
            "remaining_seconds",
            "remaining_timewindows",
            "stopped_packets",
            "stopped_flows",
            "evidence_while_blocked",
            "evidence_count",
            "alert_count",
        }
        text_rule_keys = {"ip", "status", "origin"}
        if rule_key not in numeric_rule_keys | text_rule_keys:
            rule_key = "unblock_at"
        rule_descending = self._query_value(query, "order", "asc") == "desc"
        records.sort(
            key=lambda item: (
                (
                    float(item.get(rule_key) or 0)
                    if rule_key in numeric_rule_keys
                    else str(
                        item["ip"]
                        if rule_key == "ip"
                        else (
                            item["status"]
                            if rule_key == "status"
                            else (
                                f"{item.get('recovery_status') or 'Recovered'} · "
                                f"{item.get('origin_run') or ''}"
                                if item["recovered"]
                                else "Current run"
                            )
                        )
                    ).lower()
                ),
                item["ip"],
            ),
            reverse=rule_descending,
        )
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
        history_key = self._query_value(query, "history_sort", "timestamp")
        if history_key not in {"timestamp", "ip", "action", "details"}:
            history_key = "timestamp"
        history_descending = (
            self._query_value(query, "history_order", "desc") == "desc"
        )
        history.sort(
            key=lambda item: (
                (
                    float(item["timestamp"])
                    if history_key == "timestamp"
                    else str(item[history_key]).lower()
                ),
                item["timestamp"],
                item["ip"],
            ),
            reverse=history_descending,
        )
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

    @staticmethod
    def _usable_peer_ip(value: Any) -> bool:
        """Accept a peer endpoint only when it is a usable remote address.

        Parameters:
            value: Candidate address from Pigeon or a verified connection.

        Returns:
            Whether the address can identify a remote peer.
        """
        try:
            address = ipaddress.ip_address(str(value))
        except ValueError:
            return False
        return not (
            address.is_loopback
            or address.is_unspecified
            or address.is_multicast
        )

    def _p2p_calculated_trust_history(
        self, path: Path, query: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """Read bounded actual trust samples across the selected time range.

        Parameters:
            path: Persistent P2P trust database.
            query: Selected history range or explicit time bounds.

        Returns:
            Chronological measured trust values, preserving peer endpoints.
        """
        if not path.exists():
            return []
        try:
            with sqlite3.connect(
                f"file:{path}?mode=ro", uri=True, timeout=5
            ) as connection:
                latest = connection.execute(
                    "SELECT MAX(update_time) FROM peer_trust_history"
                ).fetchone()[0]
                start, end, _ = self._time_bounds(query, latest)
                clauses = ["1=1"]
                params: List[Any] = []
                for bound, operator in ((start, ">="), (end, "<=")):
                    if bound is not None:
                        clauses.append(f"update_time {operator} ?")
                        params.append(bound)
                rows = connection.execute(
                    "WITH ordered AS (SELECT peerid, trust, update_time, "
                    "ROW_NUMBER() OVER (ORDER BY update_time, peerid) AS rn, "
                    "COUNT(*) OVER () AS total, "
                    "ROW_NUMBER() OVER (PARTITION BY peerid ORDER BY update_time) AS first_rn, "
                    "ROW_NUMBER() OVER (PARTITION BY peerid ORDER BY update_time DESC) AS last_rn "
                    "FROM peer_trust_history WHERE "
                    + " AND ".join(clauses)
                    + ") "
                    "SELECT peerid, trust, update_time FROM ordered "
                    "WHERE first_rn=1 OR last_rn=1 "
                    "OR rn % MAX(1, CAST((total + 1997) / 1998 AS INTEGER))=0 "
                    "ORDER BY update_time, peerid",
                    params,
                )
                return [
                    {
                        "peer_id": str(peer),
                        "trust": float(trust),
                        "timestamp": float(timestamp),
                    }
                    for peer, trust, timestamp in rows
                ]
        except sqlite3.Error:
            return []

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
        peer_message_counts = {
            str(peer_id): int(value)
            for peer_id, value in self.redis.hgetall(
                f"p2p_reports_by_peer_{current_tw}"
            ).items()
        }
        activity = [
            self._loads(raw, {})
            for raw in self.redis.lrange("p2p_message_history", 0, 999)
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
        validation_path = self._report_validation_path()
        trust_path = validation_path.with_name("trustdb.db")
        trust_range = "all"
        trust_history: List[Dict[str, Any]] = []
        latest_reliability: Dict[str, Dict[str, Any]] = {}
        reports: List[Dict[str, Any]] = []
        reports_received = 0
        report_counts: Counter[str] = Counter()
        peer_ips: Dict[str, Dict[str, Any]] = {}
        peer_addresses: Dict[str, Dict[str, Any]] = {}
        peer_first_seen: Dict[str, float] = {}
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
                        "WITH ordered AS ("
                        "SELECT peerid, reliability, update_time, "
                        "ROW_NUMBER() OVER (ORDER BY update_time, peerid) AS rn, "
                        "COUNT(*) OVER () AS total, "
                        "ROW_NUMBER() OVER (PARTITION BY peerid "
                        "ORDER BY update_time) AS peer_rn, "
                        "ROW_NUMBER() OVER (PARTITION BY peerid "
                        "ORDER BY update_time DESC) AS peer_last_rn "
                        f"FROM go_reliability WHERE {trust_where}) "
                        "SELECT peerid, reliability, update_time FROM ordered "
                        "WHERE rn = 1 OR rn = total OR peer_rn = 1 "
                        "OR peer_last_rn = 1 "
                        "OR rn % MAX(1, CAST((total + 1997) / 1998 AS INTEGER)) = 0 "
                        "ORDER BY update_time",
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
                        if not self._usable_peer_ip(row["ipaddress"]):
                            continue
                        peer_ips.setdefault(
                            str(row["peerid"]),
                            {
                                "ip": str(row["ipaddress"]),
                                "timestamp": self._event_timestamp(
                                    row["update_time"]
                                ),
                            },
                        )
                    if connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type = 'table' "
                        "AND name = 'peer_addresses'"
                    ).fetchone():
                        for row in connection.execute(
                            "SELECT peerid, ipaddress, update_time "
                            "FROM peer_addresses ORDER BY update_time DESC "
                            "LIMIT 1000"
                        ):
                            if not self._usable_peer_ip(row["ipaddress"]):
                                continue
                            peer_addresses.setdefault(
                                str(row["peerid"]),
                                {
                                    "ip": str(row["ipaddress"]),
                                    "timestamp": self._event_timestamp(
                                        row["update_time"]
                                    ),
                                },
                            )
                    peer_first_seen = {
                        str(row["peerid"]): self._event_timestamp(
                            row["first_seen"]
                        )
                        for row in connection.execute(
                            "SELECT peerid, MIN(update_time) AS first_seen "
                            "FROM peer_ips GROUP BY peerid"
                        )
                    }
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
        if counts:
            reports_received = counts.get("received:report", 0) + counts.get(
                "received:blame", 0
            )
            if not peer_message_counts and reports_received:
                # Existing runs already have message telemetry, while their
                # per-peer hash appears only after the writer is upgraded.
                remaining = reports_received
                for item in activity:
                    if remaining <= 0:
                        break
                    if (
                        not isinstance(item, dict)
                        or item.get("direction") != "received"
                        or item.get("message_type")
                        not in (
                            "report",
                            "blame",
                        )
                    ):
                        continue
                    peer_id = str(item.get("peer") or "")
                    if peer_id:
                        peer_message_counts[peer_id] = (
                            peer_message_counts.get(peer_id, 0) + 1
                        )
                        remaining -= 1
            report_counts = Counter(peer_message_counts)
        peer_ids = (
            set(peer_info)
            | set(peer_ips)
            | set(peer_addresses)
            | set(latest_reliability)
            | set(report_counts)
            | connected
        )
        peer_ip_values: Dict[str, str] = {}
        for peer_id in peer_ids:
            info = peer_info.get(peer_id, {})
            candidates = []
            for source, timestamp in (
                (
                    info.get("ip") or info.get("ipaddress"),
                    self._event_timestamp(info.get("timestamp")),
                ),
                (
                    peer_ips.get(peer_id, {}).get("ip"),
                    float(peer_ips.get(peer_id, {}).get("timestamp") or 0),
                ),
                (
                    peer_addresses.get(peer_id, {}).get("ip"),
                    float(
                        peer_addresses.get(peer_id, {}).get("timestamp") or 0
                    ),
                ),
            ):
                if self._usable_peer_ip(source):
                    candidates.append((timestamp, str(source)))
            remote_ips = [
                str(item["remote_ip"])
                for item in live_connections
                if str(item.get("peer_id")) == peer_id
                and self._usable_peer_ip(item.get("remote_ip"))
            ]
            peer_ip_values[peer_id] = (
                min(remote_ips)
                if remote_ips
                else max(candidates)[1] if candidates else ""
            )
        reputations: Dict[str, tuple[float, float]] = {}
        peer_ip_set = {ip for ip in peer_ip_values.values() if ip}
        if peer_ip_set and trust_path.exists():
            try:
                with sqlite3.connect(
                    f"file:{trust_path}?mode=ro", uri=True, timeout=5
                ) as connection:
                    placeholders = ",".join("?" for _ in peer_ip_set)
                    reputations = {
                        str(row[0]): (float(row[1]), float(row[2]))
                        for row in connection.execute(
                            "SELECT ipaddress, score, confidence "
                            "FROM slips_reputation WHERE source = 'local' "
                            "AND ipaddress IN "
                            f"({placeholders})",
                            tuple(peer_ip_set),
                        )
                    }
            except sqlite3.Error:
                pass
        validator = None
        if validation_path.exists():
            try:
                validator = ReportValidator(validation_path)
            except (sqlite3.Error, OSError):
                pass
        current_interface = str(analysis.get("interface") or "").split(",", 1)[
            0
        ]
        current_state = (
            self._loads(
                self.redis.hget("network_states", current_interface), {}
            )
            if current_interface
            else {}
        )
        validation_network = (
            HostProfileStore.network_id_for_state(
                current_state, self._network_run_name()
            )
            if isinstance(current_state, dict) and current_state
            else ""
        )
        peers = []
        for peer_id in peer_ids:
            info = peer_info.get(peer_id, {})
            pairing = peer_ips.get(peer_id, {})
            ip = peer_ip_values[peer_id]
            reliability = latest_reliability.get(peer_id, {})
            reliability_value = reliability.get("reliability")
            if reliability_value is None:
                try:
                    reliability_value = float(info["reliability"])
                except (KeyError, TypeError, ValueError):
                    reliability_value = None
            trust_value = None
            if reliability_value is not None and ip:
                score, confidence = reputations.get(ip, (0.5, 0.0))
                if validator is not None and validation_network:
                    try:
                        reviewed_score, reviewed_confidence, _ = (
                            validator.local_report(
                                f"{validation_network}|{ip}", max_age=None
                            )
                        )
                        score, confidence = (
                            (reviewed_score, reviewed_confidence)
                            if reviewed_score is not None
                            else (0.5, 0.0)
                        )
                    except sqlite3.Error:
                        pass
                trust_value = (
                    reliability_value * RELIABILITY_WEIGHT
                    + local_maliciousness_to_thesis_score(score) * confidence
                ) / 2
            accuracy = []
            if validator is not None:
                try:
                    accuracy = validator.peer_feedback(peer_id)
                except sqlite3.Error:
                    pass
            peers.append(
                {
                    "peer_id": peer_id,
                    "ip": ip,
                    "connected": peer_id in connected,
                    "trust": trust_value,
                    "report_accuracy": accuracy,
                    "confirmed_reports": sum(
                        item["confirmed"] for item in accuracy
                    ),
                    "false_reports": sum(
                        item["false_positive"] for item in accuracy
                    ),
                    "reliability": reliability_value,
                    "first_seen": peer_first_seen.get(peer_id)
                    or self._event_timestamp(info.get("timestamp"))
                    or float(reliability.get("timestamp") or 0),
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
            "calculated_trust_history": self._p2p_calculated_trust_history(
                trust_path, query
            ),
            "trust_range": trust_range,
            "reports": current_reports[:200],
            "activity": [
                item
                for item in activity
                if isinstance(item, dict)
                and (
                    not run_start
                    or self._event_timestamp(item.get("timestamp"))
                    >= run_start
                )
            ],
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

    def _send_reviewed_flow_export(self) -> None:
        """Stream a tab separated flow download without loading it into memory."""
        fields = (
            "uid",
            "flow",
            "label",
            "profileid",
            "twid",
            "aid",
            "event_time",
            "retention_class",
            "human_review",
        )
        self.send_response(HTTPStatus.OK)
        self.send_header(
            "Content-Type", "text/tab-separated-values; charset=utf-8"
        )
        self.send_header(
            "Content-Disposition", 'attachment; filename="reviewed_flows.tsv"'
        )
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        buffer = io.StringIO()
        writer = csv.writer(buffer, delimiter="\t")
        writer.writerow(fields)
        try:
            for index, row in enumerate(
                self.server.reader.iter_reviewed_flows(), 1
            ):
                writer.writerow([row.get(field, "") for field in fields])
                if index % 100 == 0:
                    self.wfile.write(buffer.getvalue().encode("utf-8"))
                    buffer.seek(0)
                    buffer.truncate(0)
            if buffer.tell():
                self.wfile.write(buffer.getvalue().encode("utf-8"))
        except ConnectionError:
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
        archive = query.get("archive", [""])[0]
        if archive:
            if not path.startswith(
                ("/api/evidence", "/api/alerts", "/api/hosts", "/api/flows")
            ):
                raise KeyError("This endpoint does not support archives")
            reader = reader.with_archive(
                archive,
                context=path.startswith(("/api/alerts", "/api/flows/"))
                or path.endswith("/flows"),
            )
            if path.startswith("/api/evidence/") and path.endswith("/flows"):
                reader.archive_evidence_id = unquote(
                    path[len("/api/evidence/") : -len("/flows")]
                )
        if path == "/api/identity":
            payload = reader.identity()
        elif path == "/api/archives":
            payload = reader.archives()
        elif path == "/api/live-counts":
            payload = reader.live_counts(query)
        elif path == "/api/overview":
            payload = reader.overview(query)
        elif path == "/api/overview/evidence-counts":
            payload = reader.overview_evidence_counts(query)
        elif path == "/api/metadata":
            payload = reader.metadata()
        elif path == "/api/logs":
            payload = reader.logs(query)
        elif path == "/api/metrics":
            payload = reader.metrics(query)
        elif path == "/api/alerts":
            payload = reader.alerts(query)
        elif path == "/api/evidence":
            payload = reader.evidence(query)
        elif path.startswith("/api/flows/"):
            uid = unquote(path[len("/api/flows/") :])
            payload = reader.flow_details(uid, query)
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
            payload = (
                reader.flows_for_evidence(evidence_id, query)
                if query
                else reader.flows_for_evidence(evidence_id)
            )
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
            payload = reader.host(ip, query)
        else:
            raise KeyError(path)
        if isinstance(payload, dict):
            payload.update(reader.response_metadata())
        return payload

    UNAUTHENTICATED_PATHS = {
        "/login",
        "/style.css",
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
        if parsed.path == "/api/flows/export":
            try:
                self.server.reader.validate_run_identity()
            except RunMismatchError as error:
                self._send_json(
                    {"error": "Run mismatch", "detail": str(error)},
                    HTTPStatus.CONFLICT,
                )
                return
            self._send_reviewed_flow_export()
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
            if parse_qs(parsed.query).get("archive"):
                self._send_json(
                    {"error": "Detection archives are read-only"},
                    HTTPStatus.BAD_REQUEST,
                )
                return
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
            "/api/alert-review",
            "/api/evidence-review",
        }:
            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
            return
        if (
            path
            in {"/api/whitelists", "/api/alert-review", "/api/evidence-review"}
            and not ipaddress.ip_address(self.client_address[0]).is_loopback
            and not self._require_password()
        ):
            self._send_json(
                {"error": "Remote whitelist changes require web login"},
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
                arguments = (
                    payload.get("action"),
                    payload.get("value"),
                    payload.get("direction"),
                    payload.get("ignore"),
                )
                if payload.get("evidence_type"):
                    arguments += (payload["evidence_type"],)
                if payload.get("rule_type") == "uri":
                    if len(arguments) == 4:
                        arguments += (None,)
                    arguments += ("uri",)
                saved = self.server.reader.save_whitelist_rule(*arguments)
            elif path in {"/api/alert-review", "/api/evidence-review"}:
                saved = self.server.reader.save_review(
                    "alert" if path == "/api/alert-review" else "evidence",
                    payload,
                )
            elif path == "/api/host-annotation":
                saved = self.server.reader.save_host_annotation(
                    payload.get("ip"),
                    payload.get("network_id"),
                    payload.get("name"),
                    payload.get("note"),
                    **(
                        {
                            "status": payload.get("status"),
                            "labels": payload.get("labels"),
                        }
                        if "status" in payload or "labels" in payload
                        else {}
                    ),
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
    policy = ConfigParser().detection_history_policy(
        reader._run_config()[0].get("detection_history", {})
    )
    stream = RotatingTextLog(
        Path(args.output_dir) / "web_interface" / "server.log", policy
    )
    sys.stdout = stream
    sys.stderr = stream
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
