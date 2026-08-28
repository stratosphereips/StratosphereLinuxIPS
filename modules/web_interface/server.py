# SPDX-License-Identifier: GPL-2.0-only
"""Serve the run-scoped Slips web interface."""

import argparse
import base64
import ipaddress
import json
import math
import os
import re
import socket
import sqlite3
import time
import traceback
from datetime import datetime
from collections import Counter, defaultdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import parse_qs, unquote, urlparse

import psutil
import redis
import yaml

from modules.web_interface.history import connect_history, initialize_history

LOOPBACK_ADDRESS = "127.0.0.1"
PROFILE_PREFIX = "profile_"
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 100
MAX_FLOW_LIMIT = 1000
MAX_CHART_POINTS = 1200
CLIENT_REQUEST_TIMEOUT_SECONDS = 15
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
    "ARP_SCAN": "arp",
    "ARP_OUTSIDE_LOCALNET": "arp",
    "UNSOLICITED_ARP": "arp",
    "MITM_ARP_ATTACK": "arp",
    "PASSWORD_GUESSING": "brute_force_detector",
    "ANOMALOUS_FLOW": "anomaly_detection_https",
    "SUSPICIOUS_USER_AGENT": "http_analyzer",
    "EMPTY_CONNECTIONS": "http_analyzer",
    "INCOMPATIBLE_USER_AGENT": "http_analyzer",
    "EXECUTABLE_MIME_TYPE": "http_analyzer",
    "MULTIPLE_USER_AGENT": "http_analyzer",
    "HTTP_TRAFFIC": "http_analyzer",
    "MALICIOUS_JARM": "ip_info",
    "NETWORK_GPS_LOCATION_LEAKED": "leak_detector",
    "HORIZONTAL_PORT_SCAN": "network_discovery",
    "VERTICAL_PORT_SCAN": "network_discovery",
    "ICMP_TIMESTAMP_SCAN": "network_discovery",
    "ICMP_ADDRESS_SCAN": "network_discovery",
    "ICMP_ADDRESS_MASK_SCAN": "network_discovery",
    "DHCP_SCAN": "network_discovery",
    "COMMAND_AND_CONTROL_CHANNEL": "rnn_cc_detection",
    "MALICIOUS_IP_FROM_P2P_NETWORK": "p2p_trust",
    "P2P_REPORT": "p2p_trust",
}  # pragma: allowlist secret
MODULE_BY_EVIDENCE_PREFIX = {
    "ARP_": "arp",
    "HTTP_": "http_analyzer",
    "ML_LINEAR_": "ml_linear_model",
    "ML_ONLINE_": "ml_online_model",
    "PORT_SCAN": "network_discovery",
    "VERTICAL_PORT_SCAN": "network_discovery",
    "HORIZONTAL_PORT_SCAN": "network_discovery",
    "RNN_": "rnn_cc_detection",
    "LEAK": "leak_detector",
    "MALICIOUS_JARM": "ip_info",
    "THREAT_INTELLIGENCE": "threat_intelligence",
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


class RunMismatchError(RuntimeError):
    """Raised when Redis belongs to a different Slips output directory."""


class RunDataReader:
    """Read bounded live and historical data for exactly one Slips run."""

    def __init__(self, redis_port: int, output_dir: str) -> None:
        """
        Initialize run data sources.

        Parameters:
            redis_port: Redis port assigned to this run.
            output_dir: Output directory assigned to this run.
        """
        self.redis_port = redis_port
        self.output_dir = Path(output_dir)
        self.sqlite_path = self.output_dir / "databases" / "flows.sqlite"
        self.history_path = (
            self.output_dir / "web_interface" / "history.sqlite"
        )
        self.redis = redis.Redis(
            host=LOOPBACK_ADDRESS,
            port=redis_port,
            db=0,
            decode_responses=True,
            socket_timeout=2,
        )
        self.cache = redis.Redis(
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
        candidates: List[tuple[str, str, str, Any]] = []
        for role in ("attacker", "victim"):
            entity = record.get(role)
            if not isinstance(entity, dict):
                continue
            direction = entity.get("direction")
            value = entity.get("value")
            indicator = str(entity.get("ioc_type") or "").upper()
            if value and indicator == "IP":
                candidates.append((role, "IP address", str(value), direction))
            if value and indicator == "DOMAIN":
                candidates.append((role, "Domain", str(value), "dst"))
            for ip in entity.get("DNS_resolution") or []:
                candidates.append((role, "IP address", str(ip), direction))
            domains = list(entity.get("queries") or [])
            domains.extend(entity.get("CNAME") or [])
            if entity.get("SNI"):
                domains.append(entity["SNI"])
            for domain in domains:
                candidates.append((role, "Domain", str(domain), "dst"))
        matches = []
        seen = set()
        for role, type_name, value, direction in candidates:
            for rule in rules:
                if rule.get("type") != type_name:
                    continue
                rule_value = str(rule.get("value") or "")
                value_matches = value == rule_value
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

        Parameters:
            items: Individual or grouped evidence API records.
        """
        if not items:
            return
        identifiers: List[str] = []
        for item in items:
            grouped = item.get("_evidence_ids")
            if isinstance(grouped, list):
                identifiers.extend(str(value) for value in grouped)
            elif item.get("id"):
                identifiers.append(str(item["id"]))
        live_members: set[str] = set()
        try:
            pipeline = self.redis.pipeline(transaction=False)
            for evidence_id in identifiers:
                pipeline.sismember("whitelisted_evidence", evidence_id)
            live_members = {
                evidence_id
                for evidence_id, member in zip(identifiers, pipeline.execute())
                if member is True or member == 1
            }
        except (redis.RedisError, StopIteration, TypeError):
            pass
        rules = self._runtime_whitelist_rules()
        for item in items:
            grouped_ids = item.pop("_evidence_ids", None)
            if isinstance(grouped_ids, list):
                live_count = sum(
                    evidence_id in live_members for evidence_id in grouped_ids
                )
                count = max(
                    int(item.get("whitelisted_count") or 0), live_count
                )
                item["whitelisted"] = count > 0
                item["whitelisted_count"] = count
                continue
            persisted = item.get("whitelisted") in (True, 1, "1")
            evidence_id = str(item.get("id") or "")
            item["whitelisted"] = persisted or evidence_id in live_members
            item["whitelist_matches"] = (
                self._whitelist_matches_for_record(item, rules)
                if item["whitelisted"]
                else []
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
    def _module_for_evidence(evidence_type: str) -> str:
        """Infer the producing module from a canonical evidence type."""
        if evidence_type in EVIDENCE_MODULE:
            return EVIDENCE_MODULE[evidence_type]
        for prefix, module in MODULE_BY_EVIDENCE_PREFIX.items():
            if evidence_type.startswith(prefix):
                return module
        return "flow_alerts"

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

    @classmethod
    def _time_bounds(
        cls,
        query: Dict[str, List[str]],
        latest_event: Optional[float] = None,
    ) -> tuple[Optional[float], Optional[float], str]:
        """
        Resolve named or custom time bounds against the data clock.

        Parameters:
            query: Request query-string values.
            latest_event: Newest event timestamp for offline data.

        Returns:
            Start, end, and normalized range name.
        """
        range_name = cls._query_value(query, "range", "live")
        now = float(latest_event or time.time())
        if range_name in TIME_RANGES:
            return now - TIME_RANGES[range_name], now, range_name
        if range_name in {"all", "full"}:
            return None, now, "all"
        if range_name == "custom":
            try:
                start = float(cls._query_value(query, "from"))
            except ValueError:
                start = None
            try:
                end = float(cls._query_value(query, "to"))
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
                    "'error_log_name')"
                ).fetchall()
            }
        return {
            "run_identity": {
                "output_dir": str(self.output_dir),
                "server_pid": os.getpid(),
            },
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
                evidence.update(
                    {
                        "id": canonical_id,
                        "profile_ip": profile_ip
                        or profile_id.removeprefix(PROFILE_PREFIX),
                        "twid": f"timewindow{twid}",
                        "module": self._module_for_evidence(evidence_type),
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
                "module": self._module_for_evidence(evidence_type),
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
                f"MAX({threat_expression}) AS threat_rank, "
                "evidence_module(evidence_type) AS module, "
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
        self._annotate_whitelisted_evidence(items)
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
                connection.create_function(
                    "evidence_module", 1, self._module_for_evidence
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
                        "module": (
                            "LOWER(evidence_module(COALESCE(evidence_type, '')))"
                        ),
                        "confidence": "confidence",
                        "flows": flow_expression,
                        "alert": alert_expression,
                        "score": score_expression,
                    },
                    "time",
                )
                clauses = ["1 = 1"]
                params: List[Any] = []
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
                        "LOWER(COALESCE(evidence_module(COALESCE(evidence_type, '')), '')) LIKE ? OR "
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
        self._annotate_whitelisted_evidence(items)
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
                        return [str(row["uid"]) for row in rows]
        except sqlite3.Error:
            pass
        return self._id_list(
            self.redis.hget("flows_causing_evidence", evidence_id)
        )

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
                "network_flow_total": 0,
                "protocol_flow_total": 0,
                "page_size": 0,
            }
        bounded_uids = list(dict.fromkeys(uids))[:MAX_FLOW_LIMIT]
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
            "network_flow_total": network_flow_total,
            "protocol_flow_total": protocol_flow_total,
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
        items: List[Dict[str, Any]] = []
        for row in rows[:limit]:
            host = self._live_host(str(row["ip"]))
            host["observed_at"] = float(row["observed_at"])
            host["peak_alert_score"] = (
                float(row["peak_alert_score"])
                if row["peak_alert_score"] is not None
                else None
            )
            host["load"] = self._host_load(str(row["ip"]))
            host.update(
                self._ip_context_for_ip(str(host["ip"]), host.get("dns"))
            )
            host["evidence_count"] = self._profile_evidence_count(
                str(row["ip"])
            )
            host["alert_count"] = self._profile_alert_count(str(row["ip"]))
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
                f"SELECT MAX(event_time) AS latest FROM flow_index WHERE {predicate}",
                params,
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
        if cursor:
            clauses.append("(event_time < ? OR (event_time = ? AND uid < ?))")
            params.extend([cursor[0], cursor[0], cursor[1]])
        where = " AND ".join(clauses)
        with connect_history(self.history_path, read_only=True) as history:
            count_clauses = clauses[:-1] if cursor else clauses
            count_params = params[:-3] if cursor else params
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
                f"SELECT MAX(event_time) AS latest FROM flow_index WHERE {predicate}",
                params,
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
                f"SELECT MAX(evidence_time) AS latest FROM evidence "
                f"WHERE profile_ip IN ({placeholders})",
                ips,
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
                    reset_reason = "score reset after an alert"
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
        evidence_counts: Counter[str],
        error_counts: Dict[str, int],
        analysis_complete: bool,
    ) -> List[Dict[str, Any]]:
        """Build bounded process health rows for current module PIDs."""
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
                process = self._processes.setdefault(pid, psutil.Process(pid))
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
                    "evidence_count": evidence_counts.get(name, 0),
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
        rows = connection.execute(
            "SELECT evidence_type, COUNT(*) AS count FROM evidence "
            "GROUP BY evidence_type"
        ).fetchall()
        counts: Counter[str] = Counter()
        for row in rows:
            module = self._module_for_evidence(
                str(row["evidence_type"] or "unknown")
            )
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

    def overview(self) -> Dict[str, Any]:
        """Build a bounded current-run operational overview."""
        analysis = self.redis.hgetall("analysis")
        complete = bool(analysis.get("analysis_end"))
        durable_evidence_counts: Counter[str] = Counter()
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
                durable_evidence_counts = self._durable_evidence_counts(
                    connection
                )
        except sqlite3.Error:
            alert_count = 0
            durable_evidence = 0
        redis_evidence = [] if durable_evidence else self._redis_evidence()
        evidence_count = durable_evidence or len(redis_evidence)
        evidence_counts = durable_evidence_counts or Counter(
            str(item.get("module", "unknown")) for item in redis_evidence
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
        firewall = self._firewall_overview()
        return {
            "run": {
                **analysis,
                "state": "complete" if complete else "running",
                "redis_port": self.redis_port,
                "output_dir": str(self.output_dir),
            },
            "run_metadata": self._run_metadata(),
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
            "modules": self._module_rows(
                evidence_counts, error_counts, complete
            ),
            "recent_errors": recent_errors,
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
        log_path = self.output_dir / "blocking" / "blocking.log"
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

    def p2p(self) -> Dict[str, Any]:
        """Return live P2P connectivity, report activity, and trust history."""
        connected_raw = self._loads(self.redis.get("connected_peers"), [])
        connected = set(
            connected_raw if isinstance(connected_raw, list) else []
        )
        peer_info = {
            peer_id: self._loads(raw, {})
            for peer_id, raw in self.redis.hgetall("peer_info").items()
        }
        peer_trust = self.redis.hgetall("peer_trust")
        peer_seen = dict(
            self.redis.zrange("peers_strust", 0, -1, withscores=True)
        )
        counts = {
            key: int(value)
            for key, value in self.redis.hgetall("p2p_message_counts").items()
        }
        activity = [
            self._loads(raw, {})
            for raw in self.redis.lrange("p2p_message_history", 0, 199)
        ]
        analysis = self.redis.hgetall("analysis")
        run_start = self._event_timestamp(analysis.get("analysis_start"))
        trust_path = Path("permanent") / "p2p_trust_runtime" / "trustdb.db"
        trust_history: List[Dict[str, Any]] = []
        reports: List[Dict[str, Any]] = []
        peer_ips: Dict[str, Dict[str, Any]] = {}
        if trust_path.exists():
            try:
                with sqlite3.connect(
                    f"file:{trust_path}?mode=ro", uri=True, timeout=5
                ) as connection:
                    connection.row_factory = sqlite3.Row
                    for row in connection.execute(
                        "SELECT peerid, reliability, update_time FROM go_reliability "
                        "ORDER BY update_time DESC LIMIT 500"
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
            except sqlite3.Error:
                pass
        report_counts = Counter(item["peer_id"] for item in reports)
        latest_reliability: Dict[str, Dict[str, Any]] = {}
        for item in trust_history:
            latest_reliability.setdefault(item["peer_id"], item)
        peer_ids = (
            set(peer_info)
            | set(peer_ips)
            | set(latest_reliability)
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
            peers.append(
                {
                    "peer_id": peer_id,
                    "ip": ip,
                    "connected": peer_id in connected,
                    "trust": (
                        float(peer_trust[ip]) if ip in peer_trust else None
                    ),
                    "reliability": reliability.get("reliability"),
                    "last_seen": max(
                        float(peer_seen.get(peer_id, 0)),
                        float(pairing.get("timestamp") or 0),
                        float(reliability.get("timestamp") or 0),
                    ),
                    "reports_received": report_counts[peer_id],
                }
            )
        peers.sort(
            key=lambda item: (
                not item["connected"],
                -item["last_seen"],
                item["peer_id"],
            )
        )
        p2p_log = self.output_dir / "p2p_trust" / "p2p.log"
        listener = ""
        local_peer_id = ""
        try:
            log_tail = p2p_log.read_text(encoding="utf-8", errors="replace")[
                -65536:
            ]
            matches = re.findall(r"(/ip4/[^\s]+/p2p/([^\s]+))", log_tail)
            if matches:
                listener, local_peer_id = matches[-1]
        except OSError:
            pass
        current_reports = [item for item in reports if item["this_run"]]
        return {
            "enabled": bool(self.redis.hget("PIDs", "p2p_trust"))
            or p2p_log.exists(),
            "listener": listener,
            "local_peer_id": local_peer_id,
            "peers": peers,
            "trust_history": trust_history,
            "reports": current_reports[:200],
            "activity": [item for item in activity if isinstance(item, dict)],
            "counts": {
                "connected": len(connected),
                "known": len(peers),
                "reports_sent": counts.get("sent:report", 0)
                + counts.get("sent:blame", 0),
                "reports_received": len(current_reports),
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
    """Serve exact static assets and bounded read-only JSON APIs."""

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
        self.send_response(status)
        """Send a JSON response with local-interface security headers."""
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
        self.end_headers()
        self.wfile.write(body)

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
        elif path == "/api/firewall":
            payload = reader.firewall(query)
        elif path == "/api/p2p":
            payload = reader.p2p()
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

    def do_GET(self) -> None:
        """Serve an allow-listed static asset or API response."""
        parsed = urlparse(self.path)
        assets = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "/style.css": ("style.css", "text/css; charset=utf-8"),
            "/favicon.png": (
                Path(__file__).parents[2]
                / "docs"
                / "images"
                / "slips_logo.png",
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
    return parser.parse_args()


def main() -> None:
    """Start the single-run server on the configured IPv4 address."""
    args = parse_arguments()
    reader = RunDataReader(args.redis_port, args.output_dir)
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
