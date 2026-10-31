"""Validated behavior thresholds and resource limits for SMB analysis."""

import ipaddress
import math
from dataclasses import dataclass, field, fields
from typing import Any

from modules.supported_module_names import Modules

RULES = {
    "SMB_SCAN": ("medium", 0.85),
    "SMB_SHARE_SWEEP": ("medium", 0.8),
    "SMB_SHARE_PATH_MISMATCH": ("medium", 0.75),
    "SMB_SHARE_IP_MISMATCH": ("low", 0.9),
    "SMB_SUSPECTED_PROPAGATION": ("high", 0.9),
    "SMB_EXTERNAL_CONNECTION": ("low", 0.8),
    "SMB_LARGE_TRANSFER": ("info", 0.95),
    "SMB_LARGE_FILE": ("info", 0.8),
    "SMB_SUSPICIOUS_TRANSFER": ("high", 0.85),
    "SMB_REMOTE_EXECUTION": ("high", 0.85),
    "SMB_PASSWORD_GUESSING": ("medium", 0.85),
    "SMB_PASSWORD_SPRAYING": ("high", 0.85),
    "SMB_RAPID_FILE_CHANGES": ("medium", 0.8),
    "SMB_RANSOMWARE_BEHAVIOR": ("high", 0.85),
}


@dataclass(frozen=True)
class Settings:
    """Keep all detection decisions and resource ceilings explicit."""

    enabled: bool = True
    log_file_operations: bool = True
    log_authentication_failures: bool = True
    ports: list[int] = field(default_factory=lambda: [139, 445])
    window_seconds: float = 60
    correlation_seconds: float = 900
    max_lateness_seconds: float = 1800
    scan_min_hosts: int = 20
    scan_min_failure_ratio: float = 0.8
    share_min_hosts: int = 8
    share_min_names: int = 10
    mismatch_min_hosts: int = 3
    propagation_min_hosts: int = 20
    large_transfer_bytes: int = 4 * 1024 * 1024
    large_file_bytes: int = 100 * 1024 * 1024
    auth_min_failures: int = 10
    authentication_failure_statuses: list[str] = field(
        default_factory=lambda: [
            "LOGON_FAILURE",
            "WRONG_PASSWORD",
            "NO_SUCH_USER",
        ]
    )
    spray_min_accounts: int = 5
    spray_min_hosts: int = 5
    file_change_min_files: int = 30
    ransomware_min_renames: int = 20
    ransomware_min_other_changes: int = 10
    executable_extensions: list[str] = field(
        default_factory=lambda: [
            ".exe",
            ".dll",
            ".scr",
            ".ps1",
            ".bat",
            ".cmd",
            ".vbs",
            ".msi",
        ]
    )
    external_allowed_networks: list[str] = field(default_factory=list)
    admin_shares: list[str] = field(default_factory=lambda: ["admin$", "c$"])
    remote_service_operations: list[str] = field(
        default_factory=lambda: [
            "CreateServiceW",
            "CreateServiceA",
            "CreateServiceWOW64W",
            "StartServiceW",
            "StartServiceA",
        ]
    )
    cooldown_seconds: float = 300
    evaluation_interval_seconds: float = 1
    max_sources: int = 256
    max_events_per_source: int = 2048
    max_total_events: int = 32768
    max_sessions: int = 4096
    max_cooldowns: int = 4096
    rules: dict[str, dict] = field(default_factory=dict)

    @classmethod
    def from_config(cls, conf: Any) -> "Settings":
        """Read YAML settings, rejecting invalid thresholds before processing.

        :param conf: Slips configuration reader.
        :return: Validated SMB settings.
        """
        defaults = cls()
        result = cls(
            **{
                f.name: conf.read_configuration(
                    Modules.SMB_ANALYZER.value,
                    f.name,
                    getattr(defaults, f.name),
                )
                for f in fields(cls)
            }
        )
        result.validate()
        return result

    def validate(self) -> None:
        """Reject unsafe types, impossible thresholds and unknown rule names."""
        for f in fields(self):
            value = getattr(self, f.name)
            if f.name in {
                "enabled",
                "log_file_operations",
                "log_authentication_failures",
            }:
                if not isinstance(value, bool):
                    raise ValueError(f"smb_analyzer.{f.name} must be boolean")
            elif f.name == "rules":
                if not isinstance(value, dict) or set(value) - set(RULES):
                    raise ValueError("Unknown SMB rule configuration")
            elif isinstance(getattr(Settings(), f.name), list):
                if not isinstance(value, list):
                    raise ValueError(f"smb_analyzer.{f.name} must be a list")
            elif (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(
                    f"smb_analyzer.{f.name} must be a finite positive number"
                )
            elif isinstance(
                getattr(Settings(), f.name), int
            ) and not isinstance(value, int):
                raise ValueError(f"smb_analyzer.{f.name} must be an integer")
        if self.scan_min_failure_ratio > 1:
            raise ValueError("scan_min_failure_ratio must be at most 1")
        if (
            self.correlation_seconds < self.window_seconds
            or self.max_lateness_seconds < self.window_seconds
        ):
            raise ValueError(
                "SMB correlation and lateness must cover window_seconds"
            )
        if not self.ports or any(
            type(p) is not int or not 1 <= p <= 65535 for p in self.ports
        ):
            raise ValueError("SMB ports must be between 1 and 65535")
        for name in (
            "admin_shares",
            "remote_service_operations",
            "executable_extensions",
            "external_allowed_networks",
            "authentication_failure_statuses",
        ):
            if any(
                not isinstance(v, str) or not v for v in getattr(self, name)
            ):
                raise ValueError(f"{name} must contain nonempty strings")
        for network in self.external_allowed_networks:
            ipaddress.ip_network(network, strict=False)
        for name in (
            "scan_min_hosts",
            "share_min_hosts",
            "share_min_names",
            "mismatch_min_hosts",
            "propagation_min_hosts",
            "auth_min_failures",
            "file_change_min_files",
            "ransomware_min_renames",
            "ransomware_min_other_changes",
            "spray_min_accounts",
            "spray_min_hosts",
        ):
            if (
                getattr(self, name) < 2
                or getattr(self, name) > self.max_events_per_source
            ):
                raise ValueError(
                    f"{name} must be between 2 and max_events_per_source"
                )
        for name in (
            "max_sources",
            "max_events_per_source",
            "max_total_events",
            "max_sessions",
            "max_cooldowns",
        ):
            if getattr(self, name) > 1000000:
                raise ValueError(f"{name} cannot exceed 1000000")
        if self.max_total_events < self.max_events_per_source:
            raise ValueError(
                "max_total_events must cover max_events_per_source"
            )
        for name, options in self.rules.items():
            if not isinstance(options, dict) or set(options) - {
                "enabled",
                "threat_level",
                "confidence",
            }:
                raise ValueError(f"Invalid options for {name}")
            enabled, threat, confidence = self.rule(name)
            if (
                type(enabled) is not bool
                or threat not in {"info", "low", "medium", "high", "critical"}
                or type(confidence) not in (float, int)
                or not math.isfinite(confidence)
                or not 0 <= confidence <= 1
            ):
                raise ValueError(
                    f"Invalid enabled/threat_level/confidence for {name}"
                )

    def rule(self, name: str) -> tuple[bool, str, float]:
        """Return severity and initial scan confidence, fixed for other rules.

        :param name: Registered evidence type.
        :return: Enabled flag, severity and confidence, with default values.
        """
        values = self.rules.get(name, {})
        threat, confidence = RULES[name]
        return (
            values.get("enabled", True),
            values.get("threat_level", threat),
            values.get("confidence", confidence),
        )
