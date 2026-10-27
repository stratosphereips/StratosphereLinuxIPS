"""Validated limits for horizontal scan detection."""

import math
from dataclasses import dataclass, fields
from typing import Any

from modules.supported_module_names import Modules


@dataclass(frozen=True)
class ScanSettings:
    """Bound rolling observation periods, evidence frequency and memory."""

    horizontal_fast_window_seconds: float = 60.0
    horizontal_slow_window_seconds: float = 1800.0
    horizontal_fast_min_targets: int = 10
    horizontal_slow_min_targets: int = 25
    horizontal_min_failure_ratio: float = 0.8
    horizontal_success_history_seconds: float = 3600.0
    horizontal_alert_cooldown_seconds: float = 300.0
    horizontal_evaluation_interval_seconds: float = 1.0
    horizontal_max_groups: int = 256
    horizontal_max_targets: int = 256
    vertical_window_seconds: float = 3600.0
    vertical_min_ports: int = 10
    vertical_alert_cooldown_seconds: float = 300.0
    vertical_max_groups: int = 256
    vertical_max_ports: int = 256
    other_scan_max_groups: int = 256
    other_scan_quiet_seconds: float = 300.0
    dhcp_min_addresses: int = 4

    @classmethod
    def from_config(cls, conf: Any) -> "ScanSettings":
        """Read options from the network discovery section.

        Parameters:
            conf: Slips configuration reader.

        Returns:
            Validated options, including defaults for omitted settings.
        """
        settings = cls(
            **{
                field.name: conf.read_configuration(
                    Modules.NETWORK_DISCOVERY.value, field.name, field.default
                )
                for field in fields(cls)
            }
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        """Reject invalid periods, thresholds and resource limits."""
        bounds = {
            "horizontal_fast_window_seconds": (1, 3600),
            "horizontal_slow_window_seconds": (1, 86400),
            "horizontal_fast_min_targets": (5, 4096),
            "horizontal_slow_min_targets": (5, 4096),
            "horizontal_min_failure_ratio": (0.5, 1),
            "horizontal_success_history_seconds": (1, 86400),
            "horizontal_alert_cooldown_seconds": (1, 86400),
            "horizontal_evaluation_interval_seconds": (0, 60),
            "horizontal_max_groups": (1, 4096),
            "horizontal_max_targets": (5, 4096),
            "vertical_window_seconds": (1, 86400),
            "vertical_min_ports": (5, 4096),
            "vertical_alert_cooldown_seconds": (1, 86400),
            "vertical_max_groups": (1, 4096),
            "vertical_max_ports": (5, 4096),
            "other_scan_max_groups": (1, 4096),
            "other_scan_quiet_seconds": (1, 86400),
            "dhcp_min_addresses": (2, 100),
        }
        for field in fields(self):
            value = getattr(self, field.name)
            low, high = bounds[field.name]
            if (
                isinstance(value, bool)
                or not isinstance(value, (float, int))
                or not math.isfinite(value)
                or not low <= value <= high
                or isinstance(field.default, int)
                and not isinstance(value, int)
            ):
                raise ValueError(
                    f"{field.name} must be between {low} and {high}"
                )
        if (
            self.horizontal_slow_window_seconds
            < self.horizontal_fast_window_seconds
        ):
            raise ValueError("The slow scan period must cover the fast period")
        if self.horizontal_max_targets < max(
            self.horizontal_fast_min_targets, self.horizontal_slow_min_targets
        ):
            raise ValueError(
                "horizontal_max_targets must cover both target thresholds"
            )
        if self.vertical_max_ports < self.vertical_min_ports:
            raise ValueError(
                "vertical_max_ports must cover vertical_min_ports"
            )
