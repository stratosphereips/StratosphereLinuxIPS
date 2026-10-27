"""Resource and sensitivity limits for recurring connection detection."""

import math
from dataclasses import dataclass, fields
from typing import Any

from modules.supported_module_names import Modules


@dataclass(frozen=True)
class Settings:
    """Bound the amount of traffic retained and the work done per channel."""

    min_connections: int = 12
    window_connections: int = 128
    min_span_seconds: float = 30.0
    min_period_seconds: float = 0.1
    max_period_seconds: float = 86400.0
    jitter_tolerance: float = 0.25
    min_support: float = 0.8
    max_missed: int = 2
    evaluate_every: int = 4
    evaluate_interval_seconds: float = 5.0
    max_channels: int = 2048
    max_candidates: int = 4096
    report_growth_factor: int = 10
    stable_evaluate_every: int = 32
    stable_evaluate_interval_seconds: float = 60.0
    retention_hours: float = 72.0
    alert_cooldown_seconds: float = 3600.0
    flush_interval_seconds: float = 30.0
    model_file: str = "modules/beaconing/model.json"
    c2_score_threshold: float = 0.5

    @classmethod
    def from_config(cls, conf: Any) -> "Settings":
        """Read validated YAML options.

        Parameters:
            conf: Slips configuration parser.

        Returns:
            Validated detector settings.
        """
        values = {
            f.name: conf.read_configuration(
                Modules.BEACONING.value, f.name, f.default
            )
            for f in fields(cls)
        }
        result = cls(**values)
        result.validate()
        return result

    def validate(self) -> None:
        """Reject nonfinite values, wrong types and unsafe resource limits."""
        bounds = {
            "min_connections": (6, 512),
            "window_connections": (12, 512),
            "min_span_seconds": (0, 31536000),
            "min_period_seconds": (0.001, 86400),
            "max_period_seconds": (0.001, 604800),
            "jitter_tolerance": (0.01, 0.45),
            "min_support": (0.6, 1),
            "max_missed": (0, 4),
            "evaluate_every": (1, 128),
            "evaluate_interval_seconds": (0, 3600),
            "max_channels": (16, 16384),
            "max_candidates": (16, 65536),
            "report_growth_factor": (2, 100),
            "stable_evaluate_every": (1, 512),
            "stable_evaluate_interval_seconds": (0, 3600),
            "retention_hours": (1, 8760),
            "alert_cooldown_seconds": (1, 2592000),
            "flush_interval_seconds": (5, 300),
            "c2_score_threshold": (0.5, 1),
        }
        for f in fields(self):
            value = getattr(self, f.name)
            if isinstance(f.default, str):
                if not isinstance(value, str):
                    raise ValueError(f"{f.name} must be a filename")
                continue
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise ValueError(f"{f.name} must be a finite number")
            if isinstance(f.default, int) and not isinstance(value, int):
                raise ValueError(f"{f.name} must be an integer")
            if not bounds[f.name][0] <= value <= bounds[f.name][1]:
                raise ValueError(
                    f"{f.name} must be between {bounds[f.name][0]} and {bounds[f.name][1]}"
                )
        if self.window_connections < self.min_connections:
            raise ValueError("window_connections must cover min_connections")
        if self.max_period_seconds < self.min_period_seconds:
            raise ValueError(
                "max_period_seconds must cover min_period_seconds"
            )
        if self.retention_hours * 3600 < self.max_period_seconds:
            raise ValueError("retention_hours must cover max_period_seconds")
