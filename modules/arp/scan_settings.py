"""Validated limits for ARP discovery and relationship history."""

import math
from dataclasses import dataclass, fields
from typing import Any

from modules.supported_module_names import Modules


ARP_SCAN_EXPLANATIONS = {
    "scan_window_seconds": "Seconds of requests counted together. Each target expires separately, so old questions cannot inflate a fresh burst.",
    "scan_min_targets": "Distinct targets needed before examining a burst. Repeated requests count once; this candidate count alone never produces scan evidence.",
    "scan_min_unfamiliar_targets": "Minimum targets without prior successful source-specific use for a scan. Without source history, this many targets must also be previously unobserved on the network.",
    "scan_min_unfamiliar_ratio": "Required unfamiliar share, from 0 to 1. For example 0.8 means 80%; a few new neighbours among familiar ones should not cause a scan finding.",
    "scan_broad_targets": "This many unfamiliar targets can establish a large search without an ordered sequence. A burst this large lacking enough scan indicators becomes informational ARP_DISCOVERY, which does not increase scores.",
    "scan_ordered_ratio": "Required share of successive distinct requests to adjacent IPs. Supports smaller ordered sweeps; large unfamiliar searches can be detected in random order.",
    "scan_context_wait_seconds": "Brief wait after a burst becomes a candidate, allowing arriving replies and application traffic to add context. Missing traffic remains unknown, not a failure.",
    "scan_alert_cooldown_seconds": "Minimum seconds between repeated findings for one source device/address/network. A scan can supersede informational discovery sooner, without waiting for the cooldown.",
    "scan_familiar_min_interval_seconds": "Two successful TCP/UDP contacts must be separated by this many seconds before a neighbour becomes familiar. Both directions need application bytes; ARP questions and empty probes never train history.",
    "scan_familiar_retention_days": "Expire contact history after this many days without successful use. Live contacts survive restarts and remain separate for each source MAC, gateway and subnet.",
    "scan_checkpoint_seconds": "Seconds between dirty contact-history saves. No disk writes occur per packet. Clean stops save immediately; a crash can lose learning since the last save.",
    "scan_max_sources": "Maximum source device/address/network request groups in memory. At capacity, discard oldest-used groups and warn that some context has been lost.",
    "scan_max_targets": "Maximum distinct targets and representative request IDs per source group. At capacity, discard oldest-used targets and mark evidence counts as partial.",
    "scan_max_relationships": "Maximum source-to-neighbour records, and separate limits on observed senders, source-history and duplicate-flow caches. Higher limits preserve more history at a memory and checkpoint-space cost.",
}


@dataclass(frozen=True)
class ARPScanSettings:
    """Keep scan decisions and resource use bounded."""

    scan_window_seconds: float = 30
    scan_min_targets: int = 5
    scan_min_unfamiliar_targets: int = 10
    scan_min_unfamiliar_ratio: float = 0.8
    scan_broad_targets: int = 32
    scan_ordered_ratio: float = 0.7
    scan_context_wait_seconds: float = 3
    scan_alert_cooldown_seconds: float = 300
    scan_familiar_min_interval_seconds: float = 300
    scan_familiar_retention_days: float = 30
    scan_checkpoint_seconds: float = 120
    scan_max_sources: int = 256
    scan_max_targets: int = 512
    scan_max_relationships: int = 8192

    @classmethod
    def from_config(cls, conf: Any) -> "ARPScanSettings":
        """Read and validate the arp section.

        Parameters:
            conf: Slips configuration reader.

        Returns:
            Validated settings with defaults for omitted keys.
        """
        settings = cls(
            **{
                item.name: conf.read_configuration(
                    Modules.ARP.value, item.name, item.default
                )
                for item in fields(cls)
            }
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        """Reject invalid periods, counts and memory limits."""
        bounds = {
            "scan_window_seconds": (1, 3600),
            "scan_min_targets": (2, 4096),
            "scan_min_unfamiliar_targets": (2, 4096),
            "scan_min_unfamiliar_ratio": (0.5, 1),
            "scan_broad_targets": (2, 4096),
            "scan_ordered_ratio": (0.5, 1),
            "scan_context_wait_seconds": (0, 60),
            "scan_alert_cooldown_seconds": (1, 86400),
            "scan_familiar_min_interval_seconds": (1, 86400),
            "scan_familiar_retention_days": (1, 365),
            "scan_checkpoint_seconds": (10, 3600),
            "scan_max_sources": (1, 4096),
            "scan_max_targets": (2, 4096),
            "scan_max_relationships": (1, 65536),
        }
        for name, (minimum, maximum) in bounds.items():
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not minimum <= value <= maximum
            ):
                raise ValueError(
                    f"arp.{name} must be between {minimum} and {maximum}"
                )
            if name.endswith(
                ("targets", "sources", "relationships")
            ) and not isinstance(value, int):
                raise ValueError(f"arp.{name} must be a whole number")
        if (
            not self.scan_min_targets
            <= self.scan_min_unfamiliar_targets
            <= self.scan_broad_targets
            <= self.scan_max_targets
        ):
            raise ValueError(
                "ARP counts must satisfy min_targets <= min_unfamiliar_targets <= broad_targets <= max_targets"
            )
