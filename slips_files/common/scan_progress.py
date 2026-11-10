"""Shared, bounded progress reporting for scan detection workers."""

import hashlib
import math
from collections import OrderedDict
from dataclasses import dataclass, field
from collections.abc import Iterable


class DistinctTargets:
    """Count distinct values with 1,024 registers, never expanding ID lists."""

    def __init__(self) -> None:
        """Initialize a one-KiB counter with an incrementally maintained sum."""
        self.registers = bytearray(1024)
        self.harmonic = 1024.0
        self.zeros = 1024

    def add(self, address: str) -> None:
        """Update one register in constant time; duplicate IPs do not add up.

        Parameters:
            address: Canonical target, port or share identifier from a validated event.
        """
        value = int.from_bytes(
            hashlib.blake2b(address.encode(), digest_size=8).digest(), "big"
        )
        index = value & 1023
        rank = 55 - (value >> 10).bit_length()
        previous = self.registers[index]
        if rank > previous:
            self.harmonic += math.ldexp(1.0, -rank) - math.ldexp(
                1.0, -previous
            )
            self.registers[index] = rank
            if previous == 0:
                self.zeros -= 1

    def estimate(self) -> int:
        """Return an approximate distinct count with typical error about 3.25%."""
        raw = (0.7213 / (1 + 1.079 / 1024)) * 1024**2 / self.harmonic
        if raw <= 2560 and self.zeros:
            raw = 1024 * math.log(1024 / self.zeros)
        return round(raw)


def scan_confidence(
    base: float,
    count: int,
    minimum: int,
    quality: float = 1.0,
    strong: bool = True,
) -> float:
    """Increase confidence from distinct corroborated observations, never retries.

    Parameters:
        base: Confidence at the detector's initial threshold.
        count: Exact distinct observations within its decision period.
        minimum: Minimum distinct observations required by that detector.
        quality: Fraction meeting its failure or novelty requirements.
        strong: Whether its independent scan-pattern checks passed.

    Returns:
        Initial confidence, at least 95%, or full confidence after strong support.
    """
    if not strong:
        return base
    if count >= max(100, 10 * minimum) and quality >= 0.95:
        return 1.0
    if count >= max(20, 2 * minimum) and quality >= 0.9:
        return max(base, 0.95)
    return base


@dataclass(slots=True)
class ConfirmedScan:
    """Fixed-size continuation state for an exactly confirmed scan pattern."""

    started: float
    last: float
    unit: str = "targets"
    counter: DistinctTargets = field(default_factory=DistinctTargets)
    samples: OrderedDict[str, str] = field(default_factory=OrderedDict)
    next_milestone: int = 1000

    @classmethod
    def seed(
        cls,
        observations: Iterable[tuple[str, str]],
        started: float,
        timestamp: float,
        unit: str = "targets",
    ) -> "ConfirmedScan":
        """Replace an exact observation collection with bounded continuation state.

        Parameters:
            observations: Distinct identifiers and representative flow IDs.
            started: Earliest observation time in the confirming set.
            timestamp: Confirmation time in capture seconds.
            unit: Human-readable meaning of the identifiers being counted.

        Returns:
            A counter seeded from the verified observations and at most 20 IDs.
        """
        result = cls(started, timestamp, unit)
        for identity, uid in observations:
            result.observe(identity, uid, timestamp)
        while result.next_milestone <= result.counter.estimate():
            result.next_milestone *= 10
        return result

    def observe(self, identity: str, uid: str, timestamp: float) -> None:
        """Count one eligible identifier without retaining an expanding list.

        Parameters:
            identity: Canonical target, port, share or requested address.
            uid: Representative supporting flow ID.
            timestamp: Observation time in capture seconds.
        """
        self.counter.add(identity)
        self.last = max(self.last, timestamp)
        self.samples[identity] = uid
        self.samples.move_to_end(identity)
        if len(self.samples) > 20:
            self.samples.popitem(last=False)

    def due(self) -> bool:
        """Return whether the next logarithmic growth milestone was reached."""
        return self.counter.estimate() >= self.next_milestone

    def reported(self) -> None:
        """Advance the milestone only after its evidence was emitted."""
        while self.next_milestone <= self.counter.estimate():
            self.next_milestone *= 10
