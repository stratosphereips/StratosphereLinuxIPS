"""Fixed-memory distinct destination estimates for already confirmed scans."""

import hashlib
import math


class DistinctTargets:
    """Count distinct IPs with 1,024 HyperLogLog registers, never raw IP lists."""

    def __init__(self) -> None:
        """Initialize a one-KiB counter with an incrementally maintained sum."""
        self.registers = bytearray(1024)
        self.harmonic = 1024.0
        self.zeros = 1024

    def add(self, address: str) -> None:
        """Update one register in constant time; duplicate IPs do not add up.

        Parameters:
            address: Canonical destination IP from a validated scan probe.
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
