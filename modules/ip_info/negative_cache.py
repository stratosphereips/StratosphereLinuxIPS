# SPDX-License-Identifier: GPL-2.0-only
"""Short-lived memory of failed lookups."""

import time


class NegativeCache:
    """Remember failed lookups for a while, so they aren't repeated.

    A lookup that just failed will most likely fail again, and every retry
    costs a network round trip.
    """

    MAX_ENTRIES = 4096

    def __init__(self, ttl_seconds: int = 300) -> None:
        """Start with no remembered failures.

        Parameters:
            ttl_seconds: How long a failure is remembered.
        """
        self.ttl_seconds = ttl_seconds
        self._failure_time_of_key: dict[str, float] = {}

    def has(self, key: str) -> bool:
        """Check whether a lookup failed recently.

        Parameters:
            key: What was looked up, e.g. an IP, a MAC or a domain.

        Returns:
            Whether the lookup should be skipped for now.
        """
        failure_time = self._failure_time_of_key.get(key)
        if failure_time is None:
            return False

        if (time.monotonic() - failure_time) > self.ttl_seconds:
            self._failure_time_of_key.pop(key, None)
            return False

        return True

    def add(self, key: str) -> None:
        """Remember a failed lookup, dropping the oldest one when full.

        Parameters:
            key: What was looked up.
        """
        self._failure_time_of_key[key] = time.monotonic()
        if len(self._failure_time_of_key) > self.MAX_ENTRIES:
            oldest_key = next(iter(self._failure_time_of_key))
            self._failure_time_of_key.pop(oldest_key)

    def remove(self, key: str) -> None:
        """Forget a failure, once the lookup worked.

        Parameters:
            key: What was looked up.
        """
        self._failure_time_of_key.pop(key, None)
