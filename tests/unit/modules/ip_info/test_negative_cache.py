# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for modules/ip_info/negative_cache.py"""

from unittest.mock import patch

import pytest

from tests.module_factory import ModuleFactory

NEGATIVE_CACHE = "modules.ip_info.negative_cache"


@pytest.mark.parametrize(
    "seconds_since_failure,expected_hit",
    [
        (0, True),
        (300, True),
        (301, False),
    ],
)
def test_failure_is_remembered_until_its_ttl_passes(
    seconds_since_failure: int, expected_hit: bool
) -> None:
    """Skip a failed lookup for five minutes, then allow a retry.

    Parameters:
        seconds_since_failure: Time passed since the lookup failed.
        expected_hit: Whether the lookup should still be skipped.
    """
    failed_lookups = ModuleFactory().create_ip_info_obj().rdns.failed_lookups
    with patch(f"{NEGATIVE_CACHE}.time.monotonic", return_value=1000):
        failed_lookups.add("8.8.8.8")

    with patch(
        f"{NEGATIVE_CACHE}.time.monotonic",
        return_value=1000 + seconds_since_failure,
    ):
        assert failed_lookups.has("8.8.8.8") is expected_hit


def test_unknown_and_removed_keys_are_not_skipped() -> None:
    """Only skip lookups that failed and weren't fixed since."""
    failed_lookups = ModuleFactory().create_ip_info_obj().rdns.failed_lookups
    assert failed_lookups.has("8.8.8.8") is False

    failed_lookups.add("8.8.8.8")
    failed_lookups.remove("8.8.8.8")
    failed_lookups.remove("never-added")

    assert failed_lookups.has("8.8.8.8") is False


def test_oldest_failure_is_dropped_when_the_cache_is_full() -> None:
    """Keep the memory of failures bounded."""
    failed_lookups = ModuleFactory().create_ip_info_obj().rdns.failed_lookups
    failed_lookups.MAX_ENTRIES = 2

    for key in ("first", "second", "third"):
        failed_lookups.add(key)

    assert failed_lookups.has("first") is False
    assert failed_lookups.has("second") is True
    assert failed_lookups.has("third") is True
