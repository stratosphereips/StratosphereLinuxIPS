# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for modules/ip_info/rdns_info.py"""

import socket
from unittest.mock import ANY, AsyncMock, patch

import pytest

from tests.module_factory import ModuleFactory


def test_get_rdns_valid_ip():
    rdns = ModuleFactory().create_ip_info_obj().rdns
    ip_address = "8.8.8.8"
    expected_rdns = {"reverse_dns": "dns.google"}

    with (
        patch("socket.gethostbyaddr") as mock_gethostbyaddr,
        patch("socket.inet_pton") as mock_inet_pton,
    ):
        mock_gethostbyaddr.return_value = ("dns.google", [], ["8.8.8.8"])
        mock_inet_pton.side_effect = socket.error

        result = rdns.get_rdns(ip_address)
        assert result == expected_rdns

        mock_gethostbyaddr.assert_called_once_with(ip_address)
        mock_inet_pton.assert_called_once()
        rdns.db.set_ip_info.assert_called_once_with(
            ip_address, {**expected_rdns, "reverse_dns_lookup": ANY}
        )


def test_get_rdns_negative_cache_skips_second_lookup():
    rdns = ModuleFactory().create_ip_info_obj().rdns
    ip_address = "invalid_ip"

    with patch("socket.gethostbyaddr") as mock_gethostbyaddr:
        mock_gethostbyaddr.side_effect = socket.gaierror

        assert rdns.get_rdns(ip_address) is False
        assert rdns.get_rdns(ip_address) is False

        mock_gethostbyaddr.assert_called_once_with(ip_address)


@pytest.mark.parametrize(
    "error,status,delay",
    [
        (socket.herror(1, "Unknown host"), "no_record", 86400),
        (socket.herror(2, "Try again"), "error", 300),
        (socket.gaierror(socket.EAI_AGAIN, "Temporary failure"), "error", 300),
        (OSError("Resolver unavailable"), "error", 300),
    ],
)
def test_rdns_records_lookup_outcome(
    error: OSError, status: str, delay: int
) -> None:
    """Distinguish an absent reverse name from a temporary resolver failure.

    Parameters:
        error: Resolver result to simulate.
        status: Expected stored outcome.
        delay: Minimum time before another background attempt.
    """
    rdns = ModuleFactory().create_ip_info_obj().rdns
    with (
        patch("socket.gethostbyaddr", side_effect=error),
        patch("modules.ip_info.rdns_info.time.time", return_value=1000),
    ):
        assert rdns.get_rdns("8.8.8.8") is False
    rdns.db.set_ip_info.assert_called_once_with(
        "8.8.8.8",
        {
            "reverse_dns_lookup": {
                "status": status,
                "checked_at": 1000,
                "retry_after": 1000 + delay,
            }
        },
    )


def test_rdns_negative_result_survives_module_restart() -> None:
    """Reuse saved negative results instead of repeating DNS on every run."""
    rdns = ModuleFactory().create_ip_info_obj().rdns
    rdns.db.get_ip_info.return_value = {
        "status": "no_record",
        "retry_after": 2000,
    }
    with (
        patch("socket.gethostbyaddr") as lookup,
        patch("modules.ip_info.rdns_info.time.time", return_value=1000),
    ):
        assert rdns.get_rdns("8.8.8.8") is False
    lookup.assert_not_called()


def test_get_rdns_no_reverse_dns():
    rdns = ModuleFactory().create_ip_info_obj().rdns
    ip_address = "1.1.1.1"

    with (
        patch("socket.gethostbyaddr") as mock_gethostbyaddr,
        patch("socket.inet_pton") as mock_inet_pton,
    ):
        mock_gethostbyaddr.return_value = ("1.1.1.1", [], ["1.1.1.1"])
        mock_inet_pton.return_value = b"\x01\x01\x01\x01"

        result = rdns.get_rdns(ip_address)
        assert result is False

        mock_gethostbyaddr.assert_called_once_with(ip_address)
        mock_inet_pton.assert_called_once()


async def test_get_rdns_async_runs_the_lookup_in_the_executor() -> None:
    """Keep the blocking resolver call off the event loop."""
    rdns = ModuleFactory().create_ip_info_obj().rdns
    run_in_executor = AsyncMock(return_value={"reverse_dns": "dns.google"})

    result = await rdns.get_rdns_async("8.8.8.8", run_in_executor)

    assert result == {"reverse_dns": "dns.google"}
    run_in_executor.assert_awaited_once_with(rdns.get_rdns, "8.8.8.8")


@pytest.mark.parametrize(
    "ip_address, expected_family",
    [
        # Testcase 1: IPv4 address
        ("192.168.1.1", socket.AF_INET),
        # Testcase 2: IPv6 address
        ("2001:db8::1", socket.AF_INET6),
        # Testcase 3: IPv4-mapped IPv6 address
        ("::ffff:192.0.2.1", socket.AF_INET6),
    ],
)
def test_get_ip_family(ip_address, expected_family):
    rdns = ModuleFactory().create_ip_info_obj().rdns
    assert rdns.get_ip_family(ip_address) == expected_family


def test_clear_caches_empties_the_address_family_cache() -> None:
    """Free the cached families when the module stops."""
    rdns = ModuleFactory().create_ip_info_obj().rdns
    rdns.clear_caches()
    rdns.get_ip_family("10.0.0.1")
    assert rdns._get_ip_family_cached.cache_info().currsize == 1

    rdns.clear_caches()

    assert rdns._get_ip_family_cached.cache_info().currsize == 0
