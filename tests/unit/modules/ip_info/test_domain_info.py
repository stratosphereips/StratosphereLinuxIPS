# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for modules/ip_info/domain_info.py"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from tests.module_factory import ModuleFactory


def test_query_whois_does_not_exempt_other_applications() -> None:
    """Keep enrichment without granting a host-wide TCP/43 exemption."""
    domain_info = ModuleFactory().create_ip_info_obj().domain_info
    result = Mock()
    with patch(
        "modules.ip_info.domain_info.whois.query", return_value=result
    ) as query:
        assert domain_info.query_whois("example.com") is result

    domain_info.db.record_slips_own_service_port.assert_not_called()
    query.assert_called_once_with("example.com", timeout=2.0)


@pytest.mark.parametrize("whois_result", [None, RuntimeError("whois down")])
def test_failed_whois_lookup_is_not_repeated(whois_result) -> None:
    """Skip a domain for a while after whois had nothing or failed.

    Parameters:
        whois_result: Empty answer or error of the first lookup.
    """
    domain_info = ModuleFactory().create_ip_info_obj().domain_info
    with patch(
        "modules.ip_info.domain_info.whois.query",
        side_effect=[whois_result],
    ) as query:
        assert domain_info.query_whois("example.com") is None
        assert domain_info.query_whois("example.com") is None

    query.assert_called_once_with("example.com", timeout=2.0)


def test_get_domain_info_no_creation_date():
    domain = "example.com"
    domain_info = ModuleFactory().create_ip_info_obj().domain_info
    domain_info.db.get_domain_data.return_value = None
    domain_info.query_whois = Mock()
    domain_info.query_whois.return_value = Mock(
        creation_date=None, registrant=None
    )

    result = domain_info.get_domain_info(domain)

    assert result is None
    domain_info.db.set_info_for_domains.assert_not_called()


def test_get_domain_info_invalid_tld():
    domain = "example.invalid"
    domain_info = ModuleFactory().create_ip_info_obj().domain_info
    result = domain_info.get_domain_info(domain)

    assert result is None
    domain_info.db.get_domain_data.assert_not_called()
    domain_info.db.set_info_for_domains.assert_not_called()


def test_get_domain_info_cached_data():
    domain = "cached.com"
    domain_info = ModuleFactory().create_ip_info_obj().domain_info
    domain_info.db.get_domain_data.return_value = {
        "Age": 100,
        "Org": "Cached LLC",
    }

    result = domain_info.get_domain_info(domain)

    assert result is None
    domain_info.db.set_info_for_domains.assert_not_called()


@pytest.mark.parametrize("domain", ["example.arpa", "example.local"])
def test_get_domain_info_special_domains(domain):
    domain_info = ModuleFactory().create_ip_info_obj().domain_info
    result = domain_info.get_domain_info(domain)

    assert result is None
    domain_info.db.get_domain_data.assert_not_called()
    domain_info.db.set_info_for_domains.assert_not_called()


async def test_get_domain_info_async_saves_the_owner_of_a_domain() -> None:
    """Run whois in the executor, then store the registrant it found."""
    domain_info = ModuleFactory().create_ip_info_obj().domain_info
    domain_info.db.get_domain_data.return_value = None
    whois_result = Mock(creation_date=None, registrant="Example LLC")
    run_in_executor = AsyncMock(return_value=whois_result)

    await domain_info.get_domain_info_async("example.com", run_in_executor)

    run_in_executor.assert_awaited_once_with(
        domain_info.query_whois, "example.com"
    )
    domain_info.db.set_info_for_domains.assert_called_once_with(
        "example.com", {"Org": "Example LLC"}
    )


async def test_get_domain_info_async_skips_domains_whois_cannot_know() -> None:
    """Don't spend an executor slot on a local name."""
    domain_info = ModuleFactory().create_ip_info_obj().domain_info
    run_in_executor = AsyncMock()

    await domain_info.get_domain_info_async("printer.local", run_in_executor)

    run_in_executor.assert_not_awaited()
    domain_info.db.set_info_for_domains.assert_not_called()


def test_clear_caches_forgets_checked_domains() -> None:
    """Free the cached domain checks when the module stops."""
    domain_info = ModuleFactory().create_ip_info_obj().domain_info
    domain_info.is_valid_domain("printer.local")
    assert domain_info.domain_validity_cache == {"printer.local": False}

    domain_info.clear_caches()

    assert domain_info.domain_validity_cache == {}
