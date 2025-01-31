# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/ip_info/ip_info.py"""

from tests.module_factory import ModuleFactory
import pytest
from unittest.mock import Mock, patch, call
import time
import json


@pytest.mark.parametrize(
    "ip_address, expected_asn_info",
    [
        # Testcase 1: IP with known ASN info
        (
            "108.200.116.255",
            {"asn": {"number": "AS7018", "org": "ATT-INTERNET4"}},
        ),
        # Testcase 2: IP with no ASN info
        (
            "0.0.0.0",
            {},
        ),
        # Testcase 3: Private IP address
        (
            "192.168.1.1",
            {},
        ),
    ],
)
def test_get_asn_info_from_geolite(ip_address, expected_asn_info):
    asn_info = ModuleFactory().create_asn_obj()
    assert asn_info.get_asn_info_from_geolite(ip_address) == expected_asn_info


@pytest.mark.parametrize(
    "ip_address, expected_whois_info, expected_cached_data",
    [
        # Testcase 1: Cache miss, successful ASN lookup
        (
            "8.8.8.8",
            {
                "asn_description": "GOOGLE, US",
                "asn_cidr": "8.8.8.0/24",
                "asn": "15169",
            },
            {"asn": {"number": "AS15169", "org": "GOOGLE, US"}},
        ),
        # Testcase 2: Cache miss, successful ASN lookup, different IP
        (
            "1.1.1.1",
            {
                "asn_description": "CLOUDFLARENET, US",
                "asn_cidr": "1.1.1.0/24",
                "asn": "13335",
            },
            {"asn": {"number": "AS13335", "org": "CLOUDFLARENET, US"}},
        ),
        # Testcase 3: Cache hit, return cached data
        (
            "8.8.8.8",
            {
                "asn_description": "GOOGLE, US",
                "asn_cidr": "8.8.8.0/24",
                "asn": "15169",
            },
            {"asn": {"number": "AS15169", "org": "GOOGLE, US"}},
        ),
        # Testcase 4: IP with lookup failure
        (
            "192.168.1.1",
            None,
            False,
        ),
    ],
)
def test_cache_ip_range(ip_address, expected_whois_info, expected_cached_data):
    asn_info = ModuleFactory().create_asn_obj()

    with patch("ipwhois.IPWhois.lookup_rdap") as mock_lookup_rdap:
        mock_lookup_rdap.return_value = expected_whois_info
        result = asn_info.cache_ip_range(ip_address)
        assert result == expected_cached_data


@pytest.mark.parametrize(
    "ip_address, first_octet, cached_data, expected_result",
    [
        # Testcase 1: IP in cached range
        (
            "192.168.1.100",
            "192",
            json.dumps(
                {"192.168.0.0/16": {"org": "Test Org", "number": "AS12345"}}
            ),
            {"asn": {"org": "Test Org", "number": "AS12345"}},
        ),
        # Testcase 2: IP not in cached range
        (
            "10.0.0.1",
            "10",
            json.dumps(
                {"192.168.0.0/16": {"org": "Test Org", "number": "AS12345"}}
            ),
            None,
        ),
        # Testcase 3: No cached data for first octet
        (
            "172.16.0.1",
            "172",
            None,
            None,
        ),
        # Testcase 4: Invalid IP
        (
            "invalid_ip",
            None,
            None,
            None,
        ),
        # Testcase 5: Cached range without 'number'
        (
            "192.168.1.100",
            "192",
            json.dumps({"192.168.0.0/16": {"org": "Test Org"}}),
            {"asn": {"org": "Test Org"}},
        ),
    ],
)
def test_get_cached_asn(ip_address, first_octet, cached_data, expected_result):
    asn_info = ModuleFactory().create_asn_obj()

    with patch(
        "slips_files.common.slips_utils.utils.get_first_octet"
    ) as mock_get_first_octet:
        mock_get_first_octet.return_value = first_octet

        asn_info.db.get_asn_cache.return_value = cached_data
        result = asn_info.get_cached_asn(ip_address)
        assert result == expected_result


@pytest.mark.parametrize(
    "cached_data, update_period, expected_result",
    [
        # Testcase 1: No cached data
        (
            None,
            3600,
            True,
        ),
        # Testcase 2: Cached data with no timestamp
        (
            {"asn": {}},
            3600,
            True,
        ),
        # Testcase 3: Cached data with old timestamp
        (
            {"asn": {"timestamp": time.time() - 7200}},
            3600,
            True,
        ),
        # Testcase 4: Cached data with recent timestamp
        (
            {"asn": {"timestamp": time.time() - 1800}},
            3600,
            False,
        ),
    ],
)
def test_update_asn(cached_data, update_period, expected_result):
    asn_info = ModuleFactory().create_asn_obj()
    asn_info.update_period = update_period
    result = asn_info.should_update_asn(cached_data)
    assert result == expected_result


@pytest.mark.parametrize(
    "ip_address, is_ignored, api_status_code, api_text, "
    "mock_get_side_effect, expected_result",
    [
        # Testcase 1: Valid IP with ASN info
        (
            "8.8.8.8",
            False,
            200,
            json.dumps({"as": "AS15169 Google LLC"}),
            None,
            {"asn": {"number": "AS15169", "org": "Google LLC"}},
        ),
        # Testcase 2: Valid IP without ASN info
        (
            "1.1.1.1",
            False,
            200,
            json.dumps({"as": ""}),
            None,
            None,
        ),
        # Testcase 3: API request fails
        (
            "192.168.1.1",
            False,
            404,
            "",
            None,
            {},
        ),
        # Testcase 4: Ignored IP
        (
            "127.0.0.1",
            True,
            None,
            None,
            None,
            {},
        ),
    ],
)
def test_get_asn_online(
    ip_address,
    is_ignored,
    api_status_code,
    api_text,
    mock_get_side_effect,
    expected_result,
):
    asn_info = ModuleFactory().create_asn_obj()

    with patch(
        "slips_files.common.slips_utils.utils.is_ignored_ip"
    ) as mock_is_ignored_ip:
        mock_is_ignored_ip.return_value = is_ignored

        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = api_status_code
            mock_response.text = api_text
            mock_get.return_value = mock_response
            mock_get.side_effect = mock_get_side_effect

            result = asn_info.get_asn_online(ip_address)
            assert result == expected_result


@pytest.mark.parametrize(
    "ip, cached_ip_info, asn, expected_call",
    [
        # Testcase 1: Update with new ASN info
        (
            "192.168.1.1",
            {},
            {"asn": {"number": "AS12345", "org": "Test Org"}},
            (
                "192.168.1.1",
                {
                    "asn": {"number": "AS12345", "org": "Test Org"},
                    "timestamp": 1625097600,
                },
            ),
        ),
        # Testcase 2: Update existing ASN info
        (
            "10.0.0.1",
            {"country": "US"},
            {"asn": {"number": "AS67890", "org": "Another Org"}},
            (
                "10.0.0.1",
                {
                    "country": "US",
                    "asn": {"number": "AS67890", "org": "Another Org"},
                    "timestamp": 1625097600,
                },
            ),
        ),
        # Testcase 3: Update with empty ASN info
        (
            "172.16.0.1",
            {"some_key": "some_value"},
            {},
            (
                "172.16.0.1",
                {
                    "some_key": "some_value",
                    "timestamp": 1625097600,
                },
            ),
        ),
    ],
)
def test_update_ip_info(ip, cached_ip_info, asn, expected_call):
    asn_info = ModuleFactory().create_asn_obj()

    with patch("time.time", return_value=1625097600):
        asn_info.update_ip_info(ip, cached_ip_info, asn)

        asn_info.db.set_ip_info.assert_called_once_with(*expected_call)
        expected_cached_ip_info = expected_call[1]
        assert cached_ip_info == expected_cached_ip_info


@pytest.mark.parametrize(
    "ip, cached_ip_info, cached_asn, cache_ip_range_result, "
    "geolite_asn, online_asn, expected_result, expected_calls",
    [
        # Testcase 1: ASN found in cached range
        (
            "192.168.1.1",
            {},
            {"asn": {"number": "AS12345", "org": "Cached Org"}},
            None,
            None,
            None,
            {"asn": {"number": "AS12345", "org": "Cached Org"}},
            [call.get_cached_asn("192.168.1.1")],
        ),
        # Testcase 2: ASN found by cache_ip_range
        (
            "8.8.8.8",
            {},
            None,
            {"asn": {"number": "AS15169", "org": "Google LLC"}},
            None,
            None,
            {"asn": {"number": "AS15169", "org": "Google LLC"}},
            [call.get_cached_asn("8.8.8.8"), call.cache_ip_range("8.8.8.8")],
        ),
        # Testcase 3: ASN found in GeoLite database
        (
            "1.1.1.1",
            {},
            None,
            None,
            {"asn": {"number": "AS13335", "org": "Cloudflare, Inc."}},
            None,
            {"asn": {"number": "AS13335", "org": "Cloudflare, Inc."}},
            [
                call.get_cached_asn("1.1.1.1"),
                call.cache_ip_range("1.1.1.1"),
                call.get_asn_info_from_geolite("1.1.1.1"),
            ],
        ),
        # Testcase 4: ASN found online
        (
            "203.0.113.1",
            {},
            None,
            None,
            None,
            {"asn": {"number": "AS64496", "org": "Example ISP"}},
            {"asn": {"number": "AS64496", "org": "Example ISP"}},
            [
                call.get_cached_asn("203.0.113.1"),
                call.cache_ip_range("203.0.113.1"),
                call.get_asn_info_from_geolite("203.0.113.1"),
                call.get_asn_online("203.0.113.1"),
            ],
        ),
    ],
)
def test_get_asn_with_result(
    ip,
    cached_ip_info,
    cached_asn,
    cache_ip_range_result,
    geolite_asn,
    online_asn,
    expected_result,
    expected_calls,
):
    asn_info = ModuleFactory().create_asn_obj()

    with patch.object(
        asn_info, "get_cached_asn", return_value=cached_asn
    ) as mock_get_cached_asn, patch.object(
        asn_info, "cache_ip_range", return_value=cache_ip_range_result
    ) as mock_cache_ip_range, patch.object(
        asn_info, "get_asn_info_from_geolite", return_value=geolite_asn
    ) as mock_get_geolite, patch.object(
        asn_info, "get_asn_online", return_value=online_asn
    ) as mock_get_online, patch.object(
        asn_info, "update_ip_info"
    ) as mock_update_ip_info:
        asn_info.get_asn(ip, cached_ip_info)

        actual_calls = (
            mock_get_cached_asn.mock_calls
            + mock_cache_ip_range.mock_calls
            + mock_get_geolite.mock_calls
            + mock_get_online.mock_calls
        )
        assert actual_calls == expected_calls

        mock_update_ip_info.assert_called_once_with(
            ip, cached_ip_info, expected_result
        )


def test_get_asn_without_result():
    """Testcase: ASN not found anywhere."""
    ip = "10.0.0.1"
    cached_ip_info = {}
    expected_calls = [
        call.get_cached_asn("10.0.0.1"),
        call.cache_ip_range("10.0.0.1"),
        call.get_asn_info_from_geolite("10.0.0.1"),
        call.get_asn_online("10.0.0.1"),
    ]

    asn_info = ModuleFactory().create_asn_obj()

    with patch.object(
        asn_info, "get_cached_asn", return_value=None
    ) as mock_get_cached_asn, patch.object(
        asn_info, "cache_ip_range", return_value=None
    ) as mock_cache_ip_range, patch.object(
        asn_info, "get_asn_info_from_geolite", return_value=None
    ) as mock_get_geolite, patch.object(
        asn_info, "get_asn_online", return_value=None
    ) as mock_get_online, patch.object(
        asn_info, "update_ip_info"
    ) as mock_update_ip_info:
        asn_info.get_asn(ip, cached_ip_info)

        actual_calls = (
            mock_get_cached_asn.mock_calls
            + mock_cache_ip_range.mock_calls
            + mock_get_geolite.mock_calls
            + mock_get_online.mock_calls
        )
        assert actual_calls == expected_calls

        mock_update_ip_info.assert_not_called()
