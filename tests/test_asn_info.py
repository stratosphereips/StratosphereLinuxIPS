"""Unit test for modules/ip_info/asn_info.py"""

from tests.module_factory import ModuleFactory
import pytest
from unittest.mock import Mock, patch
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
def test_get_asn_info_from_geolite(mock_db, ip_address, expected_asn_info):
    ASN_info = ModuleFactory().create_asn_obj(mock_db)
    assert ASN_info.get_asn_info_from_geolite(ip_address) == expected_asn_info


@pytest.mark.parametrize(
    "ip_address, expected_cached_data",
    [  # Testcase 1: Cache miss, successful ASN lookup
        (
            "8.8.8.8",
            {"asn": {"number": "AS15169", "org": "GOOGLE, US"}},
        ),
        # Testcase 2: Cache miss, successful ASN lookup, different IP
        (
            "1.1.1.1",
            {"asn": {"number": "AS13335", "org": "CLOUDFLARENET, US"}},
        ),
        # Testcase 3: Cache hit, return cached data
        ("8.8.8.8", {"asn": {"number": "AS15169", "org": "GOOGLE, US"}}),
    ],
)
def test_cache_ip_range(mock_db, ip_address, expected_cached_data):
    ASN_info = ModuleFactory().create_asn_obj(mock_db)
    ASN_info.cache_ip_range(ip_address)
    assert ASN_info.cache_ip_range(ip_address) == expected_cached_data


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
def test_get_cached_asn(
    mock_db, ip_address, first_octet, cached_data, expected_result
):
    ASN_info = ModuleFactory().create_asn_obj(mock_db)

    with patch(
        "slips_files.common." "slips_utils.utils.get_first_octet"
    ) as mock_get_first_octet:
        mock_get_first_octet.return_value = first_octet

        mock_db.get_asn_cache.return_value = cached_data

        result = ASN_info.get_cached_asn(ip_address)
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
def test_update_asn(mock_db, cached_data, update_period, expected_result):
    ASN_info = ModuleFactory().create_asn_obj(mock_db)
    result = ASN_info.update_asn(cached_data, update_period)
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
    mock_db,
    ip_address,
    is_ignored,
    api_status_code,
    api_text,
    mock_get_side_effect,
    expected_result,
):
    ASN_info = ModuleFactory().create_asn_obj(mock_db)

    with patch(
        "slips_files.common.slips_utils." "utils.is_ignored_ip"
    ) as mock_is_ignored_ip:
        mock_is_ignored_ip.return_value = is_ignored

        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = api_status_code
            mock_response.text = api_text
            mock_get.return_value = mock_response
            mock_get.side_effect = mock_get_side_effect

            result = ASN_info.get_asn_online(ip_address)
            assert result == expected_result


@pytest.mark.parametrize(
    "ip, cached_ip_info, asn, expected_result",
    [
        # Testcase 1: Update with new ASN info
        (
            "192.168.1.1",
            {},
            {"asn": {"number": "AS12345", "org": "Test Org"}},
            {
                "asn": {"number": "AS12345", "org": "Test Org"},
                "timestamp": 1625097600,
            },
        ),
        # Testcase 2: Update existing ASN info
        (
            "10.0.0.1",
            {"country": "US"},
            {"asn": {"number": "AS67890", "org": "Another Org"}},
            {
                "country": "US",
                "asn": {"number": "AS67890", "org": "Another Org"},
                "timestamp": 1625097600,
            },
        ),
        # Testcase 3: Update with empty ASN info
        (
            "172.16.0.1",
            {"some_key": "some_value"},
            {},
            {"some_key": "some_value", "timestamp": 1625097600},
        ),
    ],
)
def test_update_ip_info(mock_db, ip, cached_ip_info, asn, expected_result):
    ASN_info = ModuleFactory().create_asn_obj(mock_db)

    with patch("time.time") as mock_time:
        mock_time.return_value = 1625097600
        ASN_info.update_ip_info(ip, cached_ip_info, asn)
        mock_db.set_ip_info.assert_called_once_with(ip, expected_result)
        assert cached_ip_info == expected_result


@pytest.mark.parametrize(
    "ip, cached_ip_info, cached_asn, geolite_asn, "
    "online_asn, expected_result, expected_db_calls",
    [
        # Testcase 1: ASN found in cached range
        (
            "192.168.1.1",
            {},
            {"asn": {"number": "AS12345", "org": "Cached Org"}},
            None,
            None,
            {
                "asn": {"number": "AS12345", "org": "Cached Org"},
                "timestamp": 1625097600,
            },
            [
                (
                    "set_ip_info",
                    "192.168.1.1",
                    {
                        "asn": {"number": "AS12345", "org": "Cached Org"},
                        "timestamp": 1625097600,
                    },
                )
            ],
        ),
        # Testcase 2: ASN found in GeoLite database
        (
            "8.8.8.8",
            {},
            None,
            {"asn": {"number": "AS15169", "org": "Google LLC"}},
            None,
            {
                "asn": {"number": "AS15169", "org": "Google LLC"},
                "timestamp": 1625097600,
            },
            [
                (
                    "set_ip_info",
                    "8.8.8.8",
                    {
                        "asn": {"number": "AS15169", "org": "Google LLC"},
                        "timestamp": 1625097600,
                    },
                )
            ],
        ),
        # Testcase 3: ASN found online
        (
            "1.1.1.1",
            {},
            None,
            None,
            {"asn": {"number": "AS13335", "org": "Cloudflare, Inc."}},
            {
                "asn": {"number": "AS13335", "org": "Cloudflare, Inc."},
                "timestamp": 1625097600,
            },
            [
                (
                    "set_ip_info",
                    "1.1.1.1",
                    {
                        "asn": {
                            "number": "AS13335",
                            "org": "Cloudflare, Inc.",
                        },
                        "timestamp": 1625097600,
                    },
                )
            ],
        ),
        # Testcase 4: ASN not found anywhere
        (
            "10.0.0.1",
            {},
            None,
            None,
            None,
            {},
            [],
        ),
    ],
)
def test_get_asn(
    mock_db,
    ip,
    cached_ip_info,
    cached_asn,
    geolite_asn,
    online_asn,
    expected_result,
    expected_db_calls,
):
    ASN_info = ModuleFactory().create_asn_obj(mock_db)

    with patch.object(
        ASN_info, "get_cached_asn", return_value=cached_asn
    ), patch.object(
        ASN_info, "cache_ip_range", return_value=None
    ), patch.object(
        ASN_info, "get_asn_info_from_geolite", return_value=geolite_asn
    ), patch.object(
        ASN_info, "get_asn_online", return_value=online_asn
    ), patch(
        "time.time", return_value=1625097600
    ):
        ASN_info.get_asn(ip, cached_ip_info)
        assert cached_ip_info == expected_result

        actual_calls = mock_db.method_calls
        assert len(actual_calls) == len(expected_db_calls), (
            f"Expected {len(expected_db_calls)} calls, "
            f"got {len(actual_calls)}"
        )
        for i, expected_call in enumerate(expected_db_calls):
            actual_call = actual_calls[i]
            assert actual_call[0] == expected_call[0], (
                f"Expected method {expected_call[0]}, " f"got {actual_call[0]}"
            )
            assert actual_call[1] == expected_call[1:], (
                f"Expected args {expected_call[1:]}, " f"got {actual_call[1]}"
            )
