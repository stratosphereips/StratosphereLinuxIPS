# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/threat_intelligence/spamhaus.py"""

from tests.module_factory import ModuleFactory
from unittest.mock import MagicMock, patch
import pytest


@pytest.mark.parametrize(
    "ip, dns_query_result, expected",
    [
        ("1.1.1.1", [], False),  # Case where the IP is not listed
        (
            "2.2.2.2",
            ["127.0.0.2"],
            {  # IP is listed
                "source": "some_list spamhaus",
                "description": "This is a spam list",
                "threat_level": "medium",
                "tags": "spam",
            },
        ),
    ],
)
@patch("modules.threat_intelligence.spamhaus.Spamhaus._perform_dns_query")
@patch("modules.threat_intelligence.spamhaus.Spamhaus._get_list_names")
@patch("modules.threat_intelligence.spamhaus.Spamhaus._get_list_descriptions")
@patch("modules.threat_intelligence.spamhaus.Spamhaus._get_dataset_info")
def test_query(
    mock_get_dataset_info,
    mock_get_list_descriptions,
    mock_get_list_names,
    mock_perform_dns_query,
    ip,
    dns_query_result,
    expected,
):
    # Mocking the dns_query_result to return an object with a `to_text()` method
    mock_perform_dns_query.return_value = (
        [MagicMock(to_text=lambda: "127.0.0.2")] if dns_query_result else []
    )
    mock_get_list_names.return_value = {"127.0.0.2": "some_list"}
    mock_get_list_descriptions.return_value = {
        "127.0.0.2": "This is a spam list"
    }
    mock_get_dataset_info.return_value = ("some_list", "This is a spam list")

    spamhaus = ModuleFactory().create_spamhaus_obj()
    result = spamhaus.query(ip)
    assert result == expected


def test_spamhaus_dns_error(mocker):
    """
    Test the `spamhaus` method's handling of DNS resolution errors.
    """
    spamhaus = ModuleFactory().create_spamhaus_obj()
    mock_resolver = mocker.patch("dns.resolver.resolve")
    mock_resolver.side_effect = Exception("DNS resolution error")
    result = spamhaus.query("13.14.15.16")
    assert result is False
