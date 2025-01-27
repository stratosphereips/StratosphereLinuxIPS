# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
from unittest.mock import patch
from tests.module_factory import ModuleFactory
import json
from requests.auth import HTTPBasicAuth


@pytest.mark.parametrize(
    "ip, api_response, expected_result",
    [
        (  # Testcase1: Valid IP and API response
            "1.1.1.1",
            {
                "results": [
                    {
                        "lastSeen": "2023-01-01",
                        "firstSeen": "2022-01-01",
                        "resolve": "example.com",
                        "collected": "100",
                    }
                ]
            },
            [("2023-01-01", ["2022-01-01", "example.com", "100"])],
        ),
        # Testcase2: API returns an error message
        ("2.2.2.2", {"message": "Error"}, None),
        # Testcase3: API returns empty results
        ("3.3.3.3", {"results": []}, None),
    ],
)
@patch("requests.get")
def test_get_passive_dns(mock_get, ip, api_response, expected_result):
    mock_response = mock_get.return_value
    mock_response.status_code = 200
    mock_response.text = json.dumps(api_response)

    riskiq = ModuleFactory().create_riskiq_obj()
    riskiq.riskiq_email = "test@example.com"
    riskiq.riskiq_key = "testkey"

    result = riskiq.get_passive_dns(ip)
    assert result == expected_result

    mock_get.assert_called_once_with(
        "https://api.riskiq.net/pt/v2/dns/passive",
        params={"query": ip},
        timeout=5,
        verify=False,
        auth=HTTPBasicAuth("test@example.com", "testkey"),
    )


@pytest.mark.parametrize(
    "email, key, expected_result",
    [  # Testcase1: Valid email and key
        ("email@example.com", "validkey", None),
        # Testcase2: Missing email
        (None, "validkey", 1),
        # Testcase3: Missing key
        ("email@example.com", None, 1),
        # Testcase4: Missing both email and key
        (None, None, 1),
    ],
)
def test_pre_main(email, key, expected_result, mock_db):
    with patch("slips_files.common.slips_utils.utils.drop_root_privs"):
        riskiq = ModuleFactory().create_riskiq_obj()
        riskiq.riskiq_email = email
        riskiq.riskiq_key = key
        assert riskiq.pre_main() == expected_result
