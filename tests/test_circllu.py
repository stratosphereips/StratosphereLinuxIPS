# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from unittest.mock import (
    MagicMock,
    Mock,
)
import pytest
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "blacklists, expected_confidence",
    [  # Testcase 1:One blacklist
        ("blacklist1", 0.5),
        # Testcase 2:Two blacklists
        ("blacklist1 blacklist2", 0.7),
        # Testcase 3:Three or more blacklists
        ("blacklist1 blacklist2 blacklist3", 1),
    ],
)
def test_calculate_confidence(blacklists, expected_confidence):
    """
    Test `calculate_confidence` to ensure it properly assigns confidence
    scores based on the number of blacklists flagging a file.
    """
    circllu = ModuleFactory().create_circllu_obj()
    assert circllu.calculate_confidence(blacklists) == expected_confidence


def test_create_session():
    """
    Test the creation of a session for Circl.lu API requests.
    """
    circllu = ModuleFactory().create_circllu_obj()
    circllu.create_session()
    assert circllu.circl_session.verify is True
    assert circllu.circl_session.headers == {"accept": "application/json"}


@pytest.mark.parametrize(
    "status_code, response_text, expected_result",
    [  # Testcase1:successful API query
        (
            200,
            json.dumps(
                {
                    "KnownMalicious": "blacklist1 blacklist2",
                    "hashlookup:trust": "75",
                }
            ),
            {
                "confidence": 0.7,
                "threat_level": 0.25,
                "blacklist": "blacklist1 blacklist2, circl.lu",
            },
        ),
        # Testcase2:Not Found error
        (
            404,
            "{}",
            None,
        ),
        # Testcase3:500 Internal Server Error
        (
            500,
            "Internal Server Error",
            None,
        ),
    ],
)
def test_lookup(mocker, status_code, response_text, expected_result):
    """
    Test the `circl_lu` method for various Circl.lu API responses.
    """
    circllu = ModuleFactory().create_circllu_obj()
    circllu.circl_session = Mock()
    flow_info = {"flow": {"md5": "1234567890abcdef1234567890abcdef"}}
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.text = response_text
    circllu.circl_session.get.return_value = mock_response
    result = circllu.lookup(flow_info)
    assert result == expected_result


@pytest.mark.parametrize(
    "circl_trust, expected_threat_level",
    [
        # Testcase 1:Completely malicious
        ("0", 1.0),
        # Testcase 2:Completely benign
        ("100", 0.0),
        # Testcase 3:Moderately malicious
        ("50", 0.5),
        # Testcase 4:More malicious
        ("25", 0.75),
    ],
)
def test_calculate_threat_level(circl_trust, expected_threat_level):
    """
    Test `calculate_threat_level` for accurately converting
    Circl.lu trust scores to threat levels.
    """
    circllu = ModuleFactory().create_circllu_obj()
    assert circllu.calculate_threat_level(circl_trust) == expected_threat_level
