# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import patch, Mock
import pytest
import requests
import json
from modules.threat_intelligence.urlhaus import (
    URLhaus,
    ThreatLevel,
    EvidenceType,
    Direction,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "to_lookup, uri, status_code",
    [
        # Testcase1: URL lookup
        (
            {"url": "https://example.com"},
            "url",
            200,
        ),
        # Testcase2: hash lookup
        (
            {"md5_hash": "a1b2c3d4"},
            "payload",
            200,
        ),
    ],
)
@patch("modules.threat_intelligence.urlhaus.requests.session")
def test_make_urlhaus_request(mock_response, to_lookup, uri, status_code):
    """Test successful requests to the make_urlhaus_request function."""
    mock_response_instance = Mock()
    mock_response.return_value = mock_response_instance
    mock_response = Mock(status_code=status_code)
    mock_response_instance.post.return_value = mock_response

    urlhaus = ModuleFactory().create_urlhaus_obj()
    urlhaus.urlhaus_session = mock_response_instance

    response = urlhaus.make_urlhaus_request(to_lookup)

    mock_response_instance.post.assert_called_once_with(
        f"{urlhaus.base_url}/{uri}/",
        to_lookup,
        headers=mock_response_instance.headers,
    )
    assert response == mock_response


@pytest.mark.parametrize(
    "to_lookup",
    [
        ({"url": "https://example.com"}),
    ],
)
@patch("modules.threat_intelligence.urlhaus.requests.session")
def test_make_urlhaus_request_connection_error(mock_response, to_lookup):
    """Test the ConnectionError handling in make_urlhaus_request."""
    mock_response_instance = Mock()
    mock_response.return_value = mock_response_instance
    mock_response_instance.post.side_effect = (
        requests.exceptions.ConnectionError
    )

    urlhaus = ModuleFactory().create_urlhaus_obj()
    urlhaus.urlhaus_session = mock_response_instance

    response = urlhaus.make_urlhaus_request(to_lookup)
    assert response is None


@patch("modules.threat_intelligence.urlhaus.requests.session")
def test_create_urlhaus_session(
    mock_response,
):
    """Verifies session creation with successful setup."""
    mock_response_instance = Mock()
    mock_response.return_value = mock_response_instance
    urlhaus = ModuleFactory().create_urlhaus_obj()
    mock_response.assert_called_once()
    assert urlhaus.urlhaus_session == mock_response_instance
    assert urlhaus.urlhaus_session.verify is True


@pytest.mark.parametrize(
    "ioc_type, mock_response, expected_result, ioc_value",
    [
        # Testcase1: Testing URL parsing all fields present
        (
            "url",
            {
                "threat": "malware_download",
                "url_status": "online",
                "tags": ["phishing", "fake_update"],
                "payloads": [
                    {
                        "file_type": "PE32 executable (GUI) Intel 80386, for MS Windows",
                        "filename": "update.exe",
                        "response_md5": "a1b2c3d4",
                        "signature": "Trojan.GenericKD.33632270",
                        "virustotal": {
                            "percent": 80,
                        },
                    }
                ],
            },
            {
                "source": "URLhaus",
                "url": "https://malicious.com",
                "description": (
                    "Connecting to a malicious URL https://malicious.com. "
                    "Detected by: URLhaus threat: malware_download, URL status: online, "
                    "tags: phishing fake_update, the file hosted in this url is of type: "
                    "PE32 executable (GUI) Intel 80386, for MS Windows, filename: update.exe "
                    "md5: a1b2c3d4 signature: Trojan.GenericKD.33632270. and was marked by "
                    "80% of virustotal's AVs as malicious"
                ),
                "threat_level": 80,
                "tags": "phishing fake_update",
            },
            "https://malicious.com",
        ),
        # Testcase2: Testing MD5 hash parsing all fields present
        (
            "md5_hash",
            {
                "file_type": "PE32 executable (console) Intel 80386, for MS Windows",
                "filename": "malware.exe",
                "signature": "Trojan.Win32.Generic!BT",
                "virustotal": {
                    "percent": 95,
                },
            },
            {
                "blacklist": "URLhaus",
                "threat_level": 95,
                "tags": "Trojan.Win32.Generic!BT",
                "file_type": "PE32 executable (console) Intel 80386, for MS Windows",
                "file_name": "malware.exe",
            },
            "a1b2c3d4",
        ),
        # Testcase 3: MD5 hash parsing  missing 'virustotal'
        (
            "md5_hash",
            {
                "file_type": "PE32 executable (console) Intel 80386, for MS Windows",
                "filename": "malware.exe",
                "signature": "Trojan.Win32.Generic!BT",
            },
            {
                "blacklist": "URLhaus",
                "threat_level": False,
                "tags": "Trojan.Win32.Generic!BT",
                "file_type": "PE32 executable (console) Intel 80386, for MS Windows",
                "file_name": "malware.exe",
            },
            "a1b2c3d4",
        ),
    ],
)
@patch.object(URLhaus, "make_urlhaus_request")
def test_parse_urlhaus_responses(
    mock_request, ioc_type, mock_response, expected_result, ioc_value
):
    """Test parsing responses from URLhaus for different IOC types."""
    mock_request.return_value.status_code = 200
    mock_request.return_value.text = json.dumps(mock_response)
    urlhaus = ModuleFactory().create_urlhaus_obj()
    parsing_functions = {
        "url": urlhaus.parse_urlhaus_url_response,
        "md5_hash": urlhaus.parse_urlhaus_md5_response,
    }
    parse_function = parsing_functions[ioc_type]
    result = parse_function(mock_response, ioc_value)

    assert result == expected_result


@pytest.mark.parametrize(
    "ioc, type_of_ioc, expected_result, mock_response_data, mock_status_code",
    [
        # Testcase 1: Successful URL lookup
        (
            "https://example.com",
            "url",
            {
                "source": "URLhaus",
                "threat_level": 80,
                "tags": "phishing",
                "description": "Connecting to a malicious URL https://example.com. "
                "Detected by: URLhaus threat: malware_download, "
                "URL status: online, tags: phishing, "
                "the file hosted in this url is of type: "
                "PE32 executable (GUI) Intel 80386, "
                "for MS Windows, filename: malware.exe md5: "
                "a1b2c3d4 signature: Generic.Malware. "
                "and was marked by 80% of virustotal's AVs as malicious",
                "url": "https://example.com",
            },
            {
                "query_status": "ok",
                "threat": "malware_download",
                "url_status": "online",
                "tags": ["phishing"],
                "payloads": [
                    {
                        "file_type": "PE32 executable (GUI) Intel 80386, for MS Windows",
                        "filename": "malware.exe",
                        "response_md5": "a1b2c3d4",
                        "signature": "Generic.Malware",
                        "virustotal": {"percent": 80},
                    }
                ],
            },
            200,
        ),
        # Testcase 2: Successful MD5 hash lookup
        (
            "a1b2c3d4",
            "md5_hash",
            {
                "blacklist": "URLhaus",
                "file_name": "malware.exe",
                "threat_level": 80,
                "tags": "Generic.Malware",
                "file_type": "PE32 executable (GUI) Intel 80386, for MS Windows",
            },
            {
                "query_status": "ok",
                "file_type": "PE32 executable (GUI) Intel 80386, for MS Windows",
                "filename": "malware.exe",
                "signature": "Generic.Malware",
                "virustotal": {"percent": 80},
            },
            200,
        ),
        # Testcase 3: URL not found
        (
            "https://notfound.com",
            "url",
            None,
            {"query_status": "no_results"},
            200,
        ),
        # Testcase 4: Invalid URL format
        (
            "invalid-url-format",
            "url",
            None,
            {"query_status": "invalid_url"},
            200,
        ),
        # Testcase 5: MD5 hash not found
        (
            "invalidmd5hash",
            "md5_hash",
            None,
            {"query_status": "no_results"},
            200,
        ),
        # Testcase 6: HTTP error during lookup
        (
            "https://error.com",
            "url",
            None,
            {},
            404,
        ),
    ],
)
@patch("modules.threat_intelligence.urlhaus.URLhaus.make_urlhaus_request")
def test_urlhaus_lookup(
    mock_request,
    ioc,
    type_of_ioc,
    expected_result,
    mock_response_data,
    mock_status_code,
):
    """Tests urlhaus_lookup for various scenarios, including successful lookups,
    not found responses, invalid input, and HTTP errors.
    """
    mock_response = Mock()
    mock_response.status_code = mock_status_code
    mock_response.text = json.dumps(mock_response_data)
    mock_request.return_value = mock_response
    urlhaus = ModuleFactory().create_urlhaus_obj()
    result = urlhaus.lookup(ioc, type_of_ioc)
    assert result == expected_result


@patch("modules.threat_intelligence.urlhaus.URLhaus.make_urlhaus_request")
def test_urlhaus_lookup_json_decode_error(
    mock_request,
):
    """
    Test the case when the response from the API is not valid JSON.
    """
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "Invalid JSON"
    mock_request.return_value = mock_response

    urlhaus = ModuleFactory().create_urlhaus_obj()
    result = urlhaus.lookup("https://example.com", "url")
    assert result is None


@pytest.mark.parametrize(
    "url_info, expected_threat_level",
    [
        # Test case 1: Valid threat level
        (
            {"threat_level": 50, "description": "Malicious URL"},
            ThreatLevel.MEDIUM,
        ),
        # Test case 2: No threat level provided
        ({"description": "Malicious URL"}, ThreatLevel.MEDIUM),
        # Test case 3: Invalid threat level format
        (
            {"threat_level": "invalid", "description": "Malicious URL"},
            ThreatLevel.MEDIUM,
        ),
    ],
)
def test_get_threat_level(url_info, expected_threat_level):
    urlhaus = ModuleFactory().create_urlhaus_obj()
    assert urlhaus.get_threat_level(url_info) == expected_threat_level


@pytest.mark.parametrize(
    "file_info, expected_threat_level, expected_description_snippets",
    [
        (
            # Testcase 1: All fields present, threat level from VT available
            {
                "flow": {
                    "daddr": "8.8.8.8",
                    "size": 1234,
                    "file_name": "malware.exe",
                    "file_type": "PE32 executable",
                    "md5": "a1b2c3d4",
                    "tags": "trojan,ransomware",
                    "starttime": "2023-11-15 12:00:00",
                    "uid": "flow-123",
                },
                "threat_level": 80,
                "profileid": "profile_10.0.0.1",
                "twid": "timewindow1",
            },
            ThreatLevel.HIGH,
            [
                "Virustotal score: 80% malicious",
                "size: 1234",
                "file name: malware.exe",
                "file type: PE32 executable",
                "tags: trojan,ransomware",
            ],
        ),
        (
            # Testcase 2: Some fields missing in flow, threat level from VT
            # NOT available
            {
                "flow": {
                    "daddr": "8.8.8.8",
                    "md5": "a1b2c3d4",
                    "starttime": "2023-11-15 12:00:00",
                    "uid": "flow-123",
                },
                "threat_level": None,
                "profileid": "profile_10.0.0.1",
                "twid": "timewindow1",
            },
            ThreatLevel.HIGH,
            [
                "Malicious downloaded file: a1b2c3d4.",
                "from IP: 8.8.8.8",
                "by URLhaus.",
            ],
        ),
    ],
)
def test_set_evidence_malicious_hash(
    file_info, expected_threat_level, expected_description_snippets
):
    """
    Test the `set_evidence_malicious_hash`.
    """
    urlhaus = ModuleFactory().create_urlhaus_obj()
    urlhaus.set_evidence_malicious_hash(file_info)

    assert urlhaus.db.set_evidence.call_count == 2

    for call_args in urlhaus.db.set_evidence.call_args_list:
        evidence = call_args[0][0]
        assert evidence.threat_level == expected_threat_level
        for snippet in expected_description_snippets:
            assert snippet in evidence.description


@pytest.mark.parametrize(
    "url_info, expected_threat_level, expected_description",
    [
        # Testcase1: Valid threat level and description
        (
            {"threat_level": "50", "description": "Malicious URL detected"},
            ThreatLevel.MEDIUM,
            "Malicious URL detected",
        ),
        # Testcase2: No threat level provided
        (
            {"description": "Another malicious URL"},
            ThreatLevel.MEDIUM,
            "Another malicious URL",
        ),
        # Testcase3: Invalid threat level format
        (
            {
                "threat_level": "invalid",
                "description": "Yet another malicious URL",
            },
            ThreatLevel.MEDIUM,
            "Yet another malicious URL",
        ),
    ],
)
def test_set_evidence_malicious_url(
    url_info, expected_threat_level, expected_description
):
    """
    Tests the set_evidence_malicious_url method
    with different URL info inputs.
    """
    urlhaus = ModuleFactory().create_urlhaus_obj()
    daddr = "1.2.3.4"
    uid = "1234"
    timestamp = "2023-11-01 12:00:00"
    profileid = "profile_1.2.3.4"
    twid = "timewindow1"

    urlhaus.set_evidence_malicious_url(
        daddr, url_info, uid, timestamp, profileid, twid
    )

    assert urlhaus.db.set_evidence.call_count == 2
    call_args_list = urlhaus.db.set_evidence.call_args_list
    evidence_objects = [args[0][0] for args in call_args_list]

    for evidence in evidence_objects:
        assert (
            evidence.evidence_type
            == EvidenceType.THREAT_INTELLIGENCE_MALICIOUS_URL
        )
        assert evidence.threat_level == expected_threat_level
        assert evidence.confidence == 0.7
        assert evidence.description == expected_description
        assert evidence.timestamp == timestamp
        assert evidence.timewindow.number == 1
        assert evidence.uid == [uid]
    assert evidence_objects[0].attacker.direction == Direction.SRC
    assert evidence_objects[0].attacker.value == "1.2.3.4"
    assert evidence_objects[1].attacker.direction == Direction.DST
    assert evidence_objects[1].attacker.value == daddr
