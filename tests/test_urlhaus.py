from unittest.mock import patch, Mock
import pytest
import requests
import json
from modules.threat_intelligence.urlhaus import (
    URLhaus,
    ThreatLevel,
    EvidenceType,
    IDEACategory,
    Direction,
    URLHAUS_BASE_URL,
)


@pytest.fixture
def mock_db():
    mock_db = Mock()
    return mock_db


@pytest.mark.parametrize(
    "to_lookup, expected_url, status_code, side_effect",
    [
        # Testcase1: URL lookup
        (
            {"url": "https://example.com"},
            f"{URLHAUS_BASE_URL}/url/",
            200,
            None,
        ),
        # Testcase2: Payload (hash) lookup
        (
            {"md5_hash": "a1b2c3d4"},
            f"{URLHAUS_BASE_URL}/payload/",
            200,
            None,
        ),
        # Testcase3: Connection error
        (
            {"url": "https://example.com"},
            None,
            None,
            requests.exceptions.ConnectionError,
        ),
    ],
)
@patch("modules.threat_intelligence.urlhaus.requests.session")
def test_make_urlhaus_request(
    mock_session, to_lookup, expected_url, status_code, side_effect
):
    """Test the make_urlhaus_request function with different scenarios."""
    mock_session_instance = Mock()
    mock_session.return_value = mock_session_instance
    if side_effect:
        mock_session_instance.post.side_effect = side_effect
    else:
        mock_response = Mock()
        mock_response.status_code = status_code
        mock_session_instance.post.return_value = mock_response
    urlhaus = URLhaus(None)
    urlhaus.urlhaus_session = mock_session_instance
    response = urlhaus.make_urlhaus_request(to_lookup)

    if side_effect:
        assert urlhaus.urlhaus_session is mock_session_instance
    else:
        mock_session_instance.post.assert_called_once_with(
            expected_url, to_lookup, headers=mock_session_instance.headers
        )
        assert response == mock_response


def test_create_urlhaus_session():
    with patch.object(
        URLhaus, "create_urlhaus_session"
    ) as mock_create_session:
        urlhaus = URLhaus(None)
    urlhaus.create_urlhaus_session()
    mock_create_session.assert_called_once_with()


@patch.object(URLhaus, "make_urlhaus_request")
def test_parse_urlhaus_url_response_with_payloads(mock_request):
    mock_response = {
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
    }
    mock_request.return_value.status_code = 200
    mock_request.return_value.text = json.dumps(mock_response)
    urlhaus = URLhaus(None)
    url = "https://malicious.com"
    result = urlhaus.parse_urlhaus_url_response(mock_response, url)
    expected_result = {
        "source": "URLhaus",
        "url": url,
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
    }
    assert result == expected_result


@patch.object(URLhaus, "make_urlhaus_request")
def test_parse_urlhaus_md5_response(mock_request):
    mock_response = {
        "file_type": "PE32 executable (console) Intel 80386, for MS Windows",
        "filename": "malware.exe",
        "signature": "Trojan.Win32.Generic!BT",
        "virustotal": {
            "percent": 95,
        },
    }
    mock_request.return_value.status_code = 200
    mock_request.return_value.text = json.dumps(mock_response)
    urlhaus = URLhaus(None)
    md5 = "a1b2c3d4"
    result = urlhaus.parse_urlhaus_md5_response(mock_response, md5)
    expected_result = {
        "blacklist": "URLhaus",
        "threat_level": 95,
        "tags": "Trojan.Win32.Generic!BT",
        "file_type": "PE32 executable (console) Intel 80386, for MS Windows",
        "file_name": "malware.exe",
    }
    assert result == expected_result


mock_url_response_data = {
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
            "virustotal": {
                "percent": 80,
            },
        }
    ],
}
mock_md5_response_data = {
    "query_status": "ok",
    "file_type": "PE32 executable (GUI) Intel 80386, for MS Windows",
    "filename": "malware.exe",
    "signature": "Generic.Malware",
    "virustotal": {
        "percent": 80,
    },
}


@patch("modules.threat_intelligence.urlhaus.URLhaus.make_urlhaus_request")
def test_urlhaus_lookup_url_success(mock_request):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = json.dumps(mock_url_response_data)
    mock_request.return_value = mock_response
    urlhaus = URLhaus(None)
    result = urlhaus.urlhaus_lookup("https://example.com", "url")
    assert result["source"] == "URLhaus"
    assert result["threat_level"]
    assert result["tags"] == "phishing"


@patch("modules.threat_intelligence.urlhaus.URLhaus.make_urlhaus_request")
def test_urlhaus_lookup_md5_success(mock_request):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = json.dumps(mock_md5_response_data)
    mock_request.return_value = mock_response
    urlhaus = URLhaus(None)
    result = urlhaus.urlhaus_lookup("a1b2c3d4", "md5_hash")
    assert result["blacklist"] == "URLhaus"
    assert result["threat_level"]
    assert result["file_type"]


@pytest.mark.parametrize(
    "mock_response, expected_result, test_description",
    [
        (
            # Testcase1: No Results
            {"query_status": "no_results"},
            None,
            "No results found for the given URL"
        ),
        (
            # Testcase2: Invalid URL
            {"query_status": "invalid_url"},
            None,
            "Given URL is invalid"
        ),
        (
            # Testcase3: Request Error
            None,
            None,
            "Request to URLhaus failed"
        ),
        (
            # Testcase4: JSON Error
            "not json",
            None,
            "URLhaus response is not valid JSON"
        ),
    ],
)
def test_urlhaus_lookup(mock_response, expected_result, test_description):
    """Tests urlhaus_lookup with different scenarios."""
    with patch("modules.threat_intelligence.urlhaus.URLhaus.make_urlhaus_request") as mock_request:
        if mock_response is None:
            mock_request.return_value = None
        else:
            mock_response_obj = Mock()
            mock_response_obj.status_code = 200
            if isinstance(mock_response, dict):
                mock_response_obj.text = json.dumps(mock_response)
            else:
                mock_response_obj.text = mock_response
            mock_request.return_value = mock_response_obj

        urlhaus = URLhaus(None)
        result = urlhaus.urlhaus_lookup("https://example.com", "url")
        assert result == expected_result

file_info = {
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
}

url_info_with_threat_level = {
    "threat_level": 50,
    "description": "Malicious URL",
}

url_info_without_threat_level = {
    "description": "Malicious URL",
}


@pytest.mark.parametrize(
    "url_info, expected_threat_level",
    [
        (
            {"threat_level": 50, "description": "Malicious URL"},
            ThreatLevel.MEDIUM,
        ),
        ({"description": "Malicious URL"}, ThreatLevel.MEDIUM),
        (
            {"threat_level": "invalid", "description": "Malicious URL"},
            ThreatLevel.MEDIUM,
        ),
    ],
)
def test_get_threat_level(url_info, expected_threat_level):
    urlhaus = URLhaus(None)
    assert urlhaus.get_threat_level(url_info) == expected_threat_level


def test_set_evidence_malicious_hash_with_threat_level(mock_db):
    urlhaus = URLhaus(mock_db)
    urlhaus.set_evidence_malicious_hash(file_info)
    assert mock_db.set_evidence.call_count == 2
    call_args = mock_db.set_evidence.call_args_list[0][0][0]
    assert call_args.attacker.direction.name == "SRC"
    assert call_args.attacker.attacker_type.name == "IP"
    assert call_args.attacker.value == "10.0.0.1"
    assert call_args.threat_level == ThreatLevel.HIGH
    assert "Virustotal score: 80% malicious" in call_args.description
    call_args = mock_db.set_evidence.call_args_list[1][0][0]
    assert call_args.attacker.direction.name == "DST"
    assert call_args.attacker.attacker_type.name == "IP"
    assert call_args.attacker.value == "8.8.8.8"
    assert call_args.threat_level == ThreatLevel.HIGH
    assert "Virustotal score: 80% malicious" in call_args.description


def test_set_evidence_malicious_hash_without_threat_level(mock_db):
    file_info_no_threat_level = file_info.copy()
    del file_info_no_threat_level["threat_level"]

    urlhaus = URLhaus(mock_db)
    urlhaus.set_evidence_malicious_hash(file_info_no_threat_level)
    assert mock_db.set_evidence.call_count == 2
    for call_args in mock_db.set_evidence.call_args_list:
        assert call_args[0][0].threat_level == ThreatLevel.HIGH


SAMPLE_DADDR = "1.2.3.4"
SAMPLE_URL_INFO = {
    "threat_level": "50",
    "description": "Malicious URL detected",
}
SAMPLE_UID = "1234"
SAMPLE_TIMESTAMP = "2023-11-01 12:00:00"
SAMPLE_PROFILEID = "profile_1.2.3.4"
SAMPLE_TWID = "timewindow1"


@patch.object(URLhaus, "get_threat_level")
def test_set_evidence_malicious_url(mock_get_threat_level):
    mock_db = Mock()
    urlhaus_instance = URLhaus(mock_db)
    mock_get_threat_level.return_value = ThreatLevel.MEDIUM
    urlhaus_instance.set_evidence_malicious_url(
        SAMPLE_DADDR,
        SAMPLE_URL_INFO,
        SAMPLE_UID,
        SAMPLE_TIMESTAMP,
        SAMPLE_PROFILEID,
        SAMPLE_TWID,
    )
    assert mock_db.set_evidence.call_count == 2
    call_args_list = mock_db.set_evidence.call_args_list
    evidence_objects = [args[0][0] for args in call_args_list]
    for evidence in evidence_objects:
        assert (
            evidence.evidence_type
            == EvidenceType.THREAT_INTELLIGENCE_MALICIOUS_URL
        )
        assert evidence.threat_level == ThreatLevel.MEDIUM
        assert evidence.confidence == 0.7
        assert evidence.description == SAMPLE_URL_INFO["description"]
        assert evidence.timestamp == SAMPLE_TIMESTAMP
        assert evidence.category == IDEACategory.MALWARE
        assert evidence.timewindow.number == 1
        assert evidence.uid == [SAMPLE_UID]
    assert evidence_objects[0].attacker.direction == Direction.SRC
    assert evidence_objects[0].attacker.value == "1.2.3.4"
    assert evidence_objects[1].attacker.direction == Direction.DST
    assert evidence_objects[1].attacker.value == SAMPLE_DADDR
