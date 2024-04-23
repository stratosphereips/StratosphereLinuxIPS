"""Unit test for modules/http_analyzer/http_analyzer.py"""

from tests.module_factory import ModuleFactory
import random
from unittest.mock import patch, MagicMock
from modules.http_analyzer.http_analyzer import utils
import pytest
import requests

# dummy params used for testing
profileid = "profile_192.168.1.1"
twid = "timewindow1"
uid = "CAeDWs37BipkfP21u8"
timestamp = 1635765895.037696
SAFARI_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3_1) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/15.3 Safari/605.1.15"
)


def get_random_MAC():
    return "02:00:00:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    )


def test_check_suspicious_user_agents(mock_db):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    # create a flow with suspicious user agent
    assert (
            http_analyzer.check_suspicious_user_agents(
                uid,
                "147.32.80.7",
                "/wpad.dat",
                timestamp,
                "CHM_MSDN",
                profileid,
                twid,
            )
            is True
    )


def test_check_multiple_google_connections(mock_db):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    # {"ts":1635765765.435485,"uid":"C7mv0u4M1zqJBHydgj",
    # "id.orig_h":"192.168.1.28","id.orig_p":52102,"id.resp_h":"216.58.198.78",
    # "id.resp_p":80,"trans_depth":1,"method":"GET","host":"google.com","uri":"/",
    # "version":"1.1","user_agent":"Wget/1.20.3 (linux-gnu)",
    # "request_body_len":0,"response_body_len":219,
    # "status_code":301,"status_msg":"Moved Permanently","tags":[],
    # "resp_fuids":["FGhwTU1OdvlfLrzBKc"],
    # "resp_mime_types":["text/html"]}
    host = "google.com"
    uri = "/"
    request_body_len = 0
    for _ in range(4):
        found_detection = http_analyzer.check_multiple_empty_connections(
            uid, host, uri, timestamp, request_body_len, profileid, twid
        )
    assert found_detection is True


def test_parsing_online_ua_info(mock_db, mocker):
    """
    tests the parsing and processing the ua found by the online query
    """
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    # use a different profile for this unit test to make
    # sure we don't already have info about it in the db
    profileid = "profile_192.168.99.99"

    mock_db.get_user_agent_from_profile.return_value = None
    # mock the function that gets info about the given ua from an online db
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.text = """{
        "agent_name":"Safari",
        "os_type":"Macintosh",
        "os_name":"OS X"
    }"""

    # add os_type , os_name and agent_name to the db
    ua_info = http_analyzer.get_user_agent_info(SAFARI_UA, profileid)
    assert ua_info["os_type"] == "Macintosh"
    assert ua_info["browser"] == "Safari"


def test_get_user_agent_info(mock_db, mocker):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    # mock the function that gets info about the
    # given ua from an online db: get_ua_info_online()
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.text = """{
        "agent_name":"Safari",
        "os_type":"Macintosh",
        "os_name":"OS X"
    }"""

    mock_db.add_all_user_agent_to_profile.return_value = True
    mock_db.get_user_agent_from_profile.return_value = None

    expected_ret_value = {
        "browser": "Safari",
        "os_name": "OS X",
        "os_type": "Macintosh",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) "
                      "Version/15.3 Safari/605.1.15",
    }
    assert (
            http_analyzer.get_user_agent_info(SAFARI_UA, profileid)
            == expected_ret_value
    )
    # # get ua info online, and add os_type , os_name and agent_name anout this profile
    # # to the db
    # assert ua_added_to_db is not None, 'Error getting UA info online'
    # assert ua_added_to_db is not False, 'We already have UA info about this profile in the db'


def test_check_incompatible_user_agent(mock_db):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    # use a different profile for this unit test to make sure we don't already have info about
    # it in the db. it has to be a private IP for its' MAC to not be marked as the gw MAC
    profileid = "profile_192.168.77.254"

    # Mimic an intel mac vendor using safari
    mock_db.get_mac_vendor_from_profile.return_value = "Intel Corp"
    mock_db.get_user_agent_from_profile.return_value = {"browser": "safari"}

    assert (
            http_analyzer.check_incompatible_user_agent(
                "google.com", "/images", timestamp, profileid, twid, uid
            )
            is True
    )


def test_extract_info_from_UA(mock_db):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    # use another profile, because the default
    # one already has a ua in the db
    mock_db.get_user_agent_from_profile.return_value = None
    profileid = "profile_192.168.1.2"
    server_bag_ua = "server-bag[macOS,11.5.1,20G80,MacBookAir10,1]"
    assert (
            http_analyzer.extract_info_from_UA(server_bag_ua, profileid)
            == '{"user_agent": "macOS,11.5.1,20G80,MacBookAir10,1", "os_name": "macOS", "os_type": "macOS11.5.1", '
               '"browser": ""}'
    )


def test_extract_info_from_UA_valid(mock_db):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    mock_db.get_user_agent_from_profile.return_value = None
    profileid = "profile_192.168.1.2"
    server_bag_ua = "server-bag[macOS,11.5.1,20G80,MacBookAir10,1]"
    expected_output = ('{"user_agent": "macOS,11.5.1,20G80,MacBookAir10,1", "os_name": "macOS", "os_type": '
                       '"macOS11.5.1", "browser": ""}')

    assert http_analyzer.extract_info_from_UA(server_bag_ua, profileid) == expected_output


def test_check_multiple_UAs(mock_db):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    mozilla_ua = (
        "Mozilla/5.0 (X11; Fedora;Linux x86; rv:60.0) "
        "Gecko/20100101 Firefox/60.0"
    )
    # old ua
    cached_ua = {"os_type": "Fedora", "os_name": "Linux"}
    # should set evidence
    assert (
            http_analyzer.check_multiple_UAs(
                cached_ua, mozilla_ua, timestamp, profileid, twid, uid
            )
            is False
    )
    # in this case we should alert
    assert (
            http_analyzer.check_multiple_UAs(
                cached_ua, SAFARI_UA, timestamp, profileid, twid, uid
            )
            is True
    )


@pytest.mark.parametrize(
    "mime_types,expected",
    [
        ([], False),  # Empty list
        (["text/html"], False),  # Non-executable MIME type
        (["application/x-msdownload"], True),  # Executable MIME type
        (["text/html", "application/x-msdownload"], True),  # Mixed MIME types
        (["APPLICATION/X-MSDOWNLOAD"], False),  # Executable MIME types are case-insensitive
        (["text/html", "application/x-msdownload", "image/jpeg"], True),
        # Mixed executable and non-executable MIME types
    ],
)
def test_detect_executable_mime_types(mock_db, mime_types, expected):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    assert http_analyzer.detect_executable_mime_types(mime_types) is expected


def test_set_evidence_http_traffic(mock_db, mocker):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    mocker.spy(http_analyzer.db, 'set_evidence')

    http_analyzer.set_evidence_http_traffic('8.8.8.8', profileid, twid, uid, timestamp)

    http_analyzer.db.set_evidence.assert_called_once()


def test_set_evidence_weird_http_method(mock_db, mocker):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    mock_db.get_ip_identification.return_value = "Some IP identification"
    mocker.spy(http_analyzer.db, 'set_evidence')

    flow = {
        "daddr": "8.8.8.8",
        "addl": "WEIRD_METHOD",
        "uid": uid,
        "starttime": timestamp
    }

    http_analyzer.set_evidence_weird_http_method(profileid, twid, flow)

    http_analyzer.db.set_evidence.assert_called_once()


def test_set_evidence_executable_mime_type(mock_db, mocker):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    mock_db.get_ip_identification.return_value = "Some IP identification"

    mocker.spy(http_analyzer.db, 'set_evidence')

    http_analyzer.set_evidence_executable_mime_type(
        'application/x-msdownload', profileid, twid, uid, timestamp, '8.8.8.8'
    )

    assert http_analyzer.db.set_evidence.call_count == 2


def test_set_evidence_executable_mime_type_source_dest(mock_db, mocker):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    mock_db.get_ip_identification.return_value = "Some IP identification"

    mocker.spy(http_analyzer.db, 'set_evidence')

    http_analyzer.set_evidence_executable_mime_type(
        'application/x-msdownload', profileid, twid, uid, timestamp, '8.8.8.8'
    )

    assert http_analyzer.db.set_evidence.call_count == 2


@pytest.mark.parametrize(
    "config_value, expected_exception",
    [
        (1024, None),  # Valid configuration value
        (Exception("Config file missing"), Exception),  # Invalid configuration (exception)
    ],
)
def test_read_configuration(mock_db, mocker, config_value, expected_exception):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    mock_conf = mocker.patch('http_analyzer.ConfigParser')

    if isinstance(config_value, Exception):
        mock_conf.return_value.get_pastebin_download_threshold.side_effect = config_value
    else:
        mock_conf.return_value.get_pastebin_download_threshold.return_value = config_value

    if expected_exception:
        with pytest.raises(expected_exception):
            http_analyzer.read_configuration()
    else:
        http_analyzer.read_configuration()
        assert http_analyzer.pastebin_downloads_threshold == config_value


@pytest.mark.parametrize(
    "flow_name, expected_call",
    [
        ("unknown_HTTP_method", True),  # Flow name contains "unknown_HTTP_method"
        ("some_other_event", False),  # Flow name does not contain "unknown_HTTP_method"
    ],
)
def test_check_weird_http_method(mock_db, mocker, flow_name, expected_call):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    mocker.spy(http_analyzer, 'set_evidence_weird_http_method')

    msg = {
        "flow": {
            "name": flow_name,
            "daddr": "8.8.8.8",
            "addl": "WEIRD_METHOD",
            "uid": uid,
            "starttime": timestamp
        },
        "profileid": profileid,
        "twid": twid
    }

    http_analyzer.check_weird_http_method(msg)

    if expected_call:
        http_analyzer.set_evidence_weird_http_method.assert_called_once()
    else:
        http_analyzer.set_evidence_weird_http_method.assert_not_called()


def test_pre_main(mock_db, mocker):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    mocker.patch('http_analyzer.utils.drop_root_privs')

    http_analyzer.pre_main()

    utils.drop_root_privs.assert_called_once()


@pytest.mark.parametrize(
    "user_agent, expected_result",
    [
        ("Mozilla/5.0", False),  # Non-suspicious user agent
        ("chm_MSDN", True),  # Suspicious user agent (case-insensitive)
        ("", False),  # Empty user agent
        ("httpsend chm_msdn", True),  # User agent with multiple suspicious keywords     
    ],
)
def test_check_suspicious_user_agents(mock_db, user_agent, expected_result):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    result = http_analyzer.check_suspicious_user_agents(
        uid, "example.com", "/", timestamp, user_agent, profileid, twid
    )
    assert result is expected_result


def test_get_mac_vendor_from_profile(mock_db):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    mock_db.get_mac_vendor_from_profile.return_value = "Apple Inc."
    profileid = "profile_192.168.1.1"

    vendor = http_analyzer.db.get_mac_vendor_from_profile(profileid)

    assert vendor == "Apple Inc."


@pytest.mark.parametrize(
    "cached_ua, new_ua, expected_result",
    [
        ({"os_type": "Windows", "os_name": "Windows 10"},
         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 "
         "Safari/537.3",
         False),  # User agents belong to the same OS
        (None,
         "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 "
         "Safari/605.1.15",
         False),  # Missing cached user agent
    ],
)
def test_check_multiple_UAs(mock_db, cached_ua, new_ua, expected_result):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    result = http_analyzer.check_multiple_UAs(
        cached_ua, new_ua, timestamp, profileid, twid, uid
    )
    assert result is expected_result


@pytest.mark.parametrize(
    "mac_vendor, user_agent, expected_result",
    [
        ("Intel Corp", {"browser": "firefox"}, None),  # User agent is compatible with MAC vendor
        ("Apple Inc.", None, False),  # Missing user agent information
        ("Apple Inc", {"browser": "safari"}, None),  # Compatible user agent and MAC vendor
        (None, None, False),  # Missing information
    ],
)
def test_check_incompatible_user_agent(mock_db, mac_vendor, user_agent, expected_result):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    profileid = "profile_192.168.77.254"
    mock_db.get_mac_vendor_from_profile.return_value = mac_vendor
    mock_db.get_user_agent_from_profile.return_value = user_agent

    result = http_analyzer.check_incompatible_user_agent(
        "google.com", "/images", timestamp, profileid, twid, uid
    )

    assert result is expected_result


@pytest.mark.parametrize(
    "uri, request_body_len, expected_result",
    [
        ("/path/to/file", 0, False),  # Non-empty URI
        ("/", 100, False),  # Non-zero request body length
        ("/", "invalid_length", False),  # Invalid request body length
    ],
)
def test_check_multiple_empty_connections(mock_db, uri, request_body_len, expected_result):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    host = "google.com"
    result = http_analyzer.check_multiple_empty_connections(
        uid, host, uri, timestamp, request_body_len, profileid, twid
    )
    assert result is expected_result

    if uri == "/" and request_body_len == 0 and expected_result is False:
        empty_connections_threshold = http_analyzer.empty_connections_threshold
        for _ in range(empty_connections_threshold):
            http_analyzer.check_multiple_empty_connections(
                uid, host, uri, timestamp, request_body_len, profileid, twid
            )
        assert http_analyzer.connections_counter[host] == ([], 0)


@pytest.mark.parametrize(
    "user_agent, mock_side_effect, mock_status_code, mock_response_text, expected_result",
    [
        (SAFARI_UA, requests.exceptions.ConnectionError, None, None, False),  # Online service unavailable
        ("Invalid user agent", None, 200, "Invalid response", False),  # Invalid user agent string
    ],
)
def test_get_user_agent_info(mock_db, mocker, user_agent, mock_side_effect, mock_status_code, mock_response_text,
                             expected_result):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)

    if mock_side_effect:
        mocker.patch("http_analyzer.requests.get", side_effect=mock_side_effect)
    else:
        mock_requests = mocker.patch("requests.get")
        mock_requests.return_value.status_code = mock_status_code
        mock_requests.return_value.text = mock_response_text

    result = http_analyzer.get_user_agent_info(user_agent, profileid)
    assert result is expected_result


@pytest.mark.parametrize(
    "url, response_body_len, method, expected_result",
    [
        ("pastebin.com", "invalid_length", "GET", False),
        ("8.8.8.8", "1024", "GET", None),
        ("pastebin.com", "512", "GET", None),
        ("pastebin.com", "2048", "POST", None),
    ],
)
def test_check_pastebin_downloads(mock_db, url, response_body_len, method, expected_result):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)

    if url != "pastebin.com":
        mock_db.get_ip_identification.return_value = "Not a Pastebin IP"
    else:
        mock_db.get_ip_identification.return_value = "pastebin.com"
        http_analyzer.pastebin_downloads_threshold = 1024

    assert http_analyzer.check_pastebin_downloads(
        url, response_body_len, method, profileid, twid, timestamp, uid
    ) == expected_result


@pytest.mark.parametrize(
    "mock_response",
    [
        # Unexpected response format
        MagicMock(status_code=200, text="Unexpected response format"),
        # Timeout
        MagicMock(side_effect=requests.exceptions.ReadTimeout),
    ],
)
def test_get_ua_info_online_error_cases(mock_db, mock_response):
    http_analyzer = ModuleFactory().create_http_analyzer_obj(mock_db)
    with patch("requests.get", return_value=mock_response):
        assert http_analyzer.get_ua_info_online(SAFARI_UA) is False
