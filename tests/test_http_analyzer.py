"""Unit test for modules/http_analyzer/http_analyzer.py"""

import json
from dataclasses import asdict
import pytest

from slips_files.core.flows.zeek import (
    HTTP,
    Weird,
    Conn,
)
from tests.module_factory import ModuleFactory
from unittest.mock import (
    patch,
    MagicMock,
    Mock,
)
from modules.http_analyzer.http_analyzer import utils
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


def test_check_suspicious_user_agents():
    http_analyzer = ModuleFactory().create_http_analyzer_obj()
    flow = HTTP(
        starttime="1726593782.8840969",
        uid=uid,
        saddr="192.168.1.5",
        daddr="147.32.80.7",
        method="",
        host="147.32.80.7",
        uri="/wpad.dat",
        version=0,
        user_agent="CHM_MSDN",
        request_body_len=10,
        response_body_len=10,
        status_code="",
        status_msg="",
        resp_mime_types="",
        resp_fuids="",
    )
    # create a flow with suspicious user agent
    assert (
        http_analyzer.check_suspicious_user_agents(profileid, twid, flow)
        is True
    )


def test_check_multiple_google_connections():
    http_analyzer = ModuleFactory().create_http_analyzer_obj()
    # {"ts":1635765765.435485,"uid":"C7mv0u4M1zqJBHydgj",
    # "id.orig_h":"192.168.1.28","id.orig_p":52102,"id.resp_h":"216.58.198.78",
    # "id.resp_p":80,"trans_depth":1,"method":"GET","host":"google.com","uri":"/",
    # "version":"1.1","user_agent":"Wget/1.20.3 (linux-gnu)",
    # "request_body_len":0,"response_body_len":219,
    # "status_code":301,"status_msg":"Moved Permanently","tags":[],
    # "resp_fuids":["FGhwTU1OdvlfLrzBKc"],
    # "resp_mime_types":["text/html"]}
    for _ in range(4):
        flow = HTTP(
            starttime="1726593782.8840969",
            uid=uid,
            saddr="192.168.1.5",
            daddr="147.32.80.7",
            method="",
            host="google.com",
            uri="/",
            version=0,
            user_agent="CHM_MSDN",
            request_body_len=0,
            response_body_len=10,
            status_code="",
            status_msg="",
            resp_mime_types="",
            resp_fuids="",
        )
        found_detection = http_analyzer.check_multiple_empty_connections(
            "timewindow1", flow
        )
    assert found_detection is True


def test_parsing_online_ua_info(mocker):
    """
    tests the parsing and processing the ua found by the online query
    """
    http_analyzer = ModuleFactory().create_http_analyzer_obj()
    # use a different profile for this unit test to make
    # sure we don't already have info about it in the db
    profileid = "profile_192.168.99.99"

    http_analyzer.db.get_user_agent_from_profile.return_value = None
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


def test_get_user_agent_info(mocker):
    http_analyzer = ModuleFactory().create_http_analyzer_obj()
    # mock the function that gets info about the
    # given ua from an online db: get_ua_info_online()
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.text = """{
        "agent_name":"Safari",
        "os_type":"Macintosh",
        "os_name":"OS X"
    }"""

    http_analyzer.db.add_all_user_agent_to_profile.return_value = True
    http_analyzer.db.get_user_agent_from_profile.return_value = None

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


@pytest.mark.parametrize(
    "mac_vendor, user_agent, expected_result",
    [
        # User agent is compatible with MAC vendor
        ("Intel Corp", {"browser": "firefox"}, None),
        # Missing user agent information
        ("Apple Inc.", None, False),
        # Missing information
        (None, None, False),
    ],
)
def test_check_incompatible_user_agent(
    mac_vendor, user_agent, expected_result
):
    http_analyzer = ModuleFactory().create_http_analyzer_obj()
    # Use a different profile for this unit test
    profileid = "profile_192.168.77.254"

    http_analyzer.db.get_mac_vendor_from_profile.return_value = mac_vendor
    http_analyzer.db.get_user_agent_from_profile.return_value = user_agent
    flow = HTTP(
        starttime="1726593782.8840969",
        uid=uid,
        saddr="192.168.1.5",
        daddr="147.32.80.7",
        method="",
        host="google.com",
        uri="/",
        version=0,
        user_agent="CHM_MSDN",
        request_body_len=0,
        response_body_len=10,
        status_code="",
        status_msg="",
        resp_mime_types="",
        resp_fuids="",
    )

    result = http_analyzer.check_incompatible_user_agent(profileid, twid, flow)

    assert result is expected_result


def test_extract_info_from_ua():
    http_analyzer = ModuleFactory().create_http_analyzer_obj()
    # use another profile, because the default
    # one already has a ua in the db
    http_analyzer.db.get_user_agent_from_profile.return_value = None
    profileid = "profile_192.168.1.2"
    server_bag_ua = "server-bag[macOS,11.5.1,20G80,MacBookAir10,1]"
    expected_output = {
        "user_agent": "macOS,11.5.1,20G80,MacBookAir10,1",
        "os_name": "macOS",
        "os_type": "macOS11.5.1",
        "browser": "",
    }
    expected_output = json.dumps(expected_output)
    assert (
        http_analyzer.extract_info_from_ua(server_bag_ua, profileid)
        == expected_output
    )


@pytest.mark.parametrize(
    "cached_ua, new_ua, expected_result",
    [
        (
            # User agents belong to the same OS
            {"os_type": "Windows", "os_name": "Windows 10"},
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/58.0.3029.110 "
            "Safari/537.3",
            False,
        ),
        (
            # Missing cached user agent
            None,
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3_1) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 "
            "Safari/605.1.15",
            False,
        ),
        (
            # User agents belongs to different OS
            {"os_type": "Linux", "os_name": "Ubuntu"},
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3_1) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 "
            "Safari/605.1.15",
            True,
        ),
    ],
)
def test_check_multiple_user_agents_in_a_row(
    cached_ua, new_ua, expected_result
):
    http_analyzer = ModuleFactory().create_http_analyzer_obj()
    flow = HTTP(
        starttime="1726593782.8840969",
        uid=uid,
        saddr="192.168.1.5",
        daddr="147.32.80.7",
        method="",
        host="google.com",
        uri="/",
        version=0,
        user_agent=new_ua,
        request_body_len=0,
        response_body_len=10,
        status_code="",
        status_msg="",
        resp_mime_types="",
        resp_fuids="",
    )
    result = http_analyzer.check_multiple_user_agents_in_a_row(
        flow, twid, cached_ua
    )
    assert result is expected_result


@pytest.mark.parametrize(
    "mime_types, expected",
    [
        ([], False),  # Empty list
        (["text/html"], False),  # Non-executable MIME type
        (["application/x-msdownload"], True),  # Executable MIME type
        (["text/html", "application/x-msdownload"], True),  # Mixed MIME types
        (
            ["APPLICATION/X-MSDOWNLOAD"],
            False,
        ),  # Executable MIME types are case-insensitive
        (["text/html", "application/x-msdownload", "image/jpeg"], True),
        # Mixed executable and non-executable MIME types
    ],
)
def test_detect_executable_mime_types(mime_types, expected):
    http_analyzer = ModuleFactory().create_http_analyzer_obj()
    flow = HTTP(
        starttime="1726593782.8840969",
        uid=uid,
        saddr="192.168.1.5",
        daddr="147.32.80.7",
        method="",
        host="google.com",
        uri="/",
        version=0,
        user_agent="",
        request_body_len=0,
        response_body_len=10,
        status_code="",
        status_msg="",
        resp_mime_types=mime_types,
        resp_fuids="",
    )
    assert http_analyzer.detect_executable_mime_types(twid, flow) is expected


def test_set_evidence_http_traffic(mocker):
    http_analyzer = ModuleFactory().create_http_analyzer_obj()
    mocker.spy(http_analyzer.db, "set_evidence")
    flow = HTTP(
        starttime="1726593782.8840969",
        uid=uid,
        saddr="192.168.1.5",
        daddr="147.32.80.7",
        method="",
        host="google.com",
        uri="/",
        version=0,
        user_agent="",
        request_body_len=0,
        response_body_len=10,
        status_code="",
        status_msg="",
        resp_mime_types="",
        resp_fuids="",
    )
    http_analyzer.set_evidence_http_traffic(twid, flow)

    http_analyzer.db.set_evidence.assert_called_once()


def test_set_evidence_weird_http_method(mocker):
    http_analyzer = ModuleFactory().create_http_analyzer_obj()
    http_analyzer.db.get_ip_identification.return_value = (
        "Some IP identification"
    )
    mocker.spy(http_analyzer.db, "set_evidence")
    weird_flow = Weird(
        starttime="1726593782.8840969",
        uid="123",
        saddr="192.168.1.5",
        daddr="1.1.1.1",
        name="",
        addl="weird_method_here",
    )
    conn_flow = Conn(
        starttime="1726249372.312124",
        uid="123",
        saddr="192.168.1.1",
        daddr="1.1.1.1",
        dur=1,
        proto="tcp",
        appproto="",
        sport="0",
        dport="12345",
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="Established",
        history="",
    )
    http_analyzer.set_evidence_weird_http_method(
        twid, weird_flow, asdict(conn_flow)
    )
    http_analyzer.db.set_evidence.assert_called_once()


def test_set_evidence_executable_mime_type(mocker):
    http_analyzer = ModuleFactory().create_http_analyzer_obj()
    flow = HTTP(
        starttime="1726593782.8840969",
        uid=uid,
        saddr="192.168.1.5",
        daddr="147.32.80.7",
        method="WEIRD_METHOD",
        host="google.com",
        uri="/",
        version=0,
        user_agent="",
        request_body_len=0,
        response_body_len=10,
        status_code="",
        status_msg="",
        resp_mime_types="application/x-msdownload",
        resp_fuids="",
    )
    mocker.spy(http_analyzer.db, "set_evidence")
    http_analyzer.set_evidence_executable_mime_type(twid, flow)

    assert http_analyzer.db.set_evidence.call_count == 2


@pytest.mark.parametrize("config_value", [700])
def test_read_configuration_valid(mocker, config_value):
    http_analyzer = ModuleFactory().create_http_analyzer_obj()
    mock_conf = mocker.patch(
        "slips_files.common.parsers.config_parser.ConfigParser"
    )
    mock_conf.return_value.get_pastebin_download_threshold.return_value = (
        config_value
    )
    http_analyzer.read_configuration()
    assert http_analyzer.pastebin_downloads_threshold == config_value


@pytest.mark.parametrize(
    "flow_name, evidence_expected",
    [
        # Flow name contains "unknown_HTTP_method"
        (
            "unknown_HTTP_method",
            True,
        ),
        # Flow name does not contain "unknown_HTTP_method"
        (
            "some_other_event",
            False,
        ),
    ],
)
async def test_check_weird_http_method(mocker, flow_name, evidence_expected):
    http_analyzer = ModuleFactory().create_http_analyzer_obj()
    http_analyzer.set_evidence_weird_http_method = Mock()
    mocker.spy(http_analyzer, "set_evidence_weird_http_method")

    msg = {
        "flow": asdict(
            Weird(
                starttime="1726593782.8840969",
                uid="123",
                saddr="192.168.1.5",
                daddr="1.1.1.1",
                name=flow_name,
                addl=flow_name,
            )
        ),
        "twid": twid,
    }

    with patch(
        "slips_files.common.slips_utils.utils.get_original_conn_flow"
    ) as mock_get_original_conn_flow:
        mock_get_original_conn_flow.side_effect = [None, {"flow": {}}]
        await http_analyzer.check_weird_http_method(msg)

    if evidence_expected:
        http_analyzer.set_evidence_weird_http_method.assert_called_once()
    else:
        http_analyzer.set_evidence_weird_http_method.assert_not_called()


def test_pre_main(mocker):
    http_analyzer = ModuleFactory().create_http_analyzer_obj()
    mocker.patch("slips_files.common.slips_utils.Utils.drop_root_privs")
    http_analyzer.pre_main()
    utils.drop_root_privs.assert_called_once()


@pytest.mark.parametrize(
    "uri, request_body_len, expected_result",
    [
        ("/path/to/file", 0, False),  # Non-empty URI
        ("/", 100, False),  # Non-zero request body length
        ("/", "invalid_length", False),  # Invalid request body length
    ],
)
def test_check_multiple_empty_connections(
    uri, request_body_len, expected_result
):
    http_analyzer = ModuleFactory().create_http_analyzer_obj()
    host = "google.com"
    flow = HTTP(
        starttime="1726593782.8840969",
        uid=str("uid_55"),
        saddr="192.168.1.5",
        daddr="147.32.80.7",
        method="WEIRD_METHOD",
        host="google.com",
        uri=uri,
        version=0,
        user_agent="",
        request_body_len=request_body_len,
        response_body_len=10,
        status_code="",
        status_msg="",
        resp_mime_types="",
        resp_fuids="",
    )
    result = http_analyzer.check_multiple_empty_connections(twid, flow)
    assert result is expected_result

    if uri == "/" and request_body_len == 0 and expected_result is False:
        for i in range(http_analyzer.empty_connections_threshold):
            flow = HTTP(
                starttime="1726593782.8840969",
                uid=str(f"uid_{i}"),
                saddr="192.168.1.5",
                daddr="147.32.80.7",
                method="WEIRD_METHOD",
                host="google.com",
                uri=uri,
                version=0,
                user_agent="",
                request_body_len=request_body_len,
                response_body_len=10,
                status_code="",
                status_msg="",
                resp_mime_types="",
                resp_fuids="",
            )
            http_analyzer.check_multiple_empty_connections(twid, flow)
        assert http_analyzer.connections_counter[host] == ([], 0)


@pytest.mark.parametrize(
    "host, response_body_len, method, expected_result",
    [
        ("pastebin.com", "invalid_length", "GET", False),
        ("8.8.8.8", "1024", "GET", False),
        ("pastebin.com", "512", "GET", False),
        ("pastebin.com", "2048", "POST", False),
        ("pastebin.com", "2048", "GET", True),  # Large download from Pastebin
    ],
)
def test_check_pastebin_downloads(
    host, response_body_len, method, expected_result
):
    http_analyzer = ModuleFactory().create_http_analyzer_obj()
    flow = HTTP(
        starttime="1726593782.8840969",
        uid=str("uid_1"),
        saddr="192.168.1.5",
        daddr="147.32.80.7",
        method=method,
        host="google.com",
        uri=host,
        version=0,
        user_agent="",
        request_body_len=5,
        response_body_len=response_body_len,
        status_code="",
        status_msg="",
        resp_mime_types="",
        resp_fuids="",
    )
    if host != "pastebin.com":
        http_analyzer.db.get_ip_identification.return_value = (
            "Not a Pastebin domain"
        )
    else:
        http_analyzer.db.get_ip_identification.return_value = "pastebin.com"
        http_analyzer.pastebin_downloads_threshold = 1024
    result = http_analyzer.check_pastebin_downloads(twid, flow)
    assert result == expected_result


@pytest.mark.parametrize(
    "mock_response",
    [
        # Unexpected response format
        MagicMock(status_code=200, text="Unexpected response format"),
        # Timeout
        MagicMock(side_effect=requests.exceptions.ReadTimeout),
    ],
)
def test_get_ua_info_online_error_cases(mock_response):
    http_analyzer = ModuleFactory().create_http_analyzer_obj()
    with patch("requests.get", return_value=mock_response):
        assert http_analyzer.get_ua_info_online(SAFARI_UA) is False
