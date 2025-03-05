# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/http_analyzer/http_analyzer.py"""

import json
from dataclasses import asdict
import pytest
from unittest.mock import (
    patch,
    MagicMock,
    Mock,
)
import requests

from slips_files.core.flows.zeek import (
    HTTP,
    Weird,
    Conn,
)
from tests.common_test_utils import get_mock_coro
from tests.module_factory import ModuleFactory
from modules.http_analyzer.http_analyzer import utils

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
    http_analyzer.set_evidence.http_traffic(twid, flow)

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
    http_analyzer.set_evidence.weird_http_method(
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
    http_analyzer.set_evidence.executable_mime_type(twid, flow)

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
    http_analyzer.set_evidence.weird_http_method = Mock()
    mocker.spy(http_analyzer.set_evidence, "weird_http_method")

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
        http_analyzer.set_evidence.weird_http_method.assert_called_once()
    else:
        http_analyzer.set_evidence.weird_http_method.assert_not_called()


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
        http_analyzer.db.get_ip_identification.return_value = {}
    else:
        http_analyzer.db.get_ip_identification.return_value = {
            "SNI": "pastebin.com"
        }
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


####################################################


# tests for check_non_http_port_80_conns
async def test_check_non_http_port_80_conns_not_interested():
    # mock a flow that we're not interested in (e.g. not an established tcp
    # connection on port 80 with non-zero bytes)
    analyzer = ModuleFactory().create_http_analyzer_obj()
    analyzer.is_tcp_established_port_80_non_empty_flow = Mock(
        return_value=False
    )
    result = await analyzer.check_non_http_port_80_conns(None, None)
    assert result is False


async def test_check_non_http_port_80_conns_is_http():
    # when the flow is a recognized http flow, we keep track of it
    # and return false
    analyzer = ModuleFactory().create_http_analyzer_obj()
    analyzer.is_tcp_established_port_80_non_empty_flow = Mock(
        return_value=True
    )
    analyzer.is_http_proto_recognized_by_zeek = Mock(return_value=True)
    analyzer.keep_track_of_http_flow = Mock()
    flow = MagicMock(starttime=100, saddr="192.168.1.1", daddr="1.1.1.1")
    result = await analyzer.check_non_http_port_80_conns(None, flow)
    assert result is False
    analyzer.keep_track_of_http_flow.assert_called_once_with(
        flow, (flow.saddr, flow.daddr)
    )


async def test_check_non_http_port_80_conns_matching_http_past():
    # simulate a matching http flow in the past (within 5 minutes before the
    # flow's starttime)
    analyzer = ModuleFactory().create_http_analyzer_obj()
    analyzer.is_tcp_established_port_80_non_empty_flow = Mock(
        return_value=True
    )
    analyzer.is_http_proto_recognized_by_zeek = Mock(return_value=False)
    analyzer.search_http_recognized_flows_for_ts_range = Mock(
        return_value=[1.0]
    )
    flow = MagicMock(starttime=100, saddr="192.168.1.1", daddr="1.1.1.1")
    result = await analyzer.check_non_http_port_80_conns(None, flow)
    assert result is False


async def test_check_non_http_port_80_conns_matching_http_future():
    # simulate a matching http flow in the future (within 5 minutes after the
    # flow's starttime)
    analyzer = ModuleFactory().create_http_analyzer_obj()
    analyzer.is_tcp_established_port_80_non_empty_flow = Mock(
        return_value=True
    )
    analyzer.is_http_proto_recognized_by_zeek = Mock(return_value=False)
    analyzer.search_http_recognized_flows_for_ts_range = Mock(
        return_value=[1.0]
    )
    flow = MagicMock(starttime=100, saddr="192.168.1.1", daddr="1.1.1.1")
    result = await analyzer.check_non_http_port_80_conns(
        None, flow, timeout_reached=True
    )
    assert result is False


async def test_check_non_http_port_80_conns_no_matching_http_timeout():
    # simulate no matching http flows when timeout has been reached
    analyzer = ModuleFactory().create_http_analyzer_obj()
    analyzer.is_tcp_established_port_80_non_empty_flow = Mock(
        return_value=True
    )
    analyzer.is_http_proto_recognized_by_zeek = Mock(return_value=False)
    analyzer.search_http_recognized_flows_for_ts_range = Mock(return_value=[])
    analyzer.set_evidence.non_http_port_80_conn = MagicMock()
    flow = MagicMock(starttime=100, saddr="192.168.1.1", daddr="1.1.1.1")
    result = await analyzer.check_non_http_port_80_conns(
        None, flow, timeout_reached=True
    )
    assert result is True
    analyzer.set_evidence.non_http_port_80_conn.assert_called_once_with(
        None, flow
    )


async def test_check_non_http_port_80_conns_no_matching_http_no_timeout():
    # simulate no matching http flows when timeout has not been reached yet.
    # the function should sleep for 5 mins (patched to return immediately),
    # then recursively call itself with timeout_reached true
    # (which sets evidence)
    analyzer = ModuleFactory().create_http_analyzer_obj()
    analyzer.is_tcp_established_port_80_non_empty_flow = Mock(
        return_value=True
    )
    analyzer.is_http_proto_recognized_by_zeek = Mock(return_value=False)
    analyzer.search_http_recognized_flows_for_ts_range = Mock(return_value=[])
    analyzer.set_evidence.non_http_port_80_conn = MagicMock()
    # patch asyncio.sleep so that we do not really wait
    analyzer.wait_for_new_flows_or_timeout = get_mock_coro(True)

    flow = MagicMock(starttime=100, saddr="192.168.1.1", daddr="1.1.1.1")
    result = await analyzer.check_non_http_port_80_conns(None, flow)
    # even though the recursive call returns true (after setting evidence),
    # the original call always returns false
    assert result is False
    analyzer.wait_for_new_flows_or_timeout.assert_called_once()
    analyzer.set_evidence.non_http_port_80_conn.assert_called_once_with(
        None, flow
    )


# parameterized tests for helper functions


@pytest.mark.parametrize(
    "dport, proto, sbytes, dbytes, final_state, expected",
    [
        # case: established tcp connection on port 80 with non-zero
        # bytes should be considered valid
        ("80", "tcp", 100, 200, "Established", True),
        # case: connection with zero bytes is not interesting
        ("80", "tcp", 0, 0, "Established", False),
        # case: non-tcp protocol should not be considered
        ("80", "udp", 100, 200, "Established", False),
        # case: not in an established state should not be considered
        ("80", "tcp", 100, 200, "NotEstablished", False),
    ],
)
def test_is_tcp_established_port_80_non_empty_flow(
    dport, proto, sbytes, dbytes, final_state, expected
):
    # create a mock flow with the given parameters and check
    # the function's output
    analyzer = ModuleFactory().create_http_analyzer_obj()
    flow = Mock(
        dport=dport,
        cert_chain_fuids="",
        client_cert_chain_fuids="",
        pkts=80,
        proto=proto,
        sbytes=sbytes,
        dbytes=dbytes,
    )
    analyzer.db.get_final_state_from_flags.return_value = final_state
    result = analyzer.is_tcp_established_port_80_non_empty_flow(flow)
    assert result == expected


@pytest.mark.parametrize(
    "http_recognized_flows, flow_info, start, end, expected",
    [
        # case: matching timestamps within the range
        (
            {("192.168.1.1", "10.0.0.1"): [1.0, 2.0, 3.0, 4.0, 5.0]},
            {"saddr": "192.168.1.1", "daddr": "10.0.0.1"},
            2.0,
            4.0,
            [2.0, 3.0, 4.0],
        ),
        # case: no matching timestamps (empty result)
        (
            {("192.168.1.1", "10.0.0.1"): [1.0, 2.0, 3.0]},
            {"saddr": "192.168.1.1", "daddr": "10.0.0.1"},
            4.0,
            5.0,
            [],
        ),
        # case: flow does not exist in http_recognized_flows
        (
            {("192.168.1.2", "10.0.0.2"): [1.0, 2.0, 3.0]},
            {"saddr": "192.168.1.1", "daddr": "10.0.0.1"},
            1.0,
            3.0,
            [],
        ),
        # case: start and end cover all timestamps
        (
            {("192.168.1.1", "10.0.0.1"): [1.0, 2.0, 3.0, 4.0, 5.0]},
            {"saddr": "192.168.1.1", "daddr": "10.0.0.1"},
            1.0,
            5.0,
            [1.0, 2.0, 3.0, 4.0, 5.0],
        ),
    ],
)
def test_search_http_recognized_flows_for_ts_range(
    http_recognized_flows, flow_info, start, end, expected
):
    # set up the http_recognized_flows and verify the search function
    # returns the correct timestamps
    analyzer = ModuleFactory().create_http_analyzer_obj()
    analyzer.http_recognized_flows = http_recognized_flows
    flow = Mock(saddr=flow_info["saddr"], daddr=flow_info["daddr"])
    result = analyzer.search_http_recognized_flows_for_ts_range(
        flow, start, end
    )
    assert result == expected
