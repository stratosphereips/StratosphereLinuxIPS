"""Unit test for modules/flowalerts/ssl.py"""

from unittest.mock import Mock

from tests.module_factory import ModuleFactory

import json
import pytest

# dummy params used for testing
profileid = "profile_192.168.1.1"
twid = "timewindow1"
uid = "CAeDWs37BipkfP21u8"
timestamp = 1635765895.037696
daddr = "192.168.1.2"


# @pytest.mark.parametrize(
#     "test_flows, mock_get_flow_responses, "
#     "expected_check_calls, final_queue_size",
#     [
#         # Test Case 1: Single flow, found in conn.log
#         (
#             [
#                 {
#                     "daddr": "192.168.1.2",
#                     "server_name": "example.com",
#                     "uid": "flow1",
#                     "ts": 1234,
#                     "profileid": "profile1",
#                     "twid": "tw1",
#                 }
#             ],
#             [{"flow1": json.dumps({"starttime": 1234, "uid": "flow1"})}],
#             1,
#             0,
#         ),
#         # Test Case 2: Single flow, not found in conn.log
#         (
#             [
#                 {
#                     "daddr": "192.168.1.2",
#                     "server_name": "example.com",
#                     "uid": "flow1",
#                     "ts": 1234,
#                     "profileid": "profile1",
#                     "twid": "tw1",
#                 }
#             ],
#             [{}],
#             0,
#             1,
#         ),
#         # Test Case 3: Multiple flows, one found, one not found
#         (
#             [
#                 {
#                     "daddr": "192.168.1.2",
#                     "server_name": "example.com",
#                     "uid": "flow1",
#                     "ts": 1234,
#                     "profileid": "profile1",
#                     "twid": "tw1",
#                 },
#                 {
#                     "daddr": "10.0.0.1",
#                     "server_name": "another.com",
#                     "uid": "flow2",
#                     "ts": 5678,
#                     "profileid": "profile2",
#                     "twid": "tw2",
#                 },
#             ],
#             [{"flow1": json.dumps({"starttime": 1234, "uid": "flow1"})}, {}],
#             1,
#             1,
#         ),
#     ],
# )
# def test_wait_for_ssl_flows_to_appear_in_connlog(
#     mocker,
#
#     test_flows,
#     mock_get_flow_responses,
#     expected_check_calls,
#     final_queue_size,
# ):
#     ssl = ModuleFactory().create_ssl_analyzer_obj()
#     ssl.pending_ssl_flows = Queue()
#
#     mock_get_flow = mocker.patch.object(ssl.db, "get_flow")
#     mock_check_pastebin = mocker.patch.object(ssl, "check_pastebin_download")
#     for flow in test_flows:
#         ssl.pending_ssl_flows.put(tuple(flow.values()))
#
#     mock_get_flow.side_effect = mock_get_flow_responses
#     ssl.flowalerts.should_stop = Mock()
#     ssl.flowalerts.should_stop.side_effect = [False, True]
#
#     ssl.wait_for_ssl_flows_to_appear_in_connlog()
#
#     assert mock_check_pastebin.call_count == expected_check_calls
#     assert ssl.pending_ssl_flows.qsize() == final_queue_size


@pytest.mark.parametrize(
    "test_input,expected",
    [
        (
            # testcase1: checks if the validation status is "self signed",
            (
                "self signed",
                "192.168.1.2",
                "example.com",
                "profile_192.168.1.1",
                "timewindow1",
                1635765895.037696,
                "CAeDWs37BipkfP21u8",
            ),
            1,
        ),
        (
            # testcase2: checks if the validation status is  not "self signed",
            (
                "valid",
                "192.168.1.2",
                "example.com",
                "profile_192.168.1.1",
                "timewindow1",
                1635765895.037696,
                "CAeDWs37BipkfP21u8",
            ),
            0,
        ),
    ],
)
def test_check_self_signed_certs(mocker, test_input, expected):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    mock_set_evidence = mocker.patch(
        "modules.flowalerts.set_evidence."
        "SetEvidnceHelper.self_signed_certificates"
    )

    ssl.check_self_signed_certs(*test_input)

    assert mock_set_evidence.call_count == expected


@pytest.mark.parametrize(
    "test_ja3, test_ja3s, expected_ja3_calls, expected_ja3s_calls",
    [
        # Testcase 1: No JA3 or JA3S provided
        (None, None, 0, 0),
        # Testcase 2: Malicious JA3, no JA3S
        ("malicious_ja3", None, 1, 0),
        # Testcase 3: No JA3, malicious JA3S
        (None, "malicious_ja3s", 0, 1),
        # Testcase 4: Both JA3 and JA3S malicious
        ("malicious_ja3", "malicious_ja3s", 1, 1),
    ],
)
def test_detect_malicious_ja3(
    mocker,
    test_ja3,
    test_ja3s,
    expected_ja3_calls,
    expected_ja3s_calls,
):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    mock_set_evidence_ja3 = mocker.patch(
        "modules.flowalerts.set_evidence.SetEvidnceHelper.malicious_ja3"
    )
    mock_set_evidence_ja3s = mocker.patch(
        "modules.flowalerts.set_evidence.SetEvidnceHelper.malicious_ja3s"
    )

    saddr = "192.168.1.1"

    ssl.db.get_all_blacklisted_ja3.return_value = {
        "malicious_ja3": "Malicious JA3",
        "malicious_ja3s": "Malicious JA3S",
    }

    ssl.detect_malicious_ja3(
        saddr, daddr, test_ja3, test_ja3s, twid, uid, timestamp
    )
    assert mock_set_evidence_ja3.call_count == expected_ja3_calls
    assert mock_set_evidence_ja3s.call_count == expected_ja3s_calls


@pytest.mark.parametrize(
    "test_is_doh, expected_calls",
    [
        # Testcase 1: is_doh is True,
        # should call set_evidence.doh and db.set_ip_info
        (True, 1),
        # Testcase 2: is_doh is False,
        # should not call any functions
        (False, 0),
    ],
)
def test_detect_doh(mocker, test_is_doh, expected_calls):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    mock_set_evidence_doh = mocker.patch(
        "modules.flowalerts.set_evidence.SetEvidnceHelper.doh"
    )
    ssl.db.set_ip_info = Mock()

    ssl.detect_doh(test_is_doh, daddr, profileid, twid, timestamp, uid)

    assert mock_set_evidence_doh.call_count == expected_calls
    assert ssl.db.set_ip_info.call_count == expected_calls


@pytest.mark.parametrize(
    "test_server_name, test_downloaded_bytes, expected_call_count",
    [
        # Testcase 1: Server name is pastebin.com,
        # downloaded bytes exceed threshold
        ("www.pastebin.com", 15000, True),
        # Testcase 2: Server name is pastebin.com,
        # downloaded bytes below threshold
        ("www.pastebin.com", 1000, False),
        # Testcase 3: Server name is not pastebin.com
        ("www.example.com", 15000, False),
    ],
)
def test_check_pastebin_download(
    mocker,
    test_server_name,
    test_downloaded_bytes,
    expected_call_count,
):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    ssl.pastebin_downloads_threshold = 12000
    mock_set_evidence = mocker.patch(
        "modules.flowalerts.set_evidence." "SetEvidnceHelper.pastebin_download"
    )

    flow = {"resp_bytes": test_downloaded_bytes}

    ssl.check_pastebin_download(
        daddr, test_server_name, uid, timestamp, profileid, twid, flow
    )

    assert mock_set_evidence.call_count == expected_call_count


@pytest.mark.parametrize(
    "issuer, expected_call_count",
    [
        # Testcase 1: Issuer contains supported org, but IP/domain not in org.
        (
            "CN=example.com, OU=Google LLC, O=Google LLC,"
            " L=Mountain View, ST=California, C=US",
            1,
        ),
        # Testcase 2: Issuer does not contain any supported orgs.
        (
            "CN=example.com, OU=Example Inc., "
            "O=Example Inc., L=City, ST=State, C=Country",
            0,
        ),
    ],
)
def test_detect_incompatible_cn(mocker, issuer, expected_call_count):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    mock_set_evidence = mocker.patch(
        "modules.flowalerts.set_evidence." "SetEvidnceHelper.incompatible_cn"
    )

    (ssl.db.whitelist.organization_whitelist.is_ip_in_org).return_value = False
    (ssl.db.whitelist.organization_whitelist.is_domain_in_org).return_value = (
        False
    )

    ssl.detect_incompatible_cn(
        daddr, "example.com", issuer, profileid, twid, uid, timestamp
    )

    assert mock_set_evidence.call_count == expected_call_count


@pytest.mark.parametrize(
    "test_input, expected_call_count",
    [
        (
            # Testcase 1: Non-SSL connection on port 443
            {
                "profileid": "profile_192.168.1.1",
                "twid": "timewindow1",
                "stime": 1635765895.037696,
                "flow": json.dumps(
                    {
                        "CAeDWs37BipkfP21u8": json.dumps(
                            {
                                "daddr": "192.168.1.2",
                                "state": "Established",
                                "dport": 443,
                                "proto": "tcp",
                                "allbytes": 1024,
                                "appproto": "http",
                            }
                        )
                    }
                ),
            },
            1,
        ),
        (
            # Testcase 2: SSL connection on port 443
            {
                "profileid": "profile_192.168.1.1",
                "twid": "timewindow1",
                "stime": 1635765895.037696,
                "flow": json.dumps(
                    {
                        "CAeDWs37BipkfP21u8": json.dumps(
                            {
                                "daddr": "192.168.1.2",
                                "state": "Established",
                                "dport": 443,
                                "proto": "tcp",
                                "allbytes": 1024,
                                "appproto": "ssl",
                            }
                        )
                    }
                ),
            },
            0,
        ),
        (
            # Testcase 3: Connection on port 443 but not Established state
            {
                "profileid": "profile_192.168.1.1",
                "twid": "timewindow1",
                "stime": 1635765895.037696,
                "flow": json.dumps(
                    {
                        "CAeDWs37BipkfP21u8": json.dumps(
                            {
                                "daddr": "192.168.1.2",
                                "state": "SF",
                                "dport": 443,
                                "proto": "tcp",
                                "allbytes": 1024,
                                "appproto": "http",
                            }
                        )
                    }
                ),
            },
            0,
        ),
        (
            # Testcase 4: Connection on a port other than 443
            {
                "profileid": "profile_192.168.1.1",
                "twid": "timewindow1",
                "stime": 1635765895.037696,
                "flow": json.dumps(
                    {
                        "CAeDWs37BipkfP21u8": json.dumps(
                            {
                                "daddr": "192.168.1.2",
                                "state": "Established",
                                "dport": 80,
                                "proto": "tcp",
                                "allbytes": 1024,
                                "appproto": "http",
                            }
                        )
                    }
                ),
            },
            0,
        ),
        (
            # Testcase 5: Connection on port 443 with zero bytes
            {
                "profileid": "profile_192.168.1.1",
                "twid": "timewindow1",
                "stime": 1635765895.037696,
                "flow": json.dumps(
                    {
                        "CAeDWs37BipkfP21u8": json.dumps(
                            {
                                "daddr": "192.168.1.2",
                                "state": "Established",
                                "dport": 443,
                                "proto": "tcp",
                                "allbytes": 0,
                                "appproto": "http",
                            }
                        )
                    }
                ),
            },
            0,
        ),
    ],
)
def test_check_non_ssl_port_443_conns(mocker, test_input, expected_call_count):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    mock_set_evidence = mocker.patch(
        "modules.flowalerts.set_evidence."
        "SetEvidnceHelper.non_ssl_port_443_conn"
    )
    ssl.check_non_ssl_port_443_conns(test_input)
    assert mock_set_evidence.call_count == expected_call_count


@pytest.mark.parametrize(
    "channel, msg_data",
    [
        (
            "new_ssl",
            {
                "flow": json.dumps(
                    {
                        "uid": "test_uid",
                        "stime": 1635765895.037696,
                        "ja3": "test_ja3",
                        "ja3s": "test_ja3s",
                        "issuer": "test_issuer",
                        "daddr": "192.168.1.2",
                        "server_name": "example.com",
                        "validation_status": "test_status",
                        "is_DoH": True,
                    }
                ),
                "profileid": "profile_192.168.1.1",
                "twid": "timewindow1",
            },
        ),
    ],
)
def test_analyze_new_ssl_msg(
    mocker,
    channel,
    msg_data,
):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    mock_pending_ssl_flows_put = mocker.patch.object(
        ssl.pending_ssl_flows, "put"
    )
    mock_check_self_signed_certs = mocker.patch.object(
        ssl, "check_self_signed_certs"
    )
    mock_detect_malicious_ja3 = mocker.patch.object(
        ssl, "detect_malicious_ja3"
    )
    mock_detect_incompatible_cn = mocker.patch.object(
        ssl, "detect_incompatible_cn"
    )
    mock_detect_doh = mocker.patch.object(ssl, "detect_doh")

    msg = {"channel": channel, "data": json.dumps(msg_data)}

    ssl.analyze(msg)

    mock_pending_ssl_flows_put.assert_called_once_with(
        (
            "192.168.1.2",
            "example.com",
            "test_uid",
            1635765895.037696,
            "profile_192.168.1.1",
            "timewindow1",
        )
    )

    mock_check_self_signed_certs.assert_called_once_with(
        "test_status",
        "192.168.1.2",
        "example.com",
        "profile_192.168.1.1",
        "timewindow1",
        1635765895.037696,
        "test_uid",
    )

    mock_detect_malicious_ja3.assert_called_once_with(
        "192.168.1.1",
        "192.168.1.2",
        "test_ja3",
        "test_ja3s",
        "timewindow1",
        "test_uid",
        1635765895.037696,
    )

    mock_detect_incompatible_cn.assert_called_once_with(
        "192.168.1.2",
        "example.com",
        "test_issuer",
        "profile_192.168.1.1",
        "timewindow1",
        "test_uid",
        1635765895.037696,
    )

    mock_detect_doh.assert_called_once_with(
        True,
        "192.168.1.2",
        "profile_192.168.1.1",
        "timewindow1",
        1635765895.037696,
        "test_uid",
    )


@pytest.mark.parametrize(
    "channel, msg_data",
    [
        (
            "new_flow",
            {
                "profileid": "profile_192.168.1.1",
                "twid": "timewindow1",
                "stime": 1635765895.037696,
                "flow": json.dumps(
                    {
                        "test_uid": json.dumps(
                            {
                                "daddr": "192.168.1.2",
                                "state": "Established",
                                "dport": 443,
                                "proto": "tcp",
                                "allbytes": 1024,
                                "appproto": "http",
                            }
                        )
                    }
                ),
            },
        )
    ],
)
def test_analyze_new_flow_msg(mocker, channel, msg_data):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    mock_check_non_ssl_port_443_conns = mocker.patch.object(
        ssl, "check_non_ssl_port_443_conns"
    )
    msg = {"channel": channel, "data": json.dumps(msg_data)}

    ssl.analyze(msg)

    mock_check_non_ssl_port_443_conns.assert_called_once()
    call_arg = mock_check_non_ssl_port_443_conns.call_args[0][0]
    assert isinstance(call_arg, dict)
    assert call_arg["profileid"] == "profile_192.168.1.1"
    assert call_arg["twid"] == "timewindow1"
    assert call_arg["stime"] == 1635765895.037696
    assert "flow" in call_arg


def test_analyze_no_messages(
    mocker,
):
    ssl = ModuleFactory().create_ssl_analyzer_obj()

    mock_pending_ssl_flows_put = mocker.patch.object(
        ssl.pending_ssl_flows, "put"
    )
    mock_check_self_signed_certs = mocker.patch.object(
        ssl, "check_self_signed_certs"
    )
    mock_detect_malicious_ja3 = mocker.patch.object(
        ssl, "detect_malicious_ja3"
    )
    mock_detect_incompatible_cn = mocker.patch.object(
        ssl, "detect_incompatible_cn"
    )
    mock_detect_doh = mocker.patch.object(ssl, "detect_doh")
    mock_check_non_ssl_port_443_conns = mocker.patch.object(
        ssl, "check_non_ssl_port_443_conns"
    )

    ssl.analyze({})

    mock_pending_ssl_flows_put.assert_not_called()
    mock_check_self_signed_certs.assert_not_called()
    mock_detect_malicious_ja3.assert_not_called()
    mock_detect_incompatible_cn.assert_not_called()
    mock_detect_doh.assert_not_called()
    mock_check_non_ssl_port_443_conns.assert_not_called()
