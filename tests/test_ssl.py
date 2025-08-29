# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/flowalerts/ssl.py"""

from dataclasses import asdict
from unittest.mock import (
    Mock,
    MagicMock,
    patch,
)
import json
import pytest
from slips_files.core.flows.zeek import (
    SSL,
    Conn,
)
from tests.module_factory import ModuleFactory
from tests.common_test_utils import get_mock_coro

# dummy params used for testing
profileid = "profile_192.168.1.1"
twid = "timewindow1"
uid = "CAeDWs37BipkfP21u8"
timestamp = 1635765895.037696
daddr = "192.168.1.2"


def is_present_in_calls(mock_object, search_term):
    return any(
        search_term in arg
        for args, _ in mock_object.call_args_list
        for arg in args
    )


@pytest.mark.parametrize(
    "validation_status, expected_set_ev_call_count",
    [
        # testcase1: checks if the validation status is "self signed",
        ("self signed", 1),
        #  testcase2: checks if the validation status is  not "self signed",
        ("valid", 0),
    ],
)
def test_check_self_signed_certs(
    mocker, validation_status, expected_set_ev_call_count
):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    mock_set_evidence = mocker.patch(
        "modules.flowalerts.set_evidence."
        "SetEvidenceHelper.self_signed_certificates"
    )
    flow = SSL(
        starttime="1726593782.8840969",
        uid="123",
        saddr="192.168.1.1",
        daddr="192.168.1.2",
        version="",
        sport="",
        dport="",
        cipher="",
        resumed="",
        established="",
        cert_chain_fuids="",
        client_cert_chain_fuids="",
        subject="",
        issuer="",
        validation_status=validation_status,
        curve="",
        server_name="",
        ja3="",
        ja3s="",
        is_DoH="",
    )
    ssl.check_self_signed_certs(twid, flow)

    assert mock_set_evidence.call_count == expected_set_ev_call_count


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
        "modules.flowalerts.set_evidence.SetEvidenceHelper.malicious_ja3"
    )
    mock_set_evidence_ja3s = mocker.patch(
        "modules.flowalerts.set_evidence.SetEvidenceHelper.malicious_ja3s"
    )

    ssl.db.get_all_blacklisted_ja3.return_value = {
        "malicious_ja3": "Malicious JA3",
        "malicious_ja3s": "Malicious JA3S",
    }
    flow = SSL(
        starttime="1726593782.8840969",
        uid="123",
        saddr="192.168.1.1",
        daddr="192.168.1.2",
        version="",
        sport="",
        dport="",
        cipher="",
        resumed="",
        established="",
        cert_chain_fuids="",
        client_cert_chain_fuids="",
        subject="",
        issuer="",
        validation_status="",
        curve="",
        server_name="",
        ja3=test_ja3,
        ja3s=test_ja3s,
        is_DoH="",
    )
    ssl.detect_malicious_ja3(twid, flow)
    assert mock_set_evidence_ja3.call_count == expected_ja3_calls
    assert mock_set_evidence_ja3s.call_count == expected_ja3s_calls


@pytest.mark.parametrize(
    "is_doh, expected_calls",
    [
        # Testcase 1: is_doh is True,
        # should call set_evidence.doh and db.set_ip_info
        (True, 1),
        # Testcase 2: is_doh is False,
        # should not call any functions
        (False, 0),
    ],
)
def test_detect_doh(mocker, is_doh, expected_calls):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    mock_set_evidence_doh = mocker.patch(
        "modules.flowalerts.set_evidence.SetEvidenceHelper.doh"
    )
    ssl.db.set_ip_info = Mock()
    flow = SSL(
        starttime="1726593782.8840969",
        uid="123",
        saddr="192.168.1.1",
        daddr="192.168.1.2",
        version="",
        sport="",
        dport="",
        cipher="",
        resumed="",
        established="",
        cert_chain_fuids="",
        client_cert_chain_fuids="",
        subject="",
        issuer="",
        validation_status="",
        curve="",
        server_name="",
        ja3="",
        ja3s="",
        is_DoH=is_doh,
    )
    ssl.detect_doh(twid, flow)

    assert mock_set_evidence_doh.call_count == expected_calls
    assert ssl.db.set_ip_info.call_count == expected_calls


@pytest.mark.parametrize(
    "server_name, downloaded_bytes, expected_call_count",
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
async def test_check_pastebin_download(
    mocker,
    server_name,
    downloaded_bytes,
    expected_call_count,
):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    ssl.pastebin_downloads_threshold = 12000
    ssl.wait_for_new_flows_or_timeout = get_mock_coro(True)
    mock_set_evidence = mocker.patch(
        "modules.flowalerts.set_evidence.SetEvidenceHelper.pastebin_download"
    )

    flow = SSL(
        starttime="1726593782.8840969",
        uid="123",
        saddr="192.168.1.1",
        daddr="192.168.1.2",
        version="",
        sport="",
        dport="",
        cipher="",
        resumed="",
        established="",
        cert_chain_fuids="",
        client_cert_chain_fuids="",
        subject="",
        issuer="",
        validation_status="",
        curve="",
        server_name=server_name,
        ja3="",
        ja3s="",
        is_DoH="",
    )
    conn_log_flow = {"resp_bytes": downloaded_bytes}
    with patch(
        "slips_files.common.slips_utils.utils.get_original_conn_flow"
    ) as mock_get_original_conn_flow:
        mock_get_original_conn_flow.side_effect = [None, conn_log_flow]
        await ssl.check_pastebin_download(twid, flow)

    assert mock_set_evidence.call_count == expected_call_count


@pytest.mark.parametrize(
    "subject, expected_call_count",
    [
        # Testcase 1: subject contains supported org, but IP/domain not in
        # org.
        (
            "CN=example.com, OU=Google LLC, O=Google LLC,"
            " L=Mountain View, ST=California, C=US",
            1,
        ),
        # Testcase 2: subject does not contain any supported orgs.
        (
            "CN=example.com, OU=Example Inc., "
            "O=Example Inc., L=City, ST=State, C=Country",
            0,
        ),
    ],
)
def test_detect_incompatible_cn(mocker, subject, expected_call_count):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    mock_set_evidence = mocker.patch(
        "modules.flowalerts.set_evidence.SetEvidenceHelper.incompatible_cn"
    )

    ssl.db.whitelist.organization_whitelist.is_ip_in_org.return_value = False
    ssl.db.whitelist.organization_whitelist.is_domain_in_org.return_value = (
        False
    )
    flow = SSL(
        starttime="1726593782.8840969",
        uid="123",
        saddr="192.168.1.1",
        daddr="192.168.1.2",
        version="",
        sport="",
        dport="",
        cipher="",
        resumed="",
        established="",
        cert_chain_fuids="",
        client_cert_chain_fuids="",
        subject=subject,
        issuer="",
        validation_status="",
        curve="",
        server_name="",
        ja3="",
        ja3s="",
        is_DoH="",
    )
    ssl.detect_incompatible_cn(twid, flow)
    assert mock_set_evidence.call_count == expected_call_count


@pytest.mark.parametrize(
    "domain1, domain2, expected",
    [
        ("example.com", "sub.example.com", "example.com"),  # same root domain
        ("example.com", "another.com", None),  # different organizations
        ("yahoo.com", "adtech.yahoo.com", "yahoo.com"),  # partial org name
        # match
        ("example.com", "nonexistent.com", ValueError),  # domain not found
        ("nonexistent.com", "another.com", ValueError),  # domain not found
    ],
)
def test_domains_belong_to_same_org(domain1, domain2, expected):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    ssl.db.get_domain_data.side_effect = lambda domain: {
        "example.com": {"Org": "Example LLC"},
        "sub.example.com": {"Org": "Example LLC"},
        "another.com": {"Org": "Another Corp"},
        "yahoo.com": {"Org": "Yahoo Assets LLC"},
        "adtech.yahoo.com": {"Org": "Yahoo Ad Tech LLC"},
    }.get(domain, None)

    # test the function
    if expected is ValueError:
        with pytest.raises(ValueError):
            ssl.domains_belong_to_same_org(domain1, domain2)
    else:
        assert ssl.domains_belong_to_same_org(domain1, domain2) == expected


@pytest.mark.parametrize(
    "certificate_string, expected",
    [
        ("CN=example.com, OU=IT, O=Example LLC", "example.com"),  # standard CN
        (
            "O=Example LLC, CN=example.org, OU=Engineering",
            "example.org",
        ),  # CN in the middle
        ("OU=IT, O=Example LLC", None),  # no CN present
        ("", None),  # empty certificate string
        ("CN=example.com", "example.com"),  # CN only
        (
            "OU=IT, CN=sub.example.com, CN=example.com",
            "sub.example.com",
        ),  # first CN is extracted
        (
            "CN=example-with-dashes.com, O=Example Org",
            "example-with-dashes.com",
        ),  # CN with special characters
    ],
)
def test_extract_cn(certificate_string, expected):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    result = ssl.extract_cn(certificate_string)
    assert result == expected


@pytest.mark.parametrize(
    "flow, expected_call_count",
    [
        # case: cn matches server name
        ({"subject": "CN=example.com", "server_name": "example.com"}, 0),
        # case: cn does not match server name, but belongs to the same org
        ({"subject": "CN=example.com", "server_name": "sub.example.com"}, 0),
        # case: cn does not match server name, and domains don't belong to the same org
        ({"subject": "CN=example.com", "server_name": "another.com"}, 1),
        # case: no subject in flow
        ({"subject": "", "server_name": "example.com"}, 0),
        # case: cn not found in subject
        ({"subject": "O=Example LLC, OU=IT", "server_name": "example.com"}, 0),
        # case: no domain info in db, ValueError raised
        ({"subject": "CN=example.com", "server_name": "nonexistent.com"}, 0),
    ],
)
def test_detect_cn_url_mismatch(mocker, flow, expected_call_count):
    ssl = ModuleFactory().create_ssl_analyzer_obj()

    ssl.set_evidence.cn_url_mismatch = Mock()
    twid = "timewindow1"

    ssl.db.get_domain_data.side_effect = lambda domain: {
        "example.com": {"Org": "Example LLC"},
        "sub.example.com": {"Org": "Example LLC"},
        "another.com": {"Org": "Another Org"},
    }.get(domain, None)
    flow_obj = mocker.Mock(**flow)
    ssl.detect_cn_url_mismatch(twid, flow_obj)
    assert ssl.set_evidence.cn_url_mismatch.call_count == expected_call_count


async def test_analyze_new_ssl_msg(mocker):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
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

    flow = SSL(
        starttime="1726593782.8840969",
        uid="123",
        saddr="192.168.1.1",
        daddr="192.168.1.2",
        version="",
        sport="",
        dport="",
        cipher="",
        resumed="",
        established="",
        cert_chain_fuids="",
        client_cert_chain_fuids="",
        subject="",
        issuer="",
        validation_status="",
        curve="",
        server_name="",
        ja3="",
        ja3s="",
        is_DoH=True,
    )

    msg = {
        "channel": "new_ssl",
        "data": json.dumps(
            {
                "profileid": "profile_192.168.1.1",
                "twid": "timewindow1",
                "flow": asdict(flow),
            }
        ),
    }

    await ssl.analyze(msg)
    mock_check_self_signed_certs.assert_called_once_with("timewindow1", flow)
    mock_detect_malicious_ja3.assert_called_once_with("timewindow1", flow)
    mock_detect_incompatible_cn.assert_called_once_with("timewindow1", flow)

    mock_detect_doh.assert_called_once_with("timewindow1", flow)


async def test_analyze_new_flow_msg(mocker):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    mock_check_non_ssl_port_443_conns = mocker.patch.object(
        ssl, "check_non_ssl_port_443_conns"
    )
    flow = Conn(
        starttime="1726249372.312124",
        uid=uid,
        saddr="192.168.1.87",
        daddr="1.1.1.1",
        dur=1,
        proto="",
        appproto="",
        sport="0",
        dport="",
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=0,
        smac="",
        dmac="",
        state="",
        history="",
    )

    msg = {
        "channel": "new_flow",
        "data": json.dumps(
            {
                "profileid": "profile_192.168.1.1",
                "twid": "timewindow1",
                "flow": asdict(flow),
            }
        ),
    }

    await ssl.analyze(msg)

    mock_check_non_ssl_port_443_conns.assert_called_once_with(
        "timewindow1", flow
    )


async def test_analyze_no_messages(
    mocker,
):
    ssl = ModuleFactory().create_ssl_analyzer_obj()

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

    await ssl.analyze({})

    mock_check_self_signed_certs.assert_not_called()
    mock_detect_malicious_ja3.assert_not_called()
    mock_detect_incompatible_cn.assert_not_called()
    mock_detect_doh.assert_not_called()
    mock_check_non_ssl_port_443_conns.assert_not_called()


async def test_check_non_ssl_port_443_conns_not_interested():
    """mock a flow that we're not interested in in that function, like a
    dns flow or something"""
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    ssl.is_tcp_established_443_non_empty_flow = Mock(return_value=False)
    result = await ssl.check_non_ssl_port_443_conns(None, None)
    assert result is False


async def test_check_non_ssl_port_443_conns_is_ssl():
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    ssl.is_tcp_established_443_non_empty_flow = Mock(return_value=True)
    ssl.is_ssl_proto_recognized_by_zeek = Mock(return_value=True)
    ssl.keep_track_of_ssl_flow = Mock()
    flow = MagicMock(starttime=100, saddr="192.168.1.1", daddr="1.1.1.1")
    result = await ssl.check_non_ssl_port_443_conns(None, flow)
    assert result is False
    ssl.keep_track_of_ssl_flow.assert_called_once()


async def test_check_non_ssl_port_443_conns_matching_ssl_past():
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    ssl.is_tcp_established_443_non_empty_flow = Mock(return_value=True)
    ssl.is_ssl_proto_recognized_by_zeek = Mock(return_value=False)
    # Simulate a matching SSL flow
    ssl.search_ssl_recognized_flows_for_ts_range = Mock(return_value=[1.0])
    flow = MagicMock(starttime=100, saddr="192.168.1.1", daddr="1.1.1.1")
    result = await ssl.check_non_ssl_port_443_conns(None, flow)
    assert result is False


async def test_check_non_ssl_port_443_conns_matching_ssl_future():
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    ssl.is_tcp_established_443_non_empty_flow = Mock(return_value=True)
    ssl.is_ssl_proto_recognized_by_zeek = Mock(return_value=False)
    # Simulate a matching SSL flow
    ssl.search_ssl_recognized_flows_for_ts_range = Mock(return_value=[1.0])
    flow = MagicMock(starttime=100, saddr="192.168.1.1", daddr="1.1.1.1")
    result = await ssl.check_non_ssl_port_443_conns(
        None, flow, timeout_reached=True
    )
    assert result is False


async def test_check_non_ssl_port_443_conns_no_matching_ssl_timeout():
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    ssl.is_tcp_established_443_non_empty_flow = Mock(return_value=True)
    ssl.is_ssl_proto_recognized_by_zeek = Mock(return_value=False)

    # No matching SSL flows
    ssl.search_ssl_recognized_flows_for_ts_range = Mock(return_value=[])
    ssl.set_evidence = MagicMock()
    flow = MagicMock(starttime=100, saddr="192.168.1.1", daddr="1.1.1.1")
    result = await ssl.check_non_ssl_port_443_conns(
        None, flow, timeout_reached=True
    )
    assert result
    ssl.set_evidence.non_ssl_port_443_conn.assert_called_once()


async def test_check_non_ssl_port_443_conns_no_matching_ssl_no_timeout():
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    ssl.is_tcp_established_443_non_empty_flow = Mock(return_value=True)
    ssl.is_ssl_proto_recognized_by_zeek = Mock(return_value=False)
    ssl.set_evidence.non_ssl_port_443_conn = Mock()
    ssl.search_ssl_recognized_flows_for_ts_range = Mock(return_value=[])
    ssl.wait_for_new_flows_or_timeout = get_mock_coro(True)
    # No matching SSL flows
    # Mock recursive call
    # ssl.check_non_ssl_port_443_conns = AsyncMock(side_effect=[False])
    flow = MagicMock(starttime=100, saddr="192.168.1.1", daddr="1.1.1.1")
    result = await ssl.check_non_ssl_port_443_conns(None, flow)
    assert result is False
    ssl.wait_for_new_flows_or_timeout.assert_called_once()
    ssl.set_evidence.non_ssl_port_443_conn.assert_called_once()


@pytest.mark.parametrize(
    "dport, proto, sbytes, dbytes, final_state, expected",
    [
        # ("443", "tcp", 100, 200, "Established", True),
        # ("80", "tcp", 100, 200, "Established", False),
        # ("443", "udp", 100, 200, "Established", False),
        # ("443", "tcp", 100, 200, "Established", False),
        ("443", "tcp", 0, 0, "Established", False),
    ],
)
def test_is_tcp_established_443_non_empty_flow(
    dport,
    proto,
    sbytes,
    dbytes,
    final_state,
    expected,
):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    flow = Mock(
        dport=dport,
        cert_chain_fuids="",
        client_cert_chain_fuids="",
        pkts=80,
        proto=proto,
        sbytes=sbytes,
        dbytes=dbytes,
    )

    ssl.db.get_final_state_from_flags.return_value = final_state

    result = ssl.is_tcp_established_443_non_empty_flow(flow)
    assert result == expected


@pytest.mark.parametrize(
    "ssl_recognized_flows, flow, start, end, expected",
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
        # case: flow does not exist in ssl_recognized_flows
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
def test_search_ssl_recognized_flows_for_ts_range(
    ssl_recognized_flows, flow, start, end, expected
):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    ssl.ssl_recognized_flows = ssl_recognized_flows
    flow = Mock(saddr=flow["saddr"], daddr=flow["daddr"])
    result = ssl.search_ssl_recognized_flows_for_ts_range(flow, start, end)
    assert result == expected
