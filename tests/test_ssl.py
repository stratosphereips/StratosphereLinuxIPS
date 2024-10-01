"""Unit test for modules/flowalerts/ssl.py"""

from dataclasses import asdict
from unittest.mock import (
    Mock,
    patch,
)

from slips_files.core.flows.zeek import (
    SSL,
    Conn,
)
from tests.module_factory import ModuleFactory

import json
import pytest

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
        "SetEvidnceHelper.self_signed_certificates"
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
        "modules.flowalerts.set_evidence.SetEvidnceHelper.malicious_ja3"
    )
    mock_set_evidence_ja3s = mocker.patch(
        "modules.flowalerts.set_evidence.SetEvidnceHelper.malicious_ja3s"
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
        "modules.flowalerts.set_evidence.SetEvidnceHelper.doh"
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
    mock_set_evidence = mocker.patch(
        "modules.flowalerts.set_evidence.SetEvidnceHelper.pastebin_download"
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
        subject="",
        issuer=issuer,
        validation_status="",
        curve="",
        server_name="",
        ja3="",
        ja3s="",
        is_DoH="",
    )
    ssl.detect_incompatible_cn(profileid, twid, flow)
    assert mock_set_evidence.call_count == expected_call_count


@pytest.mark.parametrize(
    "state, dport, proto, dbytes, approto, expected_call_count",
    [
        # Testcase 1: Non-SSL connection on port 443
        ("Established", 443, "tcp", 1024, "http", 1),
        # Testcase 2: SSL connection on port 443
        (
            "Established",
            443,
            "tcp",
            1024,
            "ssl",
            0,
        ),
        # Testcase 3: Connection on port 443 but not Established state
        ("SF", 443, "tcp", 1024, "http", 0),
        # Testcase 4: Connection on a port other than 443
        (
            "Established",
            80,
            "tcp",
            1024,
            "http",
            0,
        ),
        # Testcase 5: Connection on port 443 with zero bytes
        (
            "Established",
            443,
            "tcp",
            0,
            "http",
            0,
        ),
    ],
)
def test_check_non_ssl_port_443_conns(
    mocker, state, dport, proto, dbytes, approto, expected_call_count
):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    mock_set_evidence = mocker.patch(
        "modules.flowalerts.set_evidence."
        "SetEvidnceHelper.non_ssl_port_443_conn"
    )
    mocker.patch.object(
        ssl.db, "get_final_state_from_flags", return_value=state
    )

    flow = Conn(
        starttime="1726249372.312124",
        uid=uid,
        saddr="192.168.1.87",
        daddr="1.1.1.1",
        dur=1,
        proto=proto,
        appproto=approto,
        sport="0",
        dport=str(dport),
        spkts=0,
        dpkts=0,
        sbytes=0,
        dbytes=dbytes,
        smac="",
        dmac="",
        state="",
        history="",
    )
    ssl.check_non_ssl_port_443_conns(twid, flow)
    assert mock_set_evidence.call_count == expected_call_count


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
    mock_detect_incompatible_cn.assert_called_once_with(
        "profile_192.168.1.1", "timewindow1", flow
    )

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
