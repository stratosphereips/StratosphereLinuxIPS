# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/flow_alerts/ssl.py"""

from dataclasses import asdict
from unittest.mock import (
    Mock,
    patch,
)
import json
import pytest
from types import SimpleNamespace
from slips_files.core.database.redis_db.database import RedisDB
from slips_files.core.flows.zeek import SSL
from tests.module_factory import ModuleFactory
from tests.unit.common_test_utils import get_mock_coro

# dummy params used for testing
profileid = "profile_192.168.1.1"
twid = "timewindow1"
uid = "CAeDWs37BipkfP21u8"
timestamp = 1635765895.037696
daddr = "192.168.1.2"


@pytest.mark.parametrize("ip,expected", [("104.244.43.176", False), ("192.0.2.77", True)])
def test_cn_recognizes_cached_twitter_network(ip: str, expected: bool) -> None:
    """Use the real cached-network lookup before declaring an incompatible CN.

    Parameters:
        ip: Captured destination inside or outside Twitter's known network.
        expected: Whether an incompatible-organization detection is expected.
    """
    factory = ModuleFactory()
    ssl = factory.create_ssl_analyzer_obj()
    whitelist = factory.create_whitelist_obj()
    analyzer = whitelist.org_analyzer
    analyzer.bloom_filters = {"twitter": {"first_octets": ["104", "192"]}}
    db = object.__new__(RedisDB)
    db.r = Mock()
    db.rcache = Mock()
    db.rcache.hget.return_value = '["104.244.40.0/21"]'
    whitelist.db.is_ip_in_org_ips.side_effect = db.is_ip_in_org_cidrs
    ssl.whitelist = whitelist
    analyzer.is_domain_in_org = Mock(return_value=False)
    ssl.set_evidence.tls_provider_impersonation = Mock()
    flow = SimpleNamespace(subject="CN=ads-twitter.com,O=Twitter", daddr=ip,
                           server_name="static.ads-twitter.com")
    ssl.detect_tls_provider_impersonation("timewindow1", flow)
    assert ssl.set_evidence.tls_provider_impersonation.called is expected
    db.r.hget.assert_not_called()


@pytest.mark.parametrize("subject,domain,known_ip,have_data,expected", [
    ("CN=mem.gfx.ms,O=Microsoft Corporation", "mem.gfx.ms", False, True, False),
    ("CN=mem.gfx.ms,O=Microsoft Corporation", "MEM.GFX.MS.", False, True, False),
    ("CN=assets.onestore.ms,O=Microsoft Corporation", "assets.onestore.ms", False, True, False),
    ("CN=other.example,O=Microsoft Corporation", "other.example", False, True, True),
    ("CN=gfx.ms.evil.example,O=Microsoft Corporation", "gfx.ms.evil.example", False, True, True),
    ("CN=notgfx.ms,O=Microsoft Corporation", "notgfx.ms", False, True, True),
    ("CN=other.example,O=Microsoft Corporation", "other.example", True, True, False),
    ("CN=other.example,O=Microsoft Corporation", "other.example", False, False, False),
    ("CN=other.example,O=Microsoft Corporation", "", False, True, False),
    ("", "other.example", False, True, False),
    ("CN=microsoft.evil.example,O=Unrelated Company", "other.example", False, True, False),
    ("CN=other.example,O=NotMicrosoftCompany", "other.example", False, True, False),
    (r"CN=other.example,O=Company\, OU=Microsoft", "other.example", False, True, False),
])
def test_provider_claim_requires_unrelated_server(
    subject: str, domain: str, known_ip: bool, have_data: bool, expected: bool
) -> None:
    """Check real provider domains, lookalikes, missing data and CDN hosting.

    Parameters:
        subject: Certificate subject, including possible provider claims.
        domain: Observed TLS server name.
        known_ip: Whether the destination belongs to the claimed provider.
        have_data: Whether the bundled provider-domain data is available.
        expected: Whether a suspected impersonation should be emitted.
    """
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    ssl.whitelist.org_analyzer.is_ip_in_org = Mock(return_value=known_ip)
    ssl.whitelist.org_analyzer.is_domain_in_org = Mock(return_value=False)
    ssl.set_evidence.tls_provider_impersonation = Mock()
    if not have_data:
        ssl.provider_domains.clear()
    flow = SimpleNamespace(subject=subject, server_name=domain, daddr="192.0.2.77")
    result = ssl.detect_tls_provider_impersonation("timewindow1", flow)
    assert result is expected
    assert ssl.set_evidence.tls_provider_impersonation.called is expected


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
        "modules.flow_alerts.set_evidence."
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
        "modules.flow_alerts.set_evidence.SetEvidenceHelper.malicious_ja3"
    )
    mock_set_evidence_ja3s = mocker.patch(
        "modules.flow_alerts.set_evidence.SetEvidenceHelper.malicious_ja3s"
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
        "modules.flow_alerts.set_evidence.SetEvidenceHelper.doh"
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
        "modules.flow_alerts.set_evidence.SetEvidenceHelper.pastebin_download"
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
def test_detect_tls_provider_impersonation(mocker, subject, expected_call_count):
    ssl = ModuleFactory().create_ssl_analyzer_obj()
    mock_set_evidence = mocker.patch(
        "modules.flow_alerts.set_evidence.SetEvidenceHelper.tls_provider_impersonation"
    )

    ssl.whitelist.org_analyzer.is_ip_in_org = Mock(return_value=False)
    ssl.whitelist.org_analyzer.is_domain_in_org = Mock(return_value=False)
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
        server_name="unrelated.example",
        ja3="",
        ja3s="",
        is_DoH="",
    )
    ssl.detect_tls_provider_impersonation(twid, flow)
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
    mock_detect_tls_provider_impersonation = mocker.patch.object(
        ssl, "detect_tls_provider_impersonation"
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
    mock_detect_tls_provider_impersonation.assert_called_once_with("timewindow1", flow)

    mock_detect_doh.assert_called_once_with("timewindow1", flow)


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
    mock_detect_tls_provider_impersonation = mocker.patch.object(
        ssl, "detect_tls_provider_impersonation"
    )
    mock_detect_doh = mocker.patch.object(ssl, "detect_doh")

    await ssl.analyze({})

    mock_check_self_signed_certs.assert_not_called()
    mock_detect_malicious_ja3.assert_not_called()
    mock_detect_tls_provider_impersonation.assert_not_called()
    mock_detect_doh.assert_not_called()
