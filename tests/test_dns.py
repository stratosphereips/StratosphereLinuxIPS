"""Unit test for modules/flowalerts/dns.py"""

from tests.module_factory import ModuleFactory
from numpy import arange
from unittest.mock import patch, Mock
import pytest
import json

# dummy params used for testing
profileid = "profile_192.168.1.1"
twid = "timewindow1"
uid = "CAeDWs37BipkfP21u8"
timestamp = 1635765895.037696
daddr = "192.168.1.2"
dst_profileid = f"profile_{daddr}"


@pytest.mark.parametrize(
    "domain, rcode_name, expected_result",
    [
        ("example.com", "NOERROR", True),
        ("example.arpa", "NOERROR", False),
        ("example.local", "NOERROR", False),
        ("*", "NOERROR", False),
        ("example.cymru.com", "NOERROR", False),
        ("example.com", "NXDOMAIN", False),
    ],
)
def test_should_detect_dns_without_conn(
    mock_db, domain, rcode_name, expected_result
):
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)
    assert (
        dns.should_detect_dns_without_conn(domain, rcode_name)
        == expected_result
    )


@pytest.mark.parametrize(
    "answers, cname_resolution, contacted_ips, expected_result",
    [
        # Testcase1: CNAME resolves to a contacted IP
        (
            ["192.168.1.1", "google.com"],
            ["192.168.1.2"],
            ["192.168.1.1", "192.168.1.2"],
            True,
        ),
        # Testcase2: CNAME does not resolve to a contacted IP
        (
            ["192.168.1.1", "google.com"],
            ["10.0.0.1"],
            ["192.168.1.1", "192.168.1.2"],
            False,
        ),
        # Testcase3: No CNAMEs in answers
        (
            ["192.168.1.1", "192.168.1.3"],
            [],
            ["192.168.1.1", "192.168.1.2"],
            False,
        ),
    ],
)
def test_is_cname_contacted(
    mock_db, answers, cname_resolution, contacted_ips, expected_result
):
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)
    mock_db.get_domain_resolution.return_value = cname_resolution

    assert dns.is_cname_contacted(answers, contacted_ips) is expected_result


@pytest.mark.parametrize(
    "domain,answers,age,should_detect,expected_result",
    [
        # Testcase1: Young domain
        ("example.com", ["192.168.1.1"], 50, True, True),
        # Testcase2: Old domain
        ("example.com", ["192.168.1.1"], 1000, True, False),
        # Testcase3: Local domain
        ("example.local", ["192.168.1.1"], 10, False, False),
        # Testcase4: ARPA domain
        ("example.arpa", ["192.168.1.1"], 20, False, False),
    ],
)
def test_detect_young_domains(
    mock_db, domain, answers, age, should_detect, expected_result
):
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)
    dns.should_detect_young_domain = Mock(return_value=should_detect)
    mock_db.get_domain_data.return_value = {"Age": age}

    assert (
        dns.detect_young_domains(
            domain, answers, timestamp, profileid, twid, uid
        )
        is expected_result
    )


@pytest.mark.parametrize(
    "domain,answers,domain_data,expected_result",
    [
        # Testcase1: No age data
        ("noage.com", ["192.168.1.1"], {}, False),
        # Testcase2: Empty domain info
        ("empty.com", ["192.168.1.1"], None, False),
    ],
)
def test_detect_young_domains_other_cases(
    mock_db, domain, answers, domain_data, expected_result
):
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)
    dns.should_detect_young_domain = Mock(return_value=True)
    mock_db.get_domain_data.return_value = domain_data

    result = dns.detect_young_domains(
        domain, answers, timestamp, profileid, twid, uid
    )

    assert result is expected_result
    dns.should_detect_young_domain.assert_called_once_with(domain)
    mock_db.get_domain_data.assert_called_once_with(domain)


def test_extract_ips_from_dns_answers(mock_db):
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)
    answers = [
        "192.168.1.1",
        "2001:db8::1",
        "CNAME_example.com",
        "MX=mail.example.com",
    ]
    extracted_ips = dns.extract_ips_from_dns_answers(answers)
    assert extracted_ips == ["192.168.1.1", "2001:db8::1"]


@pytest.mark.parametrize(
    "contacted_ips, other_ip, expected_result",
    [  # Testcase1: Connection exists from other IP version
        (["8.8.8.8"], ["192.168.1.2"], True),
        # Testcase2: No connection from other IP version
        (["1.1.1.1"], ["192.168.1.2"], None),
        # Testcase3: No contacted IPs from other IP version
        ([], ["192.168.1.2"], False),
        # Testcase4: No other IP version found
        (["8.8.8.8"], [], False),
    ],
)
def test_is_connection_made_by_different_version(
    mocker, mock_db, contacted_ips, other_ip, expected_result
):
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)
    mocker.patch.object(
        dns.db,
        "get_all_contacted_ips_in_profileid_twid",
        return_value=contacted_ips,
    )
    mocker.patch.object(
        dns.db, "get_the_other_ip_version", return_value=other_ip
    )

    assert (
        dns.is_connection_made_by_different_version(profileid, twid, "8.8.8.8")
        is expected_result
    )


@pytest.mark.parametrize(
    "string, expected_result",
    [  # Testcase1: High entropy string
        ("qwerty123!@#$%^&*()_+", True),
        # Testcase2: Low entropy string
        ("aaaaaaaaaaaaaaaaaaaa", False),
        # Testcase3: String with spaces and special characters
        ("Hello world!", False),
    ],
)
def test_estimate_shannon_entropy(mock_db, string, expected_result):
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)
    dns.shannon_entropy_threshold = 4.0

    entropy = dns.estimate_shannon_entropy(string)
    assert (entropy >= dns.shannon_entropy_threshold) == expected_result


@pytest.mark.parametrize(
    "domain, answers, " "expected_evidence_calls, expected_db_deletes",
    [  # Testcase1:Invalid answer found
        ("example.com", ["127.0.0.1"], 1, 1),
        # Testcase2:No invalid answer
        ("example.com", ["8.8.8.8"], 0, 0),
        # Testcase3:Invalid answer for localhost
        ("localhost", ["127.0.0.1"], 0, 0),
    ],
)
def test_check_invalid_dns_answers_call_counts(
    mocker,
    mock_db,
    domain,
    answers,
    expected_evidence_calls,
    expected_db_deletes,
):
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)

    mock_set_evidence = mocker.patch.object(
        dns.set_evidence, "invalid_dns_answer"
    )
    mock_delete_dns_resolution = mocker.patch.object(
        mock_db, "delete_dns_resolution"
    )

    profileid, twid, timestamp, uid = ("profile1", "tw1", 1234567890, "uid1")

    dns.check_invalid_dns_answers(
        domain, answers, profileid, twid, timestamp, uid
    )

    assert mock_set_evidence.call_count == expected_evidence_calls
    assert mock_delete_dns_resolution.call_count == expected_db_deletes


def test_check_invalid_dns_answers_with_invalid_answer(mocker, mock_db):
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)

    mock_set_evidence = mocker.patch.object(
        dns.set_evidence, "invalid_dns_answer"
    )
    mock_delete_dns_resolution = mocker.patch.object(
        mock_db, "delete_dns_resolution"
    )

    domain, answers = "example.com", ["127.0.0.1"]

    dns.check_invalid_dns_answers(
        domain, answers, profileid, twid, timestamp, uid
    )

    mock_set_evidence.assert_called_once_with(
        domain, answers[0], profileid, twid, timestamp, uid
    )
    mock_delete_dns_resolution.assert_called_once_with(answers[0])


@pytest.mark.parametrize(
    "domains, timestamps, expected_result",
    [
        # Testcase 1: Less than threshold, no scan
        (
            [f"{i}example.in-addr.arpa" for i in range(5)],
            arange(0, 1, 1 / 5),
            False,
        ),
        # Testcase 2: Reach threshold, scan detected within 2 seconds
        (
            [f"{i}example.in-addr.arpa" for i in range(10)],
            arange(0, 1, 1 / 10),
            True,
        ),
        # Testcase 3: Reach threshold, but scan takes longer than 2 seconds
        (
            [f"{i}example.in-addr.arpa" for i in range(10)],
            arange(0, 3, 3 / 10),
            False,
        ),
    ],
)
def test_check_dns_arpa_scan(mock_db, domains, timestamps, expected_result):
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)
    dns.arpa_scan_threshold = 10

    for i, (domain, ts) in enumerate(zip(domains, timestamps)):
        is_arpa_scan = dns.check_dns_arpa_scan(
            domain, timestamp + ts, profileid, twid, f"uid_{i}"
        )

    assert is_arpa_scan == expected_result


@pytest.mark.parametrize(
    "test_ip, mock_query_side_effect, expected_result",
    [
        # Testcase 1: Successful DNS query, server found
        ("8.8.8.8", None, True),
        # Testcase 2: DNS query raises exception, not a server
        ("192.168.1.100", Exception("DNS timeout error"), False),
    ],
)
def test_is_dns_server(
    mock_db, test_ip, mock_query_side_effect, expected_result
):
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)
    with patch("dns.query.udp", side_effect=mock_query_side_effect):
        result = dns.is_dns_server(test_ip)

    assert result == expected_result


def test_read_configuration(mock_db):
    """Test if read_configuration correctly reads the entropy threshold."""
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)

    with patch(
        "slips_files.common.parsers.config_parser.ConfigParser.get_entropy_threshold",
        return_value=3.5,
    ):
        dns.read_configuration()

    assert dns.shannon_entropy_threshold == 3.5


def test_check_high_entropy_dns_answers_with_call(mocker, mock_db):
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)
    dns.shannon_entropy_threshold = 4.0

    domain = "example.com"
    answers = ["A 1.2.3.4", "TXT abcdefghijklmnopqrstuvwxyz1234567890"]
    expected_entropy = 4.5

    mock_estimate_entropy = mocker.patch.object(
        dns, "estimate_shannon_entropy", return_value=expected_entropy
    )

    mock_set_evidence = mocker.patch.object(
        dns.set_evidence, "suspicious_dns_answer"
    )

    dns.check_high_entropy_dns_answers(
        domain, answers, daddr, profileid, twid, timestamp, uid
    )

    assert mock_set_evidence.call_count == 1
    mock_set_evidence.assert_called_once_with(
        domain,
        answers[1],
        expected_entropy,
        daddr,
        profileid,
        twid,
        timestamp,
        uid,
    )
    assert mock_estimate_entropy.call_count == 1


@pytest.mark.parametrize(
    "domain, answers, expected_entropy",
    [
        # Testcase 1: No TXT answer
        (
            "example.com",
            ["A 1.2.3.4", "AAAA 2001:db8::1"],
            0,
        ),
        # Testcase 2: TXT answer below entropy threshold
        (
            "example.com",
            ["A 1.2.3.4", "TXT aaaa"],
            2.0,
        ),
    ],
)
def test_check_high_entropy_dns_answers_no_call(
    mocker, mock_db, domain, answers, expected_entropy
):
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)
    dns.shannon_entropy_threshold = 4.0

    mock_estimate_entropy = mocker.patch.object(
        dns, "estimate_shannon_entropy", return_value=expected_entropy
    )

    mock_set_evidence = mocker.patch.object(
        dns.set_evidence, "suspicious_dns_answer"
    )

    dns.check_high_entropy_dns_answers(
        domain, answers, daddr, profileid, twid, timestamp, uid
    )

    assert mock_set_evidence.call_count == 0
    expected_estimate_calls = sum("TXT" in answer for answer in answers)
    assert mock_estimate_entropy.call_count == expected_estimate_calls


@pytest.mark.parametrize(
    "test_case, expected_calls",
    [
        (
            # Testcase1: Complete DNS data
            {
                "data": json.dumps(
                    {
                        "profileid": profileid,
                        "twid": twid,
                        "uid": uid,
                        "daddr": daddr,
                        "stime": timestamp,
                        "flow": json.dumps(
                            {
                                "query": "example.com",
                                "answers": ["192.168.1.1"],
                                "rcode_name": "NOERROR",
                            }
                        ),
                    }
                )
            },
            {
                "check_dns_without_connection": 1,
                "check_high_entropy_dns_answers": 1,
                "check_invalid_dns_answers": 1,
                "detect_dga": 1,
                "detect_young_domains": 1,
                "check_dns_arpa_scan": 1,
            },
        ),
        (
            # Testcase2: Missing DNS answers
            {
                "data": json.dumps(
                    {
                        "profileid": profileid,
                        "twid": twid,
                        "uid": uid,
                        "stime": timestamp,
                        "flow": json.dumps({"query": "", "answers": []}),
                    }
                )
            },
            {
                "check_dns_without_connection": 0,
                "check_high_entropy_dns_answers": 1,
                "check_invalid_dns_answers": 1,
                "detect_dga": 1,
                "detect_young_domains": 1,
                "check_dns_arpa_scan": 1,
            },
        ),
    ],
)
def test_analyze_new_flow_msg(mocker, mock_db, test_case, expected_calls):
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)
    dns.connections_checked_in_dns_conn_timer_thread = []
    mock_check_dns_without_connection = mocker.patch.object(
        dns, "check_dns_without_connection"
    )
    mock_check_high_entropy_dns_answers = mocker.patch.object(
        dns, "check_high_entropy_dns_answers"
    )
    mock_check_invalid_dns_answers = mocker.patch.object(
        dns, "check_invalid_dns_answers"
    )
    mock_detect_dga = mocker.patch.object(dns, "detect_dga")
    mock_detect_young_domains = mocker.patch.object(
        dns, "detect_young_domains"
    )
    mock_check_dns_arpa_scan = mocker.patch.object(dns, "check_dns_arpa_scan")

    dns.analyze({"channel": "new_dns", "data": test_case["data"]})

    assert (
        mock_check_dns_without_connection.call_count
        == expected_calls["check_dns_without_connection"]
    )
    assert (
        mock_check_high_entropy_dns_answers.call_count
        == expected_calls["check_high_entropy_dns_answers"]
    )
    assert (
        mock_check_invalid_dns_answers.call_count
        == expected_calls["check_invalid_dns_answers"]
    )
    assert mock_detect_dga.call_count == expected_calls["detect_dga"]
    assert (
        mock_detect_young_domains.call_count
        == expected_calls["detect_young_domains"]
    )
    assert (
        mock_check_dns_arpa_scan.call_count
        == expected_calls["check_dns_arpa_scan"]
    )


@pytest.mark.parametrize(
    "rcode_name, query, initial_nxdomains, "
    "expected_nxdomains, expected_result",
    [
        # Not NXDOMAIN
        ("NOERROR", "example.com", {}, {}, False),
        # NXDOMAIN, first occurrence
        (
            "NXDOMAIN",
            "example.com",
            {},
            {f"{profileid}_{twid}": (["example.com"], [uid])},
            False,
        ),
        # NXDOMAIN, 9th occurrence (below threshold)
        (
            "NXDOMAIN",
            "example9.com",
            {
                f"{profileid}_{twid}": (
                    [
                        "example1.com",
                        "example2.com",
                        "example3.com",
                        "example4.com",
                        "example5.com",
                        "example6.com",
                        "example7.com",
                        "example8.com",
                    ],
                    [uid] * 8,
                )
            },
            {
                f"{profileid}_{twid}": (
                    [
                        "example1.com",
                        "example2.com",
                        "example3.com",
                        "example4.com",
                        "example5.com",
                        "example6.com",
                        "example7.com",
                        "example8.com",
                        "example9.com",
                    ],
                    [uid] * 9,
                )
            },
            None,
        ),
    ],
)
def test_detect_dga_no_alert(
    mocker,
    mock_db,
    rcode_name,
    query,
    initial_nxdomains,
    expected_nxdomains,
    expected_result,
):
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)
    dns.nxdomains = initial_nxdomains
    dns.nxdomains_threshold = 10

    mocker.patch.object(
        dns.flowalerts.whitelist.domain_analyzer,
        "is_whitelisted",
        return_value=False,
    )
    mock_set_evidence = mocker.patch.object(dns.set_evidence, "dga")

    result = dns.detect_dga(rcode_name, query, timestamp, profileid, twid, uid)

    assert result == expected_result
    assert dns.nxdomains == expected_nxdomains
    mock_set_evidence.assert_not_called()


def test_detect_dga_alert(mocker, mock_db):
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)

    initial_nxdomains = {
        f"{profileid}_{twid}": (
            [
                "example1.com",
                "example2.com",
                "example3.com",
                "example4.com",
                "example5.com",
                "example6.com",
                "example7.com",
                "example8.com",
                "example9.com",
            ],
            [uid] * 9,
        )
    }
    dns.nxdomains = initial_nxdomains
    dns.nxdomains_threshold = 10

    mocker.patch.object(
        dns.flowalerts.whitelist.domain_analyzer,
        "is_whitelisted",
        return_value=False,
    )
    mock_set_evidence = mocker.patch.object(dns.set_evidence, "dga")

    result = dns.detect_dga(
        "NXDOMAIN", "example10.com", timestamp, profileid, twid, uid
    )
    expected_result = True
    assert result == expected_result
    assert dns.nxdomains == {f"{profileid}_{twid}": ([], [])}
    mock_set_evidence.assert_called_once_with(
        10, timestamp, profileid, twid, [uid] * 10
    )


def test_detect_dga_whitelisted(mocker, mock_db):
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)
    dns.nxdomains = {}
    dns.nxdomains_threshold = 10

    mocker.patch.object(
        dns.flowalerts.whitelist.domain_analyzer,
        "is_whitelisted",
        return_value=True,
    )
    mock_set_evidence = mocker.patch.object(dns.set_evidence, "dga")

    result = dns.detect_dga(
        "NXDOMAIN", "example.com", timestamp, profileid, twid, uid
    )

    expected_result = False
    assert result == expected_result
    assert dns.nxdomains == {}
    mock_set_evidence.assert_not_called()


@pytest.mark.parametrize(
    "query, expected_result",
    [  # Testcase1:NXDOMAIN_arpa_domain
        ("example.in-addr.arpa", False),
        # Testcase2:NXDOMAIN_local_domain
        ("example.local", False),
    ],
    ids=["arpa_domain", "local_domain"],
)
def test_detect_dga_special_domains(mocker, mock_db, query, expected_result):
    dns = ModuleFactory().create_dns_analyzer_obj(mock_db)
    dns.nxdomains = {}
    dns.nxdomains_threshold = 10

    mocker.patch.object(
        dns.flowalerts.whitelist.domain_analyzer,
        "is_whitelisted",
        return_value=False,
    )
    mock_set_evidence = mocker.patch.object(dns.set_evidence, "dga")

    result = dns.detect_dga("NXDOMAIN", query, timestamp, profileid, twid, uid)

    assert result == expected_result
    assert dns.nxdomains == {}
    mock_set_evidence.assert_not_called()
