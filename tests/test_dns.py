# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/flowalerts/dns.py"""

from dataclasses import asdict

from slips_files.common.slips_utils import utils
from slips_files.core.flows.zeek import DNS
from tests.common_test_utils import get_mock_coro
from tests.module_factory import ModuleFactory
from numpy import arange
from unittest.mock import (
    patch,
    Mock,
)
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
def test_should_detect_dns_without_conn(domain, rcode_name, expected_result):
    dns = ModuleFactory().create_dns_analyzer_obj()
    dns.is_running_non_stop = False
    flow = DNS(
        starttime="1726568479.5997488",
        uid="1234",
        saddr="",
        daddr="",
        dport="",
        sport="",
        proto="",
        query=domain,
        qclass_name="",
        qtype_name="AAAA",
        rcode_name=rcode_name,
        answers="",
        TTLs="",
    )
    assert dns.should_detect_dns_without_conn(flow) == expected_result


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
    answers, cname_resolution, contacted_ips, expected_result
):
    dns = ModuleFactory().create_dns_analyzer_obj()
    dns.db.get_domain_resolution.return_value = cname_resolution

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
    domain, answers, age, should_detect, expected_result
):

    dns = ModuleFactory().create_dns_analyzer_obj()
    dns.should_detect_young_domain = Mock(return_value=should_detect)
    flow = DNS(
        starttime="1726568479.5997488",
        uid="1234",
        saddr="192.168.1.5",
        daddr="1.1.1.1",
        query=domain,
        dport="",
        sport="",
        proto="",
        qclass_name="",
        qtype_name="",
        rcode_name="",
        answers=answers,
        TTLs="",
    )
    dns.db.get_domain_data.return_value = {"Age": age}

    assert dns.detect_young_domains(twid, flow) == expected_result


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
    domain, answers, domain_data, expected_result
):
    dns = ModuleFactory().create_dns_analyzer_obj()
    dns.should_detect_young_domain = Mock(return_value=True)
    dns.db.get_domain_data.return_value = domain_data
    flow = DNS(
        starttime="1726568479.5997488",
        uid="1234",
        saddr="192.168.1.5",
        daddr="1.1.1.1",
        query=domain,
        dport="",
        sport="",
        proto="",
        qclass_name="",
        qtype_name="",
        rcode_name="",
        answers=answers,
        TTLs="",
    )
    result = dns.detect_young_domains(twid, flow)
    assert result is expected_result
    dns.should_detect_young_domain.assert_called_once_with(domain)
    dns.db.get_domain_data.assert_called_once_with(domain)


def test_extract_ips_from_dns_answers():
    dns = ModuleFactory().create_dns_analyzer_obj()
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
    contacted_ips, other_ip, expected_result
):
    dns = ModuleFactory().create_dns_analyzer_obj()
    dns.db.get_all_contacted_ips_in_profileid_twid.return_value = contacted_ips
    dns.db.get_the_other_ip_version.return_value = other_ip

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
def test_estimate_shannon_entropy(string, expected_result):
    dns = ModuleFactory().create_dns_analyzer_obj()
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
    domain,
    answers,
    expected_evidence_calls,
    expected_db_deletes,
):
    dns = ModuleFactory().create_dns_analyzer_obj()
    flow = DNS(
        starttime="1726568479.5997488",
        uid="1234",
        saddr="1.1.1.1",
        daddr="192.168.1.5",
        query=domain,
        dport="",
        sport="",
        proto="",
        qclass_name="",
        qtype_name="",
        rcode_name="",
        answers=answers,
        TTLs="",
    )
    dns.set_evidence.invalid_dns_answer = Mock()
    dns.check_invalid_dns_answers(twid, flow)

    assert (
        dns.set_evidence.invalid_dns_answer.call_count
        == expected_evidence_calls
    )
    assert dns.db.delete_dns_resolution.call_count == expected_db_deletes


def test_check_invalid_dns_answers_with_invalid_answer():
    dns = ModuleFactory().create_dns_analyzer_obj()
    flow = DNS(
        starttime="1726568479.5997488",
        uid="1234",
        saddr="1.1.1.1",
        daddr="192.168.1.5",
        query="example.com",
        qclass_name="",
        dport="",
        sport="",
        proto="",
        qtype_name="",
        rcode_name="",
        answers=["127.0.0.1"],
        TTLs="",
    )
    dns.set_evidence.invalid_dns_answer = Mock()
    dns.db.delete_dns_resolution = Mock()
    dns.check_invalid_dns_answers(twid, flow)

    dns.set_evidence.invalid_dns_answer.assert_called_once_with(
        twid, flow, flow.answers[0]
    )
    dns.db.delete_dns_resolution.assert_called_once_with(flow.answers[0])


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
def test_check_dns_arpa_scan(domains, timestamps, expected_result):
    dns = ModuleFactory().create_dns_analyzer_obj()
    dns.arpa_scan_threshold = 10

    for i, (domain, ts) in enumerate(zip(domains, timestamps)):
        flow = DNS(
            starttime=ts,
            uid=f"uid_{i}",
            saddr="1.1.1.1",
            daddr="192.168.1.5",
            query=domain,
            dport="",
            sport="",
            proto="",
            qclass_name="",
            qtype_name="",
            rcode_name="",
            answers=["127.0.0.1"],
            TTLs="",
        )
        is_arpa_scan = dns.check_dns_arpa_scan(profileid, twid, flow)

    assert is_arpa_scan == expected_result


def test_read_configuration():
    """Test if read_configuration correctly reads the entropy threshold."""
    dns = ModuleFactory().create_dns_analyzer_obj()

    with patch(
        "slips_files.common.parsers.config_parser.ConfigParser."
        "get_entropy_threshold",
        return_value=3.5,
    ):
        dns.read_configuration()

    assert dns.shannon_entropy_threshold == 3.5


def test_check_high_entropy_dns_answers_with_call():
    dns = ModuleFactory().create_dns_analyzer_obj()
    dns.shannon_entropy_threshold = 4.0
    flow = DNS(
        starttime="1726568479.5997488",
        uid="1243",
        saddr="1.1.1.1",
        daddr="192.168.1.5",
        query="example.com",
        qclass_name="",
        qtype_name="",
        rcode_name="",
        dport="",
        sport="",
        proto="",
        answers=["A 1.2.3.4", "TXT abcdefghijklmnopqrstuvwxyz1234567890"],
        TTLs="",
    )
    expected_entropy = 4.5
    dns.estimate_shannon_entropy = Mock()
    dns.estimate_shannon_entropy.return_value = expected_entropy

    dns.set_evidence.suspicious_dns_answer = Mock()

    dns.check_high_entropy_dns_answers(twid, flow)
    dns.set_evidence.suspicious_dns_answer.assert_called_once_with(
        twid,
        flow,
        expected_entropy,
        flow.answers[1],
    )
    assert dns.estimate_shannon_entropy.call_count == 1


@pytest.mark.parametrize(
    "domain, saddr, answers, expected_entropy, "
    "estimate_shannon_entropy_call_count",
    [
        # Testcase 1: No TXT answer
        ("example.com", "1.1.1.1", ["A 1.2.3.4", "AAAA 2001:db8::1"], 0, 1),
        # Testcase 2: Muticast ip
        (
            "example.com",
            "224.0.0.251",
            ["A 1.2.3.4", "AAAA 2001:db8::1"],
            0,
            0,
        ),
        # Testcase 3: Muticast ip again
        (
            "example.com",
            "224.0.0.1",
            ["A 1.2.3.4", "AAAA 2001:db8::1"],
            0,
            0,
        ),
        # Testcase 4: TXT answer below entropy threshold
        ("example.com", "1.1.1.1", ["A 1.2.3.4", "TXT aaaa"], 2.0, 1),
    ],
)
def test_check_high_entropy_dns_answers_no_call(
    domain,
    answers,
    saddr,
    expected_entropy,
    estimate_shannon_entropy_call_count,
):
    dns = ModuleFactory().create_dns_analyzer_obj()
    dns.shannon_entropy_threshold = 4.0
    dns.estimate_shannon_entropy = Mock()
    dns.estimate_shannon_entropy.return_value = expected_entropy
    dns.set_evidence.suspicious_dns_answer = Mock()
    flow = DNS(
        starttime="1726568479.5997488",
        uid="1243",
        saddr=saddr,
        daddr="192.168.1.5",
        query="example.com",
        qclass_name="",
        dport="",
        sport="",
        proto="",
        qtype_name="",
        rcode_name="",
        answers=["A 1.2.3.4", "TXT abcdefghijklmnopqrstuvwxyz1234567890"],
        TTLs="",
    )
    dns.check_high_entropy_dns_answers(twid, flow)

    assert dns.set_evidence.suspicious_dns_answer.call_count == 0
    assert (
        dns.estimate_shannon_entropy.call_count
        == estimate_shannon_entropy_call_count
    )


@pytest.mark.parametrize(
    "test_case, expected_calls",
    [
        (
            # Testcase1: Complete DNS data
            {
                "data": json.dumps(
                    {
                        "flow": asdict(
                            DNS(
                                starttime="1726568479.5997488",
                                uid="1243",
                                saddr="1.1.1.1",
                                daddr="192.168.1.5",
                                query="example.com",
                                dport="",
                                sport="",
                                proto="",
                                qclass_name="",
                                qtype_name="",
                                rcode_name="NOERROR",
                                answers=["192.168.1.1"],
                                TTLs="",
                            )
                        ),
                        "profileid": profileid,
                        "twid": twid,
                    }
                ),
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
    ],
)
async def test_analyze_new_flow_msg(test_case, expected_calls):
    dns = ModuleFactory().create_dns_analyzer_obj()
    dns.connections_checked_in_dns_conn_timer_thread = []
    dns.check_dns_without_connection = get_mock_coro(True)
    dns.check_high_entropy_dns_answers = Mock()
    dns.check_invalid_dns_answers = Mock()
    dns.detect_dga = Mock()
    dns.detect_young_domains = Mock()
    dns.check_dns_arpa_scan = Mock()

    await dns.analyze({"channel": "new_dns", "data": test_case["data"]})

    assert (
        dns.check_dns_without_connection.call_count
        == expected_calls["check_dns_without_connection"]
    )
    assert (
        dns.check_high_entropy_dns_answers.call_count
        == expected_calls["check_high_entropy_dns_answers"]
    )
    assert (
        dns.check_invalid_dns_answers.call_count
        == expected_calls["check_invalid_dns_answers"]
    )
    assert dns.detect_dga.call_count == expected_calls["detect_dga"]
    assert (
        dns.detect_young_domains.call_count
        == expected_calls["detect_young_domains"]
    )
    assert (
        dns.check_dns_arpa_scan.call_count
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
    rcode_name,
    query,
    initial_nxdomains,
    expected_nxdomains,
    expected_result,
):
    dns = ModuleFactory().create_dns_analyzer_obj()
    dns.nxdomains = initial_nxdomains
    dns.nxdomains_threshold = 10
    flow = DNS(
        starttime="1726568479.5997488",
        uid=uid,
        saddr="1.1.1.1",
        daddr="192.168.1.5",
        query=query,
        qclass_name="",
        qtype_name="",
        rcode_name=rcode_name,
        dport="",
        sport="",
        proto="",
        answers=["127.0.0.1"],
        TTLs="",
    )
    dns.flowalerts.whitelist.domain_analyzer.is_whitelisted = Mock()
    dns.flowalerts.whitelist.domain_analyzer.is_whitelisted.return_value = (
        False
    )
    dns.set_evidence.dga = Mock()

    assert dns.detect_dga(profileid, twid, flow) == expected_result
    assert dns.nxdomains == expected_nxdomains
    dns.set_evidence.dga.assert_not_called()


def test_detect_dga_alert():
    dns = ModuleFactory().create_dns_analyzer_obj()

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

    dns.flowalerts.whitelist.domain_analyzer.is_whitelisted = Mock()
    dns.flowalerts.whitelist.domain_analyzer.is_whitelisted.return_value = (
        False
    )
    flow = DNS(
        starttime="1726568479.5997488",
        uid=uid,
        saddr="1.1.1.1",
        daddr="192.168.1.5",
        query="example10.com",
        dport="",
        sport="",
        proto="",
        qclass_name="",
        qtype_name="",
        rcode_name="NXDOMAIN",
        answers=["127.0.0.1"],
        TTLs="",
    )

    dns.set_evidence.dga = Mock()
    result = dns.detect_dga(profileid, twid, flow)
    expected_result = True
    assert result == expected_result
    assert dns.nxdomains == {f"{profileid}_{twid}": ([], [])}
    dns.set_evidence.dga.assert_called_once_with(twid, flow, 10, [uid] * 10)


def test_detect_dga_whitelisted():
    dns = ModuleFactory().create_dns_analyzer_obj()
    dns.nxdomains = {}
    dns.nxdomains_threshold = 10

    dns.flowalerts.whitelist.domain_analyzer.is_whitelisted = Mock()
    dns.flowalerts.whitelist.domain_analyzer.is_whitelisted.return_value = True

    dns.set_evidence.dga = Mock()
    flow = DNS(
        starttime="1726568479.5997488",
        uid=uid,
        saddr="1.1.1.1",
        daddr="192.168.1.5",
        query="example.com",
        qclass_name="",
        dport="",
        sport="",
        proto="",
        qtype_name="",
        rcode_name="NXDOMAIN",
        answers=["127.0.0.1"],
        TTLs="",
    )
    result = dns.detect_dga(profileid, twid, flow)
    expected_result = False
    assert result == expected_result
    assert dns.nxdomains == {}
    dns.set_evidence.dga.assert_not_called()


@pytest.mark.parametrize(
    "query, expected_result",
    [  # Testcase1:NXDOMAIN_arpa_domain
        ("example.in-addr.arpa", False),
        # Testcase2:NXDOMAIN_local_domain
        ("example.local", False),
    ],
    ids=["arpa_domain", "local_domain"],
)
def test_detect_dga_special_domains(query, expected_result):
    dns = ModuleFactory().create_dns_analyzer_obj()
    dns.nxdomains = {}
    dns.nxdomains_threshold = 10

    dns.flowalerts.whitelist.domain_analyzer.is_whitelisted = Mock()
    dns.flowalerts.whitelist.domain_analyzer.is_whitelisted.return_value = (
        False
    )

    dns.set_evidence.dga = Mock()
    flow = DNS(
        starttime="1726568479.5997488",
        uid=uid,
        saddr="1.1.1.1",
        daddr="192.168.1.5",
        dport="",
        sport="",
        proto="",
        query=query,
        qclass_name="",
        qtype_name="",
        rcode_name="NXDOMAIN",
        answers=["127.0.0.1"],
        TTLs="",
    )
    result = dns.detect_dga(profileid, twid, flow)

    assert result == expected_result
    assert dns.nxdomains == {}
    dns.set_evidence.dga.assert_not_called()


def get_dns_obj():
    dns = ModuleFactory().create_dns_analyzer_obj()
    dns.should_detect_dns_without_conn = Mock()
    dns.is_interface_timeout_reached = Mock()
    dns.is_any_flow_answer_contacted = Mock()
    dns.pending_dns_without_conn = Mock()
    dns.set_evidence = Mock()
    dns.check_pending_flows_timeout = Mock()
    dns.flowalerts.should_stop = Mock(side_effect=[False, True])  # to loop
    # once
    return dns


async def test_check_dns_without_connection_shouldnt_detect():
    dns = get_dns_obj()
    # Test when should_detect_dns_without_conn returns False
    dns.should_detect_dns_without_conn.return_value = False
    result = await dns.check_dns_without_connection(
        "profileid", "twid", "flow"
    )
    assert result is False


async def test_check_dns_without_connection_interface_timeout_not_reached():
    dns = get_dns_obj()
    # Test when is_interface_timeout_reached returns False
    dns.should_detect_dns_without_conn.return_value = True
    dns.is_interface_timeout_reached.return_value = False
    result = await dns.check_dns_without_connection(
        "profileid", "twid", "flow"
    )
    assert result is False


async def test_check_dns_without_connection_flow_answer_contacted_true():
    dns = get_dns_obj()
    # Test when is_any_flow_answer_contacted returns True
    dns.should_detect_dns_without_conn.return_value = True
    dns.is_interface_timeout_reached.return_value = True
    dns.is_any_flow_answer_contacted.return_value = True
    result = await dns.check_dns_without_connection(
        "profileid", "twid", "flow"
    )
    assert result is False


async def test_check_dns_without_connection_waited_for_the_conn_false():
    dns = get_dns_obj()
    # Test when waited_for_the_conn is False
    dns.should_detect_dns_without_conn.return_value = True
    dns.is_interface_timeout_reached.return_value = True
    dns.is_any_flow_answer_contacted.return_value = False
    result = await dns.check_dns_without_connection(
        "profileid", "twid", "flow", waited_for_the_conn=False
    )
    assert result is False
    dns.pending_dns_without_conn.put.assert_called_once_with(
        ("profileid", "twid", "flow")
    )


async def test_check_dns_without_connection_waited_for_the_conn_true():
    dns = get_dns_obj()
    # Test when waited_for_the_conn is True
    dns.should_detect_dns_without_conn.return_value = True
    dns.is_interface_timeout_reached.return_value = True
    dns.is_any_flow_answer_contacted.return_value = False
    result = await dns.check_dns_without_connection(
        "profileid", "twid", "flow", waited_for_the_conn=True
    )
    assert result is True
    dns.set_evidence.dns_without_conn.assert_called_once_with("twid", "flow")


def test_check_dns_without_connection_timeout_empty_queue():
    """Test that the method does nothing when the queue is empty."""
    dns = ModuleFactory().create_dns_analyzer_obj()
    # to loop once only
    dns.flowalerts.should_stop = Mock(side_effect=[False, True])
    dns.stop_event.is_set = Mock(side_effect=[False, True])

    dns.pending_dns_without_conn.empty = Mock(return_value=True)
    dns.check_pending_flows_timeout = Mock()
    dns.check_dns_without_connection_timeout()
    dns.check_pending_flows_timeout.assert_not_called()


def test_check_dns_without_connection_timeout_flow_processing():
    """Test that the method processes flows correctly."""
    dns = ModuleFactory().create_dns_analyzer_obj()
    dns.flowalerts.should_stop = Mock(side_effect=[False, True])  # to loop
    # once
    mock_flow = DNS(
        starttime="1726568479.5997488",
        uid="1234",
        saddr="",
        daddr="",
        query="",
        qclass_name="",
        qtype_name="",
        dport="",
        sport="",
        proto="",
        rcode_name="",
        answers="",
        TTLs="",
    )
    dns_flow_to_check = DNS(
        starttime="1726570879.5997488",
        uid="1234",
        saddr="",
        daddr="",
        query="",
        qclass_name="",
        dport="",
        sport="",
        proto="",
        qtype_name="",
        rcode_name="",
        answers="",
        TTLs="",
    )
    flow_info_to_check = ("profileid", "twid", dns_flow_to_check)

    dns.pending_dns_without_conn.put(flow_info_to_check)
    dns.get_dns_flow_from_queue = Mock(return_value=mock_flow)

    dns.check_dns_without_connection_timeout()
    # since it didnt pass, the flow should be put back to queue
    assert dns.pending_dns_without_conn.qsize() == 1
    assert dns.pending_dns_without_conn.get() == flow_info_to_check


def test_check_dns_without_connection_timeout_keyboard_interrupt():
    """Test that the method handles KeyboardInterrupt gracefully."""
    dns = ModuleFactory().create_dns_analyzer_obj()
    # Simulate a KeyboardInterrupt
    dns.get_dns_flow_from_queue = Mock(side_effect=KeyboardInterrupt)
    dns.check_dns_without_connection_timeout()
    # just checking that it doesnt raise an exception
    assert True


def test_check_dns_without_connection_timeout_should_stop():
    """Test that the method exits when should_stop returns True."""
    dns = ModuleFactory().create_dns_analyzer_obj()
    dns.flowalerts.should_stop = Mock(return_value=True)
    dns.get_dns_flow_from_queue = Mock()
    dns.check_dns_without_connection_timeout()

    # Assert that the method exits without processing any flows
    dns.get_dns_flow_from_queue.assert_not_called()


def test_check_pending_flows_timeout():
    reference_flow = DNS(
        starttime="1726568479.5997488",
        uid="1234",
        saddr="",
        daddr="",
        query="",
        qclass_name="",
        dport="",
        sport="",
        proto="",
        qtype_name="",
        rcode_name="",
        answers="",
        TTLs="",
    )

    # This will be 10 mins after the reference_flow
    dns_flow_to_check = DNS(
        starttime="1726570879.5997488",
        uid="5678",
        saddr="",
        daddr="",
        query="",
        qclass_name="",
        dport="",
        sport="",
        proto="",
        qtype_name="",
        rcode_name="",
        answers="",
        TTLs="",
    )
    # Simulate 10 minutes difference
    utils.get_time_diff = Mock(return_value=10)

    dns = ModuleFactory().create_dns_analyzer_obj()
    dns.check_dns_without_connection = Mock()
    dns.pending_dns_without_conn.put(
        ("profile5678", "twid_123", dns_flow_to_check)
    )

    back_to_queue = dns.check_pending_flows_timeout(reference_flow)

    utils.get_time_diff.assert_called_once_with(
        dns_flow_to_check.starttime, reference_flow.starttime, "minutes"
    )

    dns.check_dns_without_connection.assert_called_once_with(
        "profile5678", "twid_123", dns_flow_to_check, waited_for_the_conn=False
    )
    assert back_to_queue == []
