# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/threat_intelligence/threat_intelligence.py"""

from tests.module_factory import ModuleFactory
import os
import pytest
import json
from unittest.mock import (
    patch,
    Mock,
)
import ipaddress
from slips_files.core.structures.evidence import ThreatLevel


def test_parse_local_ti_file():
    """
    Test parsing of a local threat intelligence file.

    Ensures that the `parse_local_ti_file` method successfully parses known threat
    intelligence entries from "own_malicious_iocs.csv" and properly integrates
    them into the system.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    local_ti_files_dir = threatintel.path_to_local_ti_files
    local_ti_file = os.path.join(local_ti_files_dir, "own_malicious_iocs.csv")
    assert threatintel.parse_local_ti_file(local_ti_file) is True


def test_parse_ja3_file():
    """
    Test parsing of a JA3 hash file.

    Validates that the `parse_ja3_file` method can accurately process and store
    entries from "own_malicious_JA3.csv" containing JA3 hashes and associated
    threat levels and descriptions.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    local_ja3_file_dir = threatintel.path_to_local_ti_files
    local_ja3_file = os.path.join(local_ja3_file_dir, "own_malicious_JA3.csv")

    assert threatintel.parse_ja3_file(local_ja3_file) is True


def test_parse_jarm_file():
    """
    Test parsing of a JARM hash file.

    Confirms that the `parse_jarm_file` method is capable of interpreting and storing
    data from "own_malicious_JARM.csv", which includes JARM hashes along with their
    threat assessments and descriptions.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    local_jarm_file_dir = threatintel.path_to_local_ti_files
    local_jarm_file = os.path.join(
        local_jarm_file_dir, "own_malicious_JARM.csv"
    )

    assert threatintel.parse_jarm_file(local_jarm_file) is True


@pytest.mark.parametrize(
    "current_hash, old_hash, expected_return",
    [
        ("111", "222", "111"),
        ("111", "111", False),
        (False, "222", False),
    ],
)
def test_check_local_ti_files_for_update(
    current_hash, old_hash, expected_return, mocker
):
    """
    Test the logic for updating local threat intelligence files based on hash comparison.

    This test verifies the `should_update_local_ti_file` method's ability to decide
    whether a local threat intelligence file needs to be updated by comparing its
    current hash against a previously stored hash. The test covers scenarios including
    changed hashes, matching hashes, and errors in retrieving the current hash.

    Args:
        current_hash: The hash value of the current file, simulated for test scenarios.
        old_hash: The previously stored hash value for comparison.
        expected_return: The expected outcome of the comparison (new hash or False).
        mocker: The pytest-mock mocker object for patching dependencies.
    """
    # since this is a clear db, then we should update the local ti file
    threatintel = ModuleFactory().create_threatintel_obj()
    own_malicious_iocs = os.path.join(
        threatintel.path_to_local_ti_files, "own_malicious_iocs.csv"
    )

    mock_hash = mocker.patch(
        "slips_files.common.slips_utils.Utils.get_sha256_hash_of_file_contents"
    )

    mock_hash.return_value = current_hash

    threatintel.db.get_ti_feed_info.return_value = {"hash": old_hash}

    # the test asserts return value of should_update_local_tii_file
    # matches expected_return
    # for each scenario. This method should return new hash if an
    # update is needed or False if not
    assert (
        threatintel.should_update_local_ti_file(own_malicious_iocs)
        == expected_return
    )


@pytest.mark.parametrize(
    "mock_ip_ranges, expected_ipv4_ranges, expected_ipv6_ranges",
    [
        # Test case 1:  Both IPv4 and IPv6 ranges
        (
            {
                "192.168.1.0/24": '{"description": "Example range",'
                ' "source": "local_file", '
                '"threat_level": "high"}',
                "10.0.0.0/16": '{"description": "Another range", '
                '"source": "remote_feed",'
                ' "threat_level": "medium"}',
                "2001:db8::/64": '{"description": "IPv6 range", '
                '"source": "custom", "threat_level": "low"}',
            },
            {"192": ["192.168.1.0/24"], "10": ["10.0.0.0/16"]},
            {"2001": ["2001:db8::/64"]},
        ),
        # Test case 2: Only IPv4 ranges
        (
            {
                "172.17.0.0/16": '{"description": "Example range", "source":'
                ' "local_file", "threat_level": "high"}',
                "10.0.0.0/8": '{"description": "Another range", "source": '
                '"remote_feed", "threat_level": "medium"}',
            },
            {"172": ["172.17.0.0/16"], "10": ["10.0.0.0/8"]},
            {},
        ),
        # Test case 3: Only IPv6 ranges
        (
            {
                "2001:0db8:0:0:0:0:0:0/32": '{"description": "Example range",'
                ' "source": "local_file",'
                ' "threat_level": "high"}',
                "2002:c0a8:0:1::/64": '{"description": "Another range", '
                '"source": "remote_feed",'
                ' "threat_level": "medium"}',
            },
            {},
            {
                "2001": ["2001:0db8:0:0:0:0:0:0/32"],
                "2002": ["2002:c0a8:0:1::/64"],
            },
        ),
    ],
)
def test_get_malicious_ip_ranges(
    mock_ip_ranges, expected_ipv4_ranges, expected_ipv6_ranges
):
    """
    Test the retrieval and caching of malicious IP ranges from the database.
    This test covers both IPv4 and IPv6 range scenarios.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    threatintel.db.get_all_blacklisted_ip_ranges.return_value = mock_ip_ranges
    threatintel.get_all_blacklisted_ip_ranges()

    assert threatintel.cached_ipv4_ranges == expected_ipv4_ranges
    assert threatintel.cached_ipv6_ranges == expected_ipv6_ranges


@pytest.mark.parametrize(
    "daddr, uid, timestamp, profileid, twid, asn, asn_info, is_dns_response",
    [
        # Testcase 1: Standard case IP connection, medium threat level
        (
            "192.168.1.1",
            "uid123",
            "2023-11-28 12:00:00",
            "profile_10.0.0.1",
            "timewindow1",
            "AS1234",
            {
                "description": "Malicious ASN",
                "source": "TI Feed",
                "threat_level": "medium",
                "tags": "spam, botnet",
            },
            False,
        ),
        # Testcase 2: DNS response, high threat level
        (
            "192.168.1.2",
            "uid456",
            "2023-11-29 13:00:00",
            "profile_10.0.0.2",
            "timewindow2",
            "AS5678",
            {
                "description": "High risk ASN",
                "source": "Critical TI Feed",
                "threat_level": "high",
            },
            True,
        ),
        # Testcase 3: Missing tags in asn_info
        (
            "192.168.1.3",
            "uid789",
            "2023-11-30 14:00:00",
            "profile_10.0.0.3",
            "timewindow3",
            "AS9012",
            {
                "description": "ASN with no tags",
                "source": "Generic Feed",
                "threat_level": "low",
            },
            False,
        ),
        # Testcase 4: Default threat level when asn_info threat_level is invalid
        (
            "192.168.1.4",
            "uid101112",
            "2023-12-01 15:00:00",
            "profile_10.0.0.4",
            "timewindow4",
            "AS131415",
            {
                "description": "ASN with invalid threat level",
                "source": "Unreliable Feed",
                "threat_level": "invalid",
            },
            True,
        ),
    ],
)
def test_set_evidence_malicious_asn(
    daddr,
    uid,
    timestamp,
    profileid,
    twid,
    asn,
    asn_info,
    is_dns_response,
):
    """
    Test `set_evidence_malicious_asn` for setting evidence of malicious ASN interactions.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    threatintel.db.get_ip_identification.return_value = (
        " (Organization: Example Org)"
    )
    threatintel.set_evidence_malicious_asn(
        daddr=daddr,
        uid=uid,
        timestamp=timestamp,
        profileid=profileid,
        twid=twid,
        asn=asn,
        asn_info=asn_info,
        is_dns_response=is_dns_response,
    )
    threatintel.db.set_evidence.assert_called()


@pytest.mark.parametrize(
    "ip, uid, daddr, timestamp, ip_info, profileid, twid, ip_state, expected_call_count",
    [
        # Test case 1: Source IP is malicious
        (
            "1.1.1.2",
            "uid123",
            "192.168.1.1",
            "2023-11-28 12:00:00",
            {
                "description": "Malicious IP",
                "source": "TI Feed",
                "threat_level": "high",
            },
            "profile_192.168.1.1",
            "timewindow1",
            "srcip",
            1,
        ),
        # Test case 2: Destination IP is malicious
        (
            "192.168.1.1",
            "uid456",
            "10.0.0.2",
            "2023-11-29 13:00:00",
            {
                "description": "Another Malicious IP",
                "source": "Different Feed",
                "threat_level": "medium",
            },
            "profile_10.0.0.2",
            "timewindow2",
            "dstip",
            2,
        ),
        # Test case 3: No IP state specified
        (
            "192.168.1.1",
            "uid789",
            "10.0.0.3",
            "2023-11-30 14:00:00",
            {
                "description": "Yet Another Malicious IP",
                "source": "Another Feed",
                "threat_level": "low",
            },
            "profile_10.0.0.3",
            "timewindow3",
            "",
            0,
        ),
    ],
)
def test_set_evidence_malicious_ip(
    ip,
    uid,
    daddr,
    timestamp,
    ip_info,
    profileid,
    twid,
    ip_state,
    expected_call_count,
):
    """
    Test `set_evidence_malicious_ip` for recording evidence of traffic
     with malicious IPs.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    threatintel.db.get_ip_identification.return_value = (
        " (Organization: Example Org)"
    )
    threatintel.set_evidence_malicious_ip(
        ip=ip,
        uid=uid,
        daddr=daddr,
        timestamp=timestamp,
        ip_info=ip_info,
        profileid=profileid,
        twid=twid,
        ip_state=ip_state,
    )
    assert threatintel.db.set_evidence.call_count == expected_call_count


@pytest.mark.parametrize(
    "threat_level, expected",
    [
        ("low", True),
        ("medium", True),
        ("high", True),
        ("critical", True),
        ("invalid", False),
    ],
)
def test_is_valid_threat_level(threat_level, expected):
    """Test `is_valid_threat_level` for recognizing valid threat levels."""
    threatintel = ModuleFactory().create_threatintel_obj()
    assert threatintel.is_valid_threat_level(threat_level) is expected


@pytest.mark.parametrize(
    "protocol, ip_address, expected",
    [
        ("ICMP", "dstip", True),
        ("TCP", "dstip", False),
        ("ICMP", "srcip", False),
    ],
)
def test_is_outgoing_icmp_packet(protocol, ip_address, expected):
    """Test `is_outgoing_icmp_packet` for identifying outbound ICMP packets."""
    threatintel = ModuleFactory().create_threatintel_obj()
    assert (
        threatintel.is_outgoing_icmp_packet(protocol, ip_address) is expected
    )


@pytest.mark.parametrize(
    "mock_ioc_data, file_to_delete, expected_deleted_ips",
    [
        # Test case 1: Delete one IP from multiple IPs associated with the target file
        (
            {
                "192.168.1.1": '{"description": "Old IP", "source": "old_file.txt"}',
                "10.0.0.1": '{"description": "Current IP", "source": "current_file.txt"}',
                "192.168.1.2": '{"description": "Another Old IP", "source": "old_file.txt"}',
            },
            "old_file.txt",
            ["192.168.1.1", "192.168.1.2"],
        ),
        # Test case 2: Delete all IPs associated with the target file
        (
            {
                "192.168.1.1": '{"description": "Old IP", "source": "old_file.txt"}',
                "192.168.1.2": '{"description": "Another Old IP", "source": "old_file.txt"}',
            },
            "old_file.txt",
            ["192.168.1.1", "192.168.1.2"],
        ),
    ],
)
def test_delete_old_source_ips_with_deletions(
    mock_ioc_data, file_to_delete, expected_deleted_ips
):
    """
    Test `__delete_old_source_ips` when there are IPs to delete.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    threatintel.db.get_all_blacklisted_ips.return_value = mock_ioc_data
    threatintel._ThreatIntel__delete_old_source_ips(file_to_delete)
    threatintel.db.delete_ips_from_ioc_ips.assert_called_once_with(
        expected_deleted_ips
    )


@pytest.mark.parametrize(
    "mock_ioc_data, file_to_delete",
    [
        # Test case 1: No IPs to delete
        (
            {
                "10.0.0.1": '{"description": "Current IP", "source": "current_file.txt"}',
            },
            "nonexistent_file.txt",
        ),
        # Test case 2: No IPs to delete
        ({}, "old_file.txt"),
    ],
)
def test_delete_old_source_ips_no_deletions(mock_ioc_data, file_to_delete):
    """
    Test `__delete_old_source_ips` when there are no IPs to delete.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    threatintel.db.get_all_blacklisted_ips.return_value = mock_ioc_data
    threatintel._ThreatIntel__delete_old_source_ips(file_to_delete)
    threatintel.db.delete_ips_from_ioc_ips.assert_not_called()


@pytest.mark.parametrize(
    "domains_in_ioc, file_to_delete, expected_calls",
    [
        # Test Case 1:  No domains to delete
        (
            {
                "example.com": '{"description": "Old domain", "source": "old_file.txt"}',
                "current.com": '{"description": "Current domain", "source": "current_file.txt"}',
            },
            "different_file.txt",
            0,
        ),
        # Test Case 2: One domain to delete
        (
            {
                "example.com": '{"description": "Old domain", "source": "old_file.txt"}',
                "current.com": '{"description": "Current domain", "source": "current_file.txt"}',
            },
            "old_file.txt",
            1,
        ),
        # Test Case 3: Multiple domains to delete
        (
            {
                "example.com": '{"description": "Old domain", "source": "old_file.txt"}',
                "another.com": '{"description": "Another old domain", "source": "old_file.txt"}',
                "current.com": '{"description": "Current domain", "source": "current_file.txt"}',
            },
            "old_file.txt",
            1,
        ),
    ],
)
def test_delete_old_source_domains(
    domains_in_ioc, file_to_delete, expected_calls
):
    """
    Test the `__delete_old_source_domains` method
    for removing outdated domain IoCs.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    threatintel.db.get_all_blacklisted_domains.return_value = domains_in_ioc
    threatintel._ThreatIntel__delete_old_source_domains(file_to_delete)
    assert (
        threatintel.db.delete_domains_from_ioc_domains.call_count
        == expected_calls
    )


@pytest.mark.parametrize(
    "data_file, mock_ips_ioc, mock_domains_ioc, expected_delete_ips_calls, expected_delete_domains_calls",
    [
        # Test case 1: No old data for the given data file,
        (
            "new_file.txt",
            {
                "192.168.1.1": '{"description": "Old IP", "source": "old_file.txt"}',
                "10.0.0.1": '{"description": "Current IP", "source": "current_file.txt"}',
            },
            {
                "example.com": '{"description": "Old domain", "source": "old_file.txt"}',
                "current.com": '{"description": "Current domain", "source": "current_file.txt"}',
            },
            0,
            0,
        ),
        # Test case 2: Old IPs and domains exist for the given data file,
        (
            "old_file.txt",
            {
                "192.168.1.1": '{"description": "Old IP", "source": "old_file.txt"}',
                "10.0.0.1": '{"description": "Current IP", "source": "current_file.txt"}',
            },
            {
                "example.com": '{"description": "Old domain", "source": "old_file.txt"}',
                "current.com": '{"description": "Current domain", "source": "current_file.txt"}',
            },
            1,
            1,
        ),
        # Test case 3: Only old IPs exist,
        (
            "old_ip_file.txt",
            {
                "192.168.1.1": '{"description": "Old IP", "source": "old_ip_file.txt"}',
                "10.0.0.1": '{"description": "Current IP", "source": "current_file.txt"}',
            },
            {},
            1,
            0,
        ),
        # Test case 4: Only old domains exist, one deletion expected
        (
            "old_domain_file.txt",
            {},
            {
                "example.com": '{"description": "Old domain", "source": "old_domain_file.txt"}',
                "current.com": '{"description": "Current domain", "source": "current_file.txt"}',
            },
            0,
            1,
        ),
    ],
)
def test_delete_old_source_data_from_database(
    data_file,
    mock_ips_ioc,
    mock_domains_ioc,
    expected_delete_ips_calls,
    expected_delete_domains_calls,
):
    """
    Test the `__delete_old_source_data_from_database`
    method for removing both
    outdated IP and domain IoCs.
    """
    threatintel = ModuleFactory().create_threatintel_obj()

    threatintel.db.get_all_blacklisted_ips.return_value = mock_ips_ioc
    threatintel.db.get_all_blacklisted_domains.return_value = mock_domains_ioc

    threatintel._ThreatIntel__delete_old_source_data_from_database(data_file)

    assert (
        threatintel.db.delete_ips_from_ioc_ips.call_count
        == expected_delete_ips_calls
    )
    assert (
        threatintel.db.delete_domains_from_ioc_domains.call_count
        == expected_delete_domains_calls
    )


@pytest.mark.parametrize(
    "current_hash, old_hash, expected_return",
    [
        ("111", "222", "111"),
        ("111", "111", False),
        (False, "222", False),
    ],
)
def test_should_update_local_ti_file(
    current_hash,
    old_hash,
    expected_return,
    mocker,
):
    """
    Test the logic for updating local threat
    intelligence files based on hash comparison.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    own_malicious_iocs = os.path.join(
        threatintel.path_to_local_ti_files, "own_malicious_iocs.csv"
    )
    mock_hash = mocker.patch(
        "slips_files.common.slips_utils.Utils.get_sha256_hash_of_file_contents"
    )
    mock_hash.return_value = current_hash
    threatintel.db.get_ti_feed_info.return_value = {"hash": old_hash}

    assert (
        threatintel.should_update_local_ti_file(own_malicious_iocs)
        == expected_return
    )


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("example.local", True),
        ("test.arpa", True),
        ("malicious.com", None),
    ],
)
def test_is_ignored_domain(domain, expected):
    """Test `is_ignored_domain` for filtering out irrelevant domains."""
    threatintel = ModuleFactory().create_threatintel_obj()
    assert threatintel.is_ignored_domain(domain) is expected


@pytest.mark.parametrize(
    "file_info, expected_description, expected_threat_level, expected_confidence",
    [
        # Test case 1: Standard malicious file detection
        (
            {
                "flow": {
                    "saddr": "10.0.0.1",
                    "daddr": "192.168.1.1",
                    "md5": "1234567890abcdef1234567890abcdef",
                    "size": 1024,
                    "uid": "uid123",
                    "starttime": "2023-11-28 12:00:00",
                },
                "profileid": "profile_10.0.0.1",
                "twid": "timewindow1",
                "threat_level": 0.8,
                "confidence": 0.9,
                "blacklist": "VirusTotal",
            },
            (
                "Malicious downloaded file 1234567890abcdef1234567890abcdef. "
                "size: 1024 bytes. File was downloaded from server: 10.0.0.1. "
                "Detected by: VirusTotal. Confidence: 0.9. "
            ),
            ThreatLevel.HIGH,
            0.9,
        ),
        # Test case 2: Low threat level detection
        (
            {
                "flow": {
                    "saddr": "8.8.8.8",
                    "daddr": "192.168.1.2",
                    "md5": "abcdef0123456789abcdef0123456789",
                    "size": 512,
                    "uid": "uid456",
                    "starttime": "2023-11-29 08:00:00",
                },
                "profileid": "profile_8.8.8.8",
                "twid": "timewindow2",
                "threat_level": 0.2,
                "confidence": 0.5,
                "blacklist": "Example Blacklist",
            },
            (
                "Malicious downloaded file abcdef0123456789abcdef0123456789. "
                "size: 512 bytes. File was downloaded from server: 8.8.8.8. "
                "Detected by: Example Blacklist. Confidence: 0.5. "
            ),
            ThreatLevel.LOW,
            0.5,
        ),
    ],
)
def test_set_evidence_malicious_hash(
    file_info,
    expected_description,
    expected_threat_level,
    expected_confidence,
):
    """
    test for `set_evidence_malicious_hash`,
    covering different threat levels,
    confidence scores, and blacklist sources.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    threatintel.db.get_ip_identification.return_value = (
        " (Organization: Example Org)"
    )
    threatintel.set_evidence_malicious_hash(file_info)
    call_args = threatintel.db.set_evidence.call_args_list
    for call in call_args:
        evidence = call[0][0]
        assert expected_description in evidence.description
        assert evidence.threat_level == expected_threat_level
        assert evidence.confidence == expected_confidence


@pytest.mark.parametrize(
    "circl_lu_return, urlhaus_lookup_return, expected_result",
    [  # Testcase1: Circl.lu response
        (
            {"confidence": 0.8, "threat_level": 0.6, "blacklist": "CIRCL"},
            None,
            {"confidence": 0.8, "threat_level": 0.6, "blacklist": "CIRCL"},
        ),
        # Testcase2: URLhaus response
        (
            None,
            {"confidence": 0.9, "threat_level": 0.7, "blacklist": "URLhaus"},
            {"confidence": 0.9, "threat_level": 0.7, "blacklist": "URLhaus"},
        ),
        # Testcase3: No results
        (None, None, None),
    ],
)
def test_search_online_for_hash(
    mocker, circl_lu_return, urlhaus_lookup_return, expected_result
):
    """
    Test `search_online_for_hash` for querying
    online threat intelligence sources.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    threatintel.urlhaus.lookup = Mock(return_value=urlhaus_lookup_return)
    threatintel.circllu.lookup = Mock(return_value=circl_lu_return)
    flow_info = {
        "flow": {"md5": "1234567890abcdef1234567890abcdef"},
        "type": "zeek",
        "profileid": "profile_10.0.0.1",
        "twid": "timewindow1",
    }
    result = threatintel.search_online_for_hash(flow_info)
    assert result == expected_result


@pytest.mark.parametrize(
    "ip_address, mock_return_value, expected_result",
    [
        (
            "192.168.1.1",
            '{"description": "Malicious IP"}',
            json.dumps({"description": "Malicious IP"}),
        ),
        ("10.0.0.1", None, None),
    ],
)
def test_search_offline_for_ip(ip_address, mock_return_value, expected_result):
    """Test `search_offline_for_ip` for querying local
    threat intelligence data."""
    threatintel = ModuleFactory().create_threatintel_obj()
    threatintel.db.is_blacklisted_ip.return_value = mock_return_value
    result = threatintel.search_offline_for_ip(ip_address)
    assert result == expected_result


@pytest.mark.parametrize(
    "ip, ip_type, in_blacklist, expected_result",
    [
        # Testcase 1:ipv4 in blacklist
        ("192.168.1.1", "ipv4", True, True),
        # Testcase 2: ipv6 in blacklist
        ("2001:db8::", "ipv6", False, False),
        # Testcase 3: ipv6 not in blacklist
        ("2001:db8:1::1", "ipv6", False, False),
        # Testcase 4: invalid ip
        ("10.0.0.21", "invalid", False, False),
        # Testcase 5: ipv6 range not in cache
        ("2001:db8::", "ipv6", False, False),
        # Testcase 6: invalid ip range not in cache
        ("10.0.0.21", "invalid", False, False),
    ],
)
def test_ip_belongs_to_blacklisted_range(
    mocker, ip, ip_type, in_blacklist, expected_result
):
    """Test `ip_belongs_to_blacklisted_range`
    for checking malicious IP ranges."""
    threatintel = ModuleFactory().create_threatintel_obj()
    first_octet = str(
        ipaddress.ip_address(ip).exploded.split("/")[0].split(".")[0]
        if ip_type == "ipv4"
        else ipaddress.ip_address(ip).exploded.split("/")[0].split(":")[0]
    )

    range_value = (
        f"{first_octet}.0.0.0/8"
        if ip_type == "ipv4"
        else f"{first_octet}::/32"
    )
    threatintel.cached_ipv4_ranges = (
        {first_octet: [range_value]} if ip_type == "ipv4" else {}
    )
    threatintel.cached_ipv6_ranges = (
        {first_octet: [range_value]} if ip_type == "ipv6" else {}
    )
    threatintel.db.get_all_blacklisted_ip_ranges.return_value = (
        {
            range_value: '{"description": "Bad range", "source": "Example Source", "threat_level": "high"}'
        }
        if in_blacklist
        else {}
    )

    result = threatintel.ip_belongs_to_blacklisted_range(
        ip,
        "uid123",
        "10.0.0.1",
        "2023-11-28 12:00:00",
        "profile_10.0.0.1",
        "timewindow1",
        "srcip",
    )
    assert result is expected_result


@pytest.mark.parametrize(
    "url, mock_return_value, expected_result",
    [
        (
            "https://example.com",
            {"description": "Malicious URL"},
            {"description": "Malicious URL"},
        ),
        ("https://safe.com", None, None),
    ],
)
def test_search_online_for_url(
    mocker, url, mock_return_value, expected_result
):
    """Test `search_online_for_url` for
    querying online threat intelligence sources."""
    threatintel = ModuleFactory().create_threatintel_obj()
    mock_urlhaus_lookup = mocker.patch.object(threatintel.urlhaus, "lookup")
    mock_urlhaus_lookup.return_value = mock_return_value
    result = threatintel.search_online_for_url(url)
    assert result == expected_result


@pytest.mark.parametrize(
    "domain, mock_return_value, expected_result",
    [
        (
            "example.com",
            ({"description": "Malicious domain"}, False),
            ({"description": "Malicious domain"}, False),
        ),
        ("safe.com", ({}, False), (None, False)),
    ],
)
def test_search_offline_for_domain(
    mocker, domain, mock_return_value, expected_result
):
    """Test `search_offline_for_domain` for checking domain blacklisting."""
    threatintel = ModuleFactory().create_threatintel_obj()

    threatintel.db = mocker.patch.object(threatintel, "db")
    threatintel.db.is_blacklisted_domain.return_value = mock_return_value
    result = threatintel.search_offline_for_domain(domain)
    assert result == expected_result


@pytest.mark.parametrize(
    "cname, dns_query, is_subdomain, cname_info, "
    "expected_call_count, expected_confidence, expected_description",
    [
        # Test Case 1: Malicious CNAME, not a subdomain
        (
            "evil.com",
            "example.com",
            False,
            {
                "description": "Malicious CNAME",
                "source": "TI Feed",
                "threat_level": "high",
                "tags": "spam, phishing",
            },
            1,
            1.0,
            "blacklisted CNAME: evil.com when resolving example.com Description: Malicious CNAME, "
            "Found in feed: TI Feed, Confidence: 1 with tags: spam, phishing. ",  # Fixed here!
        ),
        # Test Case 2: Malicious CNAME, is a subdomain
        (
            "sub.evil.com",
            "example.com",
            True,
            {
                "description": "Malicious CNAME",
                "source": "TI Feed",
                "threat_level": "high",
                "tags": "spam, phishing",
            },
            1,
            0.7,
            "blacklisted CNAME: sub.evil.com when resolving example.com Description: Malicious CNAME, "
            "Found in feed: TI Feed, Confidence: 0.7 with tags: spam, phishing. ",
        ),
        # Test Case 3: No CNAME info
        ("noinfo.com", "example.com", False, None, 0, 1.0, None),
    ],
)
def test_set_evidence_malicious_cname_in_dns_response(
    cname,
    dns_query,
    is_subdomain,
    cname_info,
    expected_call_count,
    expected_confidence,
    expected_description,
):
    """Test `set_evidence_malicious_cname_in_dns_response`
    for recording evidence of malicious CNAMEs."""
    threatintel = ModuleFactory().create_threatintel_obj()

    threatintel.set_evidence_malicious_cname_in_dns_response(
        cname=cname,
        dns_query=dns_query,
        uid="uid123",
        timestamp="2023-11-28 12:00:00",
        cname_info=cname_info,
        is_subdomain=is_subdomain,
        profileid="profile_10.0.0.1",
        twid="timewindow1",
    )

    assert threatintel.db.set_evidence.call_count == expected_call_count

    if expected_call_count > 0:
        call_args = threatintel.db.set_evidence.call_args[0][0]
        assert call_args.description == expected_description
        assert call_args.confidence == expected_confidence


def test_pre_main(mocker):
    """Test `pre_main` for initializing the module."""
    threatintel = ModuleFactory().create_threatintel_obj()
    mocker.patch.object(threatintel, "update_local_file")
    threatintel.pre_main()
    assert threatintel.update_local_file.call_count == 4


@pytest.mark.parametrize(
    "ip, protocol, ip_state, expected_result",
    [
        # testcase1: loopback address
        ("127.0.0.1", "TCP", "dstip", False),
        # testcase2: private network
        ("10.0.0.1", "UDP", "srcip", False),
        # testcase3: private network
        ("172.16.0.1", "ICMP", "dstip", False),
        # testcase4: private network
        ("192.168.1.1", "HTTP", "srcip", False),
        # testcase5: outgoing ICMP packet
        ("1.2.3.4", "ICMP", "dstip", False),
        # testcase6: incoming ICMP packet
        ("8.8.8.8", "ICMP", "srcip", True),
        # testcase7: incoming ICMP packet on private network
        ("192.168.1.1", "ICMP", "srcip", False),
    ],
)
def test_should_lookup(ip, protocol, ip_state, expected_result):
    """
    Test `should_lookup` for various IP addresses, protocols, and states.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    assert threatintel.should_lookup(ip, protocol, ip_state) == expected_result


@pytest.mark.parametrize(
    "cname, is_domain_malicious_return, expected_result",
    [
        (
            "evil.com",
            {"description": "Malicious domain", "source": "test_source"},
            None,
        ),
        ("safe.com", {}, False),
        ("safe.com", False, False),
    ],
)
def test_is_malicious_cname(
    mocker, cname, is_domain_malicious_return, expected_result
):
    """
    Test `is_malicious_cname` for various CNAME scenarios.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    threatintel.db = mocker.patch.object(threatintel, "db")
    threatintel.db.is_blacklisted_domain.return_value = (
        is_domain_malicious_return,
        False,
    )

    result = threatintel.is_malicious_cname(
        "example.com",
        cname,
        "uid123",
        "2023-11-28 12:00:00",
        "profile_10.0.0.1",
        "timewindow1",
    )
    assert result == expected_result


@pytest.mark.parametrize(
    "cname",
    [
        "local.domain",
        "another_ignored.com",
    ],
)
def test_is_malicious_cname_ignored_cname(mocker, cname):
    """
    Test `is_malicious_cname` for ignored CNAME scenarios.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    mocker.patch.object(threatintel, "is_ignored_domain", return_value=True)

    result = threatintel.is_malicious_cname(
        "example.com",
        cname,
        "uid123",
        "2023-11-28 12:00:00",
        "profile_10.0.0.1",
        "timewindow1",
    )
    assert result is False


@pytest.mark.parametrize(
    "offline_result, online_result, expected_result",
    [  # testcase1: Offline hit
        (
            {"description": "Malicious IP", "source": "test_source"},
            None,
            True,
        ),
        # testcase2: Online hit
        (
            None,
            {"description": "Malicious IP", "source": "test_source"},
            True,
        ),
        # testcase3: No hit
        (None, None, False),
    ],
)
def test_is_malicious_ip(offline_result, online_result, expected_result):
    """Test `is_malicious_ip` for checking IP blacklisting."""
    threatintel = ModuleFactory().create_threatintel_obj()
    with patch(
        "modules.threat_intelligence.threat_intelligence.ThreatIntel.search_offline_for_ip",
        return_value=offline_result,
    ), patch(
        "modules.threat_intelligence.threat_intelligence.ThreatIntel.search_online_for_ip",
        return_value=online_result,
    ):
        result = threatintel.is_malicious_ip(
            "192.168.1.1",
            "uid123",
            "10.0.0.1",
            "2023-11-28 12:00:00",
            "profile_10.0.0.1",
            "timewindow1",
            "srcip",
        )
        assert result == expected_result


@pytest.mark.parametrize(
    "ip_address, mock_return_value, expected_result",
    [
        ("1.2.3.4", {"description": "Spam IP"}, {"description": "Spam IP"}),
        ("10.0.0.1", None, None),
    ],
)
@patch("modules.threat_intelligence.spamhaus.Spamhaus.query")
def test_search_online_for_ip(
    mock_spamhaus, ip_address, mock_return_value, expected_result
):
    """Test `search_online_for_ip` for querying online threat intelligence sources."""
    mock_spamhaus.return_value = mock_return_value
    threatintel = ModuleFactory().create_threatintel_obj()
    threatintel.is_inbound_traffic = Mock()
    threatintel.is_inbound_traffic.return_value = True
    result = threatintel.search_online_for_ip(ip_address, "dstip")
    assert result == expected_result


# External function to mock `is_global` behavior with an IP parameter
def mock_is_global(self, ip: str):
    # Check if the current IP matches the one we are passing as a parameter
    if str(self) == ip:
        return False  # Mock it to return False for the specified IP
    return self.is_global  # Otherwise, return the default behavior


@pytest.mark.parametrize(
    "ip, ip_state, is_global, expected",
    [
        # ("8.8.8.8", "src", True, True),  # Valid inbound traffic
        # ("192.168.1.2", "src", False, False),  # Not global
        # ("192.168.1.1", "src", True, False),  # Host IP
        ("192.168.1.10", "src", True, False),  # Client IP
        #         ("8.8.8.8", "dst", True, False),  # We are connecting to it,
        #         # not inboud
    ],
)
def test_is_inbound_traffic(ip, ip_state, is_global, expected):
    threatintel = ModuleFactory().create_threatintel_obj()
    threatintel.db.get_host_ip = Mock(return_value="192.168.1.1")
    client_ips = ["192.168.1.10", "10.0.0.1"]
    threatintel.client_ips = [ipaddress.ip_address(ip) for ip in client_ips]
    with patch.object(
        ipaddress.IPv4Address,
        "is_global",
        lambda self: mock_is_global(self, ip),
    ):
        result = threatintel.is_inbound_traffic(ip, ip_state)
    assert result == expected


@pytest.mark.parametrize(
    "domain, result, is_malicious",
    [
        ("example.com", {"description": "Malicious domain"}, True),
        ("safe.com", None, False),
    ],
)
def test_is_malicious_domain(domain, result, is_malicious, mocker):
    """
    Test `is_malicious_domain` for identifying
    and recording evidence of malicious domains.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    mock_search_offline_for_domain = mocker.patch.object(
        threatintel, "search_offline_for_domain"
    )
    mock_set_evidence_malicious_domain = mocker.patch.object(
        threatintel, "set_evidence_malicious_domain"
    )

    mock_search_offline_for_domain.return_value = (result, False)
    threatintel.is_malicious_domain(
        domain,
        "uid123",
        "2023-11-28 12:00:00",
        "profile_10.0.0.1",
        "timewindow1",
    )

    assert mock_set_evidence_malicious_domain.called == is_malicious

    mock_search_offline_for_domain.reset_mock()
    mock_set_evidence_malicious_domain.reset_mock()


@pytest.mark.parametrize(
    "search_online_result, expected_set_evidence_call",
    [
        # Testcase1:for a malicious hash found
        (
            {
                "confidence": 0.8,
                "threat_level": 0.6,
                "blacklist": "CIRCL",
            },
            True,
        ),
        # Testcase2:for a non-malicious hash
        (None, False),
    ],
)
def test_is_malicious_hash(
    mocker, search_online_result, expected_set_evidence_call
):
    """
    Test `is_malicious_hash` for identifying and
    recording evidence of malicious file hashes.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    threatintel.db.is_known_fp_md5_hash.return_value = False
    mock_search_online_for_hash = mocker.patch.object(
        threatintel, "search_online_for_hash"
    )

    flow_info = {
        "flow": {
            "md5": "1234567890abcdef1234567890abcdef",
            "saddr": "10.0.0.1",
            "daddr": "192.168.1.1",
            "size": 1024,
            "starttime": "2023-11-28 12:00:00",
            "uid": "uid123",
        },
        "type": "zeek",
        "profileid": "profile_10.0.0.1",
        "twid": "timewindow1",
    }
    mock_search_online_for_hash.return_value = search_online_result

    threatintel.is_malicious_hash(flow_info)

    assert threatintel.db.set_evidence.called == expected_set_evidence_call


def test_is_malicious_hash_known_fp_md5():
    threatintel = ModuleFactory().create_threatintel_obj()
    threatintel.db.is_known_fp_md5_hash.return_value = True
    flow = {"flow": {"md5": "c0eec84d09bbb7f4cd1a8896f9dff718"}}
    assert threatintel.is_malicious_hash(flow) is None


@pytest.mark.parametrize(
    "url, result, is_malicious",
    [
        ("http://malicious.com", {"description": "Malicious URL"}, True),
        ("http://safe.com", None, False),
    ],
)
def test_is_malicious_url(url, result, is_malicious, mocker):
    """
    Test `is_malicious_url` for correctly handling
    both malicious and non-malicious URLs.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    mock_search_online_for_url = mocker.patch.object(
        threatintel, "search_online_for_url"
    )
    mock_urlhaus_set_evidence = mocker.patch.object(
        threatintel.urlhaus, "set_evidence_malicious_url"
    )

    mock_search_online_for_url.return_value = result
    threatintel.is_malicious_url(
        url,
        "uid123",
        "2023-11-28 12:00:00",
        "192.168.1.1",
        "profile_10.0.0.1",
        "timewindow1",
    )

    assert mock_urlhaus_set_evidence.called == is_malicious

    mock_search_online_for_url.reset_mock()
    mock_urlhaus_set_evidence.reset_mock()


@pytest.mark.parametrize(
    "msg_data, expected_call",
    [
        # Test Case 1: Malicious CNAME in DNS response
        (
            {
                "profileid": "profile_10.0.0.1",
                "twid": "timewindow1",
                "stime": "2023-11-28 12:00:00",
                "uid": "uid123",
                "proto": "UDP",
                "daddr": "8.8.8.8",
                "is_dns_response": True,
                "dns_query": "example.com",
                "to_lookup": "evil.com",
                "type": "domain",
            },
            "is_malicious_cname",
        ),
        # Test Case 2: Malicious domain in direct query
        (
            {
                "profileid": "profile_10.0.0.1",
                "twid": "timewindow1",
                "stime": "2023-11-28 12:00:00",
                "uid": "uid123",
                "proto": "TCP",
                "daddr": "192.168.1.1",
                "to_lookup": "malicious.com",
                "type": "domain",
            },
            "is_malicious_domain",
        ),
    ],
)
def test_main_domain_lookup(mocker, msg_data, expected_call):
    """
    Test the `main` function's handling of domain name lookups,
    covering scenarios with DNS responses and direct domain queries.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    mock_call = mocker.patch.object(threatintel, expected_call)
    mock_get_msg = mocker.patch.object(threatintel, "get_msg")
    mock_get_msg.return_value = {"data": json.dumps(msg_data)}

    threatintel.main()

    mock_call.assert_called_once()


def test_main_empty_message(mocker):
    """
    Test the `main` function's behavior when receiving an empty message,
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    mock_get_msg = mocker.patch.object(threatintel, "get_msg")
    mock_get_msg.return_value = None
    threatintel.main()


def test_main_file_hash_lookup(mocker):
    """
    Test the `main` function's handling of file hash lookups,
    verifying it calls the appropriate malicious hash checks.
    """
    threatintel = ModuleFactory().create_threatintel_obj()

    mock_is_malicious_hash = mocker.patch.object(
        threatintel, "is_malicious_hash"
    )
    mock_get_msg = mocker.patch.object(threatintel, "get_msg")
    mock_get_msg.return_value = {
        "data": json.dumps(
            {
                "flow": {
                    "md5": "1234567890abcdef1234567890abcdef",
                    "saddr": "10.0.0.1",
                    "daddr": "192.168.1.1",
                    "size": 1024,
                    "starttime": "2023-11-28 12:00:00",
                    "uid": "uid123",
                },
                "type": "zeek",
                "profileid": "profile_10.0.0.1",
                "twid": "timewindow1",
            }
        )
    }
    threatintel.main()
    mock_is_malicious_hash.assert_called_once()


@pytest.mark.parametrize(
    "ip_address, is_malicious, should_lookup_return, expected_calls",
    [  # testcase1: Malicious IP
        (
            "1.2.3.4",
            True,
            True,
            {
                "is_malicious_ip": 1,
                "ip_belongs_to_blacklisted_range": 1,
                "ip_has_blacklisted_asn": 1,
            },
        ),
        # testcase2: Non-malicious IP
        (
            "10.0.0.1",
            False,
            False,
            {
                "is_malicious_ip": 0,
                "ip_belongs_to_blacklisted_range": 0,
                "ip_has_blacklisted_asn": 0,
            },
        ),
        # Testcase3: Non-malicious IP
        (
            "8.8.8.8",
            False,
            True,
            {
                "is_malicious_ip": 1,
                "ip_belongs_to_blacklisted_range": 1,
                "ip_has_blacklisted_asn": 1,
            },
        ),
    ],
)
def test_main_ip_lookup(
    mocker,
    ip_address,
    is_malicious,
    should_lookup_return,
    expected_calls,
):
    """
    Test the main function's handling of IP address lookups.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    mock_is_malicious_ip = mocker.patch.object(
        threatintel, "is_malicious_ip", return_value=is_malicious
    )
    mock_ip_belongs_to_blacklisted_range = mocker.patch.object(
        threatintel, "ip_belongs_to_blacklisted_range"
    )
    mock_ip_has_blacklisted_asn = mocker.patch.object(
        threatintel, "ip_has_blacklisted_asn"
    )
    mock_get_msg = mocker.patch.object(threatintel, "get_msg")

    mocker.patch.object(
        threatintel, "should_lookup", return_value=should_lookup_return
    )

    mock_get_msg.return_value = {
        "data": json.dumps(
            {
                "profileid": "profile_10.0.0.1",
                "twid": "timewindow1",
                "stime": "2023-11-28 12:00:00",
                "uid": "uid123",
                "proto": "TCP",
                "daddr": "192.168.1.1",
                "to_lookup": ip_address,
                "type": "ip",
                "ip_state": "srcip",
            }
        )
    }

    threatintel.main()

    assert mock_is_malicious_ip.call_count == (
        expected_calls["is_malicious_ip"]
    )
    assert mock_ip_belongs_to_blacklisted_range.call_count == (
        expected_calls["ip_belongs_to_blacklisted_range"]
    )
    assert mock_ip_has_blacklisted_asn.call_count == (
        expected_calls["ip_has_blacklisted_asn"]
    )


@pytest.mark.parametrize(
    "filename, expected_parse_function",
    [
        ("own_malicious_JA3.csv", "parse_ja3_file"),
        ("own_malicious_JARM.csv", "parse_jarm_file"),
        ("own_malicious_iocs.csv", "parse_local_ti_file"),
    ],
)
def test_update_local_file_parse_function(
    filename, expected_parse_function, mocker
):
    """
    Test `update_local_file` to ensure the correct parsing function
    is called based on the filename.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    mocker.patch.object(
        threatintel, "should_update_local_ti_file", return_value="new_hash"
    )
    mock_parse_function = mocker.patch.object(
        threatintel, expected_parse_function, return_value=True
    )

    threatintel.update_local_file(filename)

    assert mock_parse_function.called


@pytest.mark.parametrize(
    "ip_address, asn, asn_info, expected_call_count",
    [
        # testcase1: Blacklisted ASN
        (
            "1.1.1.1",
            "12345",
            json.dumps(
                {
                    "description": "Test Description",
                    "source": "Test Source",
                    "threat_level": "high",
                }
            ),
            2,
        ),
        # testcase2:Non-blacklisted ASN
        ("8.8.8.8", "15169", None, 0),
    ],
)
def test_ip_has_blacklisted_asn(
    ip_address, asn, asn_info, expected_call_count
):
    """
    Test `ip_has_blacklisted_asn` for both blacklisted and
    non-blacklisted ASNs.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    uid = "test_uid"
    timestamp = "2023-10-26 10:00:00"
    profileid = "profile_127.0.0.1"
    twid = "timewindow1"
    threatintel.db.get_ip_info.return_value = {"asn": {"number": asn}}
    threatintel.db.is_blacklisted_asn.return_value = asn_info
    threatintel.ip_has_blacklisted_asn(
        ip_address, uid, timestamp, profileid, twid
    )
    assert threatintel.db.set_evidence.call_count == expected_call_count


@pytest.mark.parametrize(
    "domain, uid, timestamp, domain_info, is_subdomain, profileid, twid, expected_evidence_count",
    [
        # TestCase 1: Malicious domain with resolution
        (
            "evil.com",
            "uid123",
            "2023-11-28 12:00:00",
            {
                "description": "Malicious Domain",
                "source": "TI Feed",
                "threat_level": "high",
            },
            False,
            "profile_10.0.0.1",
            "timewindow1",
            2,
        ),
        # TestCase 2: Malicious subdomain with resolution
        (
            "sub.evil.com",
            "uid456",
            "2023-11-29 13:00:00",
            {
                "description": "Malicious Subdomain",
                "source": "TI Feed",
                "threat_level": "medium",
            },
            True,
            "profile_10.0.0.2",
            "timewindow2",
            2,
        ),
        # TestCase 3: Malicious domain without resolution
        (
            "noresolve.com",
            "uid789",
            "2023-11-30 14:00:00",
            {
                "description": "No Resolution Domain",
                "source": "TI Feed",
                "threat_level": "low",
            },
            False,
            "profile_10.0.0.3",
            "timewindow3",
            1,
        ),
        # Test Case 4: No domain info, evidence should not be set
        (
            "noinfo.com",
            "uid901",
            "2023-12-01 15:00:00",
            None,
            False,
            "profile_10.0.0.4",
            "timewindow4",
            0,
        ),
    ],
)
def test_set_evidence_malicious_domain(
    domain,
    uid,
    timestamp,
    domain_info,
    is_subdomain,
    profileid,
    twid,
    expected_evidence_count,
):
    """
    Test `set_evidence_malicious_domain` with various scenarios.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    threatintel.db.get_domain_resolution.return_value = (
        ["192.168.1.1"] if domain != "noresolve.com" else []
    )

    threatintel.set_evidence_malicious_domain(
        domain=domain,
        uid=uid,
        timestamp=timestamp,
        domain_info=domain_info,
        is_subdomain=is_subdomain,
        profileid=profileid,
        twid=twid,
    )

    assert threatintel.db.set_evidence.call_count == expected_evidence_count


@pytest.mark.parametrize(
    "ip, uid, timestamp, ip_info, dns_query, profileid, "
    "twid, expected_description, expected_threat_level",
    [
        # TestCase 1: Medium threat level in DNS response
        (
            "192.168.1.1",
            "uid123",
            "2023-11-28 12:00:00",
            {
                "description": "Malicious IP",
                "source": "TI Feed",
                "threat_level": "medium",
            },
            "example.com",
            "profile_10.0.0.1",
            "timewindow1",
            (
                "DNS answer with a blacklisted IP: 192.168.1.1 for query: "
                "example.com Description: Malicious IP Source: TI Feed."
            ),
            ThreatLevel.MEDIUM,
        ),
        # Test Case 2: High threat level IP in DNS response
        (
            "192.168.1.2",
            "uid456",
            "2023-11-29 13:00:00",
            {
                "description": "Another Malicious IP",
                "source": "Different Feed",
                "threat_level": "high",
            },
            "test.com",
            "profile_10.0.0.2",
            "timewindow2",
            (
                "DNS answer with a blacklisted IP: 192.168.1.2 for query: "
                "test.com "
                "Description: Another Malicious IP Source: Different Feed."
            ),
            ThreatLevel.HIGH,
        ),
        # Test Case 3: Low threat level IP in DNS response
        (
            "192.168.1.3",
            "uid789",
            "2023-11-30 14:00:00",
            {
                "description": "Yet Another Malicious IP",
                "source": "Another Feed",
                "threat_level": "low",
            },
            "domain.com",
            "profile_10.0.0.3",
            "timewindow3",
            (
                "DNS answer with a blacklisted IP: 192.168.1.3 for query: "
                "domain.com "
                "Description: Yet Another Malicious IP Source: Another Feed."
            ),
            ThreatLevel.LOW,
        ),
    ],
)
def test_set_evidence_malicious_ip_in_dns_response(
    ip,
    uid,
    timestamp,
    ip_info,
    dns_query,
    profileid,
    twid,
    expected_description,
    expected_threat_level,
):
    """
    Test `set_evidence_malicious_ip_in_dns_response` for recording evidence of
    malicious IPs received in DNS responses.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    threatintel.db.get_ip_identification.return_value = (
        " (Organization: Example Org)"
    )
    threatintel.set_evidence_malicious_ip_in_dns_response(
        ip=ip,
        uid=uid,
        timestamp=timestamp,
        ip_info=ip_info,
        dns_query=dns_query,
        profileid=profileid,
        twid=twid,
    )
    call_args_list = threatintel.db.set_evidence.call_args_list
    for call_args in call_args_list:
        evidence = call_args[0][0]
        assert expected_description in evidence.description
        assert evidence.threat_level == expected_threat_level

    assert threatintel.db.set_ip_info.call_count == 1


def test_read_configuration(mocker):
    """
    Test `__read_configuration` to verify it correctly
    reads configuration settings.
    """
    threatintel = ModuleFactory().create_threatintel_obj()
    with patch(
        "modules.threat_intelligence.threat_intelligence.ConfigParser"
    ) as MockConfigParser:
        MockConfigParser.return_value.local_ti_data_path.return_value = (
            "/tmp/slips/local_ti_files"
        )
        mocker.patch("os.path.exists", return_value=False)
        mocker.patch("os.mkdir")
        threatintel._ThreatIntel__read_configuration()
        assert (
            MockConfigParser.return_value.local_ti_data_path.return_value
            == "/tmp/slips/local_ti_files"
        )
        MockConfigParser.return_value.local_ti_data_path.assert_called_once()
        os.mkdir.assert_called_once_with("/tmp/slips/local_ti_files")
