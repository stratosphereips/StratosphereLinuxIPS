"""Unit test for modules/threat_intelligence/threat_intelligence.py"""

from tests.module_factory import ModuleFactory
import os
import pytest
import json
from unittest.mock import MagicMock, patch
from modules.threat_intelligence.threat_intelligence import ThreatIntel
import ipaddress


@pytest.fixture
def threatintel_obj(mock_db, tmp_path):
    """Fixture to create a ThreatIntel object with mocked dependencies."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    threatintel = ThreatIntel(
        mock_db, output_dir=output_dir, redis_port=6379, termination_event=None
    )
    threatintel.init()
    return threatintel


def test_parse_local_ti_file(mock_db):
    """
    Test parsing of a local threat intelligence file.

    Ensures that the `parse_local_ti_file` method successfully parses known threat
    intelligence entries from "own_malicious_iocs.csv" and properly integrates
    them into the system.

    Args:
        mock_db: A fixture or mock representing the database to prevent actual
                 database modifications during testing.
    """
    threatintel = ModuleFactory().create_threatintel_obj(mock_db)
    local_ti_files_dir = threatintel.path_to_local_ti_files
    local_ti_file = os.path.join(local_ti_files_dir, "own_malicious_iocs.csv")
    # this is an ip we know we have in own_malicious_iocs.csv
    assert threatintel.parse_local_ti_file(local_ti_file) is True


def test_parse_ja3_file(mock_db):
    """
    Test parsing of a JA3 hash file.

    Validates that the `parse_ja3_file` method can accurately process and store
    entries from "own_malicious_JA3.csv" containing JA3 hashes and associated
    threat levels and descriptions.

    Args:
        mock_db: A mock database object to intercept database calls for isolation.
    """
    threatintel = ModuleFactory().create_threatintel_obj(mock_db)
    local_ja3_file_dir = threatintel.path_to_local_ti_files
    local_ja3_file = os.path.join(local_ja3_file_dir, "own_malicious_JA3.csv")

    assert threatintel.parse_ja3_file(local_ja3_file) is True


def test_parse_jarm_file(mock_db):
    """
    Test parsing of a JARM hash file.

    Confirms that the `parse_jarm_file` method is capable of interpreting and storing
    data from "own_malicious_JARM.csv", which includes JARM hashes along with their
    threat assessments and descriptions.

    Args:
        mock_db: A mock database object used to verify interactions without affecting
                 real data.
    """
    threatintel = ModuleFactory().create_threatintel_obj(mock_db)
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
    current_hash, old_hash, expected_return, mocker, mock_db
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
        mock_db: A mock database object for simulating database interactions.
    """
    # since this is a clear db, then we should update the local ti file
    threatintel = ModuleFactory().create_threatintel_obj(mock_db)
    own_malicious_iocs = os.path.join(
        threatintel.path_to_local_ti_files, "own_malicious_iocs.csv"
    )

    mock_hash = mocker.patch(
        "slips_files.common.slips_utils.Utils.get_hash_from_file"
    )

    mock_hash.return_value = current_hash

    mock_db.get_TI_file_info.return_value = {"hash": old_hash}

    # the test asserts return value of should_update_local_tii_file matches expected_return
    # for each scenario. This method should return new hash if an update is needed or False if not
    assert (
        threatintel.should_update_local_ti_file(own_malicious_iocs)
        == expected_return
    )


def test_create_circl_lu_session(mock_db):
    """
    Test the creation of a session for Circl.lu API requests.
    """
    threatintel = ModuleFactory().create_threatintel_obj(mock_db)
    threatintel.create_circl_lu_session()
    assert threatintel.circl_session.verify is True
    assert threatintel.circl_session.headers == {"accept": "application/json"}


def test_get_malicious_ip_ranges(mock_db):
    """
    Test the retrieval and caching of malicious IP ranges from the database.
    """
    threatintel = ModuleFactory().create_threatintel_obj(mock_db)
    mock_ip_ranges = {
        "192.168.1.0/24": '{"description": "Example range", "source": "local_file", "threat_level": "high"}',
        "10.0.0.0/16": '{"description": "Another range", "source": "remote_feed", "threat_level": "medium"}',
        "2001:db8::/64": '{"description": "IPv6 range", "source": "custom", "threat_level": "low"}',
    }
    mock_db.get_malicious_ip_ranges.return_value = mock_ip_ranges
    threatintel.get_malicious_ip_ranges()
    assert threatintel.cached_ipv4_ranges == {
        "192": ["192.168.1.0/24"],
        "10": ["10.0.0.0/16"],
    }
    assert threatintel.cached_ipv6_ranges == {"2001": ["2001:db8::/64"]}


def test_set_evidence_malicious_asn(threatintel_obj, mocker):
    """
    Test `set_evidence_malicious_asn` for 
    setting evidence of malicious ASN interactions.
    """
    mock_db = mocker.patch.object(threatintel_obj, "db")
    mock_db.get_ip_identification.return_value = " (Organization: Example Org)"
    asn_info = {
        "description": "Malicious ASN",
        "source": "TI Feed",
        "threat_level": "high",
        "tags": "spam, botnet",
    }
    threatintel_obj.set_evidence_malicious_asn(
        daddr="192.168.1.1",
        uid="uid123",
        timestamp="2023-11-28 12:00:00",
        profileid="profile_10.0.0.1",
        twid="timewindow1",
        asn="AS1234",
        asn_info=asn_info,
    )
    mock_db.set_evidence.assert_called()


def test_set_evidence_malicious_ip(threatintel_obj, mocker):
    """
    Test `set_evidence_malicious_ip` for 
    recording evidence of traffic with malicious IPs.
    """
    mock_db = mocker.patch.object(threatintel_obj, "db")
    mock_db.get_ip_identification.return_value = " (Organization: Example Org)"
    ip_info = {
        "description": "Malicious IP",
        "source": "TI Feed",
        "threat_level": "high",
    }
    threatintel_obj.set_evidence_malicious_ip(
        ip="192.168.1.1",
        uid="uid123",
        daddr="10.0.0.1",
        timestamp="2023-11-28 12:00:00",
        ip_info=ip_info,
        profileid="profile_192.168.1.1",
        twid="timewindow1",
        ip_state="srcip",
    )
    mock_db.set_evidence.assert_called()
    mock_db.reset_mock()
    threatintel_obj.set_evidence_malicious_ip(
        ip="192.168.1.1",
        uid="uid123",
        daddr="10.0.0.1",
        timestamp="2023-11-28 12:00:00",
        ip_info=ip_info,
        profileid="profile_10.0.0.1",
        twid="timewindow1",
        ip_state="dstip",
    )
    mock_db.set_evidence.assert_called()


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
def test_is_valid_threat_level(threatintel_obj, threat_level, expected):
    """Test `is_valid_threat_level` for recognizing valid threat levels."""
    assert threatintel_obj.is_valid_threat_level(threat_level) is expected


@pytest.mark.parametrize(
    "protocol, ip_address, expected",
    [
        ("ICMP", "dstip", True),
        ("TCP", "dstip", False),
        ("ICMP", "srcip", False),
    ],
)
def test_is_outgoing_icmp_packet(
    threatintel_obj, protocol, ip_address, expected
):
    """Test `is_outgoing_icmp_packet` for identifying outbound ICMP packets."""
    assert (
        threatintel_obj.is_outgoing_icmp_packet(protocol, ip_address)
        is expected
    )


def test_delete_old_source_ips(threatintel_obj, mocker):
    """
    Test the `__delete_old_source_ips` 
    method for removing outdated IP IoCs.
    """
    mock_db = mocker.patch.object(threatintel_obj, "db")
    mock_db.get_IPs_in_IoC.return_value = {
        "192.168.1.1": '{"description": "Old IP", "source": "old_file.txt"}',
        "10.0.0.1": '{"description": "Current IP", "source": "current_file.txt"}',
    }
    threatintel_obj._ThreatIntel__delete_old_source_ips("old_file.txt")
    mock_db.delete_ips_from_IoC_ips.assert_called_once_with(["192.168.1.1"])


def test_delete_old_source_domains(threatintel_obj, mocker):
    """
    Test the `__delete_old_source_domains`
    method for removing outdated domain IoCs.
    """
    mock_db = mocker.patch.object(threatintel_obj, "db")
    mock_db.get_Domains_in_IoC.return_value = {
        "example.com": '{"description": "Old domain", "source": "old_file.txt"}',
        "current.com": '{"description": "Current domain", "source": "current_file.txt"}',
    }
    threatintel_obj._ThreatIntel__delete_old_source_domains("old_file.txt")
    mock_db.delete_domains_from_IoC_domains.assert_called_once_with(
        ["example.com"]
    )


def test_delete_old_source_data_from_database(threatintel_obj, mocker):
    """
    Test the `__delete_old_source_data_from_database` method for removing both
    outdated IP and domain IoCs.
    """
    mocker.patch.object(threatintel_obj, "_ThreatIntel__delete_old_source_ips")
    mocker.patch.object(
        threatintel_obj, "_ThreatIntel__delete_old_source_domains"
    )
    threatintel_obj._ThreatIntel__delete_old_source_data_from_database(
        "old_file.txt"
    )
    threatintel_obj._ThreatIntel__delete_old_source_ips.assert_called_once_with(
        "old_file.txt"
    )
    threatintel_obj._ThreatIntel__delete_old_source_domains.assert_called_once_with(
        "old_file.txt"
    )


@pytest.mark.parametrize(
    "current_hash, old_hash, expected_return, expected_calls",
    [
        (
            "111",
            "222",
            "111",
            ["_ThreatIntel__delete_old_source_data_from_database"],
        ),
        ("111", "111", False, []),
        (False, "222", False, []),
    ],
)
def test_should_update_local_ti_file(
    current_hash,
    old_hash,
    expected_return,
    expected_calls,
    mocker,
    mock_db,
):
    """
    Test the logic for updating local threat 
    intelligence files based on hash comparison.
    """
    threatintel = ModuleFactory().create_threatintel_obj(mock_db)
    own_malicious_iocs = os.path.join(
        threatintel.path_to_local_ti_files, "own_malicious_iocs.csv"
    )
    mock_hash = mocker.patch(
        "slips_files.common.slips_utils.Utils.get_hash_from_file"
    )
    mock_hash.return_value = current_hash
    mock_db.get_TI_file_info.return_value = {"hash": old_hash}

    assert (
        threatintel.should_update_local_ti_file(own_malicious_iocs)
        == expected_return
    )


def test_spamhaus(threatintel_obj, mocker):
    """
    Test the `spamhaus` method for querying Spamhaus DNSBL.
    """
    mock_resolver = mocker.patch("dns.resolver.resolve")
    mock_resolver.return_value = [
        MagicMock(to_text=lambda: "127.0.0.2"),
        MagicMock(to_text=lambda: "127.0.0.4"),
    ]
    result = threatintel_obj.spamhaus("1.2.3.4")
    assert result == {
        "source": "SBL Data, XBL CBL Data, spamhaus",
        "description": "IP address of exploited systems."
        "This includes machines operating open proxies, "
        "systems infected with trojans, and other "
        "malware vectors.",
        "threat_level": "medium",
        "tags": "spam",
    }

    mock_resolver.side_effect = Exception
    result = threatintel_obj.spamhaus("1.2.3.4")
    assert result is None


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("example.local", True),
        ("test.arpa", True),
        ("malicious.com", None),
    ],
)
def test_is_ignored_domain(threatintel_obj, domain, expected):
    """Test `is_ignored_domain` for filtering out irrelevant domains."""
    assert threatintel_obj.is_ignored_domain(domain) is expected


def test_set_evidence_malicious_hash(threatintel_obj, mocker):
    """Test `set_evidence_malicious_hash` for recording evidence of malicious files."""
    mock_db = mocker.patch.object(threatintel_obj, "db")
    mock_db.get_ip_identification.return_value = " (Organization: Example Org)"
    file_info = {
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
    }
    threatintel_obj.set_evidence_malicious_hash(file_info)
    mock_db.set_evidence.assert_called()


@pytest.mark.parametrize(
    "circl_lu_return, urlhaus_lookup_return, expected_result",
    [  # Test Circl.lu response
        (
            {"confidence": 0.8, "threat_level": 0.6, "blacklist": "CIRCL"},
            None,
            {"confidence": 0.8, "threat_level": 0.6, "blacklist": "CIRCL"},
        ),
        # Test URLhaus response
        (
            None,
            {"confidence": 0.9, "threat_level": 0.7, "blacklist": "URLhaus"},
            {"confidence": 0.9, "threat_level": 0.7, "blacklist": "URLhaus"},
        ),
        (None, None, None),  # No results
    ],
)
def test_search_online_for_hash(
    threatintel_obj,
    mocker,
    circl_lu_return,
    urlhaus_lookup_return,
    expected_result,
):
    """
    Test `search_online_for_hash` for querying 
    online threat intelligence sources.
    """
    mock_circl_lu = mocker.patch.object(threatintel_obj, "circl_lu")
    mock_urlhaus_lookup = mocker.patch.object(
        threatintel_obj.urlhaus, "urlhaus_lookup"
    )
    flow_info = {
        "flow": {"md5": "1234567890abcdef1234567890abcdef"},
        "type": "zeek",
        "profileid": "profile_10.0.0.1",
        "twid": "timewindow1",
    }

    mock_circl_lu.return_value = circl_lu_return
    mock_urlhaus_lookup.return_value = urlhaus_lookup_return
    result = threatintel_obj.search_online_for_hash(flow_info)
    assert result == expected_result


@pytest.mark.parametrize(
    "ip_address, mock_return_value, expected_result",
    [
        (
            "192.168.1.1",
            '{"description": "Malicious IP"}',
            {"description": "Malicious IP"},
        ),
        ("10.0.0.1", None, False),
    ],
)
def test_search_offline_for_ip(
    threatintel_obj, mocker, ip_address, mock_return_value, expected_result
):
    """Test `search_offline_for_ip` for querying local threat intelligence data."""
    mock_db = mocker.patch.object(threatintel_obj, "db")
    mock_db.search_IP_in_IoC.return_value = mock_return_value
    result = threatintel_obj.search_offline_for_ip(ip_address)
    assert result == expected_result


@pytest.mark.parametrize(
    "ip_address, mock_return_value, expected_result",
    [
        ("1.2.3.4", {"description": "Spam IP"}, {"description": "Spam IP"}),
        ("10.0.0.1", None, None),
    ],
)
@patch("modules.threat_intelligence.threat_intelligence.ThreatIntel.spamhaus")
def test_search_online_for_ip(
    mock_spamhaus,
    threatintel_obj,
    ip_address,
    mock_return_value,
    expected_result,
):
    """Test `search_online_for_ip` for querying online threat intelligence sources."""
    mock_spamhaus.return_value = mock_return_value
    result = threatintel_obj.search_online_for_ip(ip_address)
    assert result == expected_result


@pytest.mark.parametrize(
    "ip, ip_type, in_blacklist, expected_result",
    [  # ipv4 in blacklist
        ("192.168.1.1", "ipv4", True, True),
        # ipv6 in blacklist
        ("2001:db8::", "ipv6", False, False),
        # ipv6 not in blacklist
        ("2001:db8:1::1", "ipv6", None, None),
        # invalid ip
        ("10.0.0.21", "invalid", None, None),
        # ipv6 range not in cache
        ("2001:db8::", "ipv6", None, False),
        # invalid ip range not in cache
        ("10.0.0.21", "invalid", None, None),
    ],
)
def test_ip_belongs_to_blacklisted_range(
    threatintel_obj, mocker, ip, ip_type, 
    in_blacklist, expected_result
):
    """Test `ip_belongs_to_blacklisted_range` for checking malicious IP ranges."""
    mock_db = mocker.patch.object(threatintel_obj, "db")

    if ip_type == "ipv4":
        first_octet = str(
            ipaddress.ip_address(ip).exploded.split("/")[0].split(".")[0]
        )
        threatintel_obj.cached_ipv4_ranges = {
            first_octet: [f"{first_octet}.0.0.0/8"]
        }
        range_value = f"{first_octet}.0.0.0/8"
    elif ip_type == "ipv6":
        first_octet = str(
            ipaddress.ip_address(ip).exploded.split("/")[0].split(":")[0]
        )
        threatintel_obj.cached_ipv6_ranges = {
            first_octet: [f"{first_octet}::/32"]
        }
        range_value = f"{first_octet}::/32"
    else:
        range_value = ""

    if in_blacklist:
        mock_db.get_malicious_ip_ranges.return_value = {
            range_value: '{"description": "Bad range", "source": "Example Source", "threat_level": "high"}'
        }
    else:
        mock_db.get_malicious_ip_ranges.return_value = {}

    result = threatintel_obj.ip_belongs_to_blacklisted_range(
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
    "domain, mock_return_value, expected_result",
    [
        (
            "example.com",
            ('{"description": "Malicious domain"}', False),
            ({"description": "Malicious domain"}, False),
        ),
        ("safe.com", ("{}", False), ({}, False)),
    ],
)
def test_search_offline_for_domain(
    threatintel_obj, mocker, domain, 
    mock_return_value, expected_result
):
    """Test `search_offline_for_domain` for checking domain blacklisting."""
    mock_db = mocker.patch.object(threatintel_obj, "db")
    mock_db.is_domain_malicious.return_value = mock_return_value
    result = threatintel_obj.search_offline_for_domain(domain)
    assert result == expected_result


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
    threatintel_obj, mocker, url, 
    mock_return_value, expected_result
):
    """Test `search_online_for_url` for querying online threat intelligence sources."""
    mock_urlhaus_lookup = mocker.patch.object(
        threatintel_obj.urlhaus, "urlhaus_lookup"
    )
    mock_urlhaus_lookup.return_value = mock_return_value
    result = threatintel_obj.search_online_for_url(url)
    assert result == expected_result


def test_set_evidence_malicious_cname_in_dns_response(threatintel_obj, mocker):
    """Test `set_evidence_malicious_cname_in_dns_response` 
    for recording evidence of malicious CNAMEs."""
    mock_db = mocker.patch.object(threatintel_obj, "db")
    cname_info = {
        "description": "Malicious CNAME",
        "source": "TI Feed",
        "threat_level": "high",
    }
    threatintel_obj.set_evidence_malicious_cname_in_dns_response(
        cname="evil.com",
        dns_query="example.com",
        uid="uid123",
        timestamp="2023-11-28 12:00:00",
        cname_info=cname_info,
        is_subdomain=False,
        profileid="profile_10.0.0.1",
        twid="timewindow1",
    )
    mock_db.set_evidence.assert_called()


def test_pre_main(threatintel_obj, mocker):
    """Test `pre_main` for initializing the module."""
    mocker.patch.object(threatintel_obj, "update_local_file")
    threatintel_obj.pre_main()
    assert threatintel_obj.update_local_file.call_count == 3


@pytest.mark.parametrize(
    "ip, protocol, ip_state, expected_result",
    [
        # testcase1: loopback address
        ("127.0.0.1", "TCP", "dstip", True),
        # testcase2: private network
        ("10.0.0.1", "UDP", "srcip", True),
        # testcase3: private network
        ("172.16.0.1", "ICMP", "dstip", True),
        # testcase4: private network
        ("192.168.1.1", "HTTP", "srcip", True),
        # testcase5: outgoing ICMP packet
        ("1.2.3.4", "ICMP", "dstip", True),
        # testcase6: incoming ICMP packet
        ("8.8.8.8", "ICMP", "srcip", False),
        # testcase7: incoming ICMP packet on private network
        ("192.168.1.1", "ICMP", "srcip", True),
    ],
)
def test_should_lookup(
    threatintel_obj, ip, protocol, 
    ip_state, expected_result
):
    """
    Test `should_lookup` for various IP addresses, protocols, and states.

    Verifies that the function correctly determines whether a lookup should be performed
    based on the provided IP address, protocol, and IP state.
    """
    assert (
        threatintel_obj.should_lookup(ip, protocol, ip_state)
        == expected_result
    )


@pytest.mark.parametrize(
    "cname, is_domain_malicious_return, expected_result",
    [
        (
            "evil.com",
            json.dumps(
                {"description": "Malicious domain", "source": "test_source"}
            ),
            None,
        ),
        ("safe.com", json.dumps({}), False),
        ("safe.com", "false", False),
    ],
)
def test_is_malicious_cname(
    threatintel_obj, mocker, cname, 
    is_domain_malicious_return, 
    expected_result
):
    """
    Test `is_malicious_cname` for various CNAME scenarios.
    """
    mock_db = mocker.patch.object(threatintel_obj, "db")
    mock_db.is_domain_malicious.return_value = (
        is_domain_malicious_return,
        False,
    )

    result = threatintel_obj.is_malicious_cname(
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
def test_is_malicious_cname_ignored_cname(threatintel_obj, mocker, cname):
    """
    Test `is_malicious_cname` for ignored CNAME scenarios.
    """
    mocker.patch.object(
        threatintel_obj, "is_ignored_domain", return_value=True
    )

    result = threatintel_obj.is_malicious_cname(
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
    [
        (
            {"description": "Malicious IP", "source": "test_source"},
            None,
            True,
        ),  # Offline hit
        (
            None,
            {"description": "Malicious IP", "source": "test_source"},
            True,
        ),  # Online hit
        (None, None, False),  # No hit
    ],
)
def test_is_malicious_ip(
    threatintel_obj, mocker, 
    offline_result, online_result, 
    expected_result
):
    """Test `is_malicious_ip` for checking IP blacklisting."""

    with patch(
        "modules.threat_intelligence.threat_intelligence.ThreatIntel.search_offline_for_ip",
        return_value=offline_result,
    ), patch(
        "modules.threat_intelligence.threat_intelligence.ThreatIntel.search_online_for_ip",
        return_value=online_result,
    ):
        result = threatintel_obj.is_malicious_ip(
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
    "domain, result, is_malicious",
    [
        ("example.com", {"description": "Malicious domain"}, True),
        ("safe.com", None, False),
    ],
)
def test_is_malicious_domain(
    domain, result, is_malicious, 
    threatintel_obj, mocker
):
    """
    Test `is_malicious_domain` for identifying 
    and recording evidence of malicious domains.
    """
    mock_search_offline_for_domain = mocker.patch.object(
        threatintel_obj, "search_offline_for_domain"
    )
    mock_set_evidence_malicious_domain = mocker.patch.object(
        threatintel_obj, "set_evidence_malicious_domain"
    )

    mock_search_offline_for_domain.return_value = (result, False)
    threatintel_obj.is_malicious_domain(
        domain,
        "uid123",
        "2023-11-28 12:00:00",
        "profile_10.0.0.1",
        "timewindow1",
    )

    if is_malicious:
        mock_set_evidence_malicious_domain.assert_called_once()
    else:
        mock_set_evidence_malicious_domain.assert_not_called()

    mock_search_offline_for_domain.reset_mock()
    mock_set_evidence_malicious_domain.reset_mock()


@pytest.mark.parametrize(
    "should_update_return_value, expected_parse_call, expected_db_call",
    [
        ("new_hash", True, True),  # File needs update
        (False, False, False),  # File doesn't need update
    ],
)
def test_update_local_file(
    should_update_return_value,
    expected_parse_call,
    expected_db_call,
    threatintel_obj,
    mocker,
):
    """
    Test `update_local_file` for updating local threat intelligence files.
    """
    mock_db = mocker.patch.object(threatintel_obj, "db")
    mock_parse_local_ti_file = mocker.patch.object(
        threatintel_obj, "parse_local_ti_file"
    )

    with patch(
        "modules.threat_intelligence.threat_intelligence.ThreatIntel.should_update_local_ti_file"
    ) as mock_should_update:
        mock_should_update.return_value = should_update_return_value

        threatintel_obj.update_local_file("own_malicious_iocs.csv")
        assert mock_parse_local_ti_file.called == expected_parse_call
        if expected_db_call:
            mock_db.set_TI_file_info.assert_called_once_with(
                "own_malicious_iocs.csv", {"hash": should_update_return_value}
            )
        else:
            mock_db.set_TI_file_info.assert_not_called()


@pytest.mark.parametrize(
    "filename, expected_parse_function",
    [
        ("own_malicious_JA3.csv", "parse_ja3_file"),
        ("own_malicious_JARM.csv", "parse_jarm_file"),
        ("own_malicious_iocs.csv", "parse_local_ti_file"),
    ],
)
def test_update_local_file_parse_function(
    filename, expected_parse_function, threatintel_obj, mocker
):
    """
    Test `update_local_file` to ensure the correct parsing function
    is called based on the filename.
    """
    mock_should_update_local_ti_file = mocker.patch.object(
        threatintel_obj, "should_update_local_ti_file", 
        return_value="new_hash"
    )
    mock_parse_function = mocker.patch.object(
        threatintel_obj, expected_parse_function, return_value=True
    )
    threatintel_obj.update_local_file(filename)

    assert mock_parse_function.called


@pytest.mark.parametrize(
    "search_online_result, expected_set_evidence_call",
    [
        # Testcase1:here the hash is found to be malicious
        (
            {
                "confidence": 0.8,
                "threat_level": 0.6,
                "blacklist": "CIRCL",
            },
            True,
        ),
        # Testcase2:here the hash is not found to be malicious
        (None, False),
    ],
)
def test_is_malicious_hash(
    threatintel_obj, mocker, 
    search_online_result, 
    expected_set_evidence_call
):
    """
    Test `is_malicious_hash` for identifying 
    and recording evidence of malicious file hashes.
    """
    mock_db = mocker.patch.object(threatintel_obj, "db")
    mock_search_online_for_hash = mocker.patch.object(
        threatintel_obj, "search_online_for_hash"
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
    threatintel_obj.is_malicious_hash(flow_info)
    if expected_set_evidence_call:
        mock_db.set_evidence.assert_called()
    else:
        mock_db.set_evidence.assert_not_called()


@pytest.mark.parametrize(
    "url, result, is_malicious",
    [
        ("http://malicious.com", {"description": "Malicious URL"}, True),
        ("http://safe.com", None, False),
    ],
)
def test_is_malicious_url(url, result, is_malicious, 
                          threatintel_obj, mocker):
    """
    Test `is_malicious_url` for correctly handling both malicious and non-malicious URLs.
    """
    mock_search_online_for_url = mocker.patch.object(
        threatintel_obj, "search_online_for_url"
    )
    mock_urlhaus_set_evidence = mocker.patch.object(
        threatintel_obj.urlhaus, "set_evidence_malicious_url"
    )

    mock_search_online_for_url.return_value = result
    threatintel_obj.is_malicious_url(
        url,
        "uid123",
        "2023-11-28 12:00:00",
        "192.168.1.1",
        "profile_10.0.0.1",
        "timewindow1",
    )

    if is_malicious:
        mock_urlhaus_set_evidence.assert_called_once()
    else:
        mock_urlhaus_set_evidence.assert_not_called()

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
def test_main_domain_lookup(threatintel_obj, mocker, 
                            msg_data, expected_call):
    """
    Test the `main` function's handling of domain name lookups,
    covering scenarios with DNS responses and direct domain queries.
    """
    mock_call = mocker.patch.object(threatintel_obj, expected_call)
    mock_get_msg = mocker.patch.object(threatintel_obj, "get_msg")
    mock_get_msg.return_value = {"data": json.dumps(msg_data)}

    threatintel_obj.main()

    mock_call.assert_called_once()


@pytest.mark.parametrize(
    "ip_address, is_malicious, should_lookup_return, expected_calls",
    [
        (
            "1.2.3.4",
            True,
            False,  # Malicious IP, should_lookup returns False
            {
                "is_malicious_ip": 1,
                "ip_belongs_to_blacklisted_range": 1,
                "ip_has_blacklisted_asn": 1,
            },
        ),
        (
            "10.0.0.1",
            False,
            False,  # Non-malicious IP, should_lookup returns False
            {
                "is_malicious_ip": 1,
                "ip_belongs_to_blacklisted_range": 1,
                "ip_has_blacklisted_asn": 1,
            },
        ),
        (
            "8.8.8.8",
            False,
            True,  # Non-malicious IP, should_lookup returns True
            {
                "is_malicious_ip": 0,
                "ip_belongs_to_blacklisted_range": 0,
                "ip_has_blacklisted_asn": 0,
            },
        ),
    ],
)
def test_main_ip_lookup(
    threatintel_obj,
    mocker,
    ip_address,
    is_malicious,
    should_lookup_return,
    expected_calls,
):
    """
    Test the `main` function's handling of IP address lookups,
    including scenarios with and without malicious IP detection,
    and when should_lookup returns True or False.
    """
    mock_db = mocker.patch.object(threatintel_obj, "db")
    mock_is_malicious_ip = mocker.patch.object(
        threatintel_obj, "is_malicious_ip", return_value=is_malicious
    )
    mock_ip_belongs_to_blacklisted_range = mocker.patch.object(
        threatintel_obj, "ip_belongs_to_blacklisted_range"
    )
    mock_ip_has_blacklisted_asn = mocker.patch.object(
        threatintel_obj, "ip_has_blacklisted_asn"
    )
    mock_get_msg = mocker.patch.object(threatintel_obj, "get_msg")
    mock_should_lookup = mocker.patch.object(
        threatintel_obj, "should_lookup", return_value=should_lookup_return
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
    threatintel_obj.main()
    assert mock_is_malicious_ip.call_count == (
        expected_calls["is_malicious_ip"]
    )
    assert mock_ip_belongs_to_blacklisted_range.call_count == (
        expected_calls["ip_belongs_to_blacklisted_range"]
    )
    assert mock_ip_has_blacklisted_asn.call_count == (
        expected_calls["ip_has_blacklisted_asn"]
    )


def test_main_empty_message(threatintel_obj, mocker):
    """
    Test the `main` function's behavior when receiving an empty message,
    ensuring it handles the scenario gracefully without errors.
    """
    mock_get_msg = mocker.patch.object(threatintel_obj, "get_msg")
    mock_get_msg.return_value = None
    threatintel_obj.main()


def test_main_file_hash_lookup(threatintel_obj, mocker):
    """
    Test the `main` function's handling of file hash lookups,
    verifying it calls the appropriate malicious hash checks.
    """

    mock_is_malicious_hash = mocker.patch.object(
        threatintel_obj, "is_malicious_hash"
    )
    mock_get_msg = mocker.patch.object(threatintel_obj, "get_msg")
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
    threatintel_obj.main()
    mock_is_malicious_hash.assert_called_once()


@pytest.mark.parametrize(
    "status_code, response_text, expected_result",
    [
        (
            200,
            json.dumps(
                {
                    "KnownMalicious": "blacklist1 blacklist2",
                    "hashlookup:trust": "75",
                }
            ),
            {
                "confidence": 0.7,
                "threat_level": 0.25,
                "blacklist": "blacklist1 blacklist2, circl.lu",
            },
        ),  # Test case for successful API query (200 OK)
        (
            404,
            "{}",  # Example error response
            None,
        ),  # Test case for 404 Not Found error
        (
            500,
            "Internal Server Error",  # Example error response
            None,
        ),  # Test case for 500 Internal Server Error
    ],
)
def test_circl_lu(
    threatintel_obj, mocker, 
    status_code, response_text, 
    expected_result
):
    """
    Test the `circl_lu` method for various Circl.lu API responses.
    """
    mock_session = mocker.patch.object(threatintel_obj, "circl_session")
    flow_info = {"flow": {"md5": "1234567890abcdef1234567890abcdef"}}
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.text = response_text
    mock_session.get.return_value = mock_response
    result = threatintel_obj.circl_lu(flow_info)
    assert result == expected_result


