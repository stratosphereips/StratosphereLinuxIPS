# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from tests.module_factory import ModuleFactory
import pytest
import json
from unittest.mock import MagicMock, patch, Mock, mock_open
from slips_files.core.structures.evidence import (
    Direction,
    IoCType,
    Attacker,
    Victim,
)


def test_read_whitelist():
    """
    make sure the content of whitelists is read and stored properly
    uses tests/test_whitelist.conf for testing
    """
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.db.get_whitelist.return_value = {}
    assert whitelist.parser.parse()


@pytest.mark.parametrize("org,asn", [("google", "AS6432")])
def test_load_org_asn(
    org,
    asn,
):
    whitelist = ModuleFactory().create_whitelist_obj()
    parsed_asn = whitelist.parser.load_org_asn(org)
    assert parsed_asn is not False
    assert asn in parsed_asn


@patch(
    "slips_files.core.helpers.whitelist."
    "whitelist_parser.WhitelistParser.load_org_ips"
)
def test_load_org_ips(
    mock_load_org_ips,
):
    """
    Test load_org_IPs without modifying real files.
    """
    whitelist = ModuleFactory().create_whitelist_obj()
    mock_load_org_ips.return_value = {
        "34": ["34.64.0.0/10"],
        "216": ["216.58.192.0/19"],
    }
    org_subnets = whitelist.parser.load_org_ips("google")  # Call the method

    assert "34" in org_subnets
    assert "216" in org_subnets
    assert "34.64.0.0/10" in org_subnets["34"]
    assert "216.58.192.0/19" in org_subnets["216"]

    mock_load_org_ips.assert_called_once_with("google")


@pytest.mark.parametrize(
    "flow_type, expected_result",
    [
        ("http", False),
        ("dns", False),
        ("ssl", False),
        ("arp", True),
    ],
)
def test_is_ignored_flow_type(
    flow_type,
    expected_result,
):
    whitelist = ModuleFactory().create_whitelist_obj()
    assert whitelist.match.is_ignored_flow_type(flow_type) == expected_result


def test_get_src_domains_of_flow():
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.db.get_ip_info.return_value = [{"server_name": "sni.com"}]
    whitelist.db.get_dns_resolution.return_value = {
        "domains": ["dns_resolution.com"]
    }
    flow = Mock()
    flow.saddr = "5.6.7.8"

    src_domains = whitelist.domain_analyzer.get_src_domains_of_flow(flow)
    assert "sni.com" in src_domains
    assert "dns_resolution.com" in src_domains


@pytest.mark.parametrize(
    "flow_type, expected_result",
    [
        ("ssl", ["server_name", "some_cn.com"]),
        ("http", ["http_host.com"]),
        ("dns", ["query.com"]),
    ],
)
def test_get_dst_domains_of_flow(flow_type, expected_result):
    whitelist = ModuleFactory().create_whitelist_obj()
    flow = Mock()
    flow.type_ = flow_type
    flow.server_name = "server_name"
    flow.subject = "CN=some_cn.com"
    flow.host = "http_host.com"
    flow.query = "query.com"

    domains = whitelist.domain_analyzer.get_dst_domains_of_flow(flow)
    assert domains
    for domain in expected_result:
        assert domain in domains


@pytest.mark.parametrize(
    "ip, org, cidrs, mock_bf_octets, expected_result",
    [
        # Case 1: Bloom filter hit, DB hit
        ("216.58.192.1", "google", ["216.58.192.0/19"], ["216"], True),
        # Case 2: Bloom filter hit, DB miss
        ("8.8.8.8", "cloudflare", [], ["8"], False),
        # Case 3: Bloom filter MISS
        # The 'ip' starts with "192", but we'll only put "10" in the filter
        ("192.168.1.1", "my_org", [], ["10"], False),
    ],
)
def test_is_ip_in_org_complete(
    ip,
    org,
    cidrs,
    mock_bf_octets,
    expected_result,
):
    whitelist = ModuleFactory().create_whitelist_obj()
    analyzer = whitelist.org_analyzer
    analyzer.bloom_filters = {org: {"first_octets": mock_bf_octets}}

    whitelist.db.is_ip_in_org_ips.return_value = cidrs

    result = analyzer.is_ip_in_org(ip, org)
    assert result == expected_result


@pytest.mark.parametrize(
    "domain, org, mock_bf_domains, mock_db_exact, mock_db_org_list, "
    "mock_tld_side_effect, expected_result",
    [
        # --- Case 1: Bloom Filter MISS ---
        # The domain isn't even in the bloom filter.
        ("google.com", "google", ["other.com"], None, None, None, False),
        # --- Case 2: Bloom Filter HIT, DB Exact Match HIT ---
        # BF hits, and db.is_domain_in_org_domains finds it.
        ("google.com", "google", ["google.com"], True, None, None, True),
        # --- Case 3: Subdomain Match (org_domain IN domain) ---
        # 'google.com' (from db) is IN 'ads.google.com' (flow domain)
        (
            "ads.google.com",
            "google",
            ["ads.google.com"],  # 1. BF Hit
            False,  # 2. DB Exact Miss
            ["google.com"],  # 3. DB Org List
            ["google.com", "google.com"],  # 4. TLDs match (ads.google.com
            # -> google.com, google.com -> google.com)
            True,  # 5. Expected: True
        ),
        # --- Case 4: Reverse Subdomain Match (domain IN org_domain) ---
        # 'google.com' (flow domain) is IN 'ads.google.com' (from db)
        (
            "google.com",
            "google",
            ["google.com"],  # 1. BF Hit
            False,  # 2. DB Exact Miss
            ["ads.google.com"],  # 3. DB Org List
            ["google.com", "google.com"],  # 4. TLDs match
            True,  # 5. Expected: True
        ),
        # --- Case 5: TLD Mismatch ---
        # TLDs (google.net vs google.com) don't match, so 'continue' is hit.
        (
            "google.net",
            "google",
            ["google.net"],  # 1. BF Hit
            False,  # 2. DB Exact Miss
            ["google.com"],  # 3. org_domains
            ["google.net", "google.com"],  # 4. TLDs mismatch
            False,  # 5. Expected: False
        ),
        # --- Case 6: No Match (Falls through) ---
        # TLDs match, but neither is a substring of the other.
        (
            "evil-oogle.com",
            "google",
            ["evil-google.com"],  # 1. BF should Hit
            False,  # 2. DB Exact Miss
            ["google.com"],  # 3. org_domains
            ["google.com", "google.com"],  # 4. TLDs match
            False,  # 5. Expected: False
        ),
    ],
)
def test_is_domain_in_org(
    domain,
    org,
    mock_bf_domains,
    mock_db_exact,
    mock_db_org_list,
    mock_tld_side_effect,
    expected_result,
):
    whitelist = ModuleFactory().create_whitelist_obj()
    analyzer = whitelist.org_analyzer

    analyzer.bloom_filters = {org: {"domains": mock_bf_domains}}

    whitelist.db.is_domain_in_org_domains.return_value = mock_db_exact

    whitelist.db.get_org_info.return_value = mock_db_org_list
    # The first call is for 'domain', the second for 'org_domain'
    if mock_tld_side_effect:
        analyzer.domain_analyzer.get_tld = MagicMock(
            side_effect=mock_tld_side_effect
        )
    result = analyzer.is_domain_in_org(domain, org)
    assert result == expected_result


def test_is_domain_in_org_key_error():
    """
    Tests the 'try...except KeyError' block.
    This happens if the 'org' isn't in the bloom_filters dict.
    """
    whitelist = ModuleFactory().create_whitelist_obj()
    analyzer = whitelist.org_analyzer
    analyzer.bloom_filters = {}
    # Accessing analyzer.bloom_filters["google"] will raise a KeyError,
    # which should be caught and return False.
    result = analyzer.is_domain_in_org("google.com", "google")

    assert not result


@pytest.mark.parametrize(
    "is_whitelisted_victim, is_whitelisted_attacker, expected_result",
    [
        (True, True, True),
        (False, True, True),
        (True, False, True),
        (False, False, False),
    ],
)
def test_is_whitelisted_evidence(
    is_whitelisted_victim, is_whitelisted_attacker, expected_result
):
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist._is_whitelisted_entity = Mock(
        side_effect=[is_whitelisted_victim, is_whitelisted_attacker]
    )

    mock_evidence = Mock()
    assert whitelist.is_whitelisted_evidence(mock_evidence) == expected_result


@pytest.mark.parametrize(
    "profile_ip, mac_address, direction, expected_result, whitelisted_macs",
    [
        (
            "1.2.3.4",
            "b1:b1:b1:c1:c2:c3",
            Direction.SRC,
            False,
            {"from": "src", "what_to_ignore": "alerts"},
        ),
        (
            "5.6.7.8",
            "a1:a2:a3:a4:a5:a6",
            Direction.DST,
            True,
            {"from": "dst", "what_to_ignore": "both"},
        ),
        ("9.8.7.6", "c1:c2:c3:c4:c5:c6", Direction.SRC, False, {}),
    ],
)
def test_profile_has_whitelisted_mac(
    profile_ip,
    mac_address,
    direction,
    expected_result,
    whitelisted_macs,
):
    whitelist = ModuleFactory().create_whitelist_obj()
    # act as it is present in the bloom filter
    whitelist.bloom_filters.mac_addrs = mac_address

    whitelist.db.get_mac_addr_from_profile.return_value = mac_address
    if whitelisted_macs:
        whitelist.db.is_whitelisted.return_value = json.dumps(whitelisted_macs)
    else:
        whitelist.db.is_whitelisted.return_value = None

    assert (
        whitelist.mac_analyzer.profile_has_whitelisted_mac(
            profile_ip, direction, "both"
        )
        == expected_result
    )


@pytest.mark.parametrize(
    "direction, whitelist_direction, expected_result",
    [
        (Direction.SRC, "src", True),
        (Direction.DST, "src", False),
        (Direction.SRC, "both", True),
        (Direction.DST, "both", True),
        (Direction.DST, "dst", True),
    ],
)
def test_matching_direction(direction, whitelist_direction, expected_result):
    whitelist = ModuleFactory().create_whitelist_obj()
    result = whitelist.match.direction(direction, whitelist_direction)
    assert result == expected_result


@pytest.mark.parametrize(
    "ioc_data, expected_result",
    [
        # Private IP should short-circuit -> False
        (
            {
                "ioc_type": IoCType.IP,
                "value": "192.168.1.1",
                "direction": Direction.SRC,
            },
            False,
        ),
        #         Domain belonging to whitelisted org -> True
        (
            {
                "ioc_type": IoCType.DOMAIN,
                "value": "example.com",
                "direction": Direction.DST,
            },
            True,
        ),
        #         Public IP not in whitelisted org -> False
        (
            {
                "ioc_type": IoCType.IP,
                "value": "8.8.8.8",
                "direction": Direction.SRC,
            },
            False,
        ),
    ],
)
def test_is_part_of_a_whitelisted_org(ioc_data, expected_result):
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.org_analyzer.whitelisted_orgs = {
        "google": json.dumps({"from": "both", "what_to_ignore": "both"})
    }

    # mock dependent methods
    whitelist.org_analyzer.is_domain_in_org = MagicMock(return_value=True)
    whitelist.org_analyzer.is_ip_part_of_a_whitelisted_org = MagicMock(
        return_value=False
    )

    whitelist.match = MagicMock()
    whitelist.match.direction.return_value = True
    whitelist.match.what_to_ignore.return_value = True

    with patch(
        "slips_files.core.helpers.whitelist.organization_whitelist."
        "utils.is_private_ip",
        return_value=False,
    ):
        result = whitelist.org_analyzer._is_part_of_a_whitelisted_org(
            ioc=ioc_data["value"],
            ioc_type=ioc_data["ioc_type"],
            direction=ioc_data["direction"],
            what_to_ignore="both",
        )

    assert result == expected_result


@pytest.mark.parametrize(
    "dst_domains, src_domains, whitelisted_domains, "
    "is_whitelisted_return_vals,  expected_result",
    [
        (
            ["dst_domain.net"],
            ["apple.com"],
            {"apple.com": {"from": "src", "what_to_ignore": "both"}},
            [False, True],
            True,
        ),
        (
            ["apple.com"],  # dst domains, shouldnt be whitelisted
            ["src.com"],
            {"apple.com": {"from": "src", "what_to_ignore": "both"}},
            [False, False],
            False,
        ),
        (["apple.com"], ["src.com"], {}, [False, False], False),
        # no whitelist found
        (  # no flow domains found
            [],
            [],
            {"apple.com": {"from": "src", "what_to_ignore": "both"}},
            [False, False],
            False,
        ),
    ],
)
def test_check_if_whitelisted_domains_of_flow(
    dst_domains,
    src_domains,
    whitelisted_domains,
    is_whitelisted_return_vals,
    expected_result,
):
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.bloom_filters.domains = list(whitelisted_domains.keys())
    whitelist.db.get_whitelist.return_value = whitelisted_domains

    whitelist.domain_analyzer.get_src_domains_of_flow = Mock(
        return_value=src_domains
    )

    whitelist.domain_analyzer.is_whitelisted = Mock(
        side_effect=is_whitelisted_return_vals
    )

    flow = Mock()
    result = whitelist._check_if_whitelisted_domains_of_flow(flow)
    assert result == expected_result


def test_is_whitelisted_domain_not_found():
    """
    Test when the domain is not found in the whitelisted domains.
    """
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.bloom_filters.domains = []
    whitelist.db.get_whitelist.return_value = {}
    whitelist.db.is_whitelisted_tranco_domain.return_value = False
    domain = "nonwhitelisteddomain.com"
    ignore_type = "flows"
    assert not whitelist.domain_analyzer.is_whitelisted(
        domain, Direction.DST, ignore_type
    )


@patch(
    "slips_files.common.parsers.config_parser.ConfigParser"
    ".local_whitelist_path"
)
def test_read_configuration(
    mock_config_parser,
):
    whitelist = ModuleFactory().create_whitelist_obj()
    mock_config_parser.return_value = "config_whitelist_path"
    whitelist.parser.read_configuration()
    assert whitelist.parser.local_whitelist_path == "config_whitelist_path"


@pytest.mark.parametrize(
    "ip, what_to_ignore, expected_result",
    [
        ("1.2.3.4", "flows", True),  # Whitelisted IP
        ("1.2.3.4", "alerts", True),  # Whitelisted IP
        ("1.2.3.4", "both", True),  # Whitelisted IP
        ("5.6.7.8", "both", False),  # Non-whitelisted IP
        ("5.6.7.8", "", False),  # Invalid type
        ("invalid_ip", "both", False),  # Invalid IP
    ],
)
def test_ip_analyzer_is_whitelisted(ip, what_to_ignore, expected_result):
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.bloom_filters.ips = [ip]  # Simulate presence in bloom
    # filter, because we wanna test the rest of the logic

    # only this ip is whitelisted
    if ip == "1.2.3.4":
        whitelist.db.is_whitelisted.return_value = json.dumps(
            {"from": "both", "what_to_ignore": "both"}
        )
    else:
        whitelist.db.is_whitelisted.return_value = None

    assert (
        whitelist.ip_analyzer.is_whitelisted(ip, Direction.SRC, what_to_ignore)
        == expected_result
    )


@pytest.mark.parametrize(
    "is_whitelisted_domain, is_whitelisted_org, " "expected_result",
    [
        (True, False, True),
        (True, True, True),
        (False, True, True),
        (True, False, True),
        (False, False, False),
    ],
)
def test_is_whitelisted_entity_attacker(
    is_whitelisted_domain, is_whitelisted_org, expected_result
):
    whitelist = ModuleFactory().create_whitelist_obj()
    evidence = Mock()
    evidence.attacker = Attacker(
        ioc_type=IoCType.DOMAIN,
        value="google.com",
        direction=Direction.SRC,
        AS={},
    )

    whitelist.extract_ips_from_entity = Mock(return_value=[])
    whitelist.extract_domains_from_entity = Mock(
        return_value=[evidence.attacker.value]
    )

    whitelist.domain_analyzer.is_whitelisted = Mock()
    whitelist.domain_analyzer.is_whitelisted.return_value = (
        is_whitelisted_domain
    )

    whitelist.org_analyzer.is_whitelisted_entity = Mock()
    whitelist.org_analyzer.is_whitelisted_entity.return_value = (
        is_whitelisted_org
    )

    assert (
        whitelist._is_whitelisted_entity(evidence, "attacker")
        == expected_result
    )


@pytest.mark.parametrize(
    "is_whitelisted_domain, is_whitelisted_ip, "
    "is_whitelisted_mac, is_whitelisted_org, expected_result",
    [
        (True, False, False, False, True),
        (False, True, False, False, True),
        (False, False, True, False, True),
        (False, False, False, True, True),
        (False, False, False, False, False),
    ],
)
def test_is_whitelisted_entity_victim(
    is_whitelisted_domain,
    is_whitelisted_ip,
    is_whitelisted_mac,
    is_whitelisted_org,
    expected_result,
):
    whitelist = ModuleFactory().create_whitelist_obj()
    evidence = Mock()
    evidence.victim = Victim(
        ioc_type=IoCType.IP,
        value="1.2.3.4",
        direction=Direction.SRC,
    )

    whitelist.extract_ips_from_entity = Mock(
        return_value=[evidence.victim.value]
    )
    whitelist.extract_domains_from_entity = Mock(return_value=["google.com"])

    whitelist.domain_analyzer.is_whitelisted = Mock()
    whitelist.domain_analyzer.is_whitelisted.return_value = (
        is_whitelisted_domain
    )

    whitelist.ip_analyzer.is_whitelisted = Mock()
    whitelist.ip_analyzer.is_whitelisted.return_value = is_whitelisted_ip

    whitelist.mac_analyzer.profile_has_whitelisted_mac = Mock()
    whitelist.mac_analyzer.profile_has_whitelisted_mac.return_value = (
        is_whitelisted_mac
    )

    whitelist.org_analyzer.is_whitelisted_entity = Mock()
    whitelist.org_analyzer.is_whitelisted_entity.return_value = (
        is_whitelisted_org
    )
    assert (
        whitelist._is_whitelisted_entity(evidence, "victim") == expected_result
    )


@pytest.mark.parametrize(
    "org, file_content, expected_result",
    [
        (
            "google",
            "google.com\ngoogle.co.uk\n",
            ["google.com", "google.co.uk"],
        ),
        (
            "microsoft",
            "microsoft.com\nmicrosoft.net\n",
            ["microsoft.com", "microsoft.net"],
        ),
    ],
)
def test_load_org_domains(org, file_content, expected_result):
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.db.set_org_info = MagicMock()

    # Mock the file open for reading org domains
    with patch("builtins.open", mock_open(read_data=file_content)):
        actual_result = whitelist.parser.load_org_domains(org)

    # Check contents
    assert actual_result == expected_result
    whitelist.db.set_org_info.assert_called_once_with(
        org, expected_result, "domains"
    )


@pytest.mark.parametrize(
    "domain, direction, is_whitelisted_return, expected_result",
    [
        (
            "example.com",
            Direction.SRC,
            {"from": "both", "what_to_ignore": "both"},
            True,
        ),
        (
            "test.example.com",
            Direction.DST,
            {"from": "both", "what_to_ignore": "both"},
            True,
        ),
        ("malicious.com", Direction.SRC, {}, False),
    ],
)
def test_is_domain_whitelisted(
    domain,
    direction,
    is_whitelisted_return,
    expected_result,
):
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.db.is_whitelisted.return_value = json.dumps(
        is_whitelisted_return
    )

    whitelist.db.is_whitelisted_tranco_domain.return_value = False
    whitelist.bloom_filters.domains = ["example.com"]

    for type_ in ("alerts", "flows"):
        result = whitelist.domain_analyzer.is_whitelisted(
            domain, direction, type_
        )
        assert result == expected_result


@pytest.mark.parametrize(
    "ip, org, org_asn_info, ip_asn_info, expected_result",
    [
        (
            "8.8.8.8",
            "google",
            ["AS6432"],
            {"asn": {"number": "AS6432"}},
            True,
        ),
        (
            "1.1.1.1",
            "cloudflare",
            ["AS6432"],
            {"asn": {"number": "AS6432"}},
            True,
        ),
        (
            "8.8.8.8",
            "Google",
            ["AS15169"],
            {"asn": {"number": "AS15169", "asnorg": "Google"}},
            True,
        ),
        (
            "1.1.1.1",
            "Cloudflare",
            ["AS13335"],
            {"asn": {"number": "AS15169", "asnorg": "Google"}},
            False,
        ),
        ("9.9.9.9", "IBM", ["AS36459"], {}, False),
        (
            "9.9.9.9",
            "IBM",
            ["AS36459"],
            {"asn": {"number": "Unknown"}},
            False,
        ),
    ],
)
def test_is_ip_asn_in_org_asn(
    ip, org, org_asn_info, ip_asn_info, expected_result
):
    whitelist = ModuleFactory().create_whitelist_obj()

    whitelist.db = MagicMock()
    whitelist.db.get_ip_info.return_value = ip_asn_info
    whitelist.db.get_org_info.return_value = org_asn_info

    ip_asn = ip_asn_info.get("asn", {}).get("number", None)
    whitelist.org_analyzer._is_asn_in_org = MagicMock(
        return_value=ip_asn in org_asn_info
    )

    result = whitelist.org_analyzer.is_ip_asn_in_org_asn(ip, org)
    assert result == expected_result
