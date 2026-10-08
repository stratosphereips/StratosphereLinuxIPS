# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from tests.module_factory import ModuleFactory
import pytest
import json
from unittest.mock import MagicMock, patch, Mock, mock_open
from types import SimpleNamespace
from slips_files.core.structures.evidence import (
    Direction,
    IoCType,
    Attacker,
    Victim,
)


def test_read_whitelist():
    """
    make sure the content of whitelists is read and stored properly
    uses tests/unit/test_whitelist.conf for testing
    """
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.db.get_whitelist.return_value = {}
    assert whitelist.parser.parse()


@pytest.mark.parametrize(
    "same_connection,expected",
    [(True, True), (False, False)],
)
def test_live_flow_whitelist_requires_exact_slips_socket(
    same_connection: bool, expected: bool
) -> None:
    """Keep unrelated browser traffic even when it shares the device IP.

    Parameters:
        same_connection: Whether Slips registered the full socket tuple.
        expected: Whether this flow should be excluded from profiling.
    """
    factory = ModuleFactory()
    whitelist = factory.create_whitelist_obj()
    whitelist._filter_slips_own_traffic = True
    whitelist.db.main_pid = 123
    whitelist.db.is_slips_own_source_ip.return_value = True
    whitelist.db.is_slips_own_connection.return_value = same_connection
    whitelist._check_if_whitelisted_domains_of_flow = Mock(return_value=False)
    whitelist._flow_contains_whitelisted_ip = Mock(return_value=False)
    whitelist._flow_contains_whitelisted_mac = Mock(return_value=False)
    whitelist.org_analyzer.is_whitelisted = Mock(return_value=False)
    flow = SimpleNamespace(
        saddr="192.0.2.10", sport=51234,
        daddr="198.51.100.43", dport=43,
        proto="tcp", type_="conn",
    )

    assert whitelist.is_whitelisted_flow(flow) is expected
    whitelist.db.is_slips_own_connection.assert_called_once_with(
        123, "tcp", "192.0.2.10", 51234, "198.51.100.43", 43
    )


def test_offline_flow_ignores_live_slips_socket_registry() -> None:
    """Keep captured files independent of current machine sockets."""
    factory = ModuleFactory()
    whitelist = factory.create_whitelist_obj()
    whitelist._filter_slips_own_traffic = False
    flow = SimpleNamespace(
        saddr="192.0.2.10", sport=51234,
        daddr="198.51.100.43", dport=43, proto="tcp",
    )

    assert whitelist._is_slips_own_flow(flow) is False
    whitelist.db.is_slips_own_source_ip.assert_not_called()


@pytest.mark.parametrize(
    "proto,dst_port,marked,expected",
    [
        ("tcp", 43, True, True),
        ("tcp", 43, False, False),
        ("udp", 43, True, False),
        ("tcp", 443, True, False),
    ],
)
def test_whois_subprocess_allowance_is_limited_to_tcp_43(
    proto: str, dst_port: int, marked: bool, expected: bool
) -> None:
    """Apply the brief WHOIS mark only to its source and service port.

    Parameters:
        proto: Captured transport.
        dst_port: Captured destination port.
        marked: Whether the current local IP is in the WHOIS window.
        expected: Whether this flow is excluded from profiling.
    """
    factory = ModuleFactory()
    whitelist = factory.create_whitelist_obj()
    whitelist._filter_slips_own_traffic = True
    whitelist.db.main_pid = 123
    whitelist.db.is_slips_own_service_port.return_value = marked
    whitelist.db.is_slips_own_source_ip.return_value = False
    flow = SimpleNamespace(
        saddr="192.0.2.10", sport=51234,
        daddr="198.51.100.43", dport=dst_port,
        proto=proto,
    )

    assert whitelist._is_slips_own_flow(flow) is expected
    if proto == "tcp" and dst_port == 43:
        whitelist.db.is_slips_own_service_port.assert_called_once_with(
            123, "tcp", 43, "192.0.2.10"
        )
    else:
        whitelist.db.is_slips_own_service_port.assert_not_called()


@pytest.mark.parametrize("org,asn", [("google", "AS6432")])
def test_load_org_asn(
    org,
    asn,
):
    whitelist = ModuleFactory().create_whitelist_obj()
    parsed_asn = whitelist.parser.load_org_asn(org)
    assert parsed_asn is not False
    assert asn in parsed_asn


def test_load_org_ips():
    """
    Test load_org_ips reads org IP ranges from the expected file.
    """
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.db.set_org_cidrs = MagicMock()
    file_content = "34.64.0.0/10\n216.58.192.0/19\ninvalid\n"

    with patch(
        "builtins.open", mock_open(read_data=file_content)
    ) as mock_file:
        org_subnets = whitelist.parser.load_org_ips("google")

    assert "34" in org_subnets
    assert "216" in org_subnets
    assert "34.64.0.0/10" in org_subnets["34"]
    assert "216.58.192.0/19" in org_subnets["216"]
    mock_file.assert_called_once_with(
        "slips_files/organizations_info/google_ip_ranges"
    )
    whitelist.db.set_org_cidrs.assert_called_once_with("google", org_subnets)


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
    "ip, org, cidr",
    [
        ("17.253.73.205", "apple", "17.0.0.0/8"),
        ("8.8.8.8", "google", "8.8.8.0/24"),
    ],
)
def test_known_apple_and_google_ip_ranges_match_whitelist(
    ip: str, org: str, cidr: str
) -> None:
    """Match representative public IPs from built-in organization ranges.

    Parameters:
        ip: IP address to check.
        org: Organization owning the range.
        cidr: Organization CIDR expected to contain the IP.
    """
    whitelist = ModuleFactory().create_whitelist_obj()
    analyzer = whitelist.org_analyzer
    first_octet = ip.split(".")[0]
    analyzer.bloom_filters = {
        org: {"asns": [], "first_octets": [first_octet]}
    }
    whitelist.db.get_asn_info.return_value = None
    whitelist.db.is_ip_in_org_ips.return_value = [cidr]

    assert analyzer.is_ip_part_of_a_whitelisted_org(ip, org)


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
        (
            "captive.apple.com",
            "apple",
            ["apple.com"],
            False,
            ["apple.com"],
            None,
            True,
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
    result = whitelist.match.direction(direction.name, whitelist_direction)
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
    "address, valid",
    [
        ("192.168.1.163:5353", True),
        ("[fe80::1]:5353", True),
        ("192.168.1.163", True),
        ("192.168.1.163:65536", False),
        ("192.168.1.163:abc", False),
        ("192.168.1.163:05353", False),
        ("*:5353", True),
        ("*:65536", False),
        ("*:abc", False),
        ("fe80::1:5353", True),  # A valid unscoped IPv6 address.
        ("[fe80::1]:abc", False),
    ],
)
def test_parse_ip_port_rule(address: str, valid: bool) -> None:
    """Parse IP and optional port rules without accepting invalid ports.

    :param address: Rule value to parse.
    :param valid: Whether the rule value should be stored.
    """
    whitelist = ModuleFactory().create_whitelist_obj()
    parsed = whitelist.parser.parse_line(f"ip,{address},dst,alerts")
    whitelist.parser.call_handler(parsed)

    assert (address in whitelist.parser.whitelisted_ips) == valid


@pytest.mark.parametrize(
    "address, port, direction, ignore_type, expected",
    [
        ("192.168.1.163", 5353, Direction.DST, "alerts", True),
        ("192.168.1.163", "5353", Direction.SRC, "alerts", True),
        ("192.168.1.163", 80, Direction.DST, "alerts", False),
        ("192.168.1.163", None, Direction.DST, "alerts", False),
        ("192.168.1.163", 5353, Direction.DST, "flows", False),
        ("fe80::1", 5353, Direction.DST, "alerts", True),
    ],
)
def test_ip_port_rule_matching(
    address: str,
    port: int | str | None,
    direction: Direction,
    ignore_type: str,
    expected: bool,
) -> None:
    """Match a scoped IP rule only when its IP, port and ignore type fit.

    :param address: IP address to check.
    :param port: Port on the same side as the address.
    :param direction: Side of the address in the traffic.
    :param ignore_type: Suppression target being checked.
    :param expected: Expected match result.
    """
    whitelist = ModuleFactory().create_whitelist_obj()
    rules = {
        "192.168.1.163:5353": {"from": "both", "what_to_ignore": "alerts"},
        "[fe80::1]:5353": {"from": "dst", "what_to_ignore": "alerts"},
    }
    whitelist.bloom_filters.ips = rules
    whitelist.db.is_whitelisted.side_effect = (
        lambda key, type_: json.dumps(rules[key]) if key in rules else None
    )

    assert (
        whitelist.ip_analyzer.is_whitelisted(
            address, direction, ignore_type, port
        )
        == expected
    )


def test_ip_port_rule_coexists_with_unscoped_rule() -> None:
    """Keep matching an unscoped rule when a port is available."""
    whitelist = ModuleFactory().create_whitelist_obj()
    rules = {
        "192.168.1.163": {"from": "dst", "what_to_ignore": "alerts"},
        "192.168.1.163:5353": {
            "from": "dst",
            "what_to_ignore": "flows",
        },
    }
    whitelist.bloom_filters.ips = rules
    whitelist.db.is_whitelisted.side_effect = (
        lambda key, type_: json.dumps(rules[key]) if key in rules else None
    )

    assert whitelist.ip_analyzer.is_whitelisted(
        "192.168.1.163", Direction.DST, "alerts", 80
    )
    assert whitelist.ip_analyzer.is_whitelisted(
        "192.168.1.163", Direction.DST, "flows", 5353
    )
    assert not whitelist.ip_analyzer.is_whitelisted(
        "192.168.1.163", Direction.DST, "flows", 80
    )


@pytest.mark.parametrize(
    "side, src_port, dst_port, expected",
    [
        ("src", 5353, 80, True),
        ("src", 80, 5353, False),
        ("dst", 80, 5353, True),
        ("dst", 5353, 80, False),
    ],
)
def test_flow_ip_port_uses_matching_side(
    side: str, src_port: int, dst_port: int, expected: bool
) -> None:
    """Use the source or destination port paired with the selected IP.

    :param side: Side of the scoped IP rule.
    :param src_port: Flow source port.
    :param dst_port: Flow destination port.
    :param expected: Expected match result.
    """
    whitelist = ModuleFactory().create_whitelist_obj()
    flow = Mock(
        saddr="192.168.1.10",
        daddr="192.168.1.163",
        sport=src_port,
        dport=dst_port,
        type_="conn",
    )
    address = flow.saddr if side == "src" else flow.daddr
    rule = f"{address}:5353"
    whitelist.bloom_filters.ips = [rule]
    whitelist.db.is_whitelisted.side_effect = (
        lambda key, type_: json.dumps(
            {"from": side, "what_to_ignore": "flows"}
        )
        if key == rule
        else None
    )

    assert whitelist._flow_contains_whitelisted_ip(flow) == expected


@pytest.mark.parametrize(
    "side, src_port, dst_port, expected",
    [
        ("src", 5353, 80, True),
        ("src", 80, 5353, False),
        ("dst", 80, 5353, True),
        ("dst", 5353, 80, False),
    ],
)
def test_evidence_ip_port_uses_matching_side(
    side: str, src_port: int, dst_port: int, expected: bool
) -> None:
    """Use the port belonging to the direct IP entity in evidence.

    :param side: Side of the scoped IP rule.
    :param src_port: Evidence source port.
    :param dst_port: Evidence destination port.
    :param expected: Expected match result.
    """
    whitelist = ModuleFactory().create_whitelist_obj()
    direction = Direction.SRC if side == "src" else Direction.DST
    address = "192.168.1.10" if side == "src" else "192.168.1.163"
    entity = Mock(
        ioc_type=IoCType.IP,
        value=address,
        direction=direction,
        DNS_resolution=None,
        queries=None,
        CNAME=None,
        SNI=None,
    )
    evidence = Mock(src_port=src_port, dst_port=dst_port)
    setattr(evidence, "attacker" if side == "src" else "victim", entity)
    rule = f"{address}:5353"
    whitelist.bloom_filters.ips = [rule]
    whitelist.db.is_whitelisted.side_effect = (
        lambda key, type_: json.dumps(
            {"from": side, "what_to_ignore": "alerts"}
        )
        if key == rule
        else None
    )
    whitelist.domain_analyzer.is_whitelisted = Mock(return_value=False)
    whitelist.mac_analyzer.profile_has_whitelisted_mac = Mock(
        return_value=False
    )
    whitelist.org_analyzer.is_whitelisted_entity = Mock(return_value=False)

    assert whitelist._is_whitelisted_entity(
        evidence, "attacker" if side == "src" else "victim"
    ) == expected


@pytest.mark.parametrize("destination_port, expected", [(5353, True), (80, False)])
def test_private_ip_evidence_port_whitelist(
    destination_port: int, expected: bool
) -> None:
    """Suppress only the configured private-IP destination port alert.

    :param destination_port: Port of the private-IP evidence.
    :param expected: Expected whitelist decision.
    """
    whitelist = ModuleFactory().create_whitelist_obj()
    rule = "192.168.1.163:5353"
    whitelist.parser.call_handler(
        whitelist.parser.parse_line(f"ip,{rule},dst,alerts")
    )
    rules = whitelist.parser.whitelisted_ips
    whitelist.bloom_filters.ips = rules
    whitelist.db.is_whitelisted.side_effect = (
        lambda key, type_: json.dumps(rules[key]) if key in rules else None
    )
    whitelist.domain_analyzer.is_whitelisted = Mock(return_value=False)
    whitelist.mac_analyzer.profile_has_whitelisted_mac = Mock(
        return_value=False
    )
    whitelist.org_analyzer.is_whitelisted_entity = Mock(return_value=False)
    evidence = Mock(
        attacker=Attacker(
            ioc_type=IoCType.IP,
            value="192.168.1.10",
            direction=Direction.SRC,
        ),
        victim=Victim(
            ioc_type=IoCType.IP,
            value="192.168.1.163",
            direction=Direction.DST,
        ),
        src_port=49152,
        dst_port=destination_port,
    )

    assert whitelist.is_whitelisted_evidence(evidence) == expected


@pytest.mark.parametrize(
    "side, address, src_port, dst_port, expected",
    [
        ("src", "192.168.1.10", 5353, 80, True),
        ("dst", "192.168.1.163", 80, 5353, True),
        ("src", "fe80::1", 5353, 80, True),
        ("dst", "fe80::2", 80, 5353, True),
        ("src", "192.168.1.10", 80, 5353, False),
        ("dst", "192.168.1.163", 5353, 80, False),
    ],
)
def test_wildcard_ip_port_rule_matches_evidence(
    side: str,
    address: str,
    src_port: int,
    dst_port: int,
    expected: bool,
) -> None:
    """Match a wildcard port rule on the same side as an evidence IP.

    :param side: Direction of the evidence IP.
    :param address: IPv4 or IPv6 evidence address.
    :param src_port: Evidence source port.
    :param dst_port: Evidence destination port.
    :param expected: Expected whitelist decision.
    """
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.parser.call_handler(
        whitelist.parser.parse_line("ip,*:5353,both,alerts")
    )
    rules = whitelist.parser.whitelisted_ips
    whitelist.bloom_filters.ips = rules
    whitelist.db.is_whitelisted.side_effect = (
        lambda key, type_: json.dumps(rules[key]) if key in rules else None
    )
    whitelist.domain_analyzer.is_whitelisted = Mock(return_value=False)
    whitelist.mac_analyzer.profile_has_whitelisted_mac = Mock(
        return_value=False
    )
    whitelist.org_analyzer.is_whitelisted_entity = Mock(return_value=False)
    entity = Mock(
        ioc_type=IoCType.IP,
        value=address,
        direction=Direction.SRC if side == "src" else Direction.DST,
        DNS_resolution=None,
        queries=None,
        CNAME=None,
        SNI=None,
    )
    evidence = Mock(src_port=src_port, dst_port=dst_port)
    setattr(evidence, "attacker" if side == "src" else "victim", entity)

    assert whitelist._is_whitelisted_entity(
        evidence, "attacker" if side == "src" else "victim"
    ) == expected
    assert not whitelist.ip_analyzer.is_whitelisted(
        address, entity.direction, "flows", src_port if side == "src" else dst_port
    )


@pytest.mark.parametrize(
    "side, src_port, dst_port, expected",
    [
        ("src", 5353, 80, True),
        ("dst", 80, 5353, True),
        ("src", 80, 5353, False),
        ("dst", 5353, 80, False),
        ("both", 5353, 80, True),
        ("both", 80, 5353, True),
        ("src", 80, 80, False),
    ],
)
def test_wildcard_ip_port_rule_matches_flow(
    side: str, src_port: int, dst_port: int, expected: bool
) -> None:
    """Match a wildcard port rule against either side of a flow.

    :param side: Direction configured in the rule.
    :param src_port: Flow source port.
    :param dst_port: Flow destination port.
    :param expected: Expected flow whitelist decision.
    """
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.parser.call_handler(
        whitelist.parser.parse_line(f"ip,*:5353,{side},flows")
    )
    rules = whitelist.parser.whitelisted_ips
    whitelist.bloom_filters.ips = rules
    whitelist.db.is_whitelisted.side_effect = (
        lambda key, type_: json.dumps(rules[key]) if key in rules else None
    )
    flow = Mock(
        saddr="192.168.1.10",
        daddr="192.168.1.163",
        sport=src_port,
        dport=dst_port,
        type_="conn",
    )

    assert whitelist._flow_contains_whitelisted_ip(flow) == expected


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
