# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from tests.module_factory import ModuleFactory
import pytest
import json
from unittest.mock import MagicMock, patch, Mock
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
    whitelist.db.get_ip_info.return_value = {
        "SNI": [{"server_name": "sni.com"}]
    }
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
    "ip, org, org_ips, expected_result",
    [
        ("216.58.192.1", "google", {"216": ["216.58.192.0/19"]}, True),
        ("8.8.8.8", "cloudflare", {"216": ["216.58.192.0/19"]}, False),
        ("8.8.8.8", "google", {}, False),  # no org ip info
    ],
)
def test_is_ip_in_org(
    ip,
    org,
    org_ips,
    expected_result,
):
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.db.get_org_ips.return_value = org_ips
    result = whitelist.org_analyzer.is_ip_in_org(ip, org)
    assert result == expected_result


@pytest.mark.parametrize(
    "domain, org, org_domains, expected_result",
    [
        ("www.google.com", "google", json.dumps(["google.com"]), True),
        ("www.example.com", "google", json.dumps(["google.com"]), None),
        (
            "www.google.com",
            "google",
            json.dumps([]),
            None,
        ),  # no org domain info
    ],
)
def test_is_domain_in_org(
    domain,
    org,
    org_domains,
    expected_result,
):
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.db.get_org_info.return_value = org_domains
    result = whitelist.org_analyzer.is_domain_in_org(domain, org)
    assert result == expected_result


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
            {"b1:b1:b1:c1:c2:c3": {"from": "src", "what_to_ignore": "alerts"}},
        ),
        (
            "5.6.7.8",
            "a1:a2:a3:a4:a5:a6",
            Direction.DST,
            True,
            {"a1:a2:a3:a4:a5:a6": {"from": "dst", "what_to_ignore": "both"}},
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
    whitelist.db.get_mac_addr_from_profile.return_value = mac_address
    whitelist.db.get_whitelist.return_value = whitelisted_macs
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
        (
            {
                "ioc_type": IoCType.IP,
                "value": "1.2.3.4",
                "direction": Direction.SRC,
            },
            False,
        ),
        (
            {
                "ioc_type": IoCType.DOMAIN,
                "value": "example.com",
                "direction": Direction.DST,
            },
            True,
        ),
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
def test_is_part_of_a_whitelisted_org(
    ioc_data,
    expected_result,
):
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.db.get_whitelist.return_value = {
        "google": {"from": "both", "what_to_ignore": "both"}
    }
    whitelist.db.get_org_info.return_value = json.dumps(["1.2.3.4/32"])
    whitelist.db.get_ip_info.return_value = {"asn": {"asnorg": "Google"}}
    whitelist.db.get_org_info.return_value = json.dumps(["example.com"])
    # we're mocking either an attacker or a  victim obj
    mock_ioc = MagicMock()
    mock_ioc.value = ioc_data["value"]
    mock_ioc.direction = ioc_data["direction"]
    mock_ioc.ioc_type = ioc_data["ioc_type"]

    assert (
        whitelist.org_analyzer._is_part_of_a_whitelisted_org(
            mock_ioc.value, mock_ioc.ioc_type, mock_ioc.direction, "both"
        )
        == expected_result
    )


@pytest.mark.parametrize(
    "dst_domains, src_domains, whitelisted_domains, expected_result",
    [
        (
            ["dst_domain.net"],
            ["apple.com"],
            {"apple.com": {"from": "src", "what_to_ignore": "both"}},
            True,
        ),
        (
            ["apple.com"],
            ["src.com"],
            {"apple.com": {"from": "src", "what_to_ignore": "both"}},
            False,
        ),
        (["apple.com"], ["src.com"], {}, False),  # no whitelist found
        (  # no flow domains found
            [],
            [],
            {"apple.com": {"from": "src", "what_to_ignore": "both"}},
            False,
        ),
    ],
)
def test_check_if_whitelisted_domains_of_flow(
    dst_domains,
    src_domains,
    whitelisted_domains,
    expected_result,
):
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.db.get_whitelist.return_value = whitelisted_domains

    whitelist.domain_analyzer.is_domain_in_tranco_list = Mock()
    whitelist.domain_analyzer.is_domain_in_tranco_list.return_value = False

    whitelist.domain_analyzer.get_dst_domains_of_flow = Mock()
    whitelist.domain_analyzer.get_dst_domains_of_flow.return_value = (
        dst_domains
    )

    whitelist.domain_analyzer.get_src_domains_of_flow = Mock()
    whitelist.domain_analyzer.get_src_domains_of_flow.return_value = (
        src_domains
    )

    flow = Mock()
    result = whitelist._check_if_whitelisted_domains_of_flow(flow)
    assert result == expected_result


def test_is_whitelisted_domain_not_found():
    """
    Test when the domain is not found in the whitelisted domains.
    """
    whitelist = ModuleFactory().create_whitelist_obj()
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
    whitelist.db.get_whitelist.return_value = {
        "1.2.3.4": {"from": "both", "what_to_ignore": "both"}
    }
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
    "org, expected_result",
    [
        ("google", ["google.com", "google.co.uk"]),
        ("microsoft", ["microsoft.com", "microsoft.net"]),
    ],
)
def test_load_org_domains(
    org,
    expected_result,
):
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.db.set_org_info = MagicMock()

    actual_result = whitelist.parser.load_org_domains(org)
    for domain in expected_result:
        assert domain in actual_result

    assert len(actual_result) >= len(expected_result)
    whitelist.db.set_org_info.assert_called_with(
        org, json.dumps(actual_result), "domains"
    )


@pytest.mark.parametrize(
    "domain, direction, expected_result",
    [
        ("example.com", Direction.SRC, True),
        ("test.example.com", Direction.DST, True),
        ("malicious.com", Direction.SRC, False),
    ],
)
def test_is_domain_whitelisted(
    domain,
    direction,
    expected_result,
):
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.db.get_whitelist.return_value = {
        "example.com": {"from": "both", "what_to_ignore": "both"}
    }
    whitelist.db.is_whitelisted_tranco_domain.return_value = False
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
            json.dumps(["AS6432"]),
            {"asn": {"number": "AS6432"}},
            True,
        ),
        (
            "1.1.1.1",
            "cloudflare",
            json.dumps(["AS6432"]),
            {"asn": {"number": "AS6432"}},
            True,
        ),
        (
            "8.8.8.8",
            "Google",
            json.dumps(["AS15169"]),
            {"asn": {"number": "AS15169", "asnorg": "Google"}},
            True,
        ),
        (
            "1.1.1.1",
            "Cloudflare",
            json.dumps(["AS13335"]),
            {"asn": {"number": "AS15169", "asnorg": "Google"}},
            False,
        ),
        ("9.9.9.9", "IBM", json.dumps(["AS36459"]), {}, None),
        (
            "9.9.9.9",
            "IBM",
            json.dumps(["AS36459"]),
            {"asn": {"number": "Unknown"}},
            False,
        ),
    ],
)
def test_is_ip_asn_in_org_asn(
    ip, org, org_asn_info, ip_asn_info, expected_result
):
    whitelist = ModuleFactory().create_whitelist_obj()
    whitelist.db.get_org_info.return_value = org_asn_info
    whitelist.db.get_ip_info.return_value = ip_asn_info
    assert (
        whitelist.org_analyzer.is_ip_asn_in_org_asn(ip, org) == expected_result
    )


# TODO for sekhar
# @pytest.mark.parametrize(
#     "flow_data, whitelist_data, expected_result",
#     [
#         (  # testing_is_whitelisted_flow_with_whitelisted_organization_
#             # but_ip_or_domain_not_whitelisted
#             MagicMock(saddr="9.8.7.6", daddr="5.6.7.8", type_="http", host="org.com"),
#             {"organizations": {"org": {"from": "both", "what_to_ignore": "flows"}}},
#             False,
#         ),
#         (  # testing_is_whitelisted_flow_with_non_whitelisted_organizatio
#             # n_but_ip_or_domain_whitelisted
#             MagicMock(
#                 saddr="1.2.3.4",
#                 daddr="5.6.7.8",
#                 type_="http",
#                 host="whitelisted.com",
#             ),
#             {"IPs": {"1.2.3.4": {"from": "src", "what_to_ignore": "flows"}}},
#             False,
#         ),
#         (  # testing_is_whitelisted_flow_with_whitelisted_source_ip
#             MagicMock(
#                 saddr="1.2.3.4",
#                 daddr="5.6.7.8",
#                 type_="http",
#                 server_name="example.com",
#             ),
#             {"IPs": {"1.2.3.4": {"from": "src", "what_to_ignore": "flows"}}},
#             False,
#         ),
#         (  # testing_is_whitelisted_flow_with_both_source_and_destination_ips_whitelisted
#             MagicMock(saddr="1.2.3.4", daddr="5.6.7.8", type_="http"),
#             {
#                 "IPs": {
#                     "1.2.3.4": {"from": "src", "what_to_ignore": "flows"},
#                     "5.6.7.8": {"from": "dst", "what_to_ignore": "flows"},
#                 }
#             },
#             False,
#         ),
#         (
#             # testing_is_whitelisted_flow_with_whitelisted_mac_address_but_ip_not_whitelisted
#             MagicMock(
#                 saddr="9.8.7.6",
#                 daddr="1.2.3.4",
#                 smac="b1:b1:b1:c1:c2:c3",
#                 dmac="a1:a2:a3:a4:a5:a6",
#                 type_="http",
#                 server_name="example.org",
#             ),
#             {
#                 "mac": {
#                     "b1:b1:b1:c1:c2:c3": {
#                         "from": "src",
#                         "what_to_ignore": "flows",
#                     }
#                 }
#             },
#             False,
#         ),
#     ],
# )
# def test_is_whitelisted_flow( flow_data, whitelist_data, expected_result):
#     """
#     Test the is_whitelisted_flow method with various combinations of flow data and whitelist data.
#     """
#     whitelist.db.get_all_whitelist.return_value = whitelist_data
#     whitelist = ModuleFactory().create_whitelist_obj()
#     assert whitelist.is_whitelisted_flow(flow_data) == expected_result
