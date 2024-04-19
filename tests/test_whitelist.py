from tests.module_factory import ModuleFactory
import pytest
import json
from unittest.mock import MagicMock
from unittest.mock import MagicMock, patch
from slips_files.core.evidence_structure.evidence import (
    Direction,
    IoCType 
    )
import os

@pytest.fixture
def mock_db():
    mock_db = MagicMock()
    return mock_db

def test_read_whitelist(
        mock_db
        ):
    """
    make sure the content of whitelists is read and stored properly
    uses tests/test_whitelist.conf for testing
    """
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_db.get_whitelist.return_value = {}
    whitelisted_IPs, whitelisted_domains, whitelisted_orgs, whitelisted_mac = whitelist.read_whitelist()
    assert '91.121.83.118' in whitelisted_IPs
    assert 'apple.com' in whitelisted_domains
    assert 'microsoft' in whitelisted_orgs


@pytest.mark.parametrize('org,asn', [('google', 'AS6432')])
def test_load_org_asn(org, asn,
                      mock_db
                      ):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    assert whitelist.load_org_asn(org) is not False
    assert asn in whitelist.load_org_asn(org)


def test_load_org_IPs(mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    org_info_file = os.path.join(whitelist.org_info_path, 'google')
    with open(org_info_file, 'w') as f:
        f.write('34.64.0.0/10\n')
        f.write('216.58.192.0/19\n')

    org_subnets = whitelist.load_org_IPs('google')
    assert '34' in org_subnets
    assert '216' in org_subnets
    assert '34.64.0.0/10' in org_subnets['34']
    assert '216.58.192.0/19' in org_subnets['216']
    os.remove(org_info_file)
    
@pytest.mark.parametrize("mock_ip_info, mock_org_info, ip, org, expected_result", [
    ({'asn': {'asnorg': 'microsoft'}}, [json.dumps(['microsoft']), json.dumps([])], "91.121.83.118", "microsoft", True),
    ({'asn': {'asnorg': 'microsoft'}}, [json.dumps(['microsoft']), json.dumps([])], "91.121.83.118", "apple", True),
    ({'asn': {'asnorg': 'Unknown'}}, json.dumps(['google']), "8.8.8.8", "google", None),
    ({'asn': {'asnorg': 'AS6432'}}, json.dumps([]), "8.8.8.8", "google", None),
    ({'asn': {'asnorg': 'google'}}, json.dumps(['google']), "8.8.8.8", "google", True),
    ({'asn': {'asnorg': 'google'}}, json.dumps(['google']), "1.1.1.1", "cloudflare", True),
    (None, json.dumps(['google']), "8.8.4.4", "google", None)
])
def test_is_whitelisted_asn(mock_db, mock_ip_info, mock_org_info, ip, org, expected_result):
    mock_db.get_ip_info.return_value = mock_ip_info
    if isinstance(mock_org_info, list):
        mock_db.get_org_info.side_effect = mock_org_info
    else:
        mock_db.get_org_info.return_value = mock_org_info

    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    assert whitelist.is_whitelisted_asn(ip, org) == expected_result         
    
@pytest.mark.parametrize('flow_type, expected_result', [
    ('http', None),
    ('dns', None),
    ('ssl', None),
    ('arp', True),  
])
def test_is_ignored_flow_type(flow_type, expected_result, mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    assert whitelist.is_ignored_flow_type(flow_type) == expected_result      
    
def test_get_domains_of_flow(mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_db.get_ip_info.return_value = {'SNI': [{'server_name': 'example.com'}]}
    mock_db.get_dns_resolution.side_effect = [
        {'domains': ['src.example.com']},
        {'domains': ['dst.example.net']}
    ]
    dst_domains, src_domains = whitelist.get_domains_of_flow('1.2.3.4', '5.6.7.8')
    assert 'example.com' in src_domains
    assert 'src.example.com' in src_domains
    assert 'dst.example.net' in dst_domains
    
def test_get_domains_of_flow_no_domain_info(mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_db.get_ip_info.return_value = {}
    mock_db.get_dns_resolution.side_effect = [
        {'domains': []},
        {'domains': []}
    ]
    dst_domains, src_domains = whitelist.get_domains_of_flow('1.2.3.4', '5.6.7.8')
    assert not dst_domains
    assert not src_domains     

@pytest.mark.parametrize(
    'ip, org, org_ips, expected_result',
    [
        ('216.58.192.1', 'google', {'216': ['216.58.192.0/19']}, True),
        ('8.8.8.8', 'cloudflare', {'216': ['216.58.192.0/19']}, False),
        ('8.8.8.8', 'google', {}, False), #no org ip info
    ]
)
def test_is_ip_in_org(ip, org, org_ips, expected_result, mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_db.get_org_IPs.return_value = org_ips
    result = whitelist.is_ip_in_org(ip, org)
    assert result == expected_result
        
@pytest.mark.parametrize(
    'domain, org, org_domains, expected_result',
    [
        ('www.google.com', 'google', json.dumps(['google.com']), True),
        ('www.example.com', 'google', json.dumps(['google.com']), None),
        ('www.google.com', 'google', json.dumps([]), True), #no org domain info
    ]
)
def test_is_domain_in_org(domain, org, org_domains, expected_result, mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_db.get_org_info.return_value = org_domains
    result = whitelist.is_domain_in_org(domain, org)
    assert result == expected_result      

@pytest.mark.parametrize('what_to_ignore, expected_result', [
    ('flows', True),
    ('alerts', False),
    ('both', True),
])
def test_should_ignore_flows(what_to_ignore, expected_result):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    assert whitelist.should_ignore_flows(what_to_ignore) == expected_result
    
@pytest.mark.parametrize('what_to_ignore, expected_result', [
    ('alerts', True),
    ('flows', False),
    ('both', True),
])
def test_should_ignore_alerts(what_to_ignore, expected_result):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    assert whitelist.should_ignore_alerts(what_to_ignore) == expected_result
@pytest.mark.parametrize('direction, whitelist_direction, expected_result', [
    (Direction.DST, 'dst', True),
    (Direction.DST, 'src', False),
    (Direction.SRC, 'both', True),
])
def test_should_ignore_to(direction, whitelist_direction, expected_result):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    assert whitelist.should_ignore_to(whitelist_direction) == expected_result
@pytest.mark.parametrize('direction, whitelist_direction, expected_result', [
    (Direction.SRC, 'src', True),
    (Direction.SRC, 'dst', False),
    (Direction.DST, 'both', True),
])
def test_should_ignore_from(direction, whitelist_direction, expected_result):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    assert whitelist.should_ignore_from(whitelist_direction) == expected_result

@pytest.mark.parametrize('evidence_data, expected_result', [
    ({'attacker': MagicMock(attacker_type='IP', value='1.2.3.4', direction=Direction.SRC)}, True),  # Whitelisted source IP
    ({'victim': MagicMock(victim_type='DOMAIN', value='example.com', direction=Direction.DST)}, True),  # Whitelisted destination domain
 
])
def test_is_whitelisted_evidence(evidence_data, expected_result, mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_evidence = MagicMock(**evidence_data)
    mock_db.get_all_whitelist.return_value = {
        'IPs': json.dumps({'1.2.3.4': {'from': 'src', 'what_to_ignore': 'both'}}),
        'domains': json.dumps({'example.com': {'from': 'dst', 'what_to_ignore': 'both'}})
    }
    assert whitelist.is_whitelisted_evidence(mock_evidence) == expected_result    


@pytest.mark.parametrize('profile_ip, mac_address, direction, expected_result, whitelisted_macs', [
    ('1.2.3.4', 'b1:b1:b1:c1:c2:c3', Direction.SRC, True, {'b1:b1:b1:c1:c2:c3': {'from': 'src', 'what_to_ignore': 'alerts'}}),
    ('5.6.7.8', 'a1:a2:a3:a4:a5:a6', Direction.DST, True, {'a1:a2:a3:a4:a5:a6': {'from': 'dst', 'what_to_ignore': 'both'}}),
    ('9.8.7.6', 'c1:c2:c3:c4:c5:c6', Direction.SRC, False, {}),
])
def test_profile_has_whitelisted_mac(profile_ip, mac_address, direction, expected_result, whitelisted_macs, mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_db.get_mac_addr_from_profile.return_value = [mac_address]
    assert whitelist.profile_has_whitelisted_mac(profile_ip, whitelisted_macs, direction) == expected_result
    
@pytest.mark.parametrize('direction, ignore_alerts, whitelist_direction, expected_result', [
    (Direction.SRC, True, 'src', True),
    (Direction.DST, True, 'src', None),
    (Direction.SRC, True, 'both', True),
    (Direction.DST, True, 'both', True),
    (Direction.SRC, False, 'src', None),
])
def test_ignore_alert(direction, ignore_alerts, whitelist_direction, expected_result, mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    result = whitelist.ignore_alert(direction, ignore_alerts, whitelist_direction)
    assert result == expected_result   
    
@pytest.mark.parametrize('ioc_data, expected_result', [
    (MagicMock(attacker_type=IoCType.IP.name, value='1.2.3.4', direction=Direction.SRC), None), 
    (MagicMock(victim_type=IoCType.DOMAIN.name, value='example.com', direction=Direction.DST), True),
    (MagicMock(attacker_type=IoCType.IP.name, value='8.8.8.8', direction=Direction.SRC), None),
])
def test_is_part_of_a_whitelisted_org(ioc_data, expected_result, mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_db.get_all_whitelist.return_value = {'organizations': json.dumps({'google': {'from': 'src', 'what_to_ignore': 'both'}})}
    mock_db.get_org_info.return_value = json.dumps(['1.2.3.4/32'])
    mock_db.get_ip_info.return_value = {'asn': {'asnorg': 'Google'}}
    mock_db.get_org_info.return_value = json.dumps(['example.com'])
    result = whitelist.is_part_of_a_whitelisted_org(ioc_data)
    assert result == expected_result    
        
@pytest.mark.parametrize(
    "whitelisted_domain, direction, domains_of_flow, ignore_type, expected_result, mock_db_values",
    [
        (
            "apple.com",
            Direction.SRC,
            ["sub.apple.com", "apple.com"],
            "both",
            True,
            {'apple.com': {'from': 'both', 'what_to_ignore': 'both'}},  
        ),
        # testing_is_whitelisted_domain_in_flow_ignore_type_mismatch    
        (
            "example.com",
            Direction.SRC,
            ["example.com", "sub.example.com"],
            "alerts",
            False,
            {"example.com": {'from': 'src', 'what_to_ignore': 'flows'}},  
        ),
        # testing_is_whitelisted_domain_in_flow_ignore_type_matches
        (
            "example.com",
            Direction.SRC,
            ["example.com", "sub.example.com"],
            "both",
            True,
            {"example.com": {'from': 'src', 'what_to_ignore': 'both'}},  
        ),
        # testing_is_whitelisted_domain_in_flow_direction_and_ignore_type
        (
            "apple.com",
            Direction.SRC,
            ["store.apple.com", "apple.com"],
            "alerts",
            True,
            {'apple.com': {'from': 'both', 'what_to_ignore': 'both'}},  
        ),
    ],
)
def test_is_whitelisted_domain_in_flow(
    whitelisted_domain,
    direction,
    domains_of_flow,
    ignore_type,
    expected_result,
    mock_db_values,
    mock_db,
):
    
    mock_db.get_whitelist.return_value = mock_db_values
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    result = whitelist.is_whitelisted_domain_in_flow(
        whitelisted_domain, direction, domains_of_flow, ignore_type
    )
    assert result == expected_result
    
    

def test_is_whitelisted_domain_not_found(mock_db):
    """
    Test when the domain is not found in the whitelisted domains.
    """
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    domain = 'nonwhitelisteddomain.com'
    saddr = '1.2.3.4'
    daddr = '5.6.7.8'
    ignore_type = 'flows'
    assert whitelist.is_whitelisted_domain(domain, saddr, daddr, ignore_type) == False
    
def test_is_whitelisted_domain_ignore_type_mismatch(mock_db):
    """
    Test when the domain is found in the whitelisted domains, but the ignore_type does not match the what_to_ignore value.
    """
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_db.get_whitelist.return_value = {
        'apple.com': {'from': 'both', 'what_to_ignore': 'both'}
    }
    domain = 'apple.com'
    saddr = '1.2.3.4'
    daddr = '5.6.7.8'
    ignore_type = 'alerts'
    assert whitelist.is_whitelisted_domain(domain, saddr, daddr, ignore_type) == True  
    
def test_is_whitelisted_domain_match(mock_db):
    """
    Test when the domain is found in the whitelisted domains, and the ignore_type matches the what_to_ignore value.
    """
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_db.get_whitelist.return_value = {
        'apple.com': {'from': 'both', 'what_to_ignore': 'both'}
    }
    domain = 'apple.com'
    saddr = '1.2.3.4'
    daddr = '5.6.7.8'
    ignore_type = 'both'
    assert whitelist.is_whitelisted_domain(domain, saddr, daddr, ignore_type) == True
    
def test_is_whitelisted_domain_subdomain_found(mock_db):
    """
    Test when the domain is not found in the whitelisted domains, but a subdomain of the whitelisted domain is found.
    """
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_db.get_whitelist.return_value = {
        'apple.com': {'from': 'both', 'what_to_ignore': 'both'}
    }
    domain = 'sub.apple.com'
    saddr = '1.2.3.4'
    daddr = '5.6.7.8'
    ignore_type = 'both'
    assert whitelist.is_whitelisted_domain(domain, saddr, daddr, ignore_type) == True       
    

@patch("slips_files.common.parsers.config_parser.ConfigParser")
def test_read_configuration(mock_config_parser, mock_db):
    mock_config_parser.whitelist_path.return_value = "whitelist.conf"
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    whitelist.read_configuration()
    assert whitelist.whitelist_path == "config/whitelist.conf" 
    
@pytest.mark.parametrize('ip, expected_result', [
    ('1.2.3.4', True),  # Whitelisted IP
    ('5.6.7.8', None),  # Non-whitelisted IP
])
def test_is_ip_whitelisted(ip, expected_result, mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_db.get_all_whitelist.return_value = {
        'IPs': json.dumps({'1.2.3.4': {'from': 'both', 'what_to_ignore': 'both'}})
    }
    assert whitelist.is_ip_whitelisted(ip, Direction.SRC) == expected_result
    
@pytest.mark.parametrize('attacker_data, expected_result', [
    (MagicMock(attacker_type=IoCType.IP.name, value='1.2.3.4', direction=Direction.SRC), True),  
    (MagicMock(attacker_type=IoCType.DOMAIN.name, value='example.com', direction=Direction.DST), True),  
])
def test_check_whitelisted_attacker(attacker_data, expected_result, mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_db.get_all_whitelist.return_value = {
        'IPs': json.dumps({'1.2.3.4': {'from': 'src', 'what_to_ignore': 'both'}}),
        'domains': json.dumps({'example.com': {'from': 'dst', 'what_to_ignore': 'both'}})
    }
    mock_db.is_whitelisted_tranco_domain.return_value = False
    assert whitelist.check_whitelisted_attacker(attacker_data) == expected_result
    
@pytest.mark.parametrize('victim_data, expected_result', [
    (MagicMock(victim_type=IoCType.IP.name, value='1.2.3.4', direction=Direction.SRC), True),  
    (MagicMock(victim_type=IoCType.DOMAIN.name, value='example.com', direction=Direction.DST), True),  

])
def test_check_whitelisted_victim(victim_data, expected_result, mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_db.get_all_whitelist.return_value = {
        'IPs': json.dumps({'1.2.3.4': {'from': 'src', 'what_to_ignore': 'both'}}),
        'domains': json.dumps({'example.com': {'from': 'dst', 'what_to_ignore': 'both'}})
    }
    mock_db.is_whitelisted_tranco_domain.return_value = False
    assert whitelist.check_whitelisted_victim(victim_data) == expected_result
    
    
@pytest.mark.parametrize('org, expected_result', [
    ('google', ['google.com', 'google.co.uk']),
    ('microsoft', ['microsoft.com', 'microsoft.net']),
])
def test_load_org_domains(org, expected_result, mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_db.set_org_info = MagicMock()
    actual_result = whitelist.load_org_domains(org)
    for domain in expected_result:
        assert domain in actual_result
    assert len(actual_result) >= len(expected_result)
    mock_db.set_org_info.assert_called_with(org, json.dumps(actual_result), 'domains')     
    
@pytest.mark.parametrize('direction, ignore_alerts, whitelist_direction, expected_result', [
    (Direction.SRC, True, 'src', True),
    (Direction.SRC, True, 'dst', None),
    (Direction.SRC, False, 'src', False),
])
def test_ignore_alerts_from_ip(direction, ignore_alerts, whitelist_direction, expected_result, mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    result = whitelist.ignore_alerts_from_ip(direction, ignore_alerts, whitelist_direction)
    assert result == expected_result    
    
@pytest.mark.parametrize('direction, ignore_alerts, whitelist_direction, expected_result', [
    (Direction.DST, True, 'dst', True),
    (Direction.DST, True, 'src', None),
    (Direction.DST, False, 'dst', False),
])
def test_ignore_alerts_to_ip(direction, ignore_alerts, whitelist_direction, expected_result, mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    result = whitelist.ignore_alerts_to_ip(direction, ignore_alerts, whitelist_direction)
    assert result == expected_result       
    
@pytest.mark.parametrize('domain, direction, expected_result', [
    ('example.com', Direction.SRC, True),  
    ('test.example.com', Direction.DST, True),  
    ('malicious.com', Direction.SRC, None),  
])
def test_is_domain_whitelisted(domain, direction, expected_result, mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_db.get_all_whitelist.return_value = {
        'domains': json.dumps({'example.com': {'from': 'both', 'what_to_ignore': 'both'}})
    }
    mock_db.is_whitelisted_tranco_domain.return_value = False
    assert whitelist.is_domain_whitelisted(domain, direction) == expected_result    

@pytest.mark.parametrize(
    'ip, org, org_asn_info, ip_asn_info, expected_result',
    [
        ('8.8.8.8', 'google', json.dumps(['AS6432']), {'asn': {'number': 'AS6432'}}, True),
        ('1.1.1.1', 'cloudflare', json.dumps(['AS6432']), {'asn': {'number': 'AS6432'}}, True),
        ('8.8.8.8', 'Google', json.dumps(['AS15169']), {'asn': {'number': 'AS15169', 'asnorg': 'Google'}}, True),
        ('1.1.1.1', 'Cloudflare', json.dumps(['AS13335']), {'asn': {'number': 'AS15169', 'asnorg': 'Google'}}, None),
        ('9.9.9.9', 'IBM', json.dumps(['AS36459']), {}, None),
        ('9.9.9.9', 'IBM', json.dumps(['AS36459']), {'asn': {'number': 'Unknown'}}, None),
    ]
)
def test_is_ip_asn_in_org_asn(ip, org, org_asn_info, ip_asn_info, expected_result, mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_db.get_org_info.return_value = org_asn_info
    mock_db.get_ip_info.return_value = ip_asn_info
    result = whitelist.is_ip_asn_in_org_asn(ip, org)
    assert result == expected_result
    
def test_parse_whitelist(mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_whitelist = {
        'IPs': json.dumps({'1.2.3.4': {'from': 'src', 'what_to_ignore': 'both'}}),
        'domains': json.dumps({'example.com': {'from': 'dst', 'what_to_ignore': 'both'}}),
        'organizations': json.dumps({'google': {'from': 'both', 'what_to_ignore': 'both'}}),
        'mac': json.dumps({'b1:b1:b1:c1:c2:c3': {'from': 'src', 'what_to_ignore': 'alerts'}})
    }
    whitelisted_IPs, whitelisted_domains, whitelisted_orgs, whitelisted_macs = whitelist.parse_whitelist(mock_whitelist)
    assert '1.2.3.4' in whitelisted_IPs
    assert 'example.com' in whitelisted_domains
    assert 'google' in whitelisted_orgs
    assert 'b1:b1:b1:c1:c2:c3' in whitelisted_macs  
    
def test_get_all_whitelist(mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    mock_db.get_all_whitelist.return_value = {
        'IPs': json.dumps({'1.2.3.4': {'from': 'src', 'what_to_ignore': 'both'}}),
        'domains': json.dumps({'example.com': {'from': 'dst', 'what_to_ignore': 'both'}}),
        'organizations': json.dumps({'google': {'from': 'both', 'what_to_ignore': 'both'}}),
        'mac': json.dumps({'b1:b1:b1:c1:c2:c3': {'from': 'src', 'what_to_ignore': 'alerts'}})
    }
    all_whitelist = whitelist.get_all_whitelist()
    assert all_whitelist is not None
    assert 'IPs' in all_whitelist
    assert 'domains' in all_whitelist
    assert 'organizations' in all_whitelist
    assert 'mac' in all_whitelist
    
@pytest.mark.parametrize(
    "flow_data, whitelist_data, expected_result",
    [
        (   # testing_is_whitelisted_flow_with_whitelisted_organization_but_ip_or_domain_not_whitelisted
            MagicMock(saddr="9.8.7.6", daddr="5.6.7.8", type_="http", host="org.com"), 
            {"organizations": {"org": {"from": "both", "what_to_ignore": "flows"}}},  
            False,
        ),
        (   # testing_is_whitelisted_flow_with_non_whitelisted_organization_but_ip_or_domain_whitelisted
            MagicMock(saddr="1.2.3.4", daddr="5.6.7.8", type_="http", host="whitelisted.com"),  
            {"IPs": {"1.2.3.4": {"from": "src", "what_to_ignore": "flows"}}},  
            False,
        ),
        (   # testing_is_whitelisted_flow_with_whitelisted_source_ip
            MagicMock(saddr="1.2.3.4", daddr="5.6.7.8", type_="http", server_name="example.com"),  
            {"IPs": {"1.2.3.4": {"from": "src", "what_to_ignore": "flows"}}}, 
            False,
        ),
        
        (   # testing_is_whitelisted_flow_with_both_source_and_destination_ips_whitelisted
            MagicMock(saddr="1.2.3.4", daddr="5.6.7.8", type_="http"),  
            {"IPs": {"1.2.3.4": {"from": "src", "what_to_ignore": "flows"}, "5.6.7.8": {"from": "dst", "what_to_ignore": "flows"}}},  
            False,
        ),
        (   
            # testing_is_whitelisted_flow_with_whitelisted_mac_address_but_ip_not_whitelisted
            MagicMock(saddr="9.8.7.6", daddr="1.2.3.4", smac="b1:b1:b1:c1:c2:c3", dmac="a1:a2:a3:a4:a5:a6", type_="http", server_name="example.org"),  
            {"mac": {"b1:b1:b1:c1:c2:c3": {"from": "src", "what_to_ignore": "flows"}}},  
            False,
        ),
    ],
)
def test_is_whitelisted_flow(mock_db, flow_data, whitelist_data, expected_result):
    """
    Test the is_whitelisted_flow method with various combinations of flow data and whitelist data.
    """
    mock_db.get_all_whitelist.return_value = whitelist_data
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    assert whitelist.is_whitelisted_flow(flow_data) == expected_result  

@pytest.mark.parametrize('whitelist_data, expected_ips, expected_domains, expected_orgs, expected_macs', [
    # Invalid entries invalid IPs and domains are not filtered out
    
    ({
        'IPs': json.dumps({'300.300.300.300': {'from': 'src', 'what_to_ignore': 'both'}}),
        'domains': json.dumps({'http//:invalid-domain.com': {'from': 'dst', 'what_to_ignore': 'both'}}),
        'organizations': json.dumps({}),
        'mac': json.dumps({})
    }, 
    {'300.300.300.300': {'from': 'src', 'what_to_ignore': 'both'}}, 
    {'http//:invalid-domain.com': {'from': 'dst', 'what_to_ignore': 'both'}}, 
    {}, 
    {}),
    
    # Duplicate entries last one prevails or duplicates included based on implementation
    ({
        'IPs': json.dumps({
            '1.2.3.4': {'from': 'src', 'what_to_ignore': 'both'},
            '1.2.3.4': {'from': 'dst', 'what_to_ignore': 'both'}
        }),
        'domains': json.dumps({
            'example.com': {'from': 'src', 'what_to_ignore': 'both'},
            'example.com': {'from': 'dst', 'what_to_ignore': 'both'}
        }),
        'organizations': json.dumps({'google': {'from': 'both', 'what_to_ignore': 'both'}}),
        'mac': json.dumps({
            '00:11:22:33:44:55': {'from': 'src', 'what_to_ignore': 'alerts'},
            '00:11:22:33:44:55': {'from': 'dst', 'what_to_ignore': 'alerts'}
        })
    }, 
    {'1.2.3.4': {'from': 'dst', 'what_to_ignore': 'both'}}, 
    {'example.com': {'from': 'dst', 'what_to_ignore': 'both'}}, 
    {'google': {'from': 'both', 'what_to_ignore': 'both'}},
    {'00:11:22:33:44:55': {'from': 'dst', 'what_to_ignore': 'alerts'}}),
])
def test_parse_whitelist(whitelist_data, expected_ips, expected_domains, expected_orgs, expected_macs, mock_db):
    whitelist = ModuleFactory().create_whitelist_obj(mock_db)
    whitelisted_IPs, whitelisted_domains, whitelisted_orgs, whitelisted_macs = whitelist.parse_whitelist(whitelist_data)

    assert whitelisted_IPs == expected_ips
    assert whitelisted_domains == expected_domains
    assert whitelisted_orgs == expected_orgs
    assert whitelisted_macs == expected_macs
    


  
    
 
    
