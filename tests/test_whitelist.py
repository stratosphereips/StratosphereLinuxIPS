from tests.module_factory import ModuleFactory
import pytest



def test_read_whitelist(mock_rdb):
    """
    make sure the content of whitelists is read and stored properly
    uses tests/test_whitelist.conf for testing
    """
    whitelist = ModuleFactory().create_whitelist_obj(mock_rdb)
    mock_rdb.get_whitelist.return_value = {}
    whitelisted_IPs, whitelisted_domains, whitelisted_orgs, whitelisted_mac = whitelist.read_whitelist()
    assert '91.121.83.118' in whitelisted_IPs
    assert 'apple.com' in whitelisted_domains
    assert 'microsoft' in whitelisted_orgs


@pytest.mark.parametrize('org,asn', [('google', 'AS6432')])
def test_load_org_asn(org, asn, mock_rdb):
    whitelist = ModuleFactory().create_whitelist_obj(mock_rdb)
    assert whitelist.load_org_asn(org) is not False
    assert asn in whitelist.load_org_asn(org)


@pytest.mark.parametrize('org,subnet', [('google', '216.73.80.0/20')])
def test_load_org_IPs(org, subnet, mock_rdb):
    whitelist = ModuleFactory().create_whitelist_obj(mock_rdb)
    assert whitelist.load_org_IPs(org) is not False
    # we now store subnets in a dict sorted by the first octet
    first_octet = subnet.split('.')[0]
    assert first_octet in whitelist.load_org_IPs(org)
    assert subnet in whitelist.load_org_IPs(org)[first_octet]
