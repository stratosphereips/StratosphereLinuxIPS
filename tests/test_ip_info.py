"""Unit test for modules/ip_info/ip_info.py"""
from tests.common_test_utils import do_nothing, get_db_manager
from ..modules.ip_info.ip_info import Module
from ..modules.ip_info.asn_info import ASN
import maxminddb


def create_ip_info_instance(output_queue, database):
    """Create an instance of ip_info.py
    needed by every other test in this file"""
    ip_info = Module(output_queue, database)
    # override the self.print function to avoid broken pipes
    ip_info.print = do_nothing
    return ip_info

def create_ASN_Info_instance(database):
    """Create an instance of asn_info.py
    needed by every other test in this file"""
    return ASN(database)


# ASN unit tests
def test_get_asn_info_from_geolite(database):
    """
    geolite is an offline db
    """
    ASN_info = create_ASN_Info_instance(database)
    # check an ip that we know is in the db
    expected_asn_info = {'asn': {'number': 'AS7018', 'org': 'ATT-INTERNET4'}}
    assert ASN_info.get_asn_info_from_geolite('108.200.116.255') == expected_asn_info
    # test  asn info not found in geolite
    assert ASN_info.get_asn_info_from_geolite('0.0.0.0') == {}

def test_cache_ip_range(database):
    ASN_info = create_ASN_Info_instance(database)
    assert ASN_info.cache_ip_range('8.8.8.8') == {'asn': {'number': 'AS15169', 'org': 'GOOGLE, US'}}

# GEOIP unit tests
def test_get_geocountry(output_queue, database):
    ip_info = create_ip_info_instance(output_queue, database)

    #open the db we'll be using for this test
    # ip_info.wait_for_dbs()
    ip_info.country_db = maxminddb.open_database(
                'databases/GeoLite2-Country.mmdb'
            )

    assert ip_info.get_geocountry('153.107.41.230') == {
        'geocountry': 'Australia'
    }
    assert ip_info.get_geocountry('23.188.195.255') == {
        'geocountry': 'Unknown'
    }

def test_get_vendor(output_queue, database, mocker):
    # make sure the mac db is download so that wai_for_dbs doesn't wait forever :'D
    ip_info = create_ip_info_instance(output_queue, database)
    profileid = 'profile_10.0.2.15'
    mac_addr = '08:00:27:7f:09:e1'
    host_name = 'FooBar-PC'
    #
    # # mock the online vendor
    # if the vendor isn't found offline, this mocker will run instead of get_vendor_online
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.text = 'PCS Systemtechnik GmbH'

    # tries to get vendor either online or from our offline db
    mac_info = ip_info.get_vendor(mac_addr, host_name, profileid)
    assert mac_info is not False
    assert mac_info['Vendor'].lower() == 'Pcs Systemtechnik GmbH'.lower()
