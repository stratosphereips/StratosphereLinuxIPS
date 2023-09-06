"""Unit test for modules/ip_info/ip_info.py"""
from tests.module_factory import ModuleFactory
from slips_files.core.database.database_manager import DBManager
import modules.ip_info.asn_info as asn
from unittest.mock import patch
import maxminddb


# ASN unit tests
def test_get_asn_info_from_geolite(mock_rdb):
    """
    geolite is an offline db
    """
    ASN_info = ModuleFactory().create_asn_obj(mock_rdb)
    # check an ip that we know is in the db
    expected_asn_info = {'asn': {'number': 'AS7018', 'org': 'ATT-INTERNET4'}}
    assert ASN_info.get_asn_info_from_geolite('108.200.116.255') == expected_asn_info
    # test  asn info not found in geolite
    assert ASN_info.get_asn_info_from_geolite('0.0.0.0') == {}

def test_cache_ip_range(mock_rdb):
    # Patch the database object creation before it is instantiated
    ASN_info = ModuleFactory().create_asn_obj(mock_rdb)
    assert ASN_info.cache_ip_range('8.8.8.8') == {'asn': {'number': 'AS15169', 'org': 'GOOGLE, US'}}

# GEOIP unit tests
def test_get_geocountry(mock_rdb):
    ip_info = ModuleFactory().create_ip_info_obj(mock_rdb)

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

def test_get_vendor(mocker, mock_rdb):
    # make sure the mac db is download so that wai_for_dbs doesn't wait forever :'D
    ip_info = ModuleFactory().create_ip_info_obj(mock_rdb)
    profileid = 'profile_10.0.2.15'
    mac_addr = '08:00:27:7f:09:e1'

    # # mock the online vendor
    # if the vendor isn't found offline, this mocker will run instead of get_vendor_online
    mock_requests = mocker.patch("requests.get")
    mock_requests.return_value.status_code = 200
    mock_requests.return_value.text = 'PCS Systemtechnik GmbH'
    mock_rdb.get_mac_vendor_from_profile.return_value = False

    # tries to get vendor either online or from our offline db
    mac_info = ip_info.get_vendor(mac_addr, profileid)

    assert mac_info is not False
    assert mac_info['Vendor'].lower() == 'Pcs Systemtechnik GmbH'.lower()
