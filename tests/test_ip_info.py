"""Unit test for modules/ip_info/ip_info.py"""
from ..modules.ip_info.ip_info import Module
from ..modules.ip_info.asn_info import ASN
from ..modules.update_manager.update_file_manager import UpdateFileManager
import maxminddb
import pytest

def do_nothing(*args):
    """Used to override the print function because using the self.print causes broken pipes"""
    pass


def create_ip_info_instance(outputQueue):
    """Create an instance of ip_info.py
    needed by every other test in this file"""
    ip_info = Module(outputQueue, 6380)
    # override the self.print function to avoid broken pipes
    ip_info.print = do_nothing
    return ip_info

# needed to make sure the macdb is downloaded before running the unit tests
def create_update_manager_instance(outputQueue):
    """Create an instance of update_manager.py
    needed by every other test in this file"""
    update_manager = UpdateFileManager(outputQueue, 6380)
    # override the self.print function to avoid broken pipes
    update_manager.print = do_nothing
    return update_manager

def create_ASN_Info_instance():
    """Create an instance of asn_info.py
    needed by every other test in this file"""
    ASN_Info = ASN()
    return ASN_Info


# ASN unit tests
def test_get_asn_info_from_geolite(database):
    """
    geolite is an offline db
    """
    ASN_info = create_ASN_Info_instance()
    # check an ip that we know is in the db
    expected_asn_info = {'asn': {'number': 'AS7018', 'org': 'ATT-INTERNET4'}}
    assert ASN_info.get_asn_info_from_geolite('108.200.116.255') == expected_asn_info
    # test  asn info not found in geolite
    assert ASN_info.get_asn_info_from_geolite('0.0.0.0') == {}

def test_cache_ip_range(database):
    ASN_info = create_ASN_Info_instance()
    assert ASN_info.cache_ip_range('8.8.8.8') == {'asn': {'number': 'AS15169', 'org': 'GOOGLE, US'}}

# GEOIP unit tests
def test_get_geocountry(outputQueue, database):
    ip_info = create_ip_info_instance(outputQueue)

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

def test_get_vendor(outputQueue, database, mocker):
    # make sure the mac db is download so that wai_for_dbs doesn't wait forever :'D
    ip_info = create_ip_info_instance(outputQueue)
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
    assert mac_info != False
    assert mac_info['Vendor'].lower() == 'Pcs Systemtechnik GmbH'.lower()
