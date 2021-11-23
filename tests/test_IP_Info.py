""" Unit test for modules/IP_Info/IP_Info.py """
from ..modules.IP_Info.IP_Info import Module
import configparser


def do_nothing(*args):
    """ Used to override the print function because using the self.print causes broken pipes """
    pass

def create_IP_Info_instance(outputQueue):
    """ Create an instance of asn.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    IP_Info = Module(outputQueue, config)
    # override the self.print function to avoid broken pipes
    IP_Info.print = do_nothing
    return IP_Info


#ASN unit tests
def test_get_asn_info_from_geolite(outputQueue, database):
    IP_Info = create_IP_Info_instance(outputQueue)
    # check an ip that we know is in the db
    assert IP_Info.get_asn_info_from_geolite('108.200.116.255') == {'asn': {'asnorg': 'ATT-INTERNET4'}}
    # test  asn info not found in geolite
    assert IP_Info.get_asn_info_from_geolite('0.0.0.0') == {'asn': {'asnorg': 'Unknown'}}

def test_cache_ip_range(outputQueue, database):
    IP_Info = create_IP_Info_instance(outputQueue)
    assert IP_Info.cache_ip_range('8.8.8.8') == True

#RDNS unit tests

def test_get_rdns(outputQueue, database):
    IP_Info = create_IP_Info_instance(outputQueue)
    # check an ip that we know has a rdns
    assert IP_Info.get_rdns('99.81.154.45') == {'reverse_dns': 'ec2-99-81-154-45.eu-west-1.compute.amazonaws.com'}
    # test  RDNS info not found
    assert IP_Info.get_rdns('0.0.0.0') == False

#GEOIP unit tests

def test_get_geocountry(outputQueue, database):
    IP_Info = create_IP_Info_instance(outputQueue)
    assert IP_Info.get_geocountry('153.107.41.230') == {'geocountry': 'Australia'}
    assert IP_Info.get_geocountry('23.188.195.255') == {'geocountry': 'Unknown'}


# MAC unit tests
def test_get_vendor(outputQueue, database):
    IP_Info = create_IP_Info_instance(outputQueue)
    profileid = 'profile_10.0.2.15'
    mac_addr = '08:00:27:7f:09:e1'
    host_name = 'FooBar-PC'
    mac_info = IP_Info.get_vendor(mac_addr, host_name, profileid)
    assert mac_info != False
    assert mac_info['Vendor'] == 'Pcs Systemtechnik GmbH'
