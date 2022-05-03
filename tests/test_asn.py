""" Unit test for modules/asn/asn.py """
from ..modules.asn.asn import Module
import configparser


def do_nothing(*args):
    """ Used to override the print function because using the self.print causes broken pipes """
    pass

def create_asn_instance(outputQueue):
    """ Create an instance of asn.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    asn = Module(outputQueue, config)
    # override the self.print function to avoid broken pipes
    asn.print = do_nothing
    return asn

def test_get_asn_info_from_geolite(outputQueue, database):
    asn = create_asn_instance(outputQueue)
    # check an ip that we know is in the db
    assert asn.get_asn_info_from_geolite('108.200.116.255') == {'asn': {'asnorg': 'ATT-INTERNET4'}}
    # test  asn info not found in geolite
    assert asn.get_asn_info_from_geolite('0.0.0.0') == {'asn': {'asnorg': 'Unknown'}}

def test_cache_ip_range(outputQueue, database):
    asn = create_asn_instance(outputQueue)
    assert asn.cache_ip_range('8.8.8.8') == True


