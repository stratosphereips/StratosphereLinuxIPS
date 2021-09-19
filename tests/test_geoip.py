""" Unit test for modules/geoip/geoip.py """
from ..modules.geoip.geoip import Module
import configparser


def do_nothing(*args):
    """ Used to override the print function because using the self.print causes broken pipes """
    pass

def create_geopip_instance(outputQueue):
    """ Create an instance of geoip.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    geoip = Module(outputQueue, config)
    geoip.bro_timeout=1
    # override the self.print function to avoid broken pipes
    geoip.print = do_nothing
    geoip.stop_queues = do_nothing
    return geoip

def test_get_geocountry_info(outputQueue, database):
    geoip = create_geopip_instance(outputQueue)
    assert geoip.get_geocountry_info('153.107.41.230') == {'geocountry': 'Australia'}
    assert geoip.get_geocountry_info('23.188.195.255') == {'geocountry': 'Unknown'}
