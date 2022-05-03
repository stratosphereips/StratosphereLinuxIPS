""" Unit test for modules/RDNS/RDNS.py """
from ..modules.RDNS.RDNS import Module
import configparser


def do_nothing(*args):
    """ Used to override the print function because using the self.print causes broken pipes """
    pass

def create_RDNS_instance(outputQueue):
    """ Create an instance of RDNS.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    RDNS = Module(outputQueue, config)
    # override the self.print function to avoid broken pipes
    RDNS.print = do_nothing
    return RDNS

def test_get_rdns(outputQueue, database):
    RDNS = create_RDNS_instance(outputQueue)
    # check an ip that we know has a rdns
    assert RDNS.get_rdns('99.81.154.45') == {'reverse_dns': 'ec2-99-81-154-45.eu-west-1.compute.amazonaws.com'}
    # test  RDNS info not found
    assert RDNS.get_rdns('0.0.0.0') == False
