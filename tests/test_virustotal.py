""" Unit test for modules/virustotal/virustotal.py """
from ..modules.virustotal.virustotal import Module
import configparser
import random
import pytest

def do_nothing(*args):
    """ Used to override the print function because using the self.print causes broken pipes """
    pass

def get_vt_key():
    # get the user's api key
    with open('../modules/virustotal/api_key_secret','r') as f:
        api_key = f.read()
    return api_key

@pytest.fixture
def read_configuration():
    return

def create_virustotal_instance(outputQueue):
    """ Create an instance of virustotal.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    with open("slips.conf") as conf_file:
        config.read_file(conf_file)
    virustotal = Module(outputQueue, config)
    # override the self.print function to avoid broken pipes
    virustotal.print = do_nothing
    virustotal.__read_configuration = read_configuration
    virustotal.key_file = '/media/alya/W/SLIPPS/modules/virustotal/api_key_secret'
    # virustotal.key = get_vt_key()
    return virustotal


def test_api_limit(outputQueue):
    virustotal = create_virustotal_instance(outputQueue)
    ip = str(random.randint(0, 255)) + "." + str(random.randint(0, 255)) + "."\
         + str(random.randint(0, 255)) + "." + str(random.randint(0, 255))
    virustotal.api_query_(ip)
    # remember to set a key_file

@pytest.mark.parametrize("ip", ['8.8.8.8'])
def test_api_query_(outputQueue, ip):
    virustotal = create_virustotal_instance(outputQueue)
    response = virustotal.api_query_(ip)
    # make sure response.status != 204 or 403
    assert len(response.keys())>0
    assert response['response_code'] == 1

@pytest.mark.parametrize("ip", ['8.8.8.8'])
def test_interpret_rsponse(outputQueue, ip):
    virustotal = create_virustotal_instance(outputQueue)
    response = virustotal.api_query_(ip)
    for ratio in virustotal.interpret_response(response):
        assert type(ratio) == float
