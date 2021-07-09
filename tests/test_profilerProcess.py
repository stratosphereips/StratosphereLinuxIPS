""" Unit test for ../profilerProcess.py """
from ..profilerProcess import ProfilerProcess
import configparser
import pytest

def do_nothing(*args):
    """ Used to override the print function because using the self.print causes broken pipes """
    pass

def create_profilerProcess_instance(outputQueue, inputQueue):
    """ Create an instance of profilerProcess.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    profilerProcess = ProfilerProcess(inputQueue , outputQueue,1,0, config)
    # override the self.print function to avoid broken pipes
    profilerProcess.print = do_nothing
    return profilerProcess

def test_read_whitelist(outputQueue, inputQueue):
    """
    make sure the content of whitelists is read and stored properly
    uses tests/test_whitelist.conf for testing
    """
    profilerProcess = create_profilerProcess_instance(outputQueue, inputQueue)
    # 9 is the number of lines read after the comment lines at th ebegging of the file
    assert profilerProcess.read_whitelist("tests/test_whitelist.conf") == 9
    assert '91.121.83.118' in profilerProcess.whitelisted_IPs.keys()
    assert 'apple.com' in profilerProcess.whitelisted_domains.keys()
    assert 'microsoft' in profilerProcess.whitelisted_orgs.keys()

@pytest.mark.parametrize("org,asn",[('google','as19448')])
def test_load_org_asn(org,outputQueue, inputQueue, asn):
    profilerProcess = create_profilerProcess_instance(outputQueue, inputQueue)
    assert profilerProcess.load_org_asn(org) != False
    assert asn in profilerProcess.load_org_asn(org)

@pytest.mark.parametrize("org,subnet",[('google','216.73.80.0/20')])
def test_load_org_IPs(org,outputQueue, inputQueue, subnet):
    profilerProcess = create_profilerProcess_instance(outputQueue, inputQueue)
    assert profilerProcess.load_org_IPs(org) != False
    assert subnet in profilerProcess.load_org_IPs(org)