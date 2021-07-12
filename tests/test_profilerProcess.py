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

@pytest.mark.parametrize("file,expected_value",[('dataset/sample_zeek_files-2/conn.log','zeek-tabs'),
                                                ('dataset/dataset/hide-and-seek-short.pcap','zeek'),
                                                ('dataset/suricata-flows.json','suricata'),
                                                ('dataset/test.nfdump','nfdump'),
                                                ])
def test_define_type(outputQueue, inputQueue, file, expected_value):
    profilerProcess = create_profilerProcess_instance(outputQueue, inputQueue)
    with open(file) as f:
        sample_flow = f.readline()
    # sample_flow is always a str, try to convert to a dict
    try:
        sample_flow = dict(sample_flow)
    except ValueError:
        # if it's not a dict , eg zeek tab separated line, leave it as it is
        pass
    sample_flow = {'data': sample_flow,
                   'type': expected_value}
    assert profilerProcess.define_type(sample_flow) == expected_value


@pytest.mark.parametrize("file,separator,expected_value",[('dataset/sample_zeek_files-2/conn.log','	',{'starttime': 1})])
def test_define_columns(outputQueue, inputQueue,file,separator,expected_value):
    # define_columns is called on header lines
    # line = '#fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       proto   service duration        orig_bytes      resp_bytes       conn_state      local_orig      local_resp      missed_bytes    history orig_pkts       orig_ip_bytes   resp_pkts       resp_ip_bytes   tunnel_parents'
    with open(file) as f:
        while True:
            # read from the file until you find the header
            line = f.readline()
            if line.startswith('#types'):
                break
    profilerProcess = create_profilerProcess_instance(outputQueue, inputQueue)
    line = {'data': line}
    profilerProcess.separator = separator
    assert profilerProcess.define_columns(line) == expected_value