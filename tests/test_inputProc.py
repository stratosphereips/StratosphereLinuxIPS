import pytest
from inputProcess import InputProcess
import configparser
import shutil

def do_nothing(*arg):
    """ Used to override the print function because using the self.print causes broken pipes """
    pass

def create_inputProcess_instance(outputQueue, profilerQueue, input_information, input_type):
    """ Create an instance of inputProcess.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    inputProcess = InputProcess(outputQueue, profilerQueue,
                                input_type, input_information, config, None, 'zeek')
    inputProcess.bro_timeout=1
    # override the self.print function to avoid broken pipes
    inputProcess.print = do_nothing
    inputProcess.stop_queues = do_nothing
    return inputProcess

@pytest.mark.parametrize("input_type,input_information", [('pcap','dataset/hide-and-seek-short.pcap')])
def test_handle_pcap_and_interface(outputQueue, profilerQueue, input_type, input_information):
    # no need to test interfaces because in that case read_zeek_files runs in a loop and never returns
    inputProcess = create_inputProcess_instance(outputQueue, profilerQueue, input_information, input_type)
    assert inputProcess.handle_pcap_and_interface() == True


@pytest.mark.parametrize("input_type,input_information", [('zeek_folder','dataset/sample_zeek_files-2/'),
                                                          ('zeek_folder','dataset/sample_zeek_files/')])
def test_read_zeek_folder(outputQueue, profilerQueue, input_type, input_information):
    inputProcess = create_inputProcess_instance(outputQueue, profilerQueue, input_information, input_type)
    assert inputProcess.read_zeek_folder() == True


@pytest.mark.parametrize("input_type,input_information", [('zeek_log_file','dataset/sample_zeek_files-2/conn.log'),
                                                          ('zeek_log_file','dataset/sample_zeek_files/conn.log')])
def test_handle_zeek_log_file(outputQueue, profilerQueue, input_type, input_information):
    inputProcess = create_inputProcess_instance(outputQueue, profilerQueue, input_information, input_type)
    assert inputProcess.handle_zeek_log_file() == True

@pytest.mark.parametrize("input_type,input_information", [('nfdump','dataset/test.nfdump')])
def test_handle_nfdump(outputQueue, profilerQueue, input_type, input_information):
    inputProcess = create_inputProcess_instance(outputQueue, profilerQueue, input_information, input_type)
    assert inputProcess.handle_nfdump() == True


@pytest.mark.skipif('nfdump' not in shutil.which('nfdump') , reason="nfdump is not installed")
@pytest.mark.parametrize("input_type,input_information", [('binetflow','dataset/test2.binetflow'),
                                                          ('binetflow','dataset/test3.binetflow'),
                                                          ('binetflow','dataset/test4.binetflow'),
                                                          ('binetflow','dataset/test5.binetflow')
                                                          ])
def test_handle_binetflow(outputQueue, profilerQueue, input_type, input_information):
    inputProcess = create_inputProcess_instance(outputQueue, profilerQueue, input_information, input_type)
    assert inputProcess.handle_binetflow() == True


@pytest.mark.parametrize("input_type,input_information", [('suricata','dataset/suricata-flows.json')])
def test_handle_suricata(outputQueue, profilerQueue, input_type, input_information):
    inputProcess = create_inputProcess_instance(outputQueue, profilerQueue, input_information, input_type)
    assert inputProcess.handle_suricata() == True

