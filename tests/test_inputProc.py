import pytest
from slips_files.core.inputProcess import InputProcess
import configparser
import shutil
import os

def do_nothing(*arg):
    """Used to override the print function because using the self.print causes broken pipes"""
    pass

zeek_tmp_dir = os.path.join(os.getcwd(), 'zeek_dir_for_testing' )

def create_inputProcess_instance(
    outputQueue, profilerQueue, input_information, input_type
):
    """Create an instance of inputProcess.py
    needed by every other test in this file"""
    inputProcess = InputProcess(
        outputQueue,
        profilerQueue,
        input_type,
        input_information,
        None,
        'zeek',
        zeek_tmp_dir,
        False,
        65531
    )
    inputProcess.bro_timeout = 1
    # override the self.print function to avoid broken pipes
    inputProcess.print = do_nothing
    inputProcess.stop_queues = do_nothing
    inputProcess.testing = True
    return inputProcess


@pytest.mark.parametrize(
    'input_type,input_information',
    [('pcap', 'dataset/test7-malicious.pcap')],
)
def test_handle_pcap_and_interface(
    outputQueue, profilerQueue, input_type, input_information
):
    # no need to test interfaces because in that case read_zeek_files runs in a loop and never returns
    inputProcess = create_inputProcess_instance(
        outputQueue, profilerQueue, input_information, input_type
    )
    assert inputProcess.handle_pcap_and_interface() == True


@pytest.mark.parametrize(
    'input_type,input_information',
    [
        ('zeek_folder', 'dataset/test9-mixed-zeek-dir-2/'),
        ('zeek_folder', 'dataset/test9-mixed-zeek-dir/'),
    ],
)
def test_read_zeek_folder(
    outputQueue, profilerQueue, input_type, input_information
):
    inputProcess = create_inputProcess_instance(
        outputQueue, profilerQueue, input_information, input_type
    )
    assert inputProcess.read_zeek_folder() == True


@pytest.mark.parametrize(
    'input_type,input_information',
    [
        ('zeek_log_file', 'dataset/test9-mixed-zeek-dir-2/conn.log'),
        ('zeek_log_file', 'dataset/test9-mixed-zeek-dir/conn.log'),
    ],
)
def test_handle_zeek_log_file(
    outputQueue, profilerQueue, input_type, input_information
):
    inputProcess = create_inputProcess_instance(
        outputQueue, profilerQueue, input_information, input_type
    )
    assert inputProcess.handle_zeek_log_file() == True


@pytest.mark.parametrize(
    'input_type,input_information', [('nfdump', 'dataset/test1-normal.nfdump')]
)
def test_handle_nfdump(
    outputQueue, profilerQueue, input_type, input_information
):
    inputProcess = create_inputProcess_instance(
        outputQueue, profilerQueue, input_information, input_type
    )
    assert inputProcess.handle_nfdump() == True


@pytest.mark.skipif(
    'nfdump' not in shutil.which('nfdump'), reason='nfdump is not installed'
)
@pytest.mark.parametrize(
    'input_type,input_information',
    [
        ('binetflow', 'dataset/test2-malicious.binetflow'),
        ('binetflow', 'dataset/test5-mixed.binetflow'),
    ],
)
#                                                           ('binetflow','dataset/test3-mixed.binetflow'),
#                                                           ('binetflow','dataset/test4-mixed.binetflow'),
def test_handle_binetflow(
    outputQueue, profilerQueue, input_type, input_information
):
    inputProcess = create_inputProcess_instance(
        outputQueue, profilerQueue, input_information, input_type
    )
    assert inputProcess.handle_binetflow() == True


@pytest.mark.parametrize(
    'input_type,input_information',
    [('suricata', 'dataset/test6-malicious.suricata.json')],
)
def test_handle_suricata(
    outputQueue, profilerQueue, input_type, input_information
):
    inputProcess = create_inputProcess_instance(
        outputQueue, profilerQueue, input_information, input_type
    )
    assert inputProcess.handle_suricata() == True
