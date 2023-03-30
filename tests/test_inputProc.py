import pytest
from slips_files.core.inputProcess import InputProcess
import shutil
import os
import random


zeek_tmp_dir = os.path.join(os.getcwd(), 'zeek_dir_for_testing' )
redis_port = 6531

def do_nothing(*arg):
    """Used to override the print function because using the print causes broken pipes"""
    pass

def check_zeek_or_bro():
    """
    Check if we have zeek or bro
    """
    zeek_bro = None
    if shutil.which('zeek'):
        zeek_bro = 'zeek'
    elif shutil.which('bro'):
        zeek_bro = 'bro'
    else:
        return False

    return zeek_bro

def create_inputProcess_instance(
    outputQueue, profilerQueue, input_information, input_type
):
    """Create an instance of inputProcess.py
    needed by every other test in this file"""
    global redis_port
    redis_port +=1
    inputProcess = InputProcess(
        outputQueue,
        profilerQueue,
        input_type,
        input_information,
        None,
        check_zeek_or_bro(),
        zeek_tmp_dir,
        False,
        redis_port
    )

    inputProcess.bro_timeout = 1
    # override the print function to avoid broken pipes
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
    inputProcess.zeek_pid = 'False'
    inputProcess.is_zeek_tabs = True
    assert inputProcess.handle_pcap_and_interface() == True


@pytest.mark.parametrize(
    'input_type,input_information',
    [
        ('zeek_folder', 'dataset/test10-mixed-zeek-dir/'), # tabs
        ('zeek_folder', 'dataset/test9-mixed-zeek-dir/'), # json
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
    'input_type,input_information,expected_output',
    [
        ('zeek_log_file', 'dataset/test10-mixed-zeek-dir/conn.log', True), #tabs
        ('zeek_log_file', 'dataset/test9-mixed-zeek-dir/conn.log', True), # json
        ('zeek_log_file', 'dataset/test9-mixed-zeek-dir/conn', False), # json
        ('zeek_log_file', 'dataset/test9-mixed-zeek-dir/x509.log', False), # json
    ],
)
def test_handle_zeek_log_file(
    outputQueue, profilerQueue, input_type, input_information, expected_output
):
    inputProcess = create_inputProcess_instance(
        outputQueue, profilerQueue, input_information, input_type
    )
    assert inputProcess.handle_zeek_log_file() == expected_output


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
#                                                           ('binetflow','dataset/test4-malicious.binetflow'),
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
