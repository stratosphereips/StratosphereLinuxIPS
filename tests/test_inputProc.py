import pytest
from tests.module_factory import ModuleFactory
from tests.common_test_utils import do_nothing
import shutil
import os


@pytest.mark.parametrize(
    'input_type,input_information',
    [('pcap', 'dataset/test7-malicious.pcap')],
)
def test_handle_pcap_and_interface(
    output_queue, profiler_queue, input_type, input_information
):
    # no need to test interfaces because in that case read_zeek_files runs in a loop and never returns
    inputProcess = ModuleFactory().create_inputProcess_obj(input_information, input_type)
    inputProcess.zeek_pid = 'False'
    inputProcess.is_zeek_tabs = True
    assert inputProcess.handle_pcap_and_interface() is True


@pytest.mark.parametrize(
    'input_type,input_information',
    [
        ('zeek_folder', 'dataset/test10-mixed-zeek-dir/'), # tabs
        ('zeek_folder', 'dataset/test9-mixed-zeek-dir/'), # json
    ],
)
def test_read_zeek_folder(
    output_queue, profiler_queue, input_type, input_information
):
    inputProcess = ModuleFactory().create_inputProcess_obj(input_information, input_type)
    assert inputProcess.read_zeek_folder() is True

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
    output_queue, profiler_queue, input_type, input_information, expected_output
):
    inputProcess = ModuleFactory().create_inputProcess_obj(input_information, input_type)
    assert inputProcess.handle_zeek_log_file() == expected_output


@pytest.mark.parametrize(
    'input_type,input_information', [('nfdump', 'dataset/test1-normal.nfdump')]
)
def test_handle_nfdump(
    output_queue, profiler_queue, input_type, input_information
):
    inputProcess = ModuleFactory().create_inputProcess_obj(input_information, input_type)
    assert inputProcess.handle_nfdump() is True


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
    output_queue, profiler_queue, input_type, input_information
):
    inputProcess = ModuleFactory().create_inputProcess_obj(input_information, input_type)
    assert inputProcess.handle_binetflow() is True


@pytest.mark.parametrize(
    'input_type,input_information',
    [('suricata', 'dataset/test6-malicious.suricata.json')],
)
def test_handle_suricata(
    output_queue, profiler_queue, input_type, input_information
):
    inputProcess = ModuleFactory().create_inputProcess_obj(input_information, input_type)
    assert inputProcess.handle_suricata() is True
