import pytest
from tests.module_factory import ModuleFactory
from tests.common_test_utils import do_nothing
import shutil
import os


@pytest.mark.parametrize(
    'input_type,input_information',
    [('pcap', 'dataset/test12-icmp-portscan.pcap')],
)
def test_handle_pcap_and_interface(
    input_type, input_information, mock_rdb
):
    # no need to test interfaces because in that case read_zeek_files runs in a loop and never returns
    inputProcess = ModuleFactory().create_inputProcess_obj(input_information, input_type, mock_rdb)
    inputProcess.zeek_pid = 'False'
    inputProcess.is_zeek_tabs = True
    assert inputProcess.handle_pcap_and_interface() is True
    # delete the zeek logs created
    shutil.rmtree(inputProcess.zeek_dir)


@pytest.mark.parametrize(
    'input_information',
    [
        ('dataset/test10-mixed-zeek-dir/'), # tabs
        ('dataset/test9-mixed-zeek-dir/'), # json
    ],
)
def test_read_zeek_folder(
     input_information, mock_rdb
):
    inputProcess = ModuleFactory().create_inputProcess_obj(input_information, 'zeek_folder', mock_rdb)
    # no need to get the total flows in this test, skip this part
    mock_rdb.is_growing_zeek_dir.return_value = True
    mock_rdb.get_all_zeek_file.return_value = [os.path.join(input_information, 'conn.log')]

    assert inputProcess.read_zeek_folder() is True

@pytest.mark.parametrize(
    'input_information,expected_output',
    [
        ('dataset/test10-mixed-zeek-dir/conn.log', True), #tabs
        ('dataset/test9-mixed-zeek-dir/conn.log', True), # json
        ('dataset/test9-mixed-zeek-dir/conn', False), # json
        ('dataset/test9-mixed-zeek-dir/x509.log', False), # json
    ],
)
def test_handle_zeek_log_file(
    input_information, mock_rdb, expected_output
):
    inputProcess = ModuleFactory().create_inputProcess_obj(input_information, 'zeek_log_file', mock_rdb)
    assert inputProcess.handle_zeek_log_file() == expected_output


@pytest.mark.skipif(
    'nfdump' not in shutil.which('nfdump'), reason='nfdump is not installed'
)
@pytest.mark.parametrize(
    'input_information', [('dataset/test1-normal.nfdump')]
)
def test_handle_nfdump(
    input_information, mock_rdb
):
    inputProcess = ModuleFactory().create_inputProcess_obj(input_information, 'nfdump', mock_rdb)
    assert inputProcess.handle_nfdump() is True



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
    input_type, input_information, mock_rdb
):
    inputProcess = ModuleFactory().create_inputProcess_obj(input_information, input_type, mock_rdb)
    assert inputProcess.handle_binetflow() is True


@pytest.mark.parametrize(
    'input_type,input_information',
    [('suricata', 'dataset/test6-malicious.suricata.json')],
)
def test_handle_suricata(
    input_type, input_information, mock_rdb
):
    inputProcess = ModuleFactory().create_inputProcess_obj(input_information, input_type, mock_rdb)
    assert inputProcess.handle_suricata() is True
