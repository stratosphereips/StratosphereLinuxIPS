import pytest
from tests.module_factory import ModuleFactory
from unittest.mock import patch

import shutil
import os
import json


@pytest.mark.parametrize(
    'input_type,input_information',
    [('pcap', 'dataset/test12-icmp-portscan.pcap')],
)
def test_handle_pcap_and_interface(
    input_type, input_information,
        mock_db
):
    # no need to test interfaces because in that case read_zeek_files runs in a loop and never returns
    input = ModuleFactory().create_inputProcess_obj(input_information, input_type, mock_db)
    input.zeek_pid = 'False'
    input.is_zeek_tabs = False
    assert input.handle_pcap_and_interface() is True
    # delete the zeek logs created
    shutil.rmtree(input.zeek_dir)


@pytest.mark.parametrize(
    'zeek_dir, is_tabs',
    [
        ('dataset/test10-mixed-zeek-dir/', False), # tabs
        ('dataset/test9-mixed-zeek-dir/', True), # json
    ],
)
def test_is_growing_zeek_dir(
     zeek_dir: str, is_tabs: bool,
        mock_db
):
    input = ModuleFactory().create_inputProcess_obj(zeek_dir, 'zeek_folder', mock_db)
    mock_db.get_all_zeek_files.return_value = [os.path.join(zeek_dir, 'conn.log')]

    assert input.read_zeek_folder() is True



@pytest.mark.parametrize(
    'path, expected_val',
    [
        ('dataset/test10-mixed-zeek-dir/conn.log', True), # tabs
        ('dataset/test9-mixed-zeek-dir/conn.log', False), # json
    ],
)
def test_is_zeek_tabs_file(path: str, expected_val: bool,
                           mock_db
                           ):
    input = ModuleFactory().create_inputProcess_obj(path, 'zeek_folder', mock_db)
    assert input.is_zeek_tabs_file(path) == expected_val


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
    input_information,
        mock_db, expected_output
):
    input = ModuleFactory().create_inputProcess_obj(input_information, 'zeek_log_file', mock_db)
    assert input.handle_zeek_log_file() == expected_output


@pytest.mark.parametrize(
    'path, is_tabs, line_cached',
    [
        # sllips shouldn't be able to cache teh first line as it's a comment
        ('dataset/test10-mixed-zeek-dir/conn.log', True, False),
        ('dataset/test9-mixed-zeek-dir/conn.log', False, True),
    ],
)

def test_cache_nxt_line_in_file(
        path: str, is_tabs: str, line_cached: bool ,
        mock_db
        ):
    """
    :param line_cached: should slips cache  the first line of this file or not
    """
    input = ModuleFactory().create_inputProcess_obj(path, 'zeek_log_file', mock_db)
    input.cache_lines = {}
    input.file_time = {}
    input.is_zeek_tabs = is_tabs

    assert input.cache_nxt_line_in_file(path) == line_cached
    if line_cached:
        assert input.cache_lines[path]['type'] == path
        # make sure it did read 1 line from the file
        assert input.cache_lines[path]['data']

@pytest.mark.parametrize(
    'path, is_tabs, zeek_line, expected_val',
    [
        (
            'dataset/test10-mixed-zeek-dir/conn.log',
             True,
             '1601998375.703087       ClqdMB11qLHjikB6bd      2001:718:2:1663:dc58:6d9:ef13:51a5      63580   2a00:1450:4014:80c::200a443     udp     -       30.131973       6224    10110   SF      -       -       0       Dd      14      6896    15     10830    -',
             1601998375.703087
         ),
        (
            'dataset/test9-mixed-zeek-dir/conn.log',
            False,
            '{"ts":271.102532,"uid":"CsYeNL1xflv3dW9hvb","id.orig_h":"10.0.2.15","id.orig_p":59393,'
            '"id.resp_h":"216.58.201.98","id.resp_p":443,"proto":"udp","duration":0.5936019999999758,"orig_bytes":5219,"resp_bytes":5685,"conn_state":"SF","missed_bytes":0,"history":"Dd","orig_pkts":9,"orig_ip_bytes":5471,"resp_pkts":10,"resp_ip_bytes":5965}',
            271.102532
        ),


        # this scenario is corrupted and should fail
        (
            'dataset/test9-mixed-zeek-dir/conn.log',
            False,
            '{"ts":"corrupted","uid":"CsYeNL1xflv3dW9hvb","id.orig_h":"10.0.2.15","id.orig_p":59393,'
            '"id.resp_h":"216.58.201.98","id.resp_p":443,"proto":"udp","duration":0.5936019999999758,"orig_bytes":5219,"resp_bytes":5685,"conn_state":"SF","missed_bytes":0,"history":"Dd","orig_pkts":9,"orig_ip_bytes":5471,"resp_pkts":10,"resp_ip_bytes":5965}',
            (False, False)
        )
    ],
)
def test_get_ts_from_line(
        path: str, is_tabs: str,zeek_line: str, expected_val:float,
        mock_db
        ):
    input = ModuleFactory().create_inputProcess_obj(path, 'zeek_log_file', mock_db)
    input.is_zeek_tabs = is_tabs
    input.get_ts_from_line(zeek_line)


@pytest.mark.parametrize(
    'last_updated_file_time, now, bro_timeout, expected_val, ',
    [
        (0, 20, 10, True),
        (0, 10, 10, True),
        (0, 5, 10, False),
        (0, 5, float('inf'), False),
    ]
    )
def test_reached_timeout(
        last_updated_file_time, now, bro_timeout, expected_val,
        mock_db
        ):
    input = ModuleFactory().create_inputProcess_obj(
        '', 'zeek_log_file', mock_db
        )
    input.last_updated_file_time = last_updated_file_time
    input.bro_timeout = bro_timeout
    # make it seem as we don't have cache lines anymore to be able to check the timeout
    input.cache_lines = False
    with patch('datetime.datetime') as dt:
        dt.now.return_value = now
        assert input.reached_timeout() == expected_val




@pytest.mark.skipif(
    'nfdump' not in shutil.which('nfdump'), reason='nfdump is not installed'
)
@pytest.mark.parametrize(
    'path', [('dataset/test1-normal.nfdump')]
)
def test_handle_nfdump(
    path,
        mock_db
):
    input = ModuleFactory().create_inputProcess_obj(path, 'nfdump', mock_db)
    assert input.handle_nfdump() is True


def test_get_earliest_line(
        mock_db
        ):
    input = ModuleFactory().create_inputProcess_obj(
        '', 'zeek_log_file', mock_db
        )
    input.file_time = {
        'software.log': 3,
         'ssh.log': 2,
         'notice.log': 1,
         'dhcp.log': 4,
         'arp.log': 5,
         'conn.log': 5,
         'dns.log': 6,
    }
    input.cache_lines = {
        'software.log': 'line3',
         'ssh.log': 'line2',
         'notice.log': 'line1',
         'dhcp.log': 'line4',
         'arp.log': 'line5',
         'conn.log': 'line5',
         'dns.log': 'line6',
        }
    assert input.get_earliest_line() == ('line1' , 'notice.log')



@pytest.mark.parametrize(
    'path, is_tabs, expected_val',
    [
        ('dataset/test1-normal.nfdump', False, 4646),
        ('dataset/test9-mixed-zeek-dir/conn.log', False, 577 ),
        ('dataset/test10-mixed-zeek-dir/conn.log', True, 116)
     ]
)
def test_get_flows_number(
        path: str, is_tabs: bool, expected_val: int,
        mock_db
        ):
    input = ModuleFactory().create_inputProcess_obj(path, 'nfdump', mock_db)
    input.is_zeek_tabs = is_tabs
    assert input.get_flows_number(path) == expected_val



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
    input_type, input_information,
        mock_db
):
    input = ModuleFactory().create_inputProcess_obj(input_information, input_type, mock_db)
    with patch.object(input, 'get_flows_number', return_value=5):
        assert input.handle_binetflow() is True


@pytest.mark.parametrize(
    'input_information',
    [('dataset/test6-malicious.suricata.json')],
)
def test_handle_suricata(
    input_information,
        mock_db
):
    inputProcess = ModuleFactory().create_inputProcess_obj(input_information, 'suricata', mock_db)
    assert inputProcess.handle_suricata() is True

@pytest.mark.parametrize(
    'line_type, line',
    [
        ('zeek', '{"ts":271.102532,"uid":"CsYeNL1xflv3dW9hvb","id.orig_h":"10.0.2.15","id.orig_p":59393,'
                 '"id.resp_h":"216.58.201.98","id.resp_p":443,"proto":"udp","duration":0.5936019999999758,'
                 '"orig_bytes":5219,"resp_bytes":5685,"conn_state":"SF","missed_bytes":0,"history":"Dd",'
                 '"orig_pkts":9,"orig_ip_bytes":5471,"resp_pkts":10,"resp_ip_bytes":5965}'),
        ('suricata', '{"timestamp":"2021-06-06T15:57:37.272281+0200","flow_id":2054715089912378,"event_type":"flow",'
                     '"src_ip":"193.46.255.92","src_port":49569,"dest_ip":"192.168.1.129","dest_port":8014,'
                     '"proto":"TCP","flow":{"pkts_toserver":2,"pkts_toclient":2,"bytes_toserver":120,"bytes_toclient":120,"start":"2021-06-07T15:45:48.950842+0200","end":"2021-06-07T15:45:48.951095+0200","age":0,"state":"closed","reason":"shutdown","alerted":false},"tcp":{"tcp_flags":"16","tcp_flags_ts":"02","tcp_flags_tc":"14","syn":true,"rst":true,"ack":true,"state":"closed"},"host":"stratosphere.org"}'),
        ('argus', '2019/04/05 16:15:09.194268,0.031142,udp,10.8.0.69,8278,  <->,8.8.8.8,53,CON,0,0,2,186,64,1,'),
     ],
)

def test_read_from_stdin(line_type: str, line: str,
                         mock_db
                         ):
    # slips supports reading zeek json conn.log only using stdin,
    # tabs aren't supported
    input = ModuleFactory().create_inputProcess_obj(
        line_type, 'stdin', mock_db, line_type=line_type,
        )
    with patch.object(input, 'stdin', return_value=[line, 'done\n']):
        # this function will give the line to profiler
        assert input.read_from_stdin()
        line_sent : dict = input.profiler_queue.get()
        # in case it's a zeek line, it gets sent as a dict
        expected_received_line = json.loads(line) if line_type == 'zeek' else line
        assert line_sent['line']['data'] == expected_received_line
        assert line_sent['line']['line_type'] == line_type
        assert line_sent['input_type'] == 'stdin'







@pytest.mark.parametrize(
    'line_type, line',
    [
        ('zeek', '{"ts":271.102532,"uid":"CsYeNL1xflv3dW9hvb","id.orig_h":"10.0.2.15","id.orig_p":59393,'
                 '"id.resp_h":"216.58.201.98","id.resp_p":443,"proto":"udp","duration":0.5936019999999758,'
                 '"orig_bytes":5219,"resp_bytes":5685,"conn_state":"SF","missed_bytes":0,"history":"Dd",'
                 '"orig_pkts":9,"orig_ip_bytes":5471,"resp_pkts":10,"resp_ip_bytes":5965}'),
        ('suricata', '{"timestamp":"2021-06-06T15:57:37.272281+0200","flow_id":2054715089912378,"event_type":"flow",'
                     '"src_ip":"193.46.255.92","src_port":49569,"dest_ip":"192.168.1.129","dest_port":8014,'
                     '"proto":"TCP","flow":{"pkts_toserver":2,"pkts_toclient":2,"bytes_toserver":120,"bytes_toclient":120,"start":"2021-06-07T15:45:48.950842+0200","end":"2021-06-07T15:45:48.951095+0200","age":0,"state":"closed","reason":"shutdown","alerted":false},"tcp":{"tcp_flags":"16","tcp_flags_ts":"02","tcp_flags_tc":"14","syn":true,"rst":true,"ack":true,"state":"closed"},"host":"stratosphere.org"}'),
        ('argus', '2019/04/05 16:15:09.194268,0.031142,udp,10.8.0.69,8278,  <->,8.8.8.8,53,CON,0,0,2,186,64,1,'),
     ],
)

def test_read_from_stdin(line_type: str, line: str,
                         mock_db
                         ):
    # slips supports reading zeek json conn.log only using stdin,
    # tabs aren't supported
    input = ModuleFactory().create_inputProcess_obj(
        line_type, 'stdin', mock_db, line_type=line_type,
        )
    with patch.object(input, 'stdin', return_value=[line, 'done\n']):
        # this function will give the line to profiler
        assert input.read_from_stdin()
        line_sent : dict = input.profiler_queue.get()
        # in case it's a zeek line, it gets sent as a dict
        expected_received_line = json.loads(line) if line_type == 'zeek' else line
        assert line_sent['line']['data'] == expected_received_line
        assert line_sent['line']['line_type'] == line_type
        assert line_sent['input_type'] == 'stdin'






