"""Unit test for slips_files/core/performance_profiler.py"""
import ipaddress

from tests.module_factory import ModuleFactory
from tests.common_test_utils import do_nothing
import subprocess
import pytest
import json
from slips_files.core.profiler import SUPPORTED_INPUT_TYPES, SEPARATORS
from slips_files.core.flows.zeek import Conn



@pytest.mark.parametrize(
    'file,input_type,expected_value',
    [('dataset/test6-malicious.suricata.json', 'suricata', 'suricata')]
)
def test_define_separator_suricata(file, input_type, expected_value,
                                   mock_db
                                   ):
    profilerProcess = ModuleFactory().create_profiler_obj(mock_db)
    with open(file) as f:
        while True:
            sample_flow = f.readline().replace('\n', '')
            # get the first line that isn't a comment
            if not sample_flow.startswith('#'):
                break

    sample_flow = {
        'data': sample_flow,
    }
    profiler_detected_type: str = profilerProcess.define_separator(sample_flow, input_type)
    assert profiler_detected_type == expected_value


@pytest.mark.parametrize(
    'file,input_type,expected_value',
    [('dataset/test10-mixed-zeek-dir/conn.log', 'zeek_log_file', 'zeek-tabs')],
)
def test_define_separator_zeek_tab(file, input_type, expected_value,
                                   mock_db
                                   ):
    profilerProcess = ModuleFactory().create_profiler_obj(mock_db)
    with open(file) as f:
        while True:
            sample_flow = f.readline().replace('\n', '')
            # get the first line that isn't a comment
            if not sample_flow.startswith('#'):
                break

    sample_flow = {
        'data': sample_flow,
    }
    profiler_detected_type: str = profilerProcess.define_separator(sample_flow, input_type)
    assert profiler_detected_type == expected_value


@pytest.mark.parametrize(
    'file, input_type,expected_value',
    [('dataset/test9-mixed-zeek-dir/conn.log', 'zeek_log_file', 'zeek')]
)
def test_define_separator_zeek_dict(file, input_type, expected_value,
                                    mock_db
                                    ):
    """
    :param input_type: as determined by slips.py
    """

    profilerProcess = ModuleFactory().create_profiler_obj(mock_db)
    with open(file) as f:
        sample_flow = f.readline().replace('\n', '')

    sample_flow = json.loads(sample_flow)
    sample_flow = {
        'data': sample_flow,
    }
    profiler_detected_type: str = profilerProcess.define_separator(sample_flow, input_type)
    assert profiler_detected_type == expected_value


@pytest.mark.parametrize('nfdump_file', [('dataset/test1-normal.nfdump')])
def test_define_separator_nfdump(nfdump_file,
                                 mock_db
                                 ):
    # nfdump files aren't text files so we need to process them first
    command = f'nfdump -b -N -o csv -q -r {nfdump_file}'
    # Execute command
    result = subprocess.run(command.split(), stdout=subprocess.PIPE)
    # Get command output
    nfdump_output = result.stdout.decode('utf-8')
    input_type = 'nfdump'
    for nfdump_line in nfdump_output.splitlines():
        # this line is taken from stdout we need to remove whitespaces
        nfdump_line.replace(' ', '')
        ts = nfdump_line.split(',')[0]
        if not ts[0].isdigit():
            continue
        else:
            break

    profilerProcess = ModuleFactory().create_profiler_obj(mock_db)
    sample_flow = {
        'data': nfdump_line,
    }
    profiler_detected_type: str = profilerProcess.define_separator(sample_flow, input_type)
    assert profiler_detected_type == 'nfdump'



# @pytest.mark.parametrize(
#     'file,separator,expected_value',
#     [
#         (
#             'dataset/test10-mixed-zeek-dir/conn.log',
#             '	',
#             {'dur': 9, 'proto': 7, 'state': 12},
#         )
#     ],
# )
# def test_define_columns(
#     file, separator, expected_value, mock_db
# ):
#     # define_columns is called on header lines
#     # line = '#fields ts      uid     id.orig_h       id.orig_p
#     # id.resp_h       id.resp_p       proto   service duration
#     # orig_bytes      resp_bytes       conn_state      local_orig
#     # local_resp      missed_bytes    history orig_pkts
#     # orig_ip_bytes   resp_pkts       resp_ip_bytes   tunnel_parents'
#     with open(file) as f:
#         while True:
#             # read from the file until you find the header
#             line = f.readline()
#             if line.startswith('#fields'):
#                 break
#     profilerProcess = ModuleFactory().create_profiler_obj(mock_db)
#     line = {'data': line}
#     profilerProcess.separator = separator
#     assert profilerProcess.define_columns(line) == expected_value


# pcaps are treated as zeek files in slips, no need to test twice


@pytest.mark.parametrize(
    'file,flow_type',
    [
        ('dataset/test9-mixed-zeek-dir/dns.log', 'dns'),
        ('dataset/test9-mixed-zeek-dir/conn.log', 'conn'),
        ('dataset/test9-mixed-zeek-dir/http.log', 'http'),
        ('dataset/test9-mixed-zeek-dir/ssl.log', 'ssl'),
        ('dataset/test9-mixed-zeek-dir/notice.log', 'notice'),
        # ('dataset/test9-mixed-zeek-dir/files.log', 'files.log'),
    ],
)
def test_process_line(file, flow_type, mock_db):
    profiler = ModuleFactory().create_profiler_obj(mock_db)
    # we're testing another functionality here
    profiler.whitelist.is_whitelisted_flow = do_nothing
    profiler.input_type = 'zeek'
    # get the class that handles the zeek input
    profiler.input_handler = SUPPORTED_INPUT_TYPES[profiler.input_type]()
    # set  the zeek json separator
    profiler.separator = SEPARATORS[profiler.input_type]

    # get zeek flow
    with open(file) as f:
        sample_flow = f.readline().replace('\n', '')

    sample_flow = json.loads(sample_flow)
    sample_flow = {
        'data': sample_flow,
        'type': flow_type
    }

    # process it
    profiler.flow = profiler.input_handler.process_line(sample_flow)
    assert profiler.flow

    # add to profile
    added_to_prof = profiler.add_flow_to_profile()
    assert added_to_prof is True

    uid = profiler.flow.uid
    profileid =  profiler.profileid
    twid =  profiler.twid

    # make sure it's added
    if flow_type == 'conn':
        added_flow = profiler.db.get_flow(uid, twid=twid)[uid]
    else:
        added_flow = (
            profiler.db.get_altflow_from_uid(profileid, twid, uid) is not None
        )
    assert added_flow is not None

def test_get_rev_profile(mock_db):
    profiler = ModuleFactory().create_profiler_obj(mock_db)
    profiler.flow = Conn(
                '1.0',
                '1234',
                '192.168.1.1',
                '8.8.8.8',
                5,
                'TCP',
                'dhcp',
                80,88,
                20,20,
                20,20,
                '','',
                'Established',''
            )
    mock_db.get_profileid_from_ip.return_value = None
    mock_db.get_timewindow.return_value = 'timewindow1'
    assert profiler.get_rev_profile() == ('profile_8.8.8.8', 'timewindow1')

def test_get_rev_profile_no_daddr(flow, mock_db):
    profiler = ModuleFactory().create_profiler_obj(mock_db)
    profiler.flow = flow
    profiler.flow.daddr = None
    profiler.daddr_as_obj = None
    assert profiler.get_rev_profile() == (False, False)

