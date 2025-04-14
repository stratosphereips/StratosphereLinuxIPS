# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for slips_files/core/performance_profiler.py"""

from unittest.mock import Mock

from tests.module_factory import ModuleFactory
from tests.common_test_utils import do_nothing
import subprocess
import pytest
import json
from slips_files.core.profiler import SUPPORTED_INPUT_TYPES, SEPARATORS
from slips_files.core.flows.zeek import Conn
import ipaddress
from unittest.mock import patch
import queue


@pytest.mark.parametrize(
    "file,input_type,expected_value",
    [("dataset/test6-malicious.suricata.json", "suricata", "suricata")],
)
def test_define_separator_suricata(
    file,
    input_type,
    expected_value,
):
    profiler = ModuleFactory().create_profiler_obj()
    with open(file) as f:
        while True:
            sample_flow = f.readline().replace("\n", "")
            # get the first line that isn't a comment
            if not sample_flow.startswith("#"):
                break

    sample_flow = {
        "data": sample_flow,
    }
    profiler_detected_type: str = profiler.get_input_type(
        sample_flow, input_type
    )
    assert profiler_detected_type == expected_value


@pytest.mark.parametrize(
    "file,input_type,expected_value",
    [("dataset/test10-mixed-zeek-dir/conn.log", "zeek_log_file", "zeek-tabs")],
)
def test_define_separator_zeek_tab(
    file,
    input_type,
    expected_value,
):
    profiler = ModuleFactory().create_profiler_obj()
    with open(file) as f:
        while True:
            sample_flow = f.readline().replace("\n", "")
            # get the first line that isn't a comment
            if not sample_flow.startswith("#"):
                break

    sample_flow = {
        "data": sample_flow,
    }
    profiler_detected_type: str = profiler.get_input_type(
        sample_flow, input_type
    )
    assert profiler_detected_type == expected_value


@pytest.mark.parametrize(
    "file, input_type,expected_value",
    [("dataset/test9-mixed-zeek-dir/conn.log", "zeek_log_file", "zeek")],
)
def test_define_separator_zeek_dict(
    file,
    input_type,
    expected_value,
):
    """
    :param input_type: as determined by slips.py
    """

    profiler = ModuleFactory().create_profiler_obj()
    with open(file) as f:
        sample_flow = f.readline().replace("\n", "")

    sample_flow = json.loads(sample_flow)
    sample_flow = {
        "data": sample_flow,
    }
    profiler_detected_type: str = profiler.get_input_type(
        sample_flow, input_type
    )
    assert profiler_detected_type == expected_value


@pytest.mark.parametrize("nfdump_file", ["dataset/test1-normal.nfdump"])
def test_define_separator_nfdump(
    nfdump_file,
):
    # nfdump files aren't text files so we need to process them first
    command = f"nfdump -b -N -o csv -q -r {nfdump_file}"
    # Execute command
    result = subprocess.run(command.split(), stdout=subprocess.PIPE)
    # Get command output
    nfdump_output = result.stdout.decode("utf-8")
    input_type = "nfdump"
    for nfdump_line in nfdump_output.splitlines():
        # this line is taken from stdout we need to remove whitespaces
        nfdump_line.replace(" ", "")
        ts = nfdump_line.split(",")[0]
        if not ts[0].isdigit():
            continue
        else:
            break

    profiler = ModuleFactory().create_profiler_obj()
    sample_flow = {
        "data": nfdump_line,
    }
    profiler_detected_type: str = profiler.get_input_type(
        sample_flow, input_type
    )
    assert profiler_detected_type == "nfdump"


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
#     profiler = ModuleFactory().create_profiler_obj()
#     line = {'data': line}
#     profiler.separator = separator
#     assert profiler.define_columns(line) == expected_value


# pcaps are treated as zeek files in slips, no need to test twice


# get zeek flow
def get_zeek_flow(file, flow_type):
    # returns the first flow in the given file
    with open(file) as f:
        sample_flow = f.readline().replace("\n", "")

    sample_flow = json.loads(sample_flow)
    sample_flow = {"data": sample_flow, "type": flow_type}
    return sample_flow


@pytest.mark.parametrize(
    "file, flow_type",
    [
        ("dataset/test9-mixed-zeek-dir/dns.log", "dns.log"),
        ("dataset/test9-mixed-zeek-dir/conn.log", "conn.log"),
        ("dataset/test9-mixed-zeek-dir/http.log", "http.log"),
        ("dataset/test9-mixed-zeek-dir/ssl.log", "ssl.log"),
        ("dataset/test9-mixed-zeek-dir/notice.log", "notice.log"),
        ("dataset/test9-mixed-zeek-dir/files.log", "files.log"),
    ],
)
def test_process_line(
    file,
    flow_type,
):
    profiler = ModuleFactory().create_profiler_obj()
    profiler.symbol = Mock()
    profiler.db.get_timewindow = Mock(return_value="timewindow1")
    # we're testing another functionality here
    profiler.whitelist.is_whitelisted_flow = do_nothing
    profiler.input_type = "zeek"
    # get the class that handles the zeek input
    profiler.input_handler = SUPPORTED_INPUT_TYPES[profiler.input_type]()
    # set the zeek json separator
    profiler.separator = SEPARATORS[profiler.input_type]

    sample_flow = get_zeek_flow(file, flow_type)
    # required to get a flow object to call add_flow_to_profile on
    flow = profiler.input_handler.process_line(sample_flow)

    added_to_prof = profiler.add_flow_to_profile(flow)
    assert added_to_prof

    profileid = f"profile_{flow.saddr}"
    twid = profiler.db.get_timewindow(flow.starttime, profileid)

    # make sure it's added
    if flow_type == "conn":
        flow_added = profiler.db.get_flow(flow.uid, twid=twid)[flow.uid]
    else:
        flow_added = profiler.db.get_altflow_from_uid(
            profileid, twid, flow.uid
        )

    assert flow_added


def test_get_rev_profile():
    profiler = ModuleFactory().create_profiler_obj()
    flow: Conn = Conn(
        starttime="1.0",
        uid="1234",
        saddr="192.168.1.1",
        daddr="8.8.8.8",
        dur=5,
        proto="TCP",
        appproto="dhcp",
        sport=80,
        dport=88,
        spkts=20,
        dpkts=20,
        sbytes=20,
        dbytes=20,
        smac="",
        dmac="",
        state="Established",
        history="",
    )

    profiler.db.get_profileid_from_ip.return_value = None
    profiler.db.get_timewindow.return_value = "timewindow1"
    assert profiler.get_rev_profile(flow) == ("profile_8.8.8.8", "timewindow1")


def test_get_rev_profile_no_daddr(
    flow,
):
    profiler = ModuleFactory().create_profiler_obj()
    flow.daddr = None
    assert profiler.get_rev_profile(flow) == (False, False)


def test_get_rev_profile_existing_profileid():
    profiler = ModuleFactory().create_profiler_obj()
    flow: Conn = Conn(
        starttime="1.0",
        uid="1234",
        saddr="192.168.1.1",
        daddr="8.8.8.8",
        dur=5,
        proto="TCP",
        appproto="dhcp",
        sport=80,
        dport=88,
        spkts=20,
        dpkts=20,
        sbytes=20,
        dbytes=20,
        smac="",
        dmac="",
        state="Established",
        history="",
    )

    profiler.db.get_profileid_from_ip.return_value = "existing_profile"
    profiler.db.get_timewindow.return_value = "existing_timewindow"
    assert profiler.get_rev_profile(flow) == (
        "existing_profile",
        "existing_timewindow",
    )


def test_get_rev_profile_no_timewindow():
    profiler = ModuleFactory().create_profiler_obj()
    flow: Conn = Conn(
        starttime="1.0",
        uid="1234",
        saddr="192.168.1.1",
        daddr="8.8.8.8",
        dur=5,
        proto="TCP",
        appproto="dhcp",
        sport=80,
        dport=88,
        spkts=20,
        dpkts=20,
        sbytes=20,
        dbytes=20,
        smac="",
        dmac="",
        state="Established",
        history="",
    )

    profiler.db.get_profileid_from_ip.return_value = "profile_8.8.8.8"
    profiler.db.get_timewindow.return_value = None

    profile_id, tw_id = profiler.get_rev_profile(flow)
    assert profile_id == "profile_8.8.8.8"
    assert tw_id is None


def test_define_separator_direct_support():
    profiler = ModuleFactory().create_profiler_obj()
    sample_flow = {"data": "some_data"}
    input_type = "nfdump"

    separator = profiler.get_input_type(sample_flow, input_type)
    assert separator == "nfdump"


@pytest.mark.parametrize(
    "client_ips, expected_private_ips",
    [
        (["192.168.1.1", "10.0.0.1"], ["192.168.1.1", "10.0.0.1"]),
        (["8.8.8.8", "1.1.1.1"], []),
        (["192.168.1.1", "8.8.8.8"], ["192.168.1.1"]),
    ],
)
def test_get_private_client_ips(client_ips, expected_private_ips, monkeypatch):
    profiler = ModuleFactory().create_profiler_obj()
    profiler.client_ips = client_ips
    with patch(
        "slips_files.core.profiler.utils.is_private_ip"
    ) as mock_is_private_ip:

        def is_private_ip(ip):
            ip_obj = ipaddress.ip_address(ip)
            return ipaddress.ip_address(ip_obj).is_private

        mock_is_private_ip.side_effect = is_private_ip

        private_ips = profiler.get_private_client_ips()
        assert set(private_ips) == set(expected_private_ips)


def test_convert_starttime_to_epoch():
    profiler = ModuleFactory().create_profiler_obj()
    starttime = "2023-04-04 12:00:00"

    with patch(
        "slips_files.core.profiler.utils.convert_format"
    ) as mock_convert_format:
        mock_convert_format.return_value = 1680604800

        converted = profiler.convert_starttime_to_epoch(starttime)

        mock_convert_format.assert_called_once_with(
            "2023-04-04 12:00:00", "unixtimestamp"
        )
        assert converted == 1680604800


def test_convert_starttime_to_epoch_invalid_format(monkeypatch):
    profiler = ModuleFactory().create_profiler_obj()
    starttime = "not a real time"
    monkeypatch.setattr(
        "slips_files.core.profiler.utils.convert_format",
        Mock(side_effect=ValueError),
    )
    converted = profiler.convert_starttime_to_epoch(starttime)
    assert converted == "not a real time"


@pytest.mark.parametrize(
    "saddr, is_localnet_set, expected_result",
    [
        ("192.168.1.1", False, True),
        ("192.168.1.1", True, False),
        ("8.8.8.8", False, False),
    ],
)
def test_should_set_localnet(saddr, is_localnet_set, expected_result):
    profiler = ModuleFactory().create_profiler_obj()
    flow = Mock()
    flow.saddr = saddr
    profiler.is_localnet_set = is_localnet_set

    assert profiler.should_set_localnet(flow) == expected_result


def test_should_set_localnet_already_set():
    profiler = ModuleFactory().create_profiler_obj()
    profiler.is_localnet_set = True
    flow = Mock(saddr="1.1.1.1")
    result = profiler.should_set_localnet(flow)
    assert result is False


def test_check_for_stop_msg(monkeypatch):
    profiler = ModuleFactory().create_profiler_obj()
    assert profiler.is_stop_msg("stop") is True
    assert profiler.is_stop_msg("not_stop") is False


def test_pre_main(monkeypatch):
    profiler = ModuleFactory().create_profiler_obj()

    with monkeypatch.context() as m:
        mock_drop_root_privs = Mock()
        m.setattr(
            "slips_files.core.profiler.utils.drop_root_privs",
            mock_drop_root_privs,
        )
        profiler.pre_main()

    mock_drop_root_privs.assert_called_once()


def test_main_stop_msg_received():
    profiler = ModuleFactory().create_profiler_obj()
    profiler.should_stop = Mock(side_effect=[False, True])

    profiler.profiler_queue = Mock(spec=queue.Queue)
    profiler.profiler_queue.get.return_value = "stop"

    stopped = profiler.main()
    assert stopped
    # profiler.check_for_st op_msg.assert_called()


def mock_print(*args, **kwargs):
    pass


def test_mark_process_as_done_processing(monkeypatch):
    profiler = ModuleFactory().create_profiler_obj()
    profiler.done_processing = Mock()
    profiler.is_profiler_done_event = Mock()

    monkeypatch.setattr(profiler, "print", mock_print)

    profiler.mark_process_as_done_processing()

    profiler.done_processing.release.assert_called_once()
    profiler.is_profiler_done_event.set.assert_called_once()


def test_main():
    profiler = ModuleFactory().create_profiler_obj()

    # to be able to iterate just once
    profiler.should_stop = Mock(side_effect=[False, True])

    profiler.get_msg = Mock(side_effect=[None])
    msg = {"somemsg": 1}
    profiler.get_msg_from_input_proc = Mock(side_effect=[msg])

    profiler.pending_flows_queue_lock = Mock()  # Mock the lock
    profiler.flows_to_process_q = Mock()  # Mock the queue

    # Mock the context manager behavior for the lock
    profiler.pending_flows_queue_lock.__enter__ = Mock()
    profiler.pending_flows_queue_lock.__exit__ = Mock()

    profiler.main()
    profiler.flows_to_process_q.put.assert_called_once_with(msg)
    profiler.pending_flows_queue_lock.acquire.assert_called_once()
    profiler.pending_flows_queue_lock.release.assert_called_once()


@patch("slips_files.core.profiler.ConfigParser")
def test_read_configuration(
    mock_config_parser,
):
    profiler = ModuleFactory().create_profiler_obj()
    mock_conf = mock_config_parser.return_value

    mock_conf.local_whitelist_path.return_value = "path/to/whitelist"
    mock_conf.ts_format.return_value = "unixtimestamp"
    mock_conf.analysis_direction.return_value = "all"
    mock_conf.label.return_value = "malicious"
    mock_conf.get_tw_width_as_float.return_value = 1.0
    mock_conf.client_ips.return_value = ["192.168.1.1", "10.0.0.1"]

    profiler.read_configuration()

    assert profiler.local_whitelist_path == "path/to/whitelist"
    assert profiler.timeformat == "unixtimestamp"
    assert profiler.analysis_direction == "all"
    assert profiler.label == "malicious"
    assert profiler.width == 1.0
    assert profiler.client_ips == ["192.168.1.1", "10.0.0.1"]


def test_add_flow_to_profile_unsupported_flow():
    profiler = ModuleFactory().create_profiler_obj()
    flow = Mock()
    flow.type_ = "unsupported"
    flow_parser = Mock()
    flow_parser.is_supported_flow.return_value = False

    result = profiler.add_flow_to_profile(flow)
    assert result is False


@patch("slips_files.core.helpers.flow_handler")
def test_store_features_going_out(
    mock_flow_handler,
):
    profiler = ModuleFactory().create_profiler_obj()
    flow = Mock()
    flow.type_ = "conn"
    flow_parser = mock_flow_handler.return_value

    mock_flow_parser = mock_flow_handler.return_value
    mock_flow_parser.profileid = "profile_test"
    mock_flow_parser.twid = "twid_test"
    mock_flow_parser.db = profiler.db

    profiler.store_features_going_out(flow, mock_flow_parser)
    flow_parser.handle_conn.assert_called_once()


def test_store_features_going_in_non_conn_flow():
    profiler = ModuleFactory().create_profiler_obj()
    flow = Mock(type_="dns", saddr="192.168.1.1", dport=53, proto="UDP")
    profileid = "profile_test_dns"
    twid = "tw_test_dns"
    profiler.store_features_going_in(profileid, twid, flow)
    profiler.db.add_tuple.assert_not_called()
    profiler.db.add_ips.assert_not_called()
    profiler.db.add_port.assert_not_called()
    profiler.db.add_flow.assert_not_called()
    profiler.db.mark_profile_tw_as_modified.assert_not_called()


@patch("slips_files.core.helpers.flow_handler")
def test_store_features_going_out_unsupported_type(mock_flow_handler):
    profiler = ModuleFactory().create_profiler_obj()
    flow = Mock()
    flow.type_ = "unsupported_type"
    flow_parser = Mock()

    mock_flow_parser = mock_flow_handler.return_value
    mock_flow_parser.profileid = "profile_test"
    mock_flow_parser.twid = "twid_test"
    mock_flow_parser.db = profiler.db

    result = profiler.store_features_going_out(flow, mock_flow_parser)

    flow_parser.handle_conn.assert_not_called()
    assert result is False


def test_handle_in_flows_valid_daddr():
    profiler = ModuleFactory().create_profiler_obj()
    flow = Mock(type_="conn", daddr="8.8.8.8")
    profiler.get_rev_profile = Mock(return_value=("rev_profile", "rev_twid"))
    profiler.store_features_going_in = Mock()

    profiler.handle_in_flow(flow)

    profiler.get_rev_profile.assert_called_once()
    profiler.store_features_going_in.assert_called_once_with(
        "rev_profile", "rev_twid", flow
    )


def test_shutdown_gracefully(monkeypatch):
    profiler = ModuleFactory().create_profiler_obj()
    profiler.print = Mock()
    profiler.mark_process_as_done_processing = Mock()
    profiler.rec_lines = 100

    # monkeypatch.setattr(profiler, "print", Mock())
    profiler.shutdown_gracefully()
    profiler.print.assert_called_with(
        "Stopping. Total lines read: 100", log_to_logfiles_only=True
    )
    profiler.mark_process_as_done_processing.assert_called_once()


def test_get_local_net_from_flow(monkeypatch):
    profiler = ModuleFactory().create_profiler_obj()
    flow = Mock()
    flow.saddr = "10.0.0.1"
    profiler.client_ips = []
    local_net = profiler.get_local_net(flow)

    assert local_net == "10.0.0.0/8"


@pytest.mark.parametrize(
    "client_ips, expected_cidr",
    [
        (["192.168.1.1"], "192.168.0.0/16"),
        (["172.16.0.1"], "172.16.0.0/12"),
        ([], "192.168.0.0/16"),
    ],
)
def test_get_local_net(client_ips, expected_cidr, monkeypatch):
    profiler = ModuleFactory().create_profiler_obj()
    profiler.client_ips = client_ips
    flow = Mock()
    flow.saddr = "192.168.1.1"

    local_net = profiler.get_local_net(flow)
    assert local_net == expected_cidr


def test_handle_setting_local_net_when_already_set():
    profiler = ModuleFactory().create_profiler_obj()
    profiler.is_localnet_set = True
    flow = Mock()
    profiler.handle_setting_local_net(flow)
    profiler.db.set_local_network.assert_not_called()


def test_handle_setting_local_net(monkeypatch):
    profiler = ModuleFactory().create_profiler_obj()
    flow = Mock()
    flow.saddr = "192.168.1.1"

    monkeypatch.setattr(
        profiler, "should_set_localnet", Mock(return_value=True)
    )

    monkeypatch.setattr(
        profiler, "get_local_net", Mock(return_value="192.168.1.0/24")
    )

    profiler.handle_setting_local_net(flow)
    profiler.db.set_local_network.assert_called_once_with("192.168.1.0/24")


def test_notify_observers_no_observers():
    profiler = ModuleFactory().create_profiler_obj()
    test_msg = {"action": "test"}
    try:
        profiler.notify_observers(test_msg)
    except Exception as e:
        pytest.fail(f"Unexpected error occurred: {e}")


def test_notify_observers():
    profiler = ModuleFactory().create_profiler_obj()
    observer_mock = Mock()
    profiler.observers.append(observer_mock)
    test_msg = {"test": "message"}
    profiler.notify_observers(test_msg)
    observer_mock.update.assert_called_once_with(test_msg)


def test_notify_observers_with_correct_message():
    observer_mock = Mock()
    profiler = ModuleFactory().create_profiler_obj()
    profiler.observers.append(observer_mock)
    test_msg = {"action": "test_action"}
    profiler.notify_observers(test_msg)
    observer_mock.update.assert_called_once_with(test_msg)


@patch("slips_files.core.profiler.utils.is_private_ip")
@patch("slips_files.core.profiler.utils.is_ignored_ip")
def test_get_gateway_info_sets_mac_and_ip(
    mock_is_ignored_ip, mock_is_private_ip
):
    profiler = ModuleFactory().create_profiler_obj()
    # mac not detected, ip not detected
    profiler.is_gw_info_detected = Mock()
    profiler.is_gw_info_detected.side_effect = [False, False]
    mock_is_private_ip.return_value = True
    mock_is_ignored_ip.return_value = False
    profiler.get_gw_ip_using_gw_mac = Mock()
    profiler.get_gw_ip_using_gw_mac.return_value = "8.8.8.1"
    flow: Conn = Conn(
        starttime="1.0",
        uid="1234",
        saddr="192.168.1.1",
        daddr="8.8.8.8",
        dur=5,
        proto="TCP",
        appproto="dhcp",
        sport=80,
        dport=88,
        spkts=20,
        dpkts=20,
        sbytes=20,
        dbytes=20,
        smac="",
        dmac="00:11:22:33:44:55",
        state="Established",
        history="",
    )

    profiler.get_gateway_info(flow)

    profiler.db.set_default_gateway.assert_any_call("MAC", flow.dmac)
    profiler.db.set_default_gateway.assert_any_call("IP", "8.8.8.1")


@patch("slips_files.core.profiler.utils.is_private_ip")
def test_get_gateway_info_no_mac_detected(mock_is_private_ip):
    profiler = ModuleFactory().create_profiler_obj()

    # mac not detected, ip not detected
    profiler.is_gw_info_detected = Mock()
    profiler.is_gw_info_detected.side_effect = [False, False]
    mock_is_private_ip.return_value = False
    flow: Conn = Conn(
        starttime="1.0",
        uid="1234",
        saddr="192.168.1.1",
        daddr="8.8.8.8",
        dur=5,
        proto="TCP",
        appproto="dhcp",
        sport=80,
        dport=88,
        spkts=20,
        dpkts=20,
        sbytes=20,
        dbytes=20,
        smac="",
        dmac="00:11:22:33:44:55",
        state="Established",
        history="",
    )
    profiler.get_gateway_info(flow)

    # mac and ip should not be set
    profiler.db.set_default_gateway.assert_not_called()
    profiler.print.assert_not_called()


def test_get_gateway_info_mac_detected_but_no_ip():
    profiler = ModuleFactory().create_profiler_obj()
    flow = Mock()
    flow.dmac = "123"
    # mac detected, ip not detected
    profiler.is_gw_info_detected = Mock()
    profiler.is_gw_info_detected.side_effect = [True, False]
    profiler.get_gw_ip_using_gw_mac = Mock()
    profiler.get_gw_ip_using_gw_mac.return_value = None

    profiler.get_gateway_info(flow)

    # assertions for mac
    profiler.db.set_default_gateway.assert_not_called()
    profiler.print.assert_not_called()


@pytest.mark.parametrize(
    "info_type, attr_name, db_method, db_value",
    [
        ("mac", "gw_mac", "get_gateway_mac", "00:1A:2B:3C:4D:5E"),
        ("ip", "gw_ip", "get_gateway_ip", "192.168.1.1"),
    ],
)
def test_is_gw_info_detected(info_type, attr_name, db_method, db_value):
    # create a profiler object using the ModuleFactory
    profiler = ModuleFactory().create_profiler_obj()

    # mock the profiler's database methods and attributes
    setattr(profiler, attr_name, None)
    getattr(profiler.db, db_method).return_value = db_value

    # test with info_type
    result = profiler.is_gw_info_detected(info_type)

    # assertions
    assert result
    assert getattr(profiler, attr_name) == db_value
    getattr(profiler.db, db_method).assert_called_once()


def test_is_gw_info_detected_unsupported_info_type():
    # create a profiler object using the ModuleFactory
    profiler = ModuleFactory().create_profiler_obj()

    # test with an unsupported info_type
    with pytest.raises(ValueError) as exc_info:
        profiler.is_gw_info_detected("unsupported_type")

    # assertion
    assert str(exc_info.value) == "Unsupported info_type: unsupported_type"


def test_is_gw_info_detected_when_attribute_is_already_set():
    profiler = ModuleFactory().create_profiler_obj()

    # set gw_mac attribute to a value
    profiler.gw_mac = "00:1A:2B:3C:4D:5E"

    # test with info_type "mac"
    result = profiler.is_gw_info_detected("mac")

    # assertions
    assert result
    assert profiler.gw_mac == "00:1A:2B:3C:4D:5E"


def test_process_flow_no_msg():
    profiler = ModuleFactory().create_profiler_obj()
    profiler.stop_profiler_thread = Mock()
    profiler.get_msg_from_input_proc = Mock()
    profiler.add_flow_to_profile = Mock()
    profiler.input_handler_obj = Mock()
    profiler.print = Mock()
    profiler.init_input_handlers = Mock()
    profiler.print_traceback = Mock()

    profiler.stop_profiler_thread.side_effect = [False, True]  # Run loop once
    profiler.get_msg_from_input_proc.return_value = (
        None  # Empty message (no message in queue)
    )

    profiler.process_flow()

    profiler.init_input_handlers.assert_not_called()
    profiler.input_handler_obj.process_line.assert_not_called()
    profiler.add_flow_to_profile.assert_not_called()
    profiler.print.assert_not_called()


def test_process_flow():
    profiler = ModuleFactory().create_profiler_obj()
    profiler.stop_profiler_thread = Mock()
    profiler.get_msg_from_input_proc = Mock()
    profiler.input_handler_obj = Mock()
    profiler.add_flow_to_profile = Mock()
    profiler.handle_setting_local_net = Mock()
    profiler.print = Mock()
    profiler.print_traceback = Mock()
    profiler.init_input_handlers = Mock()
    profiler.stop_profiler_thread.side_effect = [False, True]  # Run once
    profiler.get_msg_from_input_proc.return_value = {
        "line": {"key": "value"},
        "input_type": "zeek",
    }

    profiler.input_handler_obj.process_line = Mock(return_value=Mock())

    profiler.process_flow()

    profiler.init_input_handlers.assert_called_once()
    profiler.input_handler_obj.process_line.assert_called_once()
    profiler.add_flow_to_profile.assert_called_once()
    profiler.handle_setting_local_net.assert_called_once()
    profiler.db.increment_processed_flows.assert_called_once()


def test_process_flow_handle_exception():
    profiler = ModuleFactory().create_profiler_obj()
    profiler.stop_profiler_thread = Mock()
    profiler.get_msg_from_input_proc = Mock()
    profiler.input_handler_obj = Mock()
    profiler.print = Mock()
    profiler.print_traceback = Mock()

    profiler.stop_profiler_thread.side_effect = [False, True]  # Run loop
    # once
    profiler.get_msg_from_input_proc.return_value = {
        "line": {"key": "value"},
        "input_type": "invalid_type",
    }
    profiler.input_handler_obj.process_line.side_effect = Exception(
        "Test exception"
    )

    profiler.process_flow()
    profiler.print_traceback.assert_called_once()
