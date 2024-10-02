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
    profiler_detected_type: str = profiler.define_separator(
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
    profiler_detected_type: str = profiler.define_separator(
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
    profiler_detected_type: str = profiler.define_separator(
        sample_flow, input_type
    )
    assert profiler_detected_type == expected_value


@pytest.mark.parametrize("nfdump_file", [("dataset/test1-normal.nfdump")])
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
    profiler_detected_type: str = profiler.define_separator(
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


@pytest.mark.parametrize(
    "file,flow_type",
    [
        ("dataset/test9-mixed-zeek-dir/dns.log", "dns"),
        ("dataset/test9-mixed-zeek-dir/conn.log", "conn"),
        ("dataset/test9-mixed-zeek-dir/http.log", "http"),
        ("dataset/test9-mixed-zeek-dir/ssl.log", "ssl"),
        ("dataset/test9-mixed-zeek-dir/notice.log", "notice"),
        # ('dataset/test9-mixed-zeek-dir/files.log', 'files.log'),
    ],
)
def test_process_line(
    file,
    flow_type,
):
    profiler = ModuleFactory().create_profiler_obj()
    profiler.symbol = Mock()
    # we're testing another functionality here
    profiler.whitelist.is_whitelisted_flow = do_nothing
    profiler.input_type = "zeek"
    # get the class that handles the zeek input
    profiler.input_handler = SUPPORTED_INPUT_TYPES[profiler.input_type]()
    # set  the zeek json separator
    profiler.separator = SEPARATORS[profiler.input_type]

    # get zeek flow
    with open(file) as f:
        sample_flow = f.readline().replace("\n", "")

    sample_flow = json.loads(sample_flow)
    sample_flow = {"data": sample_flow, "type": flow_type}

    profiler.flow = profiler.input_handler.process_line(sample_flow)
    assert profiler.flow is not None

    added_to_prof = profiler.add_flow_to_profile()
    assert added_to_prof is True

    uid = profiler.flow.uid
    profileid = profiler.profileid
    twid = profiler.twid

    # make sure it's added
    if flow_type == "conn":
        added_flow = profiler.db.get_flow(uid, twid=twid)[uid]
    else:
        added_flow = (
            profiler.db.get_altflow_from_uid(profileid, twid, uid) is not None
        )
    assert added_flow is not None


def test_get_rev_profile():
    profiler = ModuleFactory().create_profiler_obj()
    profiler.flow = Conn(
        "1.0",
        "1234",
        "192.168.1.1",
        "8.8.8.8",
        5,
        "TCP",
        "dhcp",
        80,
        88,
        20,
        20,
        20,
        20,
        "",
        "",
        "Established",
        "",
    )
    profiler.db.get_profileid_from_ip.return_value = None
    profiler.db.get_timewindow.return_value = "timewindow1"
    assert profiler.get_rev_profile() == ("profile_8.8.8.8", "timewindow1")


def test_get_rev_profile_no_daddr(
    flow,
):
    profiler = ModuleFactory().create_profiler_obj()
    profiler.flow = flow
    profiler.flow.daddr = None
    profiler.daddr_as_obj = None
    assert profiler.get_rev_profile() == (False, False)


def test_get_rev_profile_existing_profileid():
    profiler = ModuleFactory().create_profiler_obj()
    profiler.flow = Conn(
        "1.0",
        "1234",
        "192.168.1.1",
        "8.8.8.8",
        5,
        "TCP",
        "dhcp",
        80,
        88,
        20,
        20,
        20,
        20,
        "",
        "",
        "Established",
        "",
    )
    profiler.db.get_profileid_from_ip.return_value = "existing_profile"
    profiler.db.get_timewindow.return_value = "existing_timewindow"
    assert profiler.get_rev_profile() == (
        "existing_profile",
        "existing_timewindow",
    )


def test_get_rev_profile_no_timewindow():
    profiler = ModuleFactory().create_profiler_obj()
    profiler.flow = Conn(
        "1.0",
        "1234",
        "192.168.1.1",
        "8.8.8.8",
        5,
        "TCP",
        "dhcp",
        80,
        88,
        20,
        20,
        20,
        20,
        "",
        "",
        "Established",
        "",
    )
    profiler.db.get_profileid_from_ip.return_value = "profile_8.8.8.8"
    profiler.db.get_timewindow.return_value = None

    profile_id, tw_id = profiler.get_rev_profile()
    assert profile_id == "profile_8.8.8.8"
    assert tw_id is None


def test_define_separator_direct_support():
    profiler = ModuleFactory().create_profiler_obj()
    sample_flow = {"data": "some_data"}
    input_type = "nfdump"

    separator = profiler.define_separator(sample_flow, input_type)
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
    profiler.flow = Mock()
    profiler.flow.starttime = "2023-04-04 12:00:00"

    with patch(
        "slips_files.core.profiler.utils.convert_format"
    ) as mock_convert_format:
        mock_convert_format.return_value = 1680604800

        profiler.convert_starttime_to_epoch()

        mock_convert_format.assert_called_once_with(
            "2023-04-04 12:00:00", "unixtimestamp"
        )
        assert profiler.flow.starttime == 1680604800


def test_convert_starttime_to_epoch_invalid_format(monkeypatch):
    profiler = ModuleFactory().create_profiler_obj()
    profiler.flow = Mock()
    profiler.flow.starttime = "not a real time"
    monkeypatch.setattr(
        "slips_files.core.profiler.utils.convert_format",
        Mock(side_effect=ValueError),
    )
    profiler.convert_starttime_to_epoch()
    assert profiler.flow.starttime == "not a real time"


def test_should_set_localnet():
    profiler = ModuleFactory().create_profiler_obj()

    profiler.flow = Mock()
    profiler.flow.saddr = "192.168.1.1"
    profiler.is_localnet_set = False
    assert profiler.should_set_localnet() is True

    profiler.is_localnet_set = True
    assert profiler.should_set_localnet() is False

    profiler.is_localnet_set = False
    profiler.flow.saddr = "8.8.8.8"
    assert profiler.should_set_localnet() is False


def test_should_set_localnet_already_set():
    profiler = ModuleFactory().create_profiler_obj()
    profiler.is_localnet_set = True
    result = profiler.should_set_localnet()
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


@patch("slips_files.core.profiler.Profiler.add_flow_to_profile")
@patch("slips_files.core.profiler.Profiler.handle_setting_local_net")
def test_main(mock_handle_setting_local_net, mock_add_flow_to_profile):
    profiler = ModuleFactory().create_profiler_obj()
    profiler.profiler_queue = Mock(spec=queue.Queue)
    profiler.profiler_queue.get.side_effect = [
        {"line": "sample_line", "input_type": "zeek", "total_flows": 100},
        "stop",
    ]
    profiler.should_stop = Mock(side_effect=[False, True])
    profiler.db.define_separator = Mock()
    profiler.db.define_separator.return_value = "zeek"
    profiler.input = Mock()
    profiler.input.process_line = Mock(return_value="sample_flow")

    profiler.main()

    mock_add_flow_to_profile.assert_called_once()
    mock_handle_setting_local_net.assert_called_once()


@patch("slips_files.core.profiler.ConfigParser")
def test_read_configuration(
    mock_config_parser,
):
    profiler = ModuleFactory().create_profiler_obj()
    mock_conf = mock_config_parser.return_value

    mock_conf.whitelist_path.return_value = "path/to/whitelist"
    mock_conf.ts_format.return_value = "unixtimestamp"
    mock_conf.analysis_direction.return_value = "all"
    mock_conf.label.return_value = "malicious"
    mock_conf.get_tw_width_as_float.return_value = 1.0
    mock_conf.client_ips.return_value = ["192.168.1.1", "10.0.0.1"]

    profiler.read_configuration()

    assert profiler.whitelist_path == "path/to/whitelist"
    assert profiler.timeformat == "unixtimestamp"
    assert profiler.analysis_direction == "all"
    assert profiler.label == "malicious"
    assert profiler.width == 1.0
    assert profiler.client_ips == ["192.168.1.1", "10.0.0.1"]


def test_add_flow_to_profile_unsupported_flow():
    profiler = ModuleFactory().create_profiler_obj()
    profiler.flow = Mock()
    profiler.flow.type_ = "unsupported"
    profiler.flow_parser = Mock()
    profiler.flow_parser.is_supported_flow.return_value = False

    result = profiler.add_flow_to_profile()
    assert result is False


@patch("slips_files.core.profiler.FlowHandler")
def test_store_features_going_out(
    mock_flow_handler,
):
    profiler = ModuleFactory().create_profiler_obj()
    profiler.flow = Mock()
    profiler.flow.type_ = "conn"
    profiler.flow_parser = mock_flow_handler.return_value
    profiler.profileid = "profile_test"
    profiler.twid = "twid_test"

    profiler.store_features_going_out()

    profiler.flow_parser.handle_conn.assert_called_once()


def test_store_features_going_in_non_conn_flow():
    profiler = ModuleFactory().create_profiler_obj()
    profiler.flow = Mock(
        type_="dns", saddr="192.168.1.1", dport=53, proto="UDP"
    )
    profiler.saddr_as_obj = ipaddress.ip_address("192.168.1.1")
    profileid = "profile_test_dns"
    twid = "tw_test_dns"
    profiler.store_features_going_in(profileid, twid)
    profiler.db.add_tuple.assert_not_called()
    profiler.db.add_ips.assert_not_called()
    profiler.db.add_port.assert_not_called()
    profiler.db.add_flow.assert_not_called()
    profiler.db.mark_profile_tw_as_modified.assert_not_called()


def test_store_features_going_out_unsupported_type():
    profiler = ModuleFactory().create_profiler_obj()
    profiler.flow = Mock()
    profiler.flow.type_ = "unsupported_type"
    profiler.flow_parser = Mock()
    result = profiler.store_features_going_out()
    profiler.flow_parser.handle_conn.assert_not_called()
    assert result is False


def test_handle_in_flows_valid_daddr():
    profiler = ModuleFactory().create_profiler_obj()
    profiler.flow = Mock(type_="conn", daddr="8.8.8.8")
    profiler.get_rev_profile = Mock(return_value=("rev_profile", "rev_twid"))
    profiler.store_features_going_in = Mock()

    profiler.handle_in_flows()

    profiler.get_rev_profile.assert_called_once()
    profiler.store_features_going_in.assert_called_once_with(
        "rev_profile", "rev_twid"
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
    profiler.flow = Mock()
    profiler.flow.saddr = "10.0.0.1"
    profiler.client_ips = []
    local_net = profiler.get_local_net()

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
    profiler.flow = Mock()
    profiler.flow.saddr = "192.168.1.1"

    local_net = profiler.get_local_net()
    assert local_net == expected_cidr


def test_handle_setting_local_net_when_already_set():
    profiler = ModuleFactory().create_profiler_obj()
    profiler.is_localnet_set = True
    profiler.handle_setting_local_net()
    profiler.db.set_local_network.assert_not_called()


def test_handle_setting_local_net(monkeypatch):
    profiler = ModuleFactory().create_profiler_obj()
    profiler.flow = Mock()
    profiler.flow.saddr = "192.168.1.1"

    monkeypatch.setattr(
        profiler, "should_set_localnet", Mock(return_value=True)
    )

    monkeypatch.setattr(
        profiler, "get_local_net", Mock(return_value="192.168.1.0/24")
    )

    profiler.handle_setting_local_net()

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
