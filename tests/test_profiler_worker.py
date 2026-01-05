# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for slips_files/core/iperformance_profiler.py"""

from unittest.mock import Mock, MagicMock

from tests.module_factory import ModuleFactory
from tests.common_test_utils import do_nothing
import pytest
import json
from slips_files.core.profiler import SUPPORTED_INPUT_TYPES, SEPARATORS
from slips_files.core.flows.zeek import Conn
import ipaddress
from unittest.mock import patch


# get zeek flow
def get_zeek_flow(file, flow_type):
    # returns the first flow in the given file
    with open(file) as f:
        sample_flow = f.readline().replace("\n", "")

    sample_flow = json.loads(sample_flow)
    sample_flow = {"data": sample_flow, "type": flow_type, "interface": "eth0"}
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
    profiler = ModuleFactory().create_profiler_worker_obj()
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
        flow_added = profiler.db.get_altflow_from_uid(flow.uid)

    assert flow_added


def test_get_rev_profile():
    profiler = ModuleFactory().create_profiler_worker_obj()
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
    profiler = ModuleFactory().create_profiler_worker_obj()
    flow.daddr = None
    assert profiler.get_rev_profile(flow) == (False, False)


def test_get_rev_profile_existing_profileid():
    profiler = ModuleFactory().create_profiler_worker_obj()
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
    profiler = ModuleFactory().create_profiler_worker_obj()
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


@pytest.mark.parametrize(
    "client_ips, expected_private_ips",
    [
        (["192.168.1.1", "10.0.0.1"], ["192.168.1.1", "10.0.0.1"]),
        (["8.8.8.8", "1.1.1.1"], []),
        (["192.168.1.1", "8.8.8.8"], ["192.168.1.1"]),
    ],
)
def test_get_private_client_ips(client_ips, expected_private_ips, monkeypatch):
    profiler = ModuleFactory().create_profiler_worker_obj()
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
    profiler = ModuleFactory().create_profiler_worker_obj()
    starttime = "2023-04-04 12:00:00"

    with patch(
        "slips_files.core.profiler.utils.convert_ts_format"
    ) as mock_convert_ts_format:
        mock_convert_ts_format.return_value = 1680604800

        converted = profiler.convert_starttime_to_unix_ts(starttime)

        mock_convert_ts_format.assert_called_once_with(
            "2023-04-04 12:00:00", "unixtimestamp"
        )
        assert converted == 1680604800


def test_convert_starttime_to_epoch_invalid_format(monkeypatch):
    profiler = ModuleFactory().create_profiler_worker_obj()
    starttime = "not a real time"
    monkeypatch.setattr(
        "slips_files.core.profiler.utils.convert_ts_format",
        Mock(side_effect=ValueError),
    )
    converted = profiler.convert_starttime_to_unix_ts(starttime)
    assert converted == "not a real time"


@pytest.mark.parametrize(
    "saddr, localnet_cache, running_non_stop, expected_result",
    [
        ("192.168.1.1", {}, True, True),
        ("192.168.1.1", {"eth0": "some_ip"}, True, False),
        ("8.8.8.8", {"default": "ip"}, False, False),
    ],
)
def test_should_set_localnet(
    saddr, localnet_cache, running_non_stop, expected_result
):
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.client_ips = []
    profiler.db.is_running_non_stop = Mock(return_value=running_non_stop)

    flow = Mock()
    flow.saddr = saddr
    flow.interface = "eth0"

    profiler.localnet_cache = localnet_cache
    assert profiler.should_set_localnet(flow) == expected_result


@patch("slips_files.core.profiler.ConfigParser")
def test_read_configuration(
    mock_config_parser,
):
    profiler = ModuleFactory().create_profiler_worker_obj()
    mock_conf = mock_config_parser.return_value

    mock_conf.local_whitelist_path.return_value = "path/to/whitelist"
    mock_conf.ts_format.return_value = "unixtimestamp"
    mock_conf.analysis_direction.return_value = "all"
    mock_conf.label.return_value = "malicious"
    mock_conf.get_tw_width_as_float.return_value = 1.0
    mock_conf.client_ips.return_value = ["192.168.1.1", "10.0.0.1"]
    profiler.conf = mock_conf
    profiler.read_configuration()

    assert profiler.local_whitelist_path == "path/to/whitelist"
    assert profiler.timeformat == "unixtimestamp"
    assert profiler.analysis_direction == "all"
    assert profiler.label == "malicious"
    assert profiler.width == 1.0
    assert profiler.client_ips == ["192.168.1.1", "10.0.0.1"]


def test_add_flow_to_profile_unsupported_flow():
    profiler = ModuleFactory().create_profiler_worker_obj()
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
    profiler = ModuleFactory().create_profiler_worker_obj()
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
    profiler = ModuleFactory().create_profiler_worker_obj()
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
    profiler = ModuleFactory().create_profiler_worker_obj()
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
    profiler = ModuleFactory().create_profiler_worker_obj()
    flow = Mock(type_="conn", daddr="8.8.8.8")
    profiler.get_rev_profile = Mock(return_value=("rev_profile", "rev_twid"))
    profiler.store_features_going_in = Mock()

    profiler.handle_in_flow(flow)

    profiler.get_rev_profile.assert_called_once()
    profiler.store_features_going_in.assert_called_once_with(
        "rev_profile", "rev_twid", flow
    )


@pytest.mark.parametrize(
    "client_ips, saddr, expected_cidr",
    [
        (
            [ipaddress.IPv4Network("192.168.1.0/24")],
            "10.0.0.1",
            "192.168.1.0/24",
        ),
        (
            [ipaddress.IPv4Network("172.16.0.0/16")],
            "10.0.0.1",
            "172.16.0.0/16",
        ),
        ([], "10.0.0.1", "10.0.0.0/8"),
    ],
)
def test_get_local_net(client_ips, saddr, expected_cidr):
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.args.interface = None

    flow = Mock()
    flow.saddr = saddr

    if not client_ips:
        with patch.object(
            profiler, "get_private_client_ips", return_value=client_ips
        ), patch(
            "slips_files.common.slips_utils.Utils.get_cidr_of_private_ip",
            return_value="10.0.0.0/8",
        ):
            local_net = profiler.get_local_net_of_flow(flow)
    else:
        with patch.object(
            profiler, "get_private_client_ips", return_value=client_ips
        ):
            local_net = profiler.get_local_net_of_flow(flow)

    assert local_net == {"default": expected_cidr}


def test_get_local_net_from_flow():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.args.interface = None
    with patch.object(
        profiler, "get_private_client_ips", return_value=[]
    ), patch(
        "slips_files.common.slips_utils.Utils.get_cidr_of_private_ip",
        return_value="10.0.0.0/8",
    ):
        flow = Mock()
        flow.saddr = "10.0.0.1"
        local_net = profiler.get_local_net_of_flow(flow)

    assert local_net == {"default": "10.0.0.0/8"}


def test_handle_setting_local_net_when_already_set():
    profiler = ModuleFactory().create_profiler_worker_obj()
    mock_lock = MagicMock()
    mock_lock.__enter__.return_value = None
    mock_lock.__exit__.return_value = None
    profiler.handle_setting_local_net_lock = mock_lock

    local_net = "192.168.1.0/24"
    profiler.should_set_localnet = Mock(return_value=False)
    profiler.localnet_cache = {"default": local_net}
    flow = Mock()
    profiler.handle_setting_local_net(flow)
    profiler.db.set_local_network.assert_not_called()


def test_handle_setting_local_net():
    profiler = ModuleFactory().create_profiler_worker_obj()
    mock_lock = MagicMock()
    mock_lock.__enter__.return_value = None
    mock_lock.__exit__.return_value = None
    profiler.handle_setting_local_net_lock = mock_lock

    local_net = "192.168.1.0/24"
    profiler.should_set_localnet = Mock(return_value=True)
    profiler.get_local_net_of_flow = Mock(return_value={"default": local_net})
    profiler.get_local_net = Mock(return_value=local_net)
    profiler.db.is_running_non_stop = Mock(return_value=False)

    flow = Mock()
    flow.saddr = "192.168.1.1"

    profiler.handle_setting_local_net(flow)
    profiler.db.set_local_network.assert_called_once_with(local_net, "default")


@patch("slips_files.core.profiler.utils.is_private_ip")
@patch("slips_files.core.profiler.utils.is_ignored_ip")
def test_get_gateway_info_sets_mac_and_ip(
    mock_is_ignored_ip, mock_is_private_ip
):
    profiler = ModuleFactory().create_profiler_worker_obj()
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
        interface="eth0",
    )

    profiler.get_gateway_info(flow)

    profiler.db.set_default_gateway.assert_any_call("MAC", flow.dmac, "eth0")
    profiler.db.set_default_gateway.assert_any_call("IP", "8.8.8.1", "eth0")


@patch("slips_files.core.profiler.utils.is_private_ip")
def test_get_gateway_info_no_mac_detected(mock_is_private_ip):
    profiler = ModuleFactory().create_profiler_worker_obj()

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
    profiler = ModuleFactory().create_profiler_worker_obj()
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
        ("mac", "gw_macs", "get_gateway_mac", "00:1A:2B:3C:4D:5E"),
        ("ip", "gw_ips", "get_gateway_ip", "192.168.1.1"),
    ],
)
def test_is_gw_info_detected(info_type, attr_name, db_method, db_value):
    # create a profiler object using the ModuleFactory
    profiler = ModuleFactory().create_profiler_worker_obj()

    # ensure gw_macs / gw_ips exist as dicts
    setattr(profiler, attr_name, {})

    # mock the db method
    mock_method = Mock(return_value=db_value)
    setattr(profiler.db, db_method, mock_method)

    # call the function
    result = profiler.is_gw_info_detected(info_type, "eth0")

    # verify
    assert result is True
    assert getattr(profiler, attr_name)["eth0"] == db_value
    mock_method.assert_called_once_with("eth0")


def test_is_gw_info_detected_unsupported_info_type():
    # create a profiler object using the ModuleFactory
    profiler = ModuleFactory().create_profiler_worker_obj()

    # test with an unsupported info_type
    with pytest.raises(ValueError) as exc_info:
        profiler.is_gw_info_detected("unsupported_type", "eth0")

    assert str(exc_info.value) == "Unsupported info_type: unsupported_type"


def test_run_no_msg():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.should_stop_profiler_workers = Mock()
    profiler.get_msg_from_queue = Mock()
    profiler.add_flow_to_profile = Mock()
    profiler.input_handler = Mock()
    profiler.print = Mock()
    profiler.get_handler_obj = Mock()
    profiler.print_traceback = Mock()

    profiler.should_stop_profiler_workers.side_effect = [
        False,
        True,
    ]  # Run loop once
    profiler.get_msg_from_queue.return_value = (
        None  # Empty message (no message in queue)
    )

    profiler.run()

    profiler.get_handler_obj.assert_not_called()
    profiler.input_handler.process_line.assert_not_called()
    profiler.add_flow_to_profile.assert_not_called()
    profiler.print.assert_not_called()


def test_run():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.should_stop_profiler_workers = Mock()
    profiler.get_msg_from_queue = Mock()
    profiler.input_handler = Mock()
    profiler.add_flow_to_profile = Mock()
    profiler.handle_setting_local_net = Mock()
    profiler.print = Mock()
    profiler.print_traceback = Mock()
    profiler.should_stop_profiler_workers.side_effect = [
        False,
        True,
    ]  # Run once
    profiler.get_msg_from_queue.return_value = {
        "line": {"key": "value"},
        "input_type": "zeek",
    }

    profiler.input_handler.process_line = Mock(return_value=Mock())

    profiler.run()

    profiler.input_handler.process_line.assert_called_once()
    profiler.add_flow_to_profile.assert_called_once()
    profiler.handle_setting_local_net.assert_called_once()
    profiler.db.increment_processed_flows.assert_called_once()


def test_run_handle_exception():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.should_stop_profiler_workers = Mock()
    profiler.get_msg_from_queue = Mock()
    profiler.input_handler = Mock()
    profiler.print = Mock()
    profiler.print_traceback = Mock()

    profiler.should_stop_profiler_workers.side_effect = [
        False,
        True,
    ]  # Run loop
    # once
    profiler.get_msg_from_queue.return_value = {
        "line": {"key": "value"},
        "input_type": "invalid_type",
    }
    profiler.input_handler.process_line.side_effect = Exception(
        "Test exception"
    )

    profiler.run()
    profiler.print_traceback.assert_called_once()
