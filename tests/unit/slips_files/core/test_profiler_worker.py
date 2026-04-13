# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for slips_files/core/profiler_worker.py."""

import csv
import json
from unittest.mock import Mock, patch

import pytest

from slips_files.common.input_type import InputType
from slips_files.core.flows.zeek import Conn
from slips_files.core.profiler import SEPARATORS, SUPPORTED_INPUT_TYPES
from tests.module_factory import ModuleFactory
from tests.unit.common_test_utils import do_nothing


def get_zeek_flow(file, flow_type):
    with open(file, encoding="utf-8") as f:
        sample_flow = f.readline().replace("\n", "")

    sample_flow = json.loads(sample_flow)
    return {"data": sample_flow, "type": flow_type, "interface": "eth0"}


def make_conn(**overrides):
    data = {
        "starttime": "1.0",
        "uid": "1234",
        "saddr": "192.168.1.1",
        "daddr": "8.8.8.8",
        "dur": 5,
        "proto": "TCP",
        "appproto": "dhcp",
        "sport": 80,
        "dport": 88,
        "spkts": 20,
        "dpkts": 20,
        "sbytes": 20,
        "dbytes": 20,
        "smac": "",
        "dmac": "",
        "state": "Established",
        "history": "",
        "interface": "eth0",
    }
    data.update(overrides)
    return Conn(**data)


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
def test_process_line_zeek_json(file, flow_type):
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.symbol = Mock()
    profiler.db.get_timewindow = Mock(return_value="timewindow1")
    profiler.whitelist.is_whitelisted_flow = do_nothing
    profiler.input_type = InputType.ZEEK
    profiler.input_handler = SUPPORTED_INPUT_TYPES[profiler.input_type](
        profiler.db
    )
    profiler.separator = SEPARATORS[profiler.input_type]

    flow, err = profiler.input_handler.process_line(
        get_zeek_flow(file, flow_type)
    )

    assert not err
    assert flow


def test_read_configuration():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.conf.client_ips.return_value = ["192.168.1.1", "10.0.0.1"]
    profiler.conf.local_whitelist_path.return_value = "path/to/whitelist"
    profiler.conf.ts_format.return_value = "unixtimestamp"
    profiler.conf.analysis_direction.return_value = "all"
    profiler.conf.label.return_value = "malicious"
    profiler.conf.get_tw_width_in_seconds.return_value = 1.0
    profiler.conf.generate_performance_plots.return_value = True

    profiler.read_configuration()

    assert profiler.client_ips == ["192.168.1.1", "10.0.0.1"]
    assert profiler.local_whitelist_path == "path/to/whitelist"
    assert profiler.timeformat == "unixtimestamp"
    assert profiler.analysis_direction == "all"
    assert profiler.label == "malicious"
    assert profiler.width == 1.0
    assert profiler.generate_performance_plots is True


def test_get_slips_start_time_uses_db_value():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.db.get_slips_start_time.return_value = "123.5"

    assert profiler._get_slips_start_time() == 123.5


@patch("slips_files.core.profiler_worker.time.time", return_value=99.0)
def test_get_slips_start_time_falls_back_to_now(mock_time):
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.db.get_slips_start_time.return_value = "invalid"
    mock_time.reset_mock()

    assert profiler._get_slips_start_time() == 99.0
    mock_time.assert_called_once()


@pytest.mark.parametrize(
    "name, expected_prefix",
    [
        ("profiler_worker_process_2", "profiler_worker_2"),
        ("profiler_worker", "profiler_worker"),
        ("mock_name", "mock_name"),
    ],
)
def test_get_latency_filename_prefix(name, expected_prefix):
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.name = name

    assert profiler._get_latency_filename_prefix() == expected_prefix


def test_initialize_latency_logfile_creates_header(tmp_path):
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.latency_logfile = str(tmp_path / "latency" / "worker.csv")

    profiler._initialize_latency_logfile()

    with open(profiler.latency_logfile, encoding="utf-8") as f:
        rows = list(csv.reader(f))

    assert rows == [["timestamp_now", "flow_uid", "latency_in_seconds"]]


def test_initialize_latency_logfile_is_noop_when_file_exists(tmp_path):
    profiler = ModuleFactory().create_profiler_worker_obj()
    logfile = tmp_path / "worker.csv"
    logfile.write_text("existing\n", encoding="utf-8")
    profiler.latency_logfile = str(logfile)

    profiler._initialize_latency_logfile()

    assert logfile.read_text(encoding="utf-8") == "existing\n"


@patch("slips_files.core.profiler_worker.time.time", side_effect=[0.0, 120.0])
def test_log_flow_latency_appends_row(mock_time, tmp_path):
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.generate_performance_plots = True
    profiler.slips_start_time = 100.0
    profiler.latency_logfile = str(tmp_path / "latency.csv")
    profiler._initialize_latency_logfile()
    flow = Mock(uid="flow-1")

    profiler._log_flow_latency(flow, "110")

    with open(profiler.latency_logfile, encoding="utf-8") as f:
        rows = list(csv.reader(f))

    assert rows[1] == ["20.0", "flow-1", "10"]


def test_log_flow_latency_skips_invalid_starttime(tmp_path):
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.generate_performance_plots = True
    profiler.latency_logfile = str(tmp_path / "latency.csv")
    profiler._initialize_latency_logfile()

    profiler._log_flow_latency(Mock(uid="flow-1"), "invalid")

    with open(profiler.latency_logfile, encoding="utf-8") as f:
        rows = list(csv.reader(f))

    assert len(rows) == 1


@patch(
    "slips_files.core.profiler_worker.time.time", side_effect=[0.0, 2.0, 4.5]
)
def test_update_modified_tws_batches_then_flushes(mock_time):
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler._modified_tws = {}
    profiler._time_to_update_modified_tws = 3.0
    profiler._modified_timewindows_update_period = 3
    flow1 = Mock(starttime="1")
    flow2 = Mock(starttime="2")

    profiler._update_modified_tws_in_the_db("profile1", "tw1", flow1)
    profiler._update_modified_tws_in_the_db("profile2", "tw2", flow2)

    profiler.db.mark_profile_tw_as_modified.assert_called_once_with(
        {"profile1_tw1": "1", "profile2_tw2": "2"}
    )
    assert profiler._modified_tws == {}
    assert profiler._time_to_update_modified_tws == 7.5


def test_get_rev_profile():
    profiler = ModuleFactory().create_profiler_worker_obj()
    flow = make_conn()
    profiler.db.get_timewindow.return_value = "timewindow1"

    assert profiler.get_rev_profile(flow) == ("profile_8.8.8.8", "timewindow1")
    profiler.db.add_profile.assert_called_once_with("profile_8.8.8.8", "1.0")


def test_get_rev_profile_no_daddr():
    profiler = ModuleFactory().create_profiler_worker_obj()
    flow = make_conn(daddr=None)

    assert profiler.get_rev_profile(flow) == (False, False)


def test_convert_starttime_to_unix_ts_returns_input_for_unix_timestamp():
    profiler = ModuleFactory().create_profiler_worker_obj()

    assert (
        profiler.convert_starttime_to_unix_ts("1712500000.0") == "1712500000.0"
    )


def test_convert_starttime_to_unix_ts_converts_formatted_timestamp():
    profiler = ModuleFactory().create_profiler_worker_obj()

    with patch(
        "slips_files.core.profiler_worker.utils.convert_ts_format",
        return_value=1680604800,
    ) as mock_convert:
        assert (
            profiler.convert_starttime_to_unix_ts("2023-04-04 12:00:00")
            == 1680604800
        )

    mock_convert.assert_called_once_with(
        "2023-04-04 12:00:00", "unixtimestamp"
    )


def test_convert_starttime_to_unix_ts_returns_original_on_error():
    profiler = ModuleFactory().create_profiler_worker_obj()

    with patch(
        "slips_files.core.profiler_worker.utils.convert_ts_format",
        side_effect=ValueError,
    ):
        assert (
            profiler.convert_starttime_to_unix_ts("invalid-ts") == "invalid-ts"
        )

    profiler.print.assert_called_once()


def test_get_aid_and_store_flow_in_the_db_submits_only_for_conn_handler():
    profiler = ModuleFactory().create_profiler_worker_obj()
    handle_conn = Mock()
    other_handler = Mock()
    flow = Mock()

    profiler.get_aid_and_store_flow_in_the_db(
        handle_conn, handle_conn, flow, "profile", "tw1"
    )
    profiler.get_aid_and_store_flow_in_the_db(
        other_handler, handle_conn, flow, "profile", "tw1"
    )

    profiler.aid_manager.submit_aid_task.assert_called_once_with(
        flow, "profile", "tw1", "benign"
    )


@patch("slips_files.core.profiler_worker.FlowHandler")
def test_store_features_going_out_conn_flow(mock_flow_handler):
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.get_aid_and_store_flow_in_the_db = Mock()
    profiler._update_modified_tws_in_the_db = Mock()
    flow = make_conn(type_="conn")

    assert (
        profiler.store_features_going_out(flow, "profile_test", "tw1") is True
    )

    mock_flow_handler.return_value.handle_conn.assert_called_once()
    profiler.get_aid_and_store_flow_in_the_db.assert_called_once()
    profiler._update_modified_tws_in_the_db.assert_called_once_with(
        "profile_test", "tw1", flow
    )


@patch("slips_files.core.profiler_worker.FlowHandler")
def test_store_features_going_out_matches_substring_type(mock_flow_handler):
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.get_aid_and_store_flow_in_the_db = Mock()
    profiler._update_modified_tws_in_the_db = Mock()
    flow = make_conn(type_="conn.log")

    assert (
        profiler.store_features_going_out(flow, "profile_test", "tw1") is True
    )

    mock_flow_handler.return_value.handle_conn.assert_called_once()


@patch("slips_files.core.profiler_worker.FlowHandler")
def test_store_features_going_out_unsupported_type(mock_flow_handler):
    profiler = ModuleFactory().create_profiler_worker_obj()

    assert (
        profiler.store_features_going_out(
            Mock(type_="unsupported", starttime="1"), "profile_test", "tw1"
        )
        is False
    )

    mock_flow_handler.return_value.handle_conn.assert_not_called()


def test_store_features_going_in_stores_conn_flow():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.symbol.compute = Mock()
    profiler.symbol.compute.return_value = "symbol"
    profiler._update_modified_tws_in_the_db = Mock()
    flow = make_conn(type_="conn")

    profiler.store_features_going_in("profile_test", "tw1", flow)

    profiler.db.add_tuple.assert_called_once()
    profiler.db.add_ips.assert_called_once()
    profiler.aid_manager.submit_aid_task.assert_called_once_with(
        flow, "profile_test", "tw1", profiler.label
    )
    profiler._update_modified_tws_in_the_db.assert_called_once_with(
        "profile_test", "tw1", flow
    )


def test_store_features_going_in_skips_unsupported_flow():
    profiler = ModuleFactory().create_profiler_worker_obj()

    profiler.store_features_going_in(
        "profile_test", "tw1", Mock(type_="dns", saddr="192.168.1.1")
    )

    profiler.db.add_tuple.assert_not_called()
    profiler.aid_manager.submit_aid_task.assert_not_called()


def test_store_features_going_in_skips_invalid_source_ip():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.symbol.compute = Mock(return_value="symbol")

    profiler.store_features_going_in(
        "profile_test", "tw1", Mock(type_="conn", saddr="not-an-ip")
    )

    profiler.db.add_tuple.assert_not_called()


def test_handle_in_flow_stores_reverse_profile():
    profiler = ModuleFactory().create_profiler_worker_obj()
    flow = make_conn(type_="conn")
    profiler.get_rev_profile = Mock(return_value=("rev_profile", "rev_twid"))
    profiler.store_features_going_in = Mock()

    profiler.handle_in_flow(flow)

    profiler.store_features_going_in.assert_called_once_with(
        "rev_profile", "rev_twid", flow
    )


def test_handle_in_flow_skips_software_flows():
    profiler = ModuleFactory().create_profiler_worker_obj()

    profiler.handle_in_flow(Mock(type_="software"))

    profiler.db.add_profile.assert_not_called()


@patch("slips_files.core.profiler_worker.utils.is_private_ip")
@patch("slips_files.core.profiler_worker.utils.is_ignored_ip")
def test_get_gateway_info_sets_mac_and_ip(
    mock_is_ignored_ip, mock_is_private_ip
):
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.is_gw_info_detected = Mock(side_effect=[False, False])
    profiler.get_gw_ip_using_gw_mac = Mock(return_value="8.8.8.1")
    mock_is_private_ip.return_value = True
    mock_is_ignored_ip.return_value = False
    flow = make_conn(dmac="00:11:22:33:44:55")

    profiler.get_gateway_info(flow)

    profiler.db.set_default_gateway.assert_any_call("MAC", flow.dmac, "eth0")
    profiler.db.set_default_gateway.assert_any_call("IP", "8.8.8.1", "eth0")


def test_get_gateway_info_skips_flows_without_dmac():
    profiler = ModuleFactory().create_profiler_worker_obj()
    flow = Mock(spec=["interface"])
    flow.interface = "eth0"

    profiler.get_gateway_info(flow)

    profiler.db.set_default_gateway.assert_not_called()


@patch(
    "slips_files.core.profiler_worker.utils.is_private_ip", return_value=False
)
def test_get_gateway_info_does_not_set_gateway_for_non_private_source(_mock):
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.is_gw_info_detected = Mock()
    profiler.is_gw_info_detected.side_effect = [False, False]

    profiler.get_gateway_info(make_conn(dmac="00:11:22:33:44:55"))

    profiler.db.set_default_gateway.assert_not_called()


def test_get_gw_ip_using_gw_mac_prefers_ipv4():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.db.get_ip_of_mac.return_value = json.dumps(
        ["2001:db8::1", "192.168.0.1"]
    )

    assert profiler.get_gw_ip_using_gw_mac("mac") == "192.168.0.1"


def test_get_gw_ip_using_gw_mac_returns_none_when_missing():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.db.get_ip_of_mac.return_value = None

    assert profiler.get_gw_ip_using_gw_mac("mac") is None


@pytest.mark.parametrize(
    "info_type, attr_name, db_method, db_value",
    [
        ("mac", "gw_macs", "get_gateway_mac", "00:1A:2B:3C:4D:5E"),
        ("ip", "gw_ips", "get_gateway_ip", "192.168.1.1"),
    ],
)
def test_is_gw_info_detected_loads_from_db(
    info_type, attr_name, db_method, db_value
):
    profiler = ModuleFactory().create_profiler_worker_obj()
    setattr(profiler, attr_name, {})
    setattr(profiler.db, db_method, Mock(return_value=db_value))

    assert profiler.is_gw_info_detected(info_type, "eth0") is True
    assert getattr(profiler, attr_name)["eth0"] == db_value


def test_is_gw_info_detected_uses_cached_value():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.gw_macs = {"eth0": "mac"}

    assert profiler.is_gw_info_detected("mac", "eth0") is True
    profiler.db.get_gateway_mac.assert_not_called()


def test_is_gw_info_detected_unsupported_info_type():
    profiler = ModuleFactory().create_profiler_worker_obj()

    with pytest.raises(ValueError, match="Unsupported info_type"):
        profiler.is_gw_info_detected("unsupported", "eth0")


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        ("224.0.0.1", True),
        ("127.0.0.1", True),
        ("169.254.1.1", True),
        ("240.0.0.1", True),
        ("8.8.8.8", False),
        ("not-an-ip", True),
    ],
)
def test_is_ignored_ip(ip, expected):
    profiler = ModuleFactory().create_profiler_worker_obj()

    assert profiler.is_ignored_ip(ip) is expected


@pytest.mark.parametrize(
    ("starttime", "type_", "expected"),
    [
        ("1", "conn", True),
        ("1", "http", True),
        (None, "conn", False),
        ("1", "conn.log", False),
        ("1", "unsupported", False),
    ],
)
def test_is_supported_flow_type(starttime, type_, expected):
    profiler = ModuleFactory().create_profiler_worker_obj()

    assert (
        profiler._is_supported_flow_type(
            Mock(starttime=starttime, type_=type_)
        )
        is expected
    )


def test_add_flow_to_profile_returns_false_for_unsupported_flow():
    profiler = ModuleFactory().create_profiler_worker_obj()

    assert (
        profiler.add_flow_to_profile(
            Mock(
                type_="unsupported",
                starttime="1",
                saddr="1.1.1.1",
                daddr="2.2.2.2",
            )
        )
        is False
    )


def test_add_flow_to_profile_rejects_invalid_addresses():
    profiler = ModuleFactory().create_profiler_worker_obj()
    flow = Mock(type_="conn", starttime="1", saddr="bad", daddr=None)

    assert profiler.add_flow_to_profile(flow) is False


def test_add_flow_to_profile_stops_after_whitelist():
    profiler = ModuleFactory().create_profiler_worker_obj()
    flow = make_conn(type_="conn")
    profiler.convert_starttime_to_unix_ts = Mock(return_value="2.0")
    profiler._log_flow_latency = Mock()
    profiler.get_gateway_info = Mock()
    profiler.whitelist.is_whitelisted_flow = Mock(return_value=True)
    profiler.store_features_going_out = Mock()
    assert profiler.add_flow_to_profile(flow) is True

    profiler.db.add_profile.assert_not_called()
    profiler.store_features_going_out.assert_not_called()


def test_add_flow_to_profile_stores_forward_and_reverse_flows():
    profiler = ModuleFactory().create_profiler_worker_obj()
    flow = make_conn(type_="conn")
    profiler.analysis_direction = "all"
    profiler.convert_starttime_to_unix_ts = Mock(return_value="2.0")
    profiler._log_flow_latency = Mock()
    profiler.get_gateway_info = Mock()
    profiler.whitelist.is_whitelisted_flow = Mock(return_value=False)
    profiler.store_features_going_out = Mock()
    profiler.handle_in_flow = Mock()
    profiler.db.get_timewindow.return_value = "tw1"
    profiler.db.is_cyst_enabled.return_value = False

    assert profiler.add_flow_to_profile(flow) is True

    profiler.db.add_profile.assert_called_once_with(
        "profile_192.168.1.1", "2.0"
    )
    profiler.store_features_going_out.assert_called_once_with(
        flow, "profile_192.168.1.1", "tw1"
    )
    profiler.handle_in_flow.assert_called_once_with(flow)
    assert flow.starttime == "2.0"


def test_update_the_files_input_handler_knows_about():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.input_handler.line_processor_cache = {}
    msg = {"data": json.dumps({"conn.log": {"foo": 1}})}

    profiler.update_the_files_input_handler_knows_about(msg)

    assert profiler.input_handler.line_processor_cache == {
        "conn.log": {"foo": 1}
    }


def test_is_stop_msg():
    profiler = ModuleFactory().create_profiler_worker_obj()

    assert profiler.is_stop_msg("stop") is True
    assert profiler.is_stop_msg("not_stop") is False


def test_should_stop_always_returns_false():
    profiler = ModuleFactory().create_profiler_worker_obj()

    assert profiler.should_stop() is False


def test_pre_main_updates_line_processor_cache():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.name = "profiler_worker_process_2"
    profiler.input_handler.line_processor_cache = {}
    profiler.db.get_line_processors.return_value = {
        "conn.log": json.dumps({"ts": 0})
    }

    profiler.pre_main()

    assert profiler.input_handler.line_processor_cache == {
        "conn.log": {"ts": 0}
    }


def test_main_returns_when_queue_is_empty():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.get_msg = Mock(return_value=None)
    profiler.get_msg_from_queue = Mock(return_value=None)

    assert profiler.main() is None


def test_main_stops_on_stop_message():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.get_msg = Mock(return_value=None)
    profiler.get_msg_from_queue = Mock(return_value="stop")

    assert profiler.main() == 1


def test_main_requeues_unknown_line_processor_until_input_done():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.get_msg = Mock(return_value=None)
    msg = {"line": {"foo": "bar"}}
    profiler.get_msg_from_queue = Mock(return_value=msg)
    profiler.is_input_done_event.is_set.return_value = False
    profiler.input_handler.process_line = Mock(
        return_value=(None, "unknown line_processor")
    )

    profiler.main()

    profiler.profiler_queue.put.assert_called_once_with(msg)
    profiler.db.increment_processed_flows.assert_not_called()


def test_main_does_not_requeue_unknown_line_processor_after_input_done():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.get_msg = Mock(return_value=None)
    msg = {"line": {"foo": "bar"}}
    profiler.get_msg_from_queue = Mock(return_value=msg)
    profiler.is_input_done_event.is_set.return_value = True
    profiler.input_handler.process_line = Mock(
        return_value=(None, "unknown line_processor")
    )

    profiler.main()

    profiler.profiler_queue.put.assert_not_called()


def test_main_processes_valid_flow_and_records_performance():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.generate_performance_plots = True
    profiler.get_msg = Mock(return_value=None)
    profiler.get_msg_from_queue = Mock(return_value={"line": {"foo": "bar"}})
    profiler.is_stop_msg = Mock(return_value=False)
    flow = Mock()
    profiler.input_handler.process_line = Mock(return_value=(flow, None))
    profiler.add_flow_to_profile = Mock()
    profiler.localnet_handler.handle_setting_local_net = Mock()

    assert profiler.main() is None

    profiler.add_flow_to_profile.assert_called_once_with(flow)
    profiler.localnet_handler.handle_setting_local_net.assert_called_once_with(
        flow
    )
    profiler.db.increment_processed_flows.assert_called_once()
    profiler.db.record_flow_per_minute.assert_called_once_with(profiler.name)


def test_main_collects_gc_every_10000_flows():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.get_msg = Mock(return_value=None)
    profiler.get_msg_from_queue = Mock(return_value={"line": {"foo": "bar"}})
    profiler.input_handler.process_line = Mock(return_value=(Mock(), None))
    profiler.add_flow_to_profile = Mock()
    profiler.localnet_handler.handle_setting_local_net = Mock()
    profiler.received_lines = 9999

    with patch("slips_files.core.profiler_worker.gc.collect") as mock_collect:
        profiler.main()

    mock_collect.assert_called_once()


def test_main_logs_exception():
    profiler = ModuleFactory().create_profiler_worker_obj()
    profiler.get_msg = Mock(return_value=None)
    profiler.get_msg_from_queue = Mock(return_value={"line": {"foo": "bar"}})
    profiler.input_handler.process_line = Mock(side_effect=Exception("boom"))
    profiler.print_traceback = Mock(return_value="traceback")

    profiler.main()

    profiler.print.assert_called_once()
