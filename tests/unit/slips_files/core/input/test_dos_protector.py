# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import Mock, patch

from slips_files.core.input.zeek.utils.dos_protector import DoSProtector


def make_protector(is_running_non_stop=True, flows_per_second=0):
    db = Mock()
    db.is_running_non_stop.return_value = is_running_non_stop
    db.get_core_module_flows_per_second.return_value = flows_per_second

    input_process = Mock()
    input_process.db = db
    input_process.print = Mock()

    return DoSProtector(input_process), input_process, db


def test_get_input_flows_per_min_uses_db_value():
    protector, _, _ = make_protector(flows_per_second=7)

    assert protector._get_input_flows_per_min() == 420


def test_get_sampling_ratio_returns_one_when_input_rate_is_missing():
    protector, _, db = make_protector(flows_per_second=3)
    db.get_core_module_flows_per_second.return_value = None

    assert protector._get_sampling_ratio() == 1


def test_should_run_returns_false_when_not_running_non_stop():
    protector, _, _ = make_protector(is_running_non_stop=False)

    assert protector._should_run() is False


def test_should_run_returns_true_while_sampling_window_is_active():
    protector, _, _ = make_protector(is_running_non_stop=True)
    protector.flow_sampling_stop_time = 120

    with patch(
        "slips_files.core.input.zeek.utils.dos_protector.time.time",
        return_value=100,
    ):
        assert protector._should_run() is True


def test_should_run_stops_sampling_and_prints_when_throughput_recovers():
    protector, input_process, _ = make_protector(
        is_running_non_stop=True, flows_per_second=10
    )
    protector._is_now_sampling = True

    with patch(
        "slips_files.core.input.zeek.utils.dos_protector.time.time",
        return_value=100,
    ):
        assert protector._should_run() is False

    assert protector._is_now_sampling is False
    input_process.print.assert_called_once()
    assert (
        "Throughput is back to normal" in input_process.print.call_args[0][0]
    )


def test_get_number_of_flows_to_skip_updates_sampling_window_and_prints():
    protector, input_process, _ = make_protector(
        is_running_non_stop=True, flows_per_second=50
    )
    protector.flows_per_min_threshold = 2000
    protector.sampling_time_window = 60

    with (
        patch(
            "slips_files.core.input.zeek.utils.dos_protector.time.time",
            side_effect=[100, 100, 100, 100],
        ),
        patch(
            "slips_files.core.input.zeek.utils.dos_protector.utils.convert_ts_format",
            return_value="formatted-ts",
        ),
    ):
        assert protector.get_number_of_flows_to_skip() == 449

    assert protector.flow_sampling_stop_time == 160
    assert protector._is_now_sampling is True
    input_process.print.assert_called_once()
    assert "Slips started skipping flows due to high traffic" in (
        input_process.print.call_args[0][0]
    )


def test_print_skipping_flows_warning_extends_existing_sampling_window():
    protector, input_process, _ = make_protector()
    protector._is_now_sampling = True
    protector.flow_sampling_stop_time = 160

    with patch(
        "slips_files.core.input.zeek.utils.dos_protector.utils.convert_ts_format",
        return_value="formatted-ts",
    ):
        protector.print_skipping_flows_warning(449, True)

    input_process.print.assert_called_once()
    assert "still under high traffic" in input_process.print.call_args[0][0]
