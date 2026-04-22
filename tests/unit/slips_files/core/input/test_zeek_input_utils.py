# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import pytest
from types import SimpleNamespace
from unittest.mock import Mock
from tests.module_factory import ModuleFactory
from slips_files.common.input_type import InputType
from slips_files.core.input.zeek.utils.zeek_input_utils import ZeekInputUtils


@pytest.mark.parametrize(
    "contents,expected",
    [
        ("#separator \x09\n", True),
        ("field1\tfield2\n", True),
        (json.dumps({"ts": 1}), False),
    ],
)
def test_is_zeek_tabs_file_detects_format(tmp_path, contents, expected):
    input_process = ModuleFactory().create_input_obj(
        "", InputType.ZEEK_LOG_FILE
    )
    test_file = tmp_path / "conn.log"
    test_file.write_text(contents, encoding="utf-8")

    assert (
        input_process.zeek_utils.is_zeek_tabs_file(str(test_file)) == expected
    )


def test_get_ts_from_line_returns_timestamp_for_tabs():
    input_process = ModuleFactory().create_input_obj(
        "", InputType.ZEEK_LOG_FILE
    )
    input_process.is_zeek_tabs = True

    ts, line = input_process.zeek_utils.get_ts_from_line("1.5\tfield\n")
    assert ts == 1.5
    assert line == "1.5\tfield\n"


def test_read_zeek_files_drains_generated_lines_during_live_update(tmp_path):
    test_file = tmp_path / "conn.log"
    test_file.write_text(
        "\n".join(
            [
                json.dumps({"ts": 1, "uid": "flow-1"}),
                json.dumps({"ts": 2, "uid": "flow-2"}),
                "",
            ]
        ),
        encoding="utf-8",
    )
    live_update_event = Mock()
    live_update_event.is_set.return_value = True
    db = Mock()
    db.is_running_non_stop.return_value = False
    db.get_all_zeek_files.return_value = {str(test_file): "eth0"}
    input_process = SimpleNamespace(
        args=Mock(),
        bro_timeout=100,
        conf=Mock(),
        db=db,
        give_profiler=Mock(),
        is_slips_live_updating_event=live_update_event,
        is_zeek_tabs=False,
        lines=0,
        print=Mock(),
        should_stop=Mock(return_value=True),
        store_flows_read_per_second=Mock(),
    )
    zeek_utils = ZeekInputUtils(input_process)
    zeek_utils.shutdown_zeek_runtime = Mock()
    get_flows_to_skip = Mock(return_value=0)
    zeek_utils.dos_protector.get_number_of_flows_to_skip = get_flows_to_skip

    assert zeek_utils.read_zeek_files() == 2
    assert input_process.give_profiler.call_count == 2
    zeek_utils.shutdown_zeek_runtime.assert_called_once()
    assert get_flows_to_skip.call_count >= 2


@pytest.mark.parametrize(
    "store_in_output, expected_dir",
    [
        (True, "output/zeek_files"),
        (False, "zeek_files_inputfile/"),
    ],
)
def test_get_zeek_output_dir(store_in_output, expected_dir):
    input_process = ModuleFactory().create_input_obj(
        "pcaps/inputfile.pcap", InputType.PCAP
    )
    input_process.zeek_dir = None
    input_process.args.output = "output"
    input_process.conf.store_zeek_files_in_the_output_dir.return_value = (
        store_in_output
    )

    assert input_process.zeek_utils.get_zeek_output_dir() == expected_dir
