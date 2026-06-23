# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import threading
import pytest
from pathlib import Path
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


def test_get_zeek_cmd_and_logs_dir_logs_command_to_logfiles_only(
    tmp_path: Path,
) -> None:
    """Test Zeek command logging is restricted to log files."""
    input_process = ModuleFactory().create_input_obj("", InputType.PCAP)
    input_process.print = Mock()
    command = ["zeek", "-r", "pcaps/input file.pcap"]
    input_process.zeek_utils._construct_zeek_cmd = Mock(return_value=command)

    returned_command, zeek_dir = (
        input_process.zeek_utils._get_zeek_cmd_and_logs_dir(
            str(tmp_path), "pcaps/input file.pcap"
        )
    )

    assert returned_command == command
    assert zeek_dir == str(tmp_path)
    input_process.print.assert_called_once_with(
        "Zeek command: zeek -r 'pcaps/input file.pcap'",
        log_to_logfiles_only=True,
    )


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
        (False, "zeek_files_inputfile"),
    ],
)
def test_create_zeek_output_dir(store_in_output, expected_dir):
    input_process = ModuleFactory().create_input_obj(
        "pcaps/inputfile.pcap", InputType.PCAP
    )
    input_process.zeek_dir = None
    input_process.args.output = "output"
    input_process.zeek_utils.is_running_non_stop = False
    input_process.conf.store_zeek_files_in_the_output_dir.return_value = (
        store_in_output
    )

    assert input_process.zeek_utils.create_zeek_output_dir() == expected_dir


# def test_run_zeek_publishes_stop_on_zeek_error(monkeypatch):
#     input_process = ModuleFactory().create_input_obj(
#         "pcaps/inputfile.pcap", InputType.PCAP
#     )
#     input_process.db.publish_stop = Mock()
#     input_process.print = Mock()
#
#     zeek_process = Mock()
#     zeek_process.pid = 4321
#     zeek_process.returncode = 1
#     zeek_process.communicate.return_value = (b"", b"zeek failed")
#
#     monkeypatch.setattr(
#         input_process.zeek_utils,
#         "_construct_zeek_cmd",
#         Mock(return_value=["zeek", "-r", "pcaps/inputfile.pcap"]),
#     )
#     monkeypatch.setattr(
#         subprocess,
#         "Popen",
#         Mock(return_value=zeek_process),
#     )
#
#     input_process.zeek_utils.run_zeek(".", "pcaps/inputfile.pcap")
#
#     input_process.print.assert_any_call(
#         "Zeek error. return code: 1 \nzeek failed"
#     )
#     input_process.db.publish_stop.assert_called_once_with()
#

# def test_run_zeek_publishes_stop_on_nonzero_return_code_without_stderr(
#     monkeypatch,
# ):
#     input_process = ModuleFactory().create_input_obj(
#         "pcaps/inputfile.pcap", InputType.PCAP
#     )
#     input_process.db.publish_stop = Mock()
#     input_process.print = Mock()
#
#     zeek_process = Mock()
#     zeek_process.pid = 4321
#     zeek_process.returncode = 2
#     zeek_process.communicate.return_value = (b"", b"")
#
#     monkeypatch.setattr(
#         input_process.zeek_utils,
#         "_construct_zeek_cmd",
#         Mock(return_value=["zeek", "-r", "pcaps/inputfile.pcap"]),
#     )
#     monkeypatch.setattr(
#         subprocess,
#         "Popen",
#         Mock(return_value=zeek_process),
#     )
#
#     input_process.zeek_utils.run_zeek(".", "pcaps/inputfile.pcap")
#
#     input_process.print.assert_any_call("Zeek exited with return code 2.")
#     input_process.db.publish_stop.assert_called_once_with()


def test_init_zeek_and_start_the_zeek_thread_returns_false_on_error(
    monkeypatch, tmp_path
):
    input_process = ModuleFactory().create_input_obj(
        "pcaps/inputfile.pcap", InputType.PCAP
    )
    observer = Mock()
    input_process.args.is_slips_started_by_an_update = False

    def mock_run_zeek(*args, **_kwargs):
        args[3]["error"] = "zeek failed"
        args[2].set()

    monkeypatch.setattr(
        input_process.zeek_utils,
        "run_zeek",
        mock_run_zeek,
    )

    assert (
        input_process.zeek_utils.init_zeek_and_start_the_zeek_thread(
            observer,
            str(tmp_path),
            "pcaps/inputfile.pcap",
        )
        is False
    )
    observer.start.assert_called_once_with(
        str(tmp_path), "pcaps/inputfile.pcap"
    )
    input_process.is_input_failed_event.set.assert_called_once_with()


def test_init_zeek_and_start_the_zeek_thread_returns_false_on_timeout(
    monkeypatch, tmp_path
):
    input_process = ModuleFactory().create_input_obj(
        "pcaps/inputfile.pcap", InputType.PCAP
    )
    observer = Mock()
    input_process.args.is_slips_started_by_an_update = False
    input_process.db.publish_stop = Mock()

    def mock_run_zeek(*_args, **_kwargs):
        return None

    monkeypatch.setattr(
        input_process.zeek_utils,
        "run_zeek",
        mock_run_zeek,
    )

    assert (
        input_process.zeek_utils.init_zeek_and_start_the_zeek_thread(
            observer,
            str(tmp_path),
            "pcaps/inputfile.pcap",
        )
        is False
    )
    input_process.print.assert_any_call(
        "Zeek startup timed out. Stopping Slips."
    )
    input_process.is_input_failed_event.set.assert_called_once_with()
    input_process.db.publish_stop.assert_called_once_with()


def test_check_zeek_startup_accepts_running_process(monkeypatch):
    input_process = ModuleFactory().create_input_obj(
        "pcaps/inputfile.pcap", InputType.PCAP
    )
    zeek = Mock()
    zeek.poll.return_value = None

    monkeypatch.setattr(
        "slips_files.core.input.zeek.utils.zeek_input_utils.time.sleep",
        Mock(),
    )
    monkeypatch.setattr(
        "slips_files.core.input.zeek.utils.zeek_input_utils.time.time",
        Mock(side_effect=[0, 1, 3]),
    )

    assert (
        input_process.zeek_utils._did_zeek_startup_successfully(
            zeek,
        )
        is True
    )
    zeek.communicate.assert_not_called()


def test_check_zeek_startup_rejects_immediate_exit(monkeypatch):
    input_process = ModuleFactory().create_input_obj(
        "pcaps/inputfile.pcap", InputType.PCAP
    )
    zeek = Mock()
    zeek.poll.return_value = 1
    zeek.returncode = 1
    zeek.communicate.return_value = (b"", b"startup failed")

    monkeypatch.setattr(
        "slips_files.core.input.zeek.utils.zeek_input_utils.time.time",
        Mock(return_value=0),
    )

    assert (
        input_process.zeek_utils._did_zeek_startup_successfully(
            zeek,
        )
        is False
    )
    zeek.communicate.assert_not_called()
    input_process.db.publish_stop.assert_not_called()


def test_run_zeek_skips_runtime_output_after_startup_exit(tmp_path):
    input_process = ModuleFactory().create_input_obj(
        "pcaps/inputfile.pcap", InputType.PCAP
    )
    input_process.zeek_utils._prep_and_start_the_zeek_proc = Mock()
    input_process.zeek_utils._did_zeek_startup_successfully = Mock(
        return_value=False
    )
    input_process.zeek_utils._check_running_zeek_output = Mock()

    input_process.zeek_utils.run_zeek(
        str(tmp_path),
        "pcaps/inputfile.pcap",
        startup_status={},
        startup_finished_event=threading.Event(),
    )

    input_process.zeek_utils._check_running_zeek_output.assert_not_called()


def test_handle_zeek_process_result_suppresses_expected_shutdown_stderr():
    input_process = ModuleFactory().create_input_obj(
        "pcaps/inputfile.pcap", InputType.PCAP
    )
    zeek = Mock()
    zeek.returncode = -9
    input_process.zeek_utils.zeek_shutdown_requested = True

    assert (
        input_process.zeek_utils._handle_zeek_process_result(
            zeek,
            b"",
            b"<command line>, line 3: listening on eth0",
            startup_status={},
        )
        is True
    )
    input_process.print.assert_not_called()
    input_process.db.publish_stop.assert_not_called()
