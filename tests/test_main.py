# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import MagicMock, patch, mock_open, Mock
import pytest
from tests.module_factory import ModuleFactory
from datetime import datetime, timedelta
import sys


@pytest.mark.parametrize(
    "input_information, expected_input_type, expected_line_type",
    [  # Test Case 1: Valid Argus input
        ("argus", "stdin", "argus"),
        # Test Case 2: Valid Suricata input
        ("Suricata", "stdin", "suricata"),
        # Test Case 3: Valid Zeek input
        ("Zeek", "stdin", "zeek"),
    ],
)
def test_handle_flows_from_stdin_valid_input(
    input_information, expected_input_type, expected_line_type
):
    main = ModuleFactory().create_main_obj()
    main.mode = "interactive"

    input_type, line_type = main.handle_flows_from_stdin(input_information)
    assert input_type == expected_input_type
    assert line_type == expected_line_type


def test_handle_flows_from_stdin_invalid_input():
    main = ModuleFactory().create_main_obj()
    main.mode = "interactive"

    with pytest.raises(SystemExit):
        main.handle_flows_from_stdin("invalid")


@pytest.mark.parametrize(
    "args, input_type, expected_result",
    [  # Testcase1: input module
        ({"input_module": True, "growing": False}, "zeek_folder", True),
        # Testcase2: growing
        ({"input_module": False, "growing": True}, "zeek_folder", True),
        # Testcase3: stdin
        ({"input_module": False, "growing": False}, "stdin", True),
        # Testcase4: pcap
        ({"input_module": False, "growing": False}, "pcap", True),
        # Testcase5: interface
        ({"input_module": False, "growing": False}, "interface", True),
        # Testcase6: other type, false
        ({"input_module": False, "growing": False}, "nfdump", False),
    ],
)
def test_is_total_flows_unknown(args, input_type, expected_result):
    main = ModuleFactory().create_main_obj()
    main.args = MagicMock(**args)
    main.input_type = input_type

    assert main.is_total_flows_unknown() == expected_result


@pytest.mark.parametrize(
    "mode, time_diff, expected_calls",
    [  # Testcase1: Should update stats
        ("interactive", 10, 1),
        # Testcase2: Shouldn't update stats
        ("interactive", 2, 0),
        # Testcase3: Shouldn't update stats
        ("daemonized", 10, 0),
    ],
)
def test_update_stats(mode, time_diff, expected_calls):
    main = ModuleFactory().create_main_obj()
    main.is_total_flows_unknown = Mock()
    main.is_total_flows_unknown.return_value = False
    main.mode = mode
    main.last_updated_stats_time = datetime.now() - timedelta(
        seconds=time_diff
    )
    main.db = MagicMock()
    main.db.get_modified_ips_in_the_last_tw.return_value = 5
    main.db.get_profiles_len.return_value = 10
    main.db.get_evidence_number.return_value = 2
    main.twid_width = 300

    with patch.object(main, "print") as mock_print:
        main.update_stats()
        assert mock_print.call_count == expected_calls


@pytest.mark.parametrize(
    "args_verbose, conf_verbose, args_debug, conf_debug, "
    "expected_verbose, expected_debug",
    [  # Testcase1: Use config values
        (None, 2, None, 1, 2, 1),
        # Testcase2: Use args values
        (3, 2, 2, 1, 3, 2),
        # Testcase3: Limit to minimum values
        (0, 2, -1, 1, 1, 0),
        # Testcase4: Limit to minimum values from config
        (None, 0, None, 0, 1, 0),
    ],
)
def test_setup_print_levels(
    args_verbose,
    conf_verbose,
    args_debug,
    conf_debug,
    expected_verbose,
    expected_debug,
):
    main = ModuleFactory().create_main_obj()
    main.args = MagicMock(verbose=args_verbose, debug=args_debug)
    main.conf = MagicMock()
    main.conf.verbose.return_value = conf_verbose
    main.conf.debug.return_value = conf_debug

    main.setup_print_levels()

    assert main.args.verbose == expected_verbose
    assert main.args.debug == expected_debug


@pytest.mark.parametrize(
    "mode, daemon, expected_mode, expected_daemon_type",
    [  # Test Case 1: Interactive mode, no daemon
        ("interactive", None, "interactive", type(None)),
        # Test Case 2: Daemonized mode, daemon object provided
        ("daemonized", MagicMock(), "daemonized", MagicMock),
    ],
)
def test_set_mode(mode, daemon, expected_mode, expected_daemon_type):
    main = ModuleFactory().create_main_obj()
    main.set_mode(mode, daemon)
    assert main.mode == expected_mode
    assert isinstance(main.daemon, expected_daemon_type)


@pytest.mark.parametrize(
    "txt, expected_content",
    [  # Test Case 1: Log a simple message
        ("Test log", "Test log\n"),
        # Test Case 2: Log another message
        ("Another log", "Another log\n"),
    ],
)
def test_log(txt, expected_content):
    main = ModuleFactory().create_main_obj()
    main.daemon = MagicMock()
    main.daemon.stdout = "test_stdout.log"

    with patch("builtins.open", mock_open()) as mock_open_file:
        main.log(txt)

    mock_open_file.return_value.write.assert_called_once_with(expected_content)


@pytest.mark.parametrize(
    "text, verbose, debug, log_to_logfiles_only, expected_notification",
    [  # Test Case 1: Standard print, notify observers
        (
            "Test print",
            1,
            0,
            False,
            {
                "from": "Main",
                "txt": "Test print",
                "verbose": 1,
                "debug": 0,
                "log_to_logfiles_only": False,
            },
        ),
        # Test Case 2: Debug message, notify observers with specific flags
        (
            "Debug message",
            2,
            1,
            True,
            {
                "from": "Main",
                "txt": "Debug message",
                "verbose": 2,
                "debug": 1,
                "log_to_logfiles_only": True,
            },
        ),
    ],
)
def test_print(
    text, verbose, debug, log_to_logfiles_only, expected_notification
):
    main = ModuleFactory().create_main_obj()
    main.name = "Main"
    main.printer = Mock()
    main.printer.print = Mock()
    main.print(text, verbose, debug, log_to_logfiles_only)
    main.printer.print.assert_called_once()


@pytest.mark.parametrize(
    "given_path, cmd_result, expected_input_type",
    [
        # Test Case 1: Valid PCAP file
        ("/path/to/file.pcap", b"pcap capture file", "pcap"),
        # Test Case 2: Valid NFDUMP file
        ("/path/to/file.nfcap", b"nfcap file", "nfdump"),
        # Test Case 3: Valid BINETFLOW (CSV) file
        ("/path/to/file.csv", b"CSV text", "binetflow"),
        # Test Case 4: Valid SURICATA (JSON) file
        ("/path/to/file.json", b'{"flow_id": "123"}', "suricata"),
        # Test Case 5: Valid ZEEK log file
        ("/path/to/file.log", b"2021-01-01\tsome\tdata", "zeek_log_file"),
        # Test Case 6: Valid BINETFLOW (tab-separated) file
        (
            "/path/to/file.binetflow",
            b"StartTime\tDur\tProto\tSrcAddr\tSport",
            "binetflow-tabs",
        ),
    ],
)
def test_get_input_file_type(given_path, cmd_result, expected_input_type):
    main = ModuleFactory().create_main_obj()

    with (
        patch("subprocess.run") as mock_run,
        patch("os.path.isfile", return_value=True),
        patch(
            "os.path.isdir", return_value=expected_input_type == "zeek_folder"
        ),
        patch("builtins.open", mock_open(read_data=cmd_result.decode())),
    ):
        mock_run.return_value.stdout = cmd_result

        result = main.get_input_file_type(given_path)

        assert result == expected_input_type


@pytest.mark.parametrize(
    "input_information, expected_filepath",
    [
        # Test Case 1: Simple filename
        ("input.pcap", "output/input"),
        # Test Case 2: Filename with trailing slash
        ("input.pcap/", "output/input"),
        # Test Case 3: Filename with path
        ("path/to/input.pcap", "output/input"),
    ],
)
def test_save_the_db(input_information, expected_filepath):
    main = ModuleFactory().create_main_obj()
    main.input_information = input_information
    main.args = MagicMock()
    main.args.output = "output"
    main.db = MagicMock()
    main.save_the_db()
    main.db.save.assert_called_once_with(expected_filepath)


@pytest.mark.parametrize(
    "input_type, is_running_non_stop, expected_result",
    [
        # Test Case 1: PCAP input, not a growing Zeek directory
        ("pcap", False, True),
        # Test Case 2: Interface input, not a growing Zeek directory
        ("interface", False, True),
        # Test Case 3: Zeek folder input, is a growing Zeek directory
        ("zeek_folder", True, True),
        # Test Case 4: Other input type, not a growing Zeek directory
        ("binetflow", False, False),
    ],
)
def test_was_running_zeek(input_type, is_running_non_stop, expected_result):
    main = ModuleFactory().create_main_obj()
    main.db = MagicMock()
    main.db.get_input_type.return_value = input_type
    main.db.is_running_non_stop.return_value = is_running_non_stop

    assert main.was_running_zeek() == expected_result


def test_delete_zeek_files_enabled():
    main = ModuleFactory().create_main_obj()
    main.conf = MagicMock()
    main.conf.delete_zeek_files.return_value = True
    main.zeek_dir = "zeek_dir"

    with patch("shutil.rmtree") as mock_rmtree:
        main.delete_zeek_files()
        mock_rmtree.assert_called_once_with("zeek_dir")


def test_delete_zeek_files_disabled():
    main = ModuleFactory().create_main_obj()
    main.conf = MagicMock()
    main.conf.delete_zeek_files.return_value = False
    main.zeek_dir = "zeek_dir"

    with patch("shutil.rmtree") as mock_rmtree:
        main.delete_zeek_files()
        mock_rmtree.assert_not_called()


# TODO should be moved to utils unit tests after the PR is merged
# def test_get_slips_version():
#     main = ModuleFactory().create_main_obj()
#     version_content = "1.2.3"
#
#     with patch(
#         "builtins.open", mock_open(read_data=version_content)
#     ) as mock_file:
#         result = main.get_slips_version()
#
#     mock_file.assert_called_once_with("VERSION", "r")
#     assert result == version_content


def test_check_zeek_or_bro_zeek_found():
    main = ModuleFactory().create_main_obj()
    main.input_type = "pcap"

    with patch("shutil.which") as mock_which:
        mock_which.return_value = "zeek"
        result = main.check_zeek_or_bro()

    assert result == "zeek"


def test_check_zeek_or_bro_bro_found():
    main = ModuleFactory().create_main_obj()
    main.input_type = "pcap"

    with patch("shutil.which") as mock_which:
        mock_which.side_effect = [None, "bro"]
        result = main.check_zeek_or_bro()

    assert result == "bro"


def test_check_zeek_or_bro_not_needed():
    main = ModuleFactory().create_main_obj()
    main.input_type = "file"

    result = main.check_zeek_or_bro()
    expected_result = False
    assert result == expected_result


def test_check_zeek_or_bro_not_found():
    main = ModuleFactory().create_main_obj()
    main.input_type = "pcap"

    with (
        patch("shutil.which", return_value=None),
        patch.object(main, "terminate_slips") as mock_terminate,
    ):
        result = main.check_zeek_or_bro()

    expected_result = False
    assert result == expected_result
    mock_terminate.assert_called_once()


@pytest.mark.parametrize(
    "store_in_output, expected_dir",
    [
        # Test Case 1: Store Zeek files in the output directory
        (True, "output/zeek_files"),
        # Test Case 2: Use default directory for Zeek files
        (False, "zeek_files_inputfile/"),
    ],
)
def test_prepare_zeek_output_dir(store_in_output, expected_dir):
    main = ModuleFactory().create_main_obj()
    main.input_information = "/path/to/inputfile.pcap"
    main.args = Mock()
    main.args.output = "output"
    main.conf = Mock()
    main.conf.store_zeek_files_in_the_output_dir.return_value = store_in_output

    with patch("os.path.join", lambda *args: "/".join(args)):
        main.prepare_zeek_output_dir()

    assert main.zeek_dir == expected_dir


def test_terminate_slips_interactive():
    main = ModuleFactory().create_main_obj()
    main.mode = "interactive"
    main.conf = MagicMock()
    main.conf.get_cpu_profiler_enable.return_value = False

    with patch.object(sys, "exit") as mock_exit:
        main.terminate_slips()

    mock_exit.assert_called_once_with(0)


def test_terminate_slips_daemonized():
    main = ModuleFactory().create_main_obj()
    main.mode = "daemonized"
    main.daemon = MagicMock()
    main.conf = MagicMock()
    main.conf.get_cpu_profiler_enable.return_value = False

    with patch.object(sys, "exit") as mock_exit:
        main.terminate_slips()

    main.daemon.stop.assert_called_once()
    mock_exit.assert_called_once_with(0)


def test_terminate_slips_cpu_profiler_enabled():
    main = ModuleFactory().create_main_obj()
    main.mode = "interactive"
    main.conf = MagicMock()
    main.conf.get_cpu_profiler_enable.return_value = True

    with patch.object(sys, "exit") as mock_exit:
        main.terminate_slips()

    mock_exit.assert_not_called()


def test_prepare_output_dir_with_o_flag():
    main = ModuleFactory().create_main_obj()
    main.args = MagicMock()
    main.args.output = "custom_output_dir"
    main.args.testing = False

    with (
        patch.object(sys, "argv", ["-o"]),
        patch("os.path.exists", return_value=True),
        patch("os.listdir", return_value=["file1.txt", "dir1"]),
        patch("os.path.isfile", return_value=True),
        patch("os.remove") as mock_remove,
        patch("os.path.isdir", return_value=False),
    ):
        main.prepare_output_dir()
        assert mock_remove.call_count == 2


@pytest.mark.parametrize(
    "testing, filename, " "expected_call_count",
    [
        # Test Case 1: Testing mode,
        # slips_output.txt should not be deleted
        (True, "slips_output.txt", 0),
        # Test Case 2: Not testing mode,
        # slips_output.txt should be deleted
        (False, "slips_output.txt", 1),
        # Test Case 3: Testing mode,
        # other files should be deleted
        (True, "other_file.txt", 1),
        # Test Case 4: Not testing mode,
        # other files should be deleted
        (False, "other_file.txt", 1),
    ],
)
def test_prepare_output_dir_testing_mode(
    testing, filename, expected_call_count
):
    main = ModuleFactory().create_main_obj()
    main.args = MagicMock()
    main.args.output = "test_output"
    main.args.testing = testing

    with (
        patch.object(sys, "argv", ["-o"]),
        patch("os.path.exists", return_value=True),
        patch("os.listdir", return_value=[filename]),
        patch("os.path.isfile", return_value=True),
        patch("os.remove") as mock_remove,
    ):
        main.prepare_output_dir()
        assert mock_remove.call_count == expected_call_count
