# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import MagicMock, mock_open, patch, call as mockedcall
import pytest
from tests.module_factory import ModuleFactory
from pathlib import Path


@pytest.mark.parametrize(
    "msg, expected_log_content",
    [
        (
            # Testcase1:Regular message logging
            {"from": "sender", "txt": "message_text"},
            "formatted_datetime [sender] message_text\n",
        ),
        (
            # Testcase2:Empty message handling
            {"from": "sender", "txt": ""},
            "formatted_datetime [sender] \n",
        ),
        (
            # Testcase3:Message with special characters
            {"from": "sender", "txt": "Message with !@#$%^&*()_+=-`~"},
            "formatted_datetime [sender] Message with !@#$%^&*()_+=-`~\n",
        ),
    ],
)
@patch("slips_files.common.slips_utils.Utils.convert_format")
def test_log_line(mock_convert_format, msg, expected_log_content):
    """Test that the log_line method logs the correct message
    to the slips.log file."""
    mock_convert_format.return_value = "formatted_datetime"

    output = ModuleFactory().create_output_obj()
    output.slips_logfile = "path/to/slips.log"

    with patch("builtins.open", mock_open()) as mock_file:
        output.log_line(msg)

        mock_file.assert_called_once_with("path/to/slips.log", "a")
        handle = mock_file()
        handle.write.assert_called_once_with(expected_log_content)


def test_print():
    output = ModuleFactory().create_output_obj()
    sender = "SenderName"
    txt = "This is a test message."

    with patch("builtins.print") as mock_print:
        output.print(sender, txt)

    (mock_print.assert_called_once_with(f"[{sender}] {txt}", end="\n"))


@pytest.mark.parametrize(
    "output_verbose, input_verbose, expected_result",
    [  # Testcase1: Input verbose less than output verbose
        (2, 1, True),
        # Testcase2: Input verbose equal to output verbose
        (2, 2, True),
        # Testcase3: Input verbose greater than output verbose
        (2, 3, False),
        # Testcase4: Input verbose is 0
        (1, 0, False),
        # Testcase5: Input verbose is negative
        (1, -1, False),
        # Testcase6: Input verbose greater than the maximum
        (3, 4, False),
    ],
)
def test_enough_verbose(output_verbose, input_verbose, expected_result):
    """Test that the enough_verbose method returns the correct result."""
    output = ModuleFactory().create_output_obj()
    output.verbose = output_verbose

    assert output.enough_verbose(input_verbose) == expected_result


@pytest.mark.parametrize(
    "output_debug, input_debug, expected_result",
    [  # Testcase1: Input debug less than output debug
        (2, 1, True),
        # Testcase2: Input debug equal to output debug
        (2, 2, True),
        # Testcase3: Input debug greater than output debug
        (2, 3, False),
        # Testcase4: Input debug is 0
        (1, 0, False),
        # Testcase5: Input debug is negative
        (1, -1, False),
        # Testcase6: Input debug greater than the maximum
        (3, 4, False),
    ],
)
def test_enough_debug(output_debug, input_debug, expected_result):
    """Test that the enough_debug method returns the correct result."""
    output = ModuleFactory().create_output_obj()
    output.debug = output_debug

    assert output.enough_debug(input_debug) == expected_result


@patch("slips_files.core.output.Output.print")
@patch("slips_files.core.output.Output.log_line")
@patch("slips_files.core.output.Output.log_error")
def test_output_line_all_outputs(mock_log_error, mock_log_line, mock_print):
    output = ModuleFactory().create_output_obj()
    output.verbose = 2
    output.debug = 2

    msg = {
        "from": "SenderName",
        "txt": "Normal message",
        "verbose": 2,
        "debug": 1,
    }

    output.output_line_to_cli_and_logfiles(msg)

    mock_print.assert_called_with(msg["from"], msg["txt"], end="\n")
    mock_log_line.assert_called_with(msg)
    mock_log_error.assert_called_with(msg)


@patch("slips_files.core.output.Output.print")
@patch("slips_files.core.output.Output.log_line")
@patch("slips_files.core.output.Output.log_error")
def test_output_line_no_outputs(mock_log_error, mock_log_line, mock_print):
    """
    Test that output_line doesn't print or log when the provided
    verbose level (3) is higher than the module's verbose level (2).
    """
    output = ModuleFactory().create_output_obj()
    output.verbose = 2
    output.debug = 2

    msg = {
        "from": "SenderName",
        "txt": "High verbose message",
        "verbose": 3,
        "debug": 0,
    }

    output.output_line_to_cli_and_logfiles(msg)

    mock_print.assert_not_called()
    mock_log_line.assert_not_called()
    mock_log_error.assert_not_called()


@patch("slips_files.core.output.Output.print")
@patch("slips_files.core.output.Output.log_line")
@patch("slips_files.core.output.Output.log_error")
def test_output_line_no_error_log(mock_log_error, mock_log_line, mock_print):
    output = ModuleFactory().create_output_obj()
    output.verbose = 2
    output.debug = 2

    msg = {
        "from": "SenderName",
        "txt": "Non-error debug message",
        "verbose": 1,
        "debug": 2,
    }

    output.output_line_to_cli_and_logfiles(msg)

    mock_print.assert_called_with(msg["from"], msg["txt"], end="\n")
    mock_log_line.assert_called_with(msg)
    mock_log_error.assert_not_called()


@pytest.mark.parametrize(
    "msg, expected_output_line_calls",
    [
        (  # Testcase 1: a valid msg
            {"from": "SenderName", "txt": "This is a test message."},
            [{"from": "SenderName", "txt": "This is a test message."}],
        ),
        (  # Testcase 2: Empty message
            {},
            [{}],
        ),
    ],
)
def test_update(msg, expected_output_line_calls):
    """Test that the update method handles
    different cases correctly."""
    output = ModuleFactory().create_output_obj()
    output.output_line_to_cli_and_logfiles = MagicMock()

    output.update(msg)

    assert output.output_line_to_cli_and_logfiles.call_count == len(
        expected_output_line_calls
    )
    for call in expected_output_line_calls:
        output.output_line_to_cli_and_logfiles.assert_any_call(call)


def test_update_log_to_logfiles_only():
    """Test that the update method handles
    log_to_logfiles_only correctly."""
    output = ModuleFactory().create_output_obj()
    output.log_line = MagicMock()

    msg = {
        "from": "SenderName",
        "txt": "Log only message",
        "log_to_logfiles_only": True,
    }
    output.update(msg)

    output.log_line.assert_called_once_with(msg)


def test_create_logfile_existing():
    output = ModuleFactory().create_output_obj()
    path = "/existing/path/file.log"

    with patch("builtins.open", mock_open()) as mocked_open:
        with patch.object(Path, "mkdir") as mock_mkdir:
            output.create_logfile(path)

            mocked_open.assert_called_once_with(path, "a")
            mock_mkdir.assert_not_called()
            mocked_open().close.assert_called_once()


def test_create_logfile_new():
    output = ModuleFactory().create_output_obj()
    path = "/new/path/newfile.log"
    mock_file_error = mock_open()
    mock_file_error.side_effect = FileNotFoundError
    mock_file_success = mock_open()

    open_mocks = [mock_file_error, mock_file_success]

    def side_effect(*args, **kwargs):
        return open_mocks.pop(0)()

    with patch("builtins.open", side_effect=side_effect) as mocked_open:
        with patch.object(Path, "mkdir") as mock_mkdir:
            with patch("os.path.dirname", return_value="/new/path"):
                output.create_logfile(path)

            assert mocked_open.call_count == 2
            mocked_open.assert_has_calls(
                [mockedcall(path, "a"), mockedcall(path, "w")]
            )
            mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)
            mock_file_success().close.assert_called_once()


def test_create_logfile_permission_error():
    output = ModuleFactory().create_output_obj()
    path = "/root/restricted.log"

    with patch("builtins.open", side_effect=PermissionError):
        with pytest.raises(PermissionError):
            output.create_logfile(path)


def test_create_logfile_disk_full():
    output = ModuleFactory().create_output_obj()
    path = "/mnt/full_disk/file.log"

    with patch("builtins.open", side_effect=IOError):
        with pytest.raises(IOError):
            output.create_logfile(path)
