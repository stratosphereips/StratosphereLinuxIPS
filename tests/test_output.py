from unittest.mock import MagicMock, mock_open, patch, call as mockedcall
import pytest
from tests.module_factory import ModuleFactory
from pathlib import Path
import sys
from io import StringIO


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


def test_print_no_pbar():
    """Test printing when has_pbar is False."""
    output = ModuleFactory().create_output_obj()
    output.has_pbar = False
    output.tell_pbar = MagicMock()
    sender = "SenderName"
    txt = "This is a test message."

    with patch("builtins.print") as mock_print:
        output.print(sender, txt)

    (mock_print.assert_called_once_with(f"[{sender}] {txt}", end="\n"))
    output.tell_pbar.assert_not_called()


def test_print_pbar_finished():
    """Test printing when pbar is finished."""
    output = ModuleFactory().create_output_obj()
    output.has_pbar = True
    output.pbar_finished = MagicMock()
    output.pbar_finished.is_set.return_value = True
    output.tell_pbar = MagicMock()
    sender = "SenderName"
    txt = "This is a test message."

    with patch("builtins.print") as mock_print:
        output.print(sender, txt)

    (mock_print.assert_called_once_with(f"[{sender}] {txt}", end="\n"))
    output.tell_pbar.assert_not_called()


def test_print_pbar_active_with_sender():
    """Test printing with active pbar and a sender."""
    output = ModuleFactory().create_output_obj()
    output.has_pbar = True
    output.pbar_finished = MagicMock()
    output.pbar_finished.is_set.return_value = False
    output.tell_pbar = MagicMock()
    sender = "SenderName"
    txt = "This is a test message."

    with patch("builtins.print") as mock_print:
        output.print(sender, txt)

    (
        output.tell_pbar.assert_called_once_with(
            {"event": "print", "txt": f"[{sender}] {txt}"}
        )
    )
    mock_print.assert_not_called()


def test_print_pbar_active_no_sender():
    """Test printing with active pbar and no sender."""
    output = ModuleFactory().create_output_obj()
    output.has_pbar = True
    output.pbar_finished = MagicMock()
    output.pbar_finished.is_set.return_value = False
    output.tell_pbar = MagicMock()
    sender = ""
    txt = "This is a message with no sender."

    with patch("builtins.print") as mock_print:
        output.print(sender, txt)

    (output.tell_pbar.assert_called_once_with({"event": "print", "txt": txt}))
    mock_print.assert_not_called()


def test_handle_printing_stats_pbar_not_finished():
    """Test when pbar is not finished, stats should be sent to pbar."""
    output = ModuleFactory().create_output_obj()
    output.has_pbar = True
    output.pbar_finished = MagicMock()
    output.pbar_finished.is_set.return_value = False
    output.tell_pbar = MagicMock() 
    stats = "Analyzed IPs: 10"

    output.handle_printing_stats(stats)

    output.tell_pbar.assert_called_once_with(
        {"event": "update_stats", "stats": stats}
    )


def test_handle_printing_stats_pbar_finished():
    """Test when pbar is finished, stats should be printed directly."""
    output = ModuleFactory().create_output_obj()
    output.has_pbar = True
    output.pbar_finished = MagicMock()
    output.pbar_finished.is_set.return_value = True

    original_stdout = sys.stdout
    captured_output = StringIO()
    sys.stdout = captured_output

    stats = "Analyzed IPs: 20"
    output.handle_printing_stats(stats)

    sys.stdout = original_stdout
    assert captured_output.getvalue().strip() == stats


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

    output.output_line(msg)

    mock_print.assert_called_with(msg["from"], msg["txt"])
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

    output.output_line(msg)

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

    output.output_line(msg)

    mock_print.assert_called_with(msg["from"], msg["txt"])
    mock_log_line.assert_called_with(msg)
    mock_log_error.assert_not_called()


@pytest.mark.parametrize(
    "is_set_return_value, expected_result",
    [  # Testcase 1: pbar_finished is set
        (True, True),
        # Testcase 2: pbar_finished is not set
        (False, False),
    ],
)
def test_is_pbar_finished(is_set_return_value, expected_result):
    """Test that the is_pbar_finished method returns the correct result."""
    output = ModuleFactory().create_output_obj()
    output.pbar_finished = MagicMock()
    output.pbar_finished.is_set.return_value = is_set_return_value

    assert output.is_pbar_finished() == expected_result


@pytest.mark.parametrize(
    "msg, expected_forward_progress_bar_calls, " "expected_output_line_calls",
    [
        (  # Testcase 1: msg contains 'bar' key with 'init'
            {"bar": "init", "bar_info": {"total_flows": 1000}},
            [{"bar": "init", "bar_info": {"total_flows": 1000}}],
            [],
        ),
        (  # Testcase 2: msg contains 'bar' key with 'update'
            {"bar": "update"},
            [{"bar": "update"}],
            [],
        ),
        (  # Testcase 3: msg does not contain 'bar' key
            {"from": "SenderName", "txt": "This is a test message."},
            [],
            [{"from": "SenderName", "txt": "This is a test message."}],
        ),
        (  # Testcase 4: Empty message
            {},
            [],
            [{}],
        ),
    ],
)
def test_update(
    msg, expected_forward_progress_bar_calls, expected_output_line_calls
):
    """Test that the update method handles
    different cases correctly."""
    output = ModuleFactory().create_output_obj()

    output.forward_progress_bar_msgs = MagicMock()
    output.output_line = MagicMock()

    output.update(msg)

    assert output.forward_progress_bar_msgs.call_count == len(
        expected_forward_progress_bar_calls
    )
    for call in expected_forward_progress_bar_calls:
        output.forward_progress_bar_msgs.assert_any_call(call)

    assert output.output_line.call_count == len(expected_output_line_calls)
    for call in expected_output_line_calls:
        output.output_line.assert_any_call(call)


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


@pytest.mark.parametrize(
    "msg, expected_call",
    [
        (  # Testcase 1: Initialization message
            {"bar": "init", "bar_info": {"total_flows": 1000}},
            {"event": "init", "total_flows": 1000},
        ),
        (  # Testcase 2: Update message
            {"bar": "update"},
            {"event": "update_bar"},
        ),
    ],
)
def test_forward_progress_bar_msgs_valid(msg, expected_call):
    """Test valid progress bar messages."""
    output = ModuleFactory().create_output_obj()
    output.tell_pbar = MagicMock()
    output.is_pbar_finished = MagicMock(return_value=False)

    output.forward_progress_bar_msgs(msg)

    output.tell_pbar.assert_called_once_with(expected_call)


def test_forward_progress_bar_msgs_update_finished():
    """Test update message when progress bar is finished."""
    output = ModuleFactory().create_output_obj()
    output.tell_pbar = MagicMock()
    output.is_pbar_finished = MagicMock(return_value=True)

    output.forward_progress_bar_msgs({"bar": "update"})

    output.tell_pbar.assert_not_called()


def test_forward_progress_bar_msgs_unknown_bar():
    """Test message with unknown 'bar' value."""
    output = ModuleFactory().create_output_obj()
    output.tell_pbar = MagicMock()

    output.forward_progress_bar_msgs({"bar": "unknown"})

    output.tell_pbar.assert_not_called()


def test_tell_pbar():
    """Test that tell_pbar sends the message through the pipe."""
    output = ModuleFactory().create_output_obj()
    output.pbar_sender_pipe = MagicMock()

    msg = {"event": "update", "progress": 50}
    output.tell_pbar(msg)

    output.pbar_sender_pipe.send.assert_called_once_with(msg)


def test_tell_pbar_empty_message():
    """Test that tell_pbar handles empty messages correctly."""
    output = ModuleFactory().create_output_obj()
    output.pbar_sender_pipe = MagicMock()

    msg = {}
    output.tell_pbar(msg)

    output.pbar_sender_pipe.send.assert_called_once_with(msg)


def test_tell_pbar_none_message():
    """Test that tell_pbar handles None messages correctly."""
    output = ModuleFactory().create_output_obj()
    output.pbar_sender_pipe = MagicMock()

    msg = None
    output.tell_pbar(msg)

    output.pbar_sender_pipe.send.assert_called_once_with(msg)


def test_tell_pbar_large_message():
    """Test that tell_pbar can handle large messages."""
    output = ModuleFactory().create_output_obj()
    output.pbar_sender_pipe = MagicMock()

    msg = {"event": "update", "data": "x" * 1000000}
    output.tell_pbar(msg)

    output.pbar_sender_pipe.send.assert_called_once_with(msg)


def test_tell_pbar_multiple_calls():
    """Test that tell_pbar works correctly
    for multiple consecutive calls."""
    output = ModuleFactory().create_output_obj()
    output.pbar_sender_pipe = MagicMock()

    msgs = [
        {"event": "init"},
        {"event": "update", "progress": 25},
        {"event": "update", "progress": 50},
        {"event": "update", "progress": 75},
        {"event": "finish"},
    ]

    for msg in msgs:
        output.tell_pbar(msg)

    assert output.pbar_sender_pipe.send.call_count == len(msgs)
    for msg in msgs:
        output.pbar_sender_pipe.send.assert_any_call(msg)


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
