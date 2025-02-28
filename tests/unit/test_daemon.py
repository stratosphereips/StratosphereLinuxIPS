# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os
import pytest
from unittest.mock import patch, mock_open, call
from exclusiveprocess import CannotAcquireLock
from tests.module_factory import ModuleFactory
from io import StringIO
import signal
import sys


@pytest.mark.parametrize(
    "test_message, expected_log_content",
    [  # testcase1: Simple message
        ("Test message 1", "Test message 1\n"),
        # testcase2: Multiline message
        ("Multiline\nmessage", "Multiline\nmessage\n"),
        # testcase3: Empty message
        ("", "\n"),
    ],
)
def test_print(test_message, expected_log_content, tmpdir):
    output_dir = tmpdir.mkdir("output")
    daemon = ModuleFactory().create_daemon_object()
    daemon.logsfile = os.path.join(output_dir, daemon.logsfile)
    daemon.print(test_message)
    with open(daemon.logsfile, "r") as f:
        log_content = f.read()
    assert log_content == expected_log_content


@pytest.mark.parametrize(
    "argv, stderr, stdout, logsfile, expected_files",
    [  # testcase1: Create all streams
        (
            [],
            "errors.log",
            "slips.log",
            "slips.log",
            ["errors.log", "slips.log"],
        ),
        # testcase2: Create only stderr when stopping
        (["-S"], "errors.log", "slips.log", "slips.log", ["errors.log"]),
    ],
)
def test_create_std_streams(
    argv, stderr, stdout, logsfile, expected_files, tmpdir
):
    output_dir = tmpdir.mkdir("output")
    daemon = ModuleFactory().create_daemon_object()

    daemon.stderr = stderr
    daemon.stdout = stdout
    daemon.logsfile = logsfile

    daemon.prepare_std_streams(str(output_dir))

    with patch.object(sys, "argv", argv):
        daemon.create_std_streams()

        expected_paths = [os.path.join(output_dir, f) for f in expected_files]
        created_files = [
            os.path.join(output_dir, f) for f in os.listdir(output_dir)
        ]
        assert sorted(created_files) == sorted(expected_paths)


@pytest.mark.parametrize(
    "output_dir, expected_stderr, " "expected_stdout, expected_logsfile",
    [  # testcase1: Using /var/log/slips/ directory
        (
            "/var/log/slips/",
            "/var/log/slips/errors.log",
            "/var/log/slips/slips.log",
            "/var/log/slips/slips.log",
        ),
        # testcase2: Using custom output directory
        (
            "/tmp/slips",
            "/tmp/slips/errors.log",
            "/tmp/slips/slips.log",
            "/tmp/slips/slips.log",
        ),
    ],
)
def test_prepare_std_streams(
    output_dir,
    expected_stderr,
    expected_stdout,
    expected_logsfile,
):
    daemon = ModuleFactory().create_daemon_object()
    daemon.prepare_std_streams(output_dir)
    assert daemon.stderr == expected_stderr
    assert daemon.stdout == expected_stdout
    assert daemon.logsfile == expected_logsfile


@patch("os.fork")
@patch("os.setsid")
@patch("os.umask")
@patch("os.dup2")
@patch("builtins.open", new_callable=mock_open)
@patch("sys.stdin")
@patch("sys.stdout")
@patch("sys.stderr")
def test_daemonize(
    mock_stderr,
    mock_stdout,
    mock_stdin,
    mock_open,
    mock_dup2,
    mock_umask,
    mock_setsid,
    mock_fork,
):
    mock_stdin.fileno.return_value = 0
    mock_stdout.fileno.return_value = 1
    mock_stderr.fileno.return_value = 2

    mock_fork.side_effect = [0, 0]
    daemon = ModuleFactory().create_daemon_object()
    daemon.daemonize()

    assert mock_fork.call_count == 2

    mock_setsid.assert_called_once()
    mock_umask.assert_called_once_with(0)

    assert mock_dup2.call_count == 3

    mock_open.assert_called_with(daemon.pidfile, "w+")
    mock_open().write.assert_called_once()


@patch("os.fork")
@patch("sys.stderr", new_callable=StringIO)
def test_daemonize_fork_error(mock_stderr, mock_fork):
    mock_fork.side_effect = OSError("Fork failed")
    daemon = ModuleFactory().create_daemon_object()
    with pytest.raises(SystemExit):
        daemon.daemonize()

    assert "Fork #1 failed" in mock_stderr.getvalue()


@pytest.mark.parametrize(
    "file_content, expected_result",
    [
        # Test case 1: Valid daemon info
        (
            "# Some comment\n"
            "Date,Time,Port,DB,InputType,OutputDir,"
            "PID,IsDaemon\n"
            "2023-07-25,10:00:00,6379,redis,pcap,"
            "/tmp/output,12345,True\n",
            ("6379", "/tmp/output", "12345"),
        ),
        # Test case 2: Multiple entries, last one is daemon
        (
            "2023-07-25,09:00:00,6380,redis,pcap,"
            "/tmp/output1,12344,False\n"
            "2023-07-25,10:00:00,6379,redis,pcap,"
            "/tmp/output2,12345,True\n",
            ("6379", "/tmp/output2", "12345"),
        ),
        # Test case 3: Empty file
        ("", None),
    ],
)
def test_get_last_opened_daemon_info(file_content, expected_result):
    daemon = ModuleFactory().create_daemon_object()
    daemon.slips.redis_man.running_logfile = "mock_logfile.txt"

    with patch("builtins.open", mock_open(read_data=file_content)):
        result = daemon.get_last_opened_daemon_info()

    assert result == expected_result


@pytest.mark.parametrize(
    "pidfile_exists, expected_output, " "expected_remove_calls",
    [
        # Test case 1: pidfile exists and is deleted
        (True, ["pidfile deleted."], [call("/tmp/slips_daemon.lock")]),
        # Test case 2: pidfile doesn't exist
        (
            False,
            [
                "Can't delete pidfile, /tmp/slips_daemon.lock doesn't exist.",
                "Either Daemon stopped normally or an error occurred.",
            ],
            [],
        ),
    ],
)
def test_delete_pidfile(
    pidfile_exists, expected_output, expected_remove_calls
):
    daemon = ModuleFactory().create_daemon_object()
    with patch("os.path.exists", return_value=pidfile_exists), patch(
        "os.remove"
    ) as mock_remove, patch.object(daemon, "print") as mock_print:
        daemon.delete_pidfile()

        mock_remove.assert_has_calls(expected_remove_calls)
        mock_print.assert_has_calls([call(line) for line in expected_output])


@pytest.mark.parametrize(
    "pid, os_kill_side_effect",
    [
        # Test case 1: Successfully kill the daemon
        (12345, None),
        # Test case 2: Daemon already killed
        (12345, ProcessLookupError),
    ],
)
def test_killdaemon(pid, os_kill_side_effect):
    daemon = ModuleFactory().create_daemon_object()
    daemon.pid = str(pid)

    with patch("os.kill", side_effect=os_kill_side_effect) as mock_kill:
        daemon.killdaemon()

    mock_kill.assert_called_once_with(pid, signal.SIGTERM)


@pytest.mark.parametrize(
    "pid, lock_side_effect," " expected_result",
    [
        # Testcase1:pid exists lock acquired
        (12345, None, True),
        # Testcase2:no pid lock acquired
        (None, None, False),
        # Testcase3:pid exists lock not acquired
        (12345, CannotAcquireLock(), True),
        # Testcase4:no pid lock not acquired
        (None, CannotAcquireLock(), False),
    ],
)
def test_is_running(pid, lock_side_effect, expected_result):
    daemon = ModuleFactory().create_daemon_object()
    daemon.pid = pid

    with patch("exclusiveprocess.Lock") as mock_lock:
        mock_lock.return_value.__enter__.side_effect = lock_side_effect

        result = daemon._is_running()

    assert result == expected_result
