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
import multiprocessing
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import psutil

from managers.process_manager.instance_control import RunningInstance
import json


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
        (["-S"], "errors.log", "slips.log", "slips.log", ["errors.log", "slips.log"]),
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
    daemon.notify_started()


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
        daemon._kill_self()

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

    with patch.object(daemon, "is_pid_running", return_value=bool(pid)), patch(
        "exclusiveprocess.Lock"
    ) as mock_lock:
        mock_lock.return_value.__enter__.side_effect = lock_side_effect

        result = daemon._is_running()

    assert result == expected_result


@pytest.mark.parametrize(
    "pid, expected_result",
    [
        (12345, True),
        (None, False),
    ],
)
def test_is_pid_running(pid, expected_result):
    daemon = ModuleFactory().create_daemon_object()
    daemon.pid = pid

    with patch("os.kill") as mock_kill:
        result = daemon.is_pid_running()

    assert result == expected_result
    if expected_result:
        mock_kill.assert_called_once_with(pid, 0)
    else:
        mock_kill.assert_not_called()


def test_is_running_removes_stale_pidfile():
    daemon = ModuleFactory().create_daemon_object()
    daemon.pid = 12345

    with patch.object(
        daemon, "is_pid_running", return_value=False
    ), patch.object(daemon, "delete_pidfile") as mock_delete_pidfile:
        result = daemon._is_running()

    assert result is False
    mock_delete_pidfile.assert_called_once()


def test_start_updates_slips_pid():
    daemon = ModuleFactory().create_daemon_object()
    daemon.pid = None
    daemon_module = sys.modules[daemon.__class__.__module__]

    def mock_daemonize():
        daemon.pid = "23456"

    with patch.object(
        daemon, "daemonize", side_effect=mock_daemonize
    ), patch.object(daemon, "print"), patch("builtins.print"), patch(
        "os.getpid", return_value=23456
    ), patch.object(
        daemon_module, "Lock"
    ):
        daemon.start()

    assert daemon.slips.pid == 23456
    daemon.slips.start.assert_called_once()


def daemon_semaphore_worker(event: object, marker: str) -> None:
    """Use a semaphore created before detachment inside a spawn worker.

    Parameters:
        event: Named semaphore that must survive the original parent's exit.
        marker: File reporting successful semaphore reconstruction.
    """
    assert event.wait(5)
    Path(marker).write_text("worker ran")


def daemon_startup_probe(folder: str, scenario: str) -> None:
    """Run the real double fork without touching Slips databases or captures.

    Parameters:
        folder: Isolated log and state directory.
        scenario: Successful spawn, failed PID directory, or startup failure.
    """
    manager = ModuleFactory().create_process_manager_obj()
    daemon_class = ModuleFactory().create_daemon_object().__class__
    location = Path(folder)
    permanent = location / "state"
    if scenario == "pid_directory":
        permanent.write_text("not a directory")
    slips = SimpleNamespace(
        conf=SimpleNamespace(permanent_dir=lambda: str(permanent), logs_file=lambda: "slips.log",
                             stdout=lambda: "slips.log", stderr=lambda: "errors.log"),
        args=SimpleNamespace(stopdaemon=False, is_slips_started_by_an_update=False, output=str(location)),
        proc_man=manager,
    )
    slips.set_mode = lambda mode, daemon: setattr(slips, "daemon", daemon)
    event = multiprocessing.get_context("spawn").Event()

    def run() -> None:
        """Start an isolated spawn worker, acknowledge readiness, and wait."""
        if scenario == "startup_exception":
            raise RuntimeError("intentional startup failure")
        if scenario == "early_exit":
            return
        slips.daemon.notify_started()
        deadline = time.monotonic() + 10
        while not (location / "launch-worker").exists() and time.monotonic() < deadline:
            time.sleep(.05)
        child = multiprocessing.get_context("spawn").Process(target=daemon_semaphore_worker,
            args=(event, str(location / "worker-ran")))
        child.start()
        event.set()
        child.join(10)
        if child.is_alive():
            child.kill()
            child.join(3)
        assert child.exitcode == 0
        deadline = time.monotonic() + 15
        while not (location / "finish").exists() and time.monotonic() < deadline:
            time.sleep(.05)

    slips.start = run
    daemon = daemon_class(slips)
    daemon.daemon_start_lock = "daemon-test-" + location.name
    daemon.start()


@pytest.mark.parametrize("scenario", ["spawn", "pid_directory", "startup_exception", "early_exit"])
def test_real_daemon_reports_startup_and_preserves_spawn_semaphores(tmp_path: Path, scenario: str) -> None:
    """Verify real fork/spawn behavior and terminal feedback on startup errors.

    Parameters:
        tmp_path: Isolated state directory; live Slips data is never opened.
        scenario: Successful startup or a failure to report to the terminal.
    """
    factory = ModuleFactory()
    entrypoint = tmp_path / "slips.py"
    entrypoint.write_text("from tests.unit.slips.test_daemon import daemon_startup_probe\nimport sys\nif __name__ == '__main__':\n    daemon_startup_probe(sys.argv[1],sys.argv[2])\n")
    command = [sys.executable, "-c", "import runpy,sys; script=sys.argv.pop(1); runpy.run_path(script,run_name='__main__')", str(entrypoint), str(tmp_path), scenario]
    pid_path = tmp_path / "state" / "slips_daemon.lock"
    try:
        # The pre-fork resource tracker can retain a terminal descriptor;
        # wait for the launcher PID, as a shell does, rather than pipe EOF.
        with (tmp_path / "terminal-output").open("w") as stdout, (tmp_path / "terminal-errors").open("w") as stderr:
            result = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=20)
        output = (tmp_path / "terminal-output").read_text()
        errors = (tmp_path / "terminal-errors").read_text()
        if scenario == "spawn":
            assert result.returncode == 0, errors
            assert "Slips daemon started." in output
            (tmp_path / "launch-worker").touch()
            deadline = time.monotonic() + 10
            while not (tmp_path / "worker-ran").exists() and time.monotonic() < deadline:
                time.sleep(.05)
            assert (tmp_path / "worker-ran").read_text() == "worker ran"
            pid = int(pid_path.read_text())
            assert psutil.Process(pid).is_running()
            assert str(tmp_path / "state" / "slips_daemon.lock") in (tmp_path / "slips.log").read_text()
        else:
            assert result.returncode == 1
            assert "startup failed" in errors
            assert not pid_path.exists()
        assert factory is not None
    finally:
        (tmp_path / "finish").touch()
        deadline = time.monotonic() + 5
        while pid_path.exists() and time.monotonic() < deadline:
            time.sleep(.05)
        if pid_path.exists():
            process = psutil.Process(int(pid_path.read_text()))
            process.kill()


def test_daemon_logs_are_preserved(tmp_path: Path) -> None:
    """Keep old error and normal log contents when opening daemon streams.

    Parameters:
        tmp_path: Directory containing an earlier run's logs.
    """
    daemon = ModuleFactory().create_daemon_object()
    daemon.prepare_std_streams(str(tmp_path))
    for name in ("errors.log", "slips.log"):
        (tmp_path / name).write_text("previous run\n")
    daemon.create_std_streams()
    assert (tmp_path / "errors.log").read_text() == "previous run\n"
    assert (tmp_path / "slips.log").read_text() == "previous run\n"


@pytest.mark.parametrize("is_daemon", [False, True])
def test_stop_daemon_uses_verified_instance_shutdown(is_daemon: bool) -> None:
    """Use the shared stop flow only for a verified daemon identity.

    Parameters:
        is_daemon: Whether the PID really belongs to a daemon from this checkout.
    """
    daemon = ModuleFactory().create_daemon_object()
    daemon.pid = 12345
    daemon_module = sys.modules[daemon.__class__.__module__]
    instance = RunningInstance(12345, 1, ("-D",) if is_daemon else ("-i", "eth0"))
    with patch.object(daemon, "_is_running", return_value=True), patch.object(daemon_module, "Lock"), patch.object(daemon_module.psutil, "Process"), patch.object(daemon_module, "inspect_instance", return_value=instance), patch.object(daemon_module, "stop_instances", return_value=0) as stop:
        result = daemon.stop()
    assert result["stopped"] is is_daemon
    assert stop.call_count == int(is_daemon)


@pytest.mark.parametrize("value,expected", [("", None), ("unfinished", None), ("0", None), ("-1", None), ("12345", 12345)])
def test_read_pidfile_rejects_invalid_or_incomplete_data(tmp_path: Path, value: str, expected: int | None) -> None:
    """Treat an incomplete PID file as absent rather than a startup crash.

    Parameters:
        tmp_path: Isolated PID file directory.
        value: Saved PID text to read.
        expected: Valid positive PID, or no usable identity.
    """
    daemon = ModuleFactory().create_daemon_object()
    daemon.pidfile = str(tmp_path / "daemon.lock")
    Path(daemon.pidfile).write_text(value)
    assert daemon.read_pidfile() == expected


@pytest.mark.parametrize("status,expected", [("ready", 0), ("error", 1), ("eof", 1)])
def test_startup_pipe_reports_success_failure_and_unexpected_exit(status: str, expected: int) -> None:
    """Return failure when detachment succeeds but the daemon never starts.

    Parameters:
        status: Final startup message, or an unexpected closed pipe.
        expected: Exit status returned to the shell.
    """
    daemon = ModuleFactory().create_daemon_object()
    read_fd, write_fd = os.pipe()
    if status != "eof":
        os.write(write_fd, (json.dumps({"status": status, "message": "12345"}) + "\n").encode())
    os.close(write_fd)
    assert daemon._wait_for_startup(read_fd) == expected
