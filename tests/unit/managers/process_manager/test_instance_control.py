"""Verify scoped discovery and graceful shutdown without touching live runs."""

import argparse
import builtins
import json
import os
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import time
from unittest.mock import Mock, patch

import psutil
import pytest

from managers.process_manager import instance_control as control
from slips_files.common.parsers.arg_parser import ArgumentParser
from tests.module_factory import ModuleFactory


def candidate(pid: int, entrypoint: Path, *arguments: str) -> Mock:
    """Create a process double whose main script has a verifiable path.

    Parameters:
        pid: Process identifier.
        entrypoint: Executed script.
        arguments: Capture arguments following the script.

    Returns:
        Process double with stable identity and no children.
    """
    process = Mock(pid=pid)
    process.cmdline.return_value = ["python3", str(entrypoint), *arguments]
    process.cwd.return_value = str(Path.cwd())
    process.create_time.return_value = 100.0
    process.status.return_value = psutil.STATUS_RUNNING
    process.is_running.return_value = True
    process.children.return_value = []
    process.parents.return_value = []
    return process


@pytest.mark.parametrize(
    "command, expected",
    [
        ([], None),
        (["slips.py", "-i", "eth0"], 0),
        (["python3", "./slips.py", "-c", "config/slips.yaml"], 1),
        (["venv/bin/Python", "-u", "./slips.py"], 2),
        (["python3.11", "-X", "dev", "-B", "slips.py"], 4),
        (["python", "-Wignore", "--", "slips.py"], 3),
        (["python", "--check-hash-based-pycs", "always", "slips.py"], 3),
        (["python", "-c", "slips.py"], None),
        (["python", "-cpass", "slips.py"], None),
        (["python", "-uc", "slips.py"], None),
        (["python", "-m", "slips.py"], None),
        (["python", "-mmodule", "slips.py"], None),
        (["python", "other.py", "slips.py"], None),
        (["echo", "slips.py"], None),
        (["python", "-", "slips.py"], None),
        (["python", "-X"], None),
    ],
)
def test_script_position(command: list[str], expected: int | None) -> None:
    """Distinguish a real entry point from an argument or Python code string.

    Parameters:
        command: Candidate argument vector.
        expected: Script position, or None for non-captures.
    """
    _factory = ModuleFactory()
    assert control.script_position(command) == expected


@pytest.mark.parametrize("command,expected", [
    (["python3", "slips.py"], ()),
    (["python3", "-u", "slips.py", "-D", "--keep-history"], ("-D", "--keep-history")),
    (["./slips.py", "-i", "eth0"], ("-i", "eth0")),
    (["python3", "slips.py", "--restart"], None),
    (["python3", "slips.py", "--restart=123"], None),
    (["python3", "slips.py", "--stop=all"], None),
    (["python3", "slips.py", "--list-instances"], None),
    (["python3", "slips.py", "-h"], None),
    (["python3", "other.py", "slips.py"], None),
    (["python3", "-c", "pass", "slips.py"], None),
    (["echo", "slips.py"], None),
    ([], None),
])
def test_capture_arguments(command: list[str], expected: tuple[str, ...] | None) -> None:
    """Use the same capture classification for discovery and resource checks.

    Parameters:
        command: Candidate process command line.
        expected: Capture arguments or None for a management/unrelated command.
    """
    _factory = ModuleFactory()
    assert control.capture_arguments(command) == expected


@pytest.mark.parametrize(
    "arguments, names, expected",
    [
        (("-i", "eth0"), ("-i", "--interface"), "eth0"),
        (("--interface=en0",), ("-i", "--interface"), "en0"),
        (("-ooutput/test",), ("-o", "--output"), "output/test"),
        (("-i",), ("-i", "--interface"), "—"),
        (("-f", "capture.pcap"), ("-i", "--interface"), "—"),
    ],
)
def test_argument_value(arguments: tuple[str, ...], names: tuple[str, ...], expected: str) -> None:
    """Display launch values without loading a configuration.

    Parameters:
        arguments: Existing launch arguments.
        names: Recognized spellings.
        expected: Displayed value.
    """
    _factory = ModuleFactory()
    assert control.argument_value(arguments, *names) == expected


@pytest.mark.parametrize("case", ["capture", "relative", "other_checkout", "self", "zombie", "denied", "management", "legacy_stop", "restart", "restart_pid"])
def test_inspect_instance_scope(tmp_path: Path, case: str) -> None:
    """Reject other programs, stale processes and management invocations.

    Parameters:
        tmp_path: Isolated script location.
        case: Candidate process identity.
    """
    _factory = ModuleFactory()
    entrypoint = tmp_path / "slips.py"
    process = candidate(41001, entrypoint, "-i", "eth0")
    if case == "relative":
        process.cmdline.return_value[1] = "./slips.py"
        process.cwd.return_value = str(tmp_path)
    elif case == "other_checkout":
        process.cmdline.return_value[1] = str(tmp_path / "other" / "slips.py")
    elif case == "self":
        process.pid = os.getpid()
    elif case == "zombie":
        process.status.return_value = psutil.STATUS_ZOMBIE
    elif case == "denied":
        process.cmdline.side_effect = psutil.AccessDenied(process.pid)
    elif case in {"management", "legacy_stop"}:
        process.cmdline.return_value.append("--stop=all" if case == "management" else "-S")
    elif case in {"restart", "restart_pid"}:
        process.cmdline.return_value.append("--restart" if case == "restart" else "--restart=41002")
    actual = control.inspect_instance(process, entrypoint)
    if case in {"capture", "relative"}:
        assert actual == control.RunningInstance(41001, 100.0, ("-i", "eth0"))
    else:
        assert actual is None


def test_list_and_print_instances(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """List only verified main processes and display their input and output.

    Parameters:
        tmp_path: Isolated entry point.
        capsys: Captured listing output.
    """
    _factory = ModuleFactory()
    entrypoint = tmp_path / "slips.py"
    first = candidate(41002, entrypoint, "-D", "-f", "test.pcap", "-o", "output/test")
    second = candidate(41001, entrypoint, "-i", "eth0")
    other = candidate(41003, tmp_path / "other.py")
    with patch.object(control.psutil, "process_iter", return_value=[first, other, second]):
        instances = control.list_instances(entrypoint)
    assert [instance.pid for instance in instances] == [41001, 41002]
    control.print_instances(instances)
    listing = capsys.readouterr().out
    assert "eth0" in listing and "test.pcap" in listing
    assert "daemon" in listing and "output/test" in listing
    assert "41003" not in listing
    control.print_instances([])
    assert "No accessible running" in capsys.readouterr().out


@pytest.mark.parametrize("case", ["forked", "nested", "other_checkout", "denied"])
def test_discovery_excludes_forked_workers(tmp_path: Path, case: str) -> None:
    """Exclude workers inheriting slips.py arguments on fork-based systems.

    Parameters:
        tmp_path: Isolated checkout path.
        case: Worker ancestry or unrelated/inaccessible parent.
    """
    _factory = ModuleFactory()
    entrypoint = tmp_path / "slips.py"
    main = candidate(41001, entrypoint, "-D", "-i", "eth0")
    worker = candidate(41002, entrypoint, "-D", "-i", "eth0")
    ancestor = candidate(41003, tmp_path / "other.py")
    worker.parents.return_value = [main] if case == "forked" else [ancestor, main]
    if case == "other_checkout":
        ancestor.cmdline.return_value[1] = str(tmp_path / "other" / "slips.py")
        worker.parents.return_value = [ancestor]
    elif case == "denied":
        ancestor.cmdline.side_effect = psutil.AccessDenied(ancestor.pid)
        worker.parents.return_value = [ancestor]
    with patch.object(control.psutil, "process_iter", return_value=[main, worker]):
        instances = control.list_instances(entrypoint)
    if case in {"forked", "nested"}:
        assert [instance.pid for instance in instances] == [main.pid]
        assert control.inspect_instance(worker, entrypoint) is None
    else:
        assert [instance.pid for instance in instances] == [main.pid, worker.pid]


@pytest.mark.parametrize("case, expected", [("normal", 0), ("gone", 0), ("reused", 1), ("denied", 1), ("slow", 1)])
def test_stop_revalidates_and_waits(tmp_path: Path, case: str, expected: int) -> None:
    """Never signal a reused PID or force-kill a slow capture or its workers.

    Parameters:
        tmp_path: Isolated entry point.
        case: Process state at stop time.
        expected: Exit status.
    """
    _factory = ModuleFactory()
    entrypoint = tmp_path / "slips.py"
    process = candidate(41001, entrypoint, "-i", "eth0")
    child = Mock(pid=41002)
    process.children.return_value = [child]
    instance = control.inspect_instance(process, entrypoint)
    if case == "reused":
        process.create_time.return_value += 1
    if case == "denied":
        process.children.side_effect = psutil.AccessDenied(process.pid)
    with patch.object(control.psutil, "Process", return_value=process) as constructor, patch.object(
        control.psutil, "wait_procs", return_value=([], [child] if case == "slow" else [])
    ) as wait:
        if case == "gone":
            constructor.side_effect = psutil.NoSuchProcess(process.pid)
        assert control.stop_instances([instance], entrypoint, timeout=0.1) == expected
    if case in {"normal", "slow"}:
        process.send_signal.assert_called_once_with(signal.SIGTERM)
        assert {item.pid for item in wait.call_args.args[0]} == {41001, 41002}
        assert wait.call_args.kwargs["timeout"] == 0.1
    else:
        process.send_signal.assert_not_called()
        wait.assert_not_called()
    process.kill.assert_not_called()
    child.kill.assert_not_called()
    child.send_signal.assert_not_called()


@pytest.mark.parametrize(
    "arguments, count, selected, expected",
    [
        (["--list-instances"], 2, [], 0),
        (["--stop"], 0, [], 0),
        (["--stop"], 1, [41001], 0),
        (["--stop"], 2, [], 1),
        (["--stop", "41002"], 2, [41002], 0),
        (["--stop=all"], 2, [41001, 41002], 0),
        (["--stop", "41003"], 2, [], 1),
        (["--stop", "41003"], 0, [], 1),
    ],
)
def test_management_selection(arguments: list[str], count: int, selected: list[int], expected: int) -> None:
    """Require an explicit choice when more than one analysis is running.

    Parameters:
        arguments: Management command.
        count: Number of discovered captures.
        selected: Expected main PIDs to stop.
        expected: Exit status.
    """
    _factory = ModuleFactory()
    instances = [control.RunningInstance(41001 + index, 100.0, ()) for index in range(count)]
    with patch.object(control, "list_instances", return_value=instances), patch.object(control, "stop_instances", return_value=0) as stop:
        assert control.handle_instance_command(arguments) == expected
    if selected:
        assert [instance.pid for instance in stop.call_args.args[0]] == selected
    else:
        stop.assert_not_called()


@pytest.mark.parametrize("arguments", [["-S"], ["--stopdaemon"], ["-S", "-c", "config/not-read.yaml"], ["--stop", "0"], ["--stop", "-1"], ["--stop", "abc"], ["--stop", "--list-instances"], ["--stop", "-i", "eth0"], ["-S", "--stop"], ["-S", "--list-instances"], ["-S", "-i", "eth0"], ["--restart", "0"], ["--restart", "-1"], ["--restart", "all"], ["--restart", "abc"], ["--restart", "--stop"], ["--restart", "--list-instances"], ["--restart", "-c", "config/not-read.yaml"]])
def test_management_rejects_invalid_commands(arguments: list[str]) -> None:
    """Reject ambiguous options before discovery or any stop request.

    Parameters:
        arguments: Invalid management options.
    """
    _factory = ModuleFactory()
    with patch.object(control, "list_instances") as discover, patch.object(control, "stop_instances") as stop:
        with pytest.raises(SystemExit) as error:
            control.handle_instance_command(arguments)
    assert error.value.code == 2
    discover.assert_not_called()
    stop.assert_not_called()


def test_management_help_and_capture_passthrough() -> None:
    """Expose the same controls in help while leaving ordinary capture alone."""
    _factory = ModuleFactory()
    parser = argparse.ArgumentParser()
    control.add_instance_arguments(parser)
    full_parser = ArgumentParser(add_help=False)
    with patch.object(sys, "argv", ["slips.py", "--list-instances"]):
        assert full_parser.parse_arguments().list_instances
    options = {option for action in full_parser._actions for option in action.option_strings}
    assert "--stop" in options
    assert "--restart" in options
    assert not {"-S", "--stopdaemon"}.intersection(options)
    assert parser.parse_args(["--stop"]).stop == "auto"
    assert parser.parse_args(["--restart"]).restart == "auto"
    assert parser.parse_args(["--restart", "41001"]).restart == "41001"
    with patch.object(sys, "argv", ["slips.py", "--list-instances"]):
        assert ArgumentParser(add_help=False).parse_arguments().list_instances
    with patch.object(control, "list_instances") as discover:
        assert control.handle_instance_command(["-i", "eth0"]) is None
        with pytest.raises(SystemExit) as error:
            control.handle_instance_command(["--stop", "--help"])
    assert error.value.code == 0
    discover.assert_not_called()


@pytest.mark.parametrize("arguments, expected", [
    (["--list-instances"], 0),
    (["--stop"], 0),
    (["--stop", "all"], 0),
    (["--restart"], 1),
    (["--restart", "41001"], 1),
    (["-S"], 2),
    (["--stopdaemon"], 2),
    (["-S", "-c", "config/not-read.yaml"], 2),
])
def test_entrypoint_management_does_not_import_capture(arguments: list[str], expected: int) -> None:
    """Run the actual entry point without initializing Main, config or Redis.

    Parameters:
        arguments: Management or removed options to execute.
        expected: Exit status for supported or rejected commands.
    """
    _factory = ModuleFactory()
    original_import = builtins.__import__
    with patch.object(sys, "argv", ["slips.py", *arguments]), patch.object(
        control, "list_instances", return_value=[]
    ), patch("builtins.__import__", wraps=original_import) as imports:
        with pytest.raises(SystemExit) as error:
            runpy.run_path("slips.py", run_name="__main__")
    assert error.value.code == expected
    assert not any(call.args[0] in {"slips.main", "slips.daemon", "slips_files.common.parsers.config_parser"} for call in imports.call_args_list)


@pytest.mark.parametrize("arguments, selected, expected", [
    (["--stop"], [], 1),
    (["--stop", "41001"], [0], 0),
    (["--stop", "41002"], [1], 0),
    (["--stop", "41003"], [2], 0),
    (["--stop", "all"], [0, 1, 2], 0),
])
def test_stop_selects_across_launch_modes(arguments: list[str], selected: list[int], expected: int) -> None:
    """Use one option for daemon, foreground and PCAP analyses.

    Parameters:
        arguments: Stop command and optional selection.
        selected: Indices of instances to stop.
        expected: Command exit status.
    """
    _factory = ModuleFactory()
    instances = [control.RunningInstance(41001, 1, ("-i", "eth0")),
                 control.RunningInstance(41002, 2, ("-f", "file.pcap")),
                 control.RunningInstance(41003, 3, ("-D", "-i", "en0"))]
    with patch.object(control, "list_instances", return_value=instances), patch.object(control, "stop_instances", return_value=0) as stop:
        assert control.handle_instance_command(arguments) == expected
    if selected:
        assert stop.call_args.args[0] == [instances[index] for index in selected]
    else:
        stop.assert_not_called()


@pytest.mark.parametrize("arguments, modes, selected, expected", [
    (["--restart"], [], None, 1),
    (["--restart"], ["-i"], None, 1),
    (["--restart"], ["-D"], 41001, 0),
    (["--restart"], ["-i", "--daemon", "-f"], 41002, 0),
    (["--restart"], ["-D", "--daemon"], None, 1),
    (["--restart=41002"], ["-D", "--daemon"], 41002, 0),
    (["--restart", "41001"], ["-i", "-D"], None, 1),
    (["--restart", "41003"], ["-D", "-f"], None, 1),
])
def test_restart_selects_daemons(
    arguments: list[str], modes: list[str], selected: int | None, expected: int,
) -> None:
    """Select a daemon without stopping foreground captures or analyses.

    Parameters:
        arguments: Restart command and optional PID.
        modes: Launch flags of discovered instances.
        selected: Selected daemon PID, or None for rejected requests.
        expected: Management exit status.
    """
    _factory = ModuleFactory()
    instances = [control.RunningInstance(41001 + index, 1, (mode,))
                 for index, mode in enumerate(modes)]
    with patch.object(control, "list_instances", return_value=instances), patch.object(
        control, "restart_instance", return_value=0
    ) as restart, patch.object(control, "stop_instances") as stop:
        assert control.handle_instance_command(arguments) == expected
    if selected is None:
        restart.assert_not_called()
    else:
        assert restart.call_args.args[0].pid == selected
    stop.assert_not_called()


@pytest.mark.parametrize("direct_script", [False, True])
def test_restart_preserves_launch_arguments_and_directory(tmp_path: Path, direct_script: bool) -> None:
    """Relaunch only after shutdown, preserving argument boundaries and cwd.

    Parameters:
        tmp_path: Original working directory.
        direct_script: Whether Slips was launched through its shebang.
    """
    _factory = ModuleFactory()
    entrypoint = tmp_path / "slips.py"
    arguments = ("-D", "-c", "config with spaces.yaml", "-i", "eth0",
                 "-w", "--web-port", "55012", "-o", "output/live capture", "--keep-history")
    process = candidate(41001, entrypoint, *arguments)
    process.cwd.return_value = str(tmp_path)
    original = ["./slips.py", *arguments]
    process.cmdline.return_value = original if direct_script else ["python3", "-u", *original]
    instance = control.RunningInstance(41001, 100.0, arguments)
    order = Mock()
    order.stop.return_value = 0
    order.launch.return_value.returncode = 0
    with patch.object(control.psutil, "Process", return_value=process), patch.object(
        control, "stop_instances", order.stop
    ), patch.object(control.subprocess, "run", order.launch):
        assert control.restart_instance(instance, entrypoint) == 0
    assert [call[0] for call in order.mock_calls] == ["stop", "launch"]
    order.stop.assert_called_once_with([instance], entrypoint)
    expected = [sys.executable, *([] if direct_script else ["-u"]), *original]
    order.launch.assert_called_once_with(expected, cwd=str(tmp_path), check=False)


@pytest.mark.parametrize("case", ["foreground", "gone", "reused", "denied", "slow", "launch_error", "startup_failed"])
def test_restart_handles_failures(tmp_path: Path, case: str) -> None:
    """Refuse unverified restarts and propagate shutdown or launcher failures.

    Parameters:
        tmp_path: Isolated checkout.
        case: Failure during verification, shutdown or startup.
    """
    _factory = ModuleFactory()
    entrypoint = tmp_path / "slips.py"
    process = candidate(41001, entrypoint, "-D", "-i", "eth0")
    instance = control.inspect_instance(process, entrypoint)
    if case == "foreground":
        instance = control.RunningInstance(41001, 100.0, ("-i", "eth0"))
    elif case == "reused":
        process.create_time.return_value += 1
    elif case == "denied":
        process.cwd.side_effect = psutil.AccessDenied(process.pid)
    with patch.object(control.psutil, "Process", return_value=process) as constructor, patch.object(
        control, "stop_instances", return_value=1 if case == "slow" else 0
    ) as stop, patch.object(control.subprocess, "run") as launch:
        launch.return_value.returncode = 3
        if case == "gone":
            constructor.side_effect = psutil.NoSuchProcess(process.pid)
        if case == "launch_error":
            launch.side_effect = OSError("Python executable unavailable")
        assert control.restart_instance(instance, entrypoint) == (3 if case == "startup_failed" else 1)
    if case in {"foreground", "gone", "reused", "denied"}:
        stop.assert_not_called()
    if case not in {"launch_error", "startup_failed"}:
        launch.assert_not_called()


def test_native_restart_preserves_arguments_and_waits_for_worker(tmp_path: Path) -> None:
    """Restart an isolated daemon after its worker exits and state is saved.

    Parameters:
        tmp_path: Private fixture scripts, launch data and shutdown checkpoint.
    """
    _factory = ModuleFactory()
    entrypoint = tmp_path / "slips.py"
    marker = tmp_path / "ready.json"
    saved = tmp_path / "saved.json"
    (tmp_path / "config with spaces.yaml").write_text(Path("config/slips.yaml").read_text())
    (tmp_path / "VERSION").write_text(Path("VERSION").read_text())
    history = tmp_path / "output" / "capture with spaces"
    (history / "databases").mkdir(parents=True)
    (history / "databases" / "flows.sqlite").write_text("retained history")
    (history / "metadata").mkdir()
    (history / "metadata" / "info.txt").write_text("File: eth0\n")
    entrypoint.write_text('''"""Isolated daemon for restart verification."""
import json
import os
from pathlib import Path
import signal
import sys
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, __PROJECT_DIRECTORY__)
import psutil
from managers.process_manager.instance_control import inspect_instance, restart_instance
if sys.argv[1:2] == ["--restart"]:
    instance = inspect_instance(psutil.Process(int(sys.argv[2])), Path(__file__))
    raise SystemExit(restart_instance(instance, Path(__file__)))
from managers.redis_manager import RedisManager
parent = psutil.Process(os.getppid())
parent.info = parent.as_dict(attrs=["pid", "cmdline"])
args = SimpleNamespace(interface="eth0", output="output/capture with spaces",
    multiinstance=False, db=None, port=None, is_slips_started_by_an_update=False)
with patch("managers.redis_manager.psutil.process_iter", return_value=[parent]):
    assert RedisManager(SimpleNamespace(args=args)).validate_keep_history()
if os.fork():
    raise SystemExit(0)
os.setsid()
if os.fork():
    os._exit(0)
with open(os.devnull, "r+") as stream:
    for descriptor in (0, 1, 2):
        os.dup2(stream.fileno(), descriptor)
worker = os.fork()
if worker == 0:
    while True:
        signal.pause()
def stop(number: int, frame: object) -> None:
    """Stop the worker before recording a completed shutdown."""
    os.kill(worker, signal.SIGTERM)
    os.waitpid(worker, 0)
    Path("saved.json").write_text(json.dumps({"pid": os.getpid()}))
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
Path("ready.tmp").write_text(json.dumps({
    "pid": os.getpid(), "worker": worker, "arguments": sys.argv[1:],
    "cwd": os.getcwd(), "prefix": sys.prefix,
    "previous_stop": json.loads(Path("saved.json").read_text()) if Path("saved.json").exists() else None,
}))
Path("ready.tmp").replace("ready.json")
while True:
    signal.pause()
'''.replace("__PROJECT_DIRECTORY__", repr(str(Path.cwd()))))
    arguments = ["--daemon", "-i", "eth0", "-c", "config with spaces.yaml",
                 "-o", "output/capture with spaces", "--web-port", "55012", "--keep-history"]
    previous = None
    current = None
    try:
        launched = subprocess.run([sys.executable, "-u", "./slips.py", *arguments], cwd=tmp_path, timeout=10)
        assert launched.returncode == 0
        deadline = time.monotonic() + 10
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        previous = json.loads(marker.read_text())
        instance = control.inspect_instance(psutil.Process(previous["pid"]), entrypoint)
        assert instance is not None
        restarted = subprocess.run([sys.executable, "./slips.py", "--restart", str(instance.pid)],
                                   cwd=tmp_path, capture_output=True, text=True, timeout=20)
        assert restarted.returncode == 0, restarted.stdout + restarted.stderr
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            current = json.loads(marker.read_text())
            if current["pid"] != previous["pid"]:
                break
            time.sleep(0.02)
        assert current["pid"] != previous["pid"]
        assert current["arguments"] == arguments
        assert current["cwd"] == str(tmp_path.resolve())
        assert current["prefix"] == sys.prefix
        assert current["previous_stop"] == {"pid": previous["pid"]}
        assert not psutil.pid_exists(previous["pid"])
        assert not psutil.pid_exists(previous["worker"])
        assert json.loads(saved.read_text()) == {"pid": previous["pid"]}
        assert (history / "databases" / "flows.sqlite").read_text() == "retained history"
    finally:
        if marker.exists():
            current = json.loads(marker.read_text())
            instance = control.inspect_instance(psutil.Process(current["pid"]), entrypoint)
            if instance is not None:
                control.stop_instances([instance], entrypoint, timeout=5)
        for record in (previous, current):
            if record:
                for pid in (record["pid"], record["worker"]):
                    if psutil.pid_exists(pid):
                        process = psutil.Process(pid)
                        process.kill()
                        process.wait(timeout=5)


def test_native_shutdown_waits_for_checkpoint_and_worker(tmp_path: Path) -> None:
    """Stop an owned native fixture after its worker exits and state is saved.

    Parameters:
        tmp_path: Private fixture scripts and checkpoint markers.
    """
    _factory = ModuleFactory()
    entrypoint = tmp_path / "slips.py"
    marker = tmp_path / "ready.json"
    saved = tmp_path / "saved"
    entrypoint.write_text('''"""Isolated Slips-shaped process for shutdown tests."""
import json
import os
from pathlib import Path
import signal
import sys
child_pid = os.fork()
if child_pid == 0:
    while True:
        signal.pause()
def stop(number: int, frame: object) -> None:
    """Save fixture state after its child has stopped."""
    os.kill(child_pid, signal.SIGTERM)
    os.waitpid(child_pid, 0)
    Path(sys.argv[2]).write_text("saved")
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
Path(sys.argv[1]).write_text(json.dumps({"child": child_pid}))
while True:
    signal.pause()
''')
    process = subprocess.Popen([sys.executable, str(entrypoint), str(marker), str(saved)])
    child_pid = None
    try:
        deadline = time.monotonic() + 10
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        child_pid = json.loads(marker.read_text())["child"]
        instance = control.inspect_instance(psutil.Process(process.pid), entrypoint)
        assert instance is not None
        assert control.inspect_instance(psutil.Process(child_pid), entrypoint) is None
        assert [item.pid for item in control.list_instances(entrypoint)] == [process.pid]
        assert control.stop_instances([instance], entrypoint, timeout=5) == 0
        assert saved.read_text() == "saved"
        assert process.wait(timeout=5) == 0
        assert not psutil.pid_exists(child_pid)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        if child_pid and psutil.pid_exists(child_pid):
            psutil.Process(child_pid).terminate()
