"""Tests for finding, stopping and restarting Slips instances.

No real Slips run is touched; processes are fakes or small throwaway scripts."""

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
from types import SimpleNamespace

import psutil
import pytest

from managers.process_manager import instance_control as control
from slips_files.common.parsers.arg_parser import (
    ArgumentParser,
    create_instance_parser,
)
from tests.module_factory import ModuleFactory


def create_process(pid: int, slips_script: Path, *arguments: str) -> Mock:
    """Make a fake psutil process that is running slips.py.

    Parameters:
        pid: PID of the fake process.
        slips_script: Path of the slips.py it is running.
        arguments: Arguments given after slips.py.

    Returns:
        A fake process with no children and no parents.
    """
    process = Mock(pid=pid)
    process.cmdline.return_value = ["python3", str(slips_script), *arguments]
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
def test_get_slips_script_index(command: list[str], expected: int | None) -> None:
    """Only a real slips.py script counts, not a mention of it in other arguments.

    Parameters:
        command: The command line to check.
        expected: Position of slips.py, or None if it is not being run.
    """
    _factory = ModuleFactory()
    assert control._get_slips_script_index(command) == expected


@pytest.mark.parametrize("command,expected", [
    (["python3", "slips.py"], ()),
    (["python3", "-u", "slips.py", "-D", "--keep-history"], ("-D", "--keep-history")),
    (["./slips.py", "-i", "eth0"], ("-i", "eth0")),
    (["python3", "slips.py", "--restart"], None),
    (["python3", "slips.py", "--restart=123"], None),
    (["python3", "slips.py", "--stop=all"], None),
    (["python3", "slips.py", "--list-instances"], None),
    (["python3", "slips.py", "--view", "output/saved"], None),
    (["python3", "slips.py", "--view=output/saved", "-D"], None),
    (["python3", "slips.py", "-h"], None),
    (["python3", "other.py", "slips.py"], None),
    (["python3", "-c", "pass", "slips.py"], None),
    (["echo", "slips.py"], None),
    ([], None),
])
def test_get_slips_run_arguments(command: list[str], expected: tuple[str, ...] | None) -> None:
    """Starting a run gives its arguments; stop/list/view/help commands give None.

    Parameters:
        command: The command line to check.
        expected: The arguments after slips.py, or None if it does not start a run.
    """
    _factory = ModuleFactory()
    assert control.get_slips_run_arguments(command) == expected


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
def test_get_argument_value(arguments: tuple[str, ...], names: tuple[str, ...], expected: str) -> None:
    """Read an option value in every way it can be typed.

    Parameters:
        arguments: The arguments a run was started with.
        names: The spellings of the option to look for.
        expected: The value that should be found.
    """
    _factory = ModuleFactory()
    assert control._get_argument_value(arguments, *names) == expected


@pytest.mark.parametrize("case,expected", [
    ("normal_run", [55123]), ("viewer", [55001]), ("orphan", [55123]),
    ("disabled", []), ("starting", []), ("other_output", []),
    ("old_server", []), ("denied", []), ("reused", []),
])
def test_web_ports_use_owned_listening_sockets(
    tmp_path: Path, case: str, expected: list[int]
) -> None:
    """Web ports come from sockets the web server is really listening on.

    They are not guessed from the arguments or taken from the Redis port.

    Parameters:
        tmp_path: Folder used as the working directory.
        case: Which kind of run or edge case is being tested.
        expected: The ports that should be reported.
    """
    _factory = ModuleFactory()
    arguments = ("--view", "output/saved", "--web-port", "55000") if case == "viewer" else ("-i", "eth0", "-o", "output/live")
    instance = control.RunningInstance(41001, 100.0, arguments)
    main = create_process(instance.pid, tmp_path / "slips.py", *arguments)
    main.cwd.return_value = str(tmp_path)
    main.net_connections.return_value = [SimpleNamespace(status=psutil.CONN_LISTEN, laddr=SimpleNamespace(port=55001))]
    server = Mock(pid=41002)
    server.cmdline.return_value = ["python3", "-m", "modules.web_interface.server", "--output-dir", "output/live", "--port", "55123"]
    server.info = {"cmdline": server.cmdline.return_value}
    server.cwd.return_value = str(tmp_path)
    server.create_time.return_value = 101.0
    server.net_connections.return_value = [
        SimpleNamespace(status=psutil.CONN_LISTEN, laddr=SimpleNamespace(port=55123)),
        SimpleNamespace(status=psutil.CONN_ESTABLISHED, laddr=SimpleNamespace(port=45678)),
    ]
    redis_child = Mock(pid=41003)
    redis_child.cmdline.return_value = ["redis-server", "127.0.0.1:6379"]
    main.children.return_value = [server, redis_child]
    if case in {"disabled", "orphan"}:
        main.children.return_value = [redis_child]
    if case == "starting":
        server.net_connections.return_value = []
    elif case == "other_output":
        server.cmdline.return_value[4] = "output/other"
    elif case == "old_server":
        server.create_time.return_value = 99.0
    elif case == "denied":
        server.net_connections.side_effect = psutil.AccessDenied(server.pid)
    elif case == "reused":
        main.create_time.return_value = 102.0
    with patch.object(control.psutil, "Process", return_value=main), patch.object(
        control.psutil, "process_iter", return_value=[server] if case == "orphan" else []
    ):
        assert control._get_web_ports_of_instance(instance) == expected
    redis_child.net_connections.assert_not_called()
    if case == "viewer":
        main.children.assert_not_called()


@pytest.mark.parametrize("case", ["normal_run", "relative", "other_slips_folder", "self", "zombie", "denied", "management", "legacy_stop", "restart", "restart_pid"])
def test_get_verified_instance_scope(tmp_path: Path, case: str) -> None:
    """Only a live Slips run from this folder counts as an instance.

    Other programs, dead processes and stop/restart commands are rejected.

    Parameters:
        tmp_path: Folder holding the slips.py of this test.
        case: Which kind of process is being checked.
    """
    _factory = ModuleFactory()
    slips_script = tmp_path / "slips.py"
    process = create_process(41001, slips_script, "-i", "eth0")
    if case == "relative":
        process.cmdline.return_value[1] = "./slips.py"
        process.cwd.return_value = str(tmp_path)
    elif case == "other_slips_folder":
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
    actual = control.get_verified_instance(process, slips_script)
    if case in {"normal_run", "relative"}:
        assert actual == control.RunningInstance(41001, 100.0, ("-i", "eth0"))
    else:
        assert actual is None


def test_list_and_print_instances(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """Only real Slips instances are listed, with their input and output.

    Parameters:
        tmp_path: Folder holding the slips.py of this test.
        capsys: Used to read what was printed.
    """
    _factory = ModuleFactory()
    slips_script = tmp_path / "slips.py"
    first = create_process(41002, slips_script, "-D", "-f", "test.pcap", "-o", "output/test")
    second = create_process(41001, slips_script, "-i", "eth0")
    other = create_process(41003, tmp_path / "other.py")
    with patch.object(control.psutil, "process_iter", return_value=[first, other, second]):
        instances = control.list_instances(slips_script)
    assert [instance.pid for instance in instances] == [41001, 41002]
    with patch.object(control, "_get_web_ports_of_instance", side_effect=[[55000], []]):
        control._print_running_slips_instances(instances)
    listing = capsys.readouterr().out
    assert "eth0" in listing and "test.pcap" in listing
    assert "daemon" in listing and "output/test" in listing
    assert "WEB PORT" in listing and "55000" in listing
    assert "41003" not in listing
    control._print_running_slips_instances([])
    assert "No accessible running" in capsys.readouterr().out


@pytest.mark.parametrize("background", [False, True])
def test_saved_viewer_discovery_and_listing(background: bool, capsys: pytest.CaptureFixture) -> None:
    """Viewers of saved results are found as instances, but they are not runs.

    Parameters:
        background: Whether the viewer was started with -D.
        capsys: Used to read what was printed.
    """
    _factory = ModuleFactory()
    slips_script = Path("slips.py")
    arguments = ["--view", "output/saved", *( ["-D"] if background else [])]
    process = create_process(41001, slips_script, *arguments)
    instance = control.get_verified_instance(process, slips_script)
    assert instance is not None
    assert control.get_slips_run_arguments(process.cmdline()) is None
    control._print_running_slips_instances([instance])
    listing = capsys.readouterr().out
    assert "saved results" in listing and "output/saved" in listing
    assert ("view-bg" if background else "viewer") in listing


@pytest.mark.parametrize("case", ["forked", "nested", "other_slips_folder", "denied"])
def test_discovery_excludes_forked_workers(tmp_path: Path, case: str) -> None:
    """Workers forked from a Slips instance are not instances themselves.

    On systems that fork, workers show the same slips.py arguments as the
    main process.

    Parameters:
        tmp_path: Folder holding the slips.py of this test.
        case: How the worker is related to the main process.
    """
    _factory = ModuleFactory()
    slips_script = tmp_path / "slips.py"
    main = create_process(41001, slips_script, "-D", "-i", "eth0")
    worker = create_process(41002, slips_script, "-D", "-i", "eth0")
    ancestor = create_process(41003, tmp_path / "other.py")
    worker.parents.return_value = [main] if case == "forked" else [ancestor, main]
    if case == "other_slips_folder":
        ancestor.cmdline.return_value[1] = str(tmp_path / "other" / "slips.py")
        worker.parents.return_value = [ancestor]
    elif case == "denied":
        ancestor.cmdline.side_effect = psutil.AccessDenied(ancestor.pid)
        worker.parents.return_value = [ancestor]
    with patch.object(control.psutil, "process_iter", return_value=[main, worker]):
        instances = control.list_instances(slips_script)
    if case in {"forked", "nested"}:
        assert [instance.pid for instance in instances] == [main.pid]
        assert control.get_verified_instance(worker, slips_script) is None
    else:
        assert [instance.pid for instance in instances] == [main.pid, worker.pid]


@pytest.mark.parametrize("case, expected", [("normal", 0), ("gone", 0), ("reused", 1), ("denied", 1), ("slow", 1)])
def test_stop_revalidates_and_waits(tmp_path: Path, case: str, expected: int) -> None:
    """Stopping must not signal a PID that was reused by another process.

    A slow instance or its workers must never be force-killed either.

    Parameters:
        tmp_path: Folder holding the slips.py of this test.
        case: State of the process when we try to stop it.
        expected: The exit code that should be returned.
    """
    _factory = ModuleFactory()
    slips_script = tmp_path / "slips.py"
    process = create_process(41001, slips_script, "-i", "eth0")
    child = Mock(pid=41002)
    process.children.return_value = [child]
    instance = control.get_verified_instance(process, slips_script)
    if case == "reused":
        process.create_time.return_value += 1
    if case == "denied":
        process.children.side_effect = psutil.AccessDenied(process.pid)
    with patch.object(control.psutil, "Process", return_value=process) as constructor, patch.object(
        control.psutil, "wait_procs", return_value=([], [child] if case == "slow" else [])
    ) as wait:
        if case == "gone":
            constructor.side_effect = psutil.NoSuchProcess(process.pid)
        assert control.stop_instances([instance], slips_script, timeout=0.1) == expected
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


@pytest.mark.parametrize("status", [psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD])
def test_stop_does_not_wait_for_exited_unreaped_workers(tmp_path: Path, status: str) -> None:
    """Don't wait for workers that already exited but were not cleaned up.

    This happens in containers, where the parent never reaps them.

    Parameters:
        tmp_path: Folder holding the slips.py of this test.
        status: State reported by the exited processes after the signal.
    """
    _factory = ModuleFactory()
    slips_script = tmp_path / "slips.py"
    process = create_process(41001, slips_script, "-i", "eth0")
    child = Mock(pid=41002)
    child.is_running.return_value = True
    child.status.return_value = status
    process.children.return_value = [child]
    instance = control.get_verified_instance(process, slips_script)
    process.send_signal.side_effect = lambda _: setattr(process.status, "return_value", status)
    with patch.object(control.psutil, "Process", return_value=process), patch.object(control.psutil, "wait_procs") as wait:
        assert control.stop_instances([instance], slips_script, timeout=0.1) == 0
    wait.assert_not_called()
    process.send_signal.assert_called_once_with(signal.SIGTERM)
    child.kill.assert_not_called()


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
    """With more than one instance running, the user must say which to stop.

    Parameters:
        arguments: The stop or list command.
        count: Number of running instances.
        selected: PIDs that should be stopped.
        expected: The exit code that should be returned.
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
    """Bad or conflicting options are rejected before looking for instances.

    Parameters:
        arguments: The invalid options.
    """
    _factory = ModuleFactory()
    with patch.object(control, "list_instances") as discover, patch.object(control, "stop_instances") as stop:
        with pytest.raises(SystemExit) as error:
            control.handle_instance_command(arguments)
    assert error.value.code == 2
    discover.assert_not_called()
    stop.assert_not_called()


def test_management_help_and_capture_passthrough() -> None:
    """The new options show up in the parser and normal runs are left alone."""
    _factory = ModuleFactory()
    parser = create_instance_parser()
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
    """Running slips.py with stop/list commands must not load Main, the config or Redis.

    Parameters:
        arguments: The stop, list or removed options to run.
        expected: The exit code that should be returned.
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
    """The same stop option works for daemons, interface runs and file runs.

    Parameters:
        arguments: The stop command, with an optional PID.
        selected: Positions of the instances that should be stopped.
        expected: The exit code that should be returned.
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
    """Restart picks a daemon and leaves non-daemon instances alone.

    Parameters:
        arguments: The restart command, with an optional PID.
        modes: The launch flag of each running instance.
        selected: PID of the daemon that should be restarted, or None if
            the request should be rejected.
        expected: The exit code that should be returned.
    """
    _factory = ModuleFactory()
    instances = [control.RunningInstance(41001 + index, 1, (mode,))
                 for index, mode in enumerate(modes)]
    with patch.object(control, "list_instances", return_value=instances), patch.object(
        control, "_restart_instance", return_value=0
    ) as restart, patch.object(control, "stop_instances") as stop:
        assert control.handle_instance_command(arguments) == expected
    if selected is None:
        restart.assert_not_called()
    else:
        assert restart.call_args.args[0].pid == selected
    stop.assert_not_called()


@pytest.mark.parametrize("direct_script", [False, True])
def test_restart_preserves_launch_arguments_and_directory(tmp_path: Path, direct_script: bool) -> None:
    """A restart starts only after the stop, with the same arguments and folder.

    Arguments with spaces must stay as one argument.

    Parameters:
        tmp_path: The daemon's original working directory.
        direct_script: Whether it was started as ./slips.py instead of
            through python.
    """
    _factory = ModuleFactory()
    slips_script = tmp_path / "slips.py"
    arguments = ("-D", "-c", "config with spaces.yaml", "-i", "eth0",
                 "-w", "--web-port", "55012", "-o", "output/live capture", "--keep-history")
    process = create_process(41001, slips_script, *arguments)
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
        assert control._restart_instance(instance, slips_script) == 0
    assert [call[0] for call in order.mock_calls] == ["stop", "launch"]
    order.stop.assert_called_once_with(
        [instance], slips_script, timeout=control.RESTART_STOP_TIMEOUT_SECONDS
    )
    expected = [sys.executable, *([] if direct_script else ["-u"]), *original]
    order.launch.assert_called_once_with(expected, cwd=str(tmp_path), check=False)


@pytest.mark.parametrize("case", ["foreground", "gone", "reused", "denied", "slow", "launch_error", "startup_failed"])
def test_restart_handles_failures(tmp_path: Path, case: str) -> None:
    """Restart gives up when the daemon can't be checked, and reports failures.

    Parameters:
        tmp_path: Folder holding the slips.py of this test.
        case: What goes wrong: checking the daemon, stopping it or starting it.
    """
    _factory = ModuleFactory()
    slips_script = tmp_path / "slips.py"
    process = create_process(41001, slips_script, "-D", "-i", "eth0")
    instance = control.get_verified_instance(process, slips_script)
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
        assert control._restart_instance(instance, slips_script) == (3 if case == "startup_failed" else 1)
    if case in {"foreground", "gone", "reused", "denied"}:
        stop.assert_not_called()
    if case not in {"launch_error", "startup_failed"}:
        launch.assert_not_called()


def _pid_is_gone(pid: int) -> bool:
    """Tell if a process is gone, counting zombies as gone like Slips does.

    Inside a CI container, PID 1 may never reap orphans, so a stopped
    daemon can stay a zombie forever.

    Parameters:
        pid: Process to check.
    """
    try:
        return psutil.Process(pid).status() in {
            psutil.STATUS_ZOMBIE,
            psutil.STATUS_DEAD,
        }
    except psutil.NoSuchProcess:
        return True


@pytest.mark.parametrize("cleanup_delay", [0, 46])
def test_native_restart_preserves_arguments_and_waits_for_worker(tmp_path: Path, cleanup_delay: int) -> None:
    """Restart a fake daemon for real and check the whole sequence.

    The old daemon must finish saving its state, and its worker must exit,
    before the new one starts.

    Parameters:
        tmp_path: Folder for the fake slips.py, its files and its saved state.
        cleanup_delay: Seconds the daemon spends saving after its worker
            exits. 46 is longer than the normal stop timeout.
    """
    _factory = ModuleFactory()
    slips_script = tmp_path / "slips.py"
    marker = tmp_path / "ready.json"
    saved = tmp_path / "saved.json"
    (tmp_path / "config with spaces.yaml").write_text(Path("config/slips.yaml").read_text())
    (tmp_path / "VERSION").write_text(Path("VERSION").read_text())
    history = tmp_path / "output" / "capture with spaces"
    (history / "databases").mkdir(parents=True)
    (history / "databases" / "flows.sqlite").write_text("retained history")
    (history / "metadata").mkdir()
    (history / "metadata" / "info.txt").write_text("File: eth0\n")
    slips_script.write_text('''"""A fake daemon used to test restarting."""
import json
import os
from pathlib import Path
import signal
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, __PROJECT_DIRECTORY__)
import psutil
from managers.process_manager.instance_control import get_verified_instance, _restart_instance
if sys.argv[1:2] == ["--restart"]:
    instance = get_verified_instance(psutil.Process(int(sys.argv[2])), Path(__file__))
    raise SystemExit(_restart_instance(instance, Path(__file__)))
from managers.redis_manager import RedisManager
parent = psutil.Process(os.getppid())
parent.info = parent.as_dict(attrs=["pid", "cmdline"])
args = SimpleNamespace(interface="eth0", output="output/capture with spaces",
    multiinstance=False, db=None, port=None, is_slips_started_by_an_update=False)
with patch("managers.redis_manager.psutil.process_iter", return_value=[parent]):
    assert RedisManager(SimpleNamespace(args=args)).validate_keep_history_and_find_saved_history()
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
    """Stop the worker, then save the state and exit."""
    os.kill(worker, signal.SIGTERM)
    os.waitpid(worker, 0)
    if not Path("saved.json").exists():
        time.sleep(__CLEANUP_DELAY__)
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
'''.replace("__PROJECT_DIRECTORY__", repr(str(Path.cwd()))).replace("__CLEANUP_DELAY__", str(cleanup_delay)))
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
        instance = control.get_verified_instance(psutil.Process(previous["pid"]), slips_script)
        assert instance is not None
        restarted = subprocess.run([sys.executable, "./slips.py", "--restart", str(instance.pid)],
                                   cwd=tmp_path, capture_output=True, text=True, timeout=cleanup_delay + 20)
        assert restarted.returncode == 0, restarted.stdout + restarted.stderr
        if cleanup_delay:
            assert "Shutdown in progress" in restarted.stdout
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
        assert _pid_is_gone(previous["pid"])
        assert _pid_is_gone(previous["worker"])
        assert json.loads(saved.read_text()) == {"pid": previous["pid"]}
        assert (history / "databases" / "flows.sqlite").read_text() == "retained history"
    finally:
        if marker.exists():
            current = json.loads(marker.read_text())
            instance = control.get_verified_instance(psutil.Process(current["pid"]), slips_script)
            if instance is not None:
                control.stop_instances([instance], slips_script, timeout=5)
        for record in (previous, current):
            if record:
                for pid in (record["pid"], record["worker"]):
                    # a zombie that isn't our child can't be waited on
                    if not _pid_is_gone(pid):
                        process = psutil.Process(pid)
                        process.kill()
                        process.wait(timeout=5)


def test_native_shutdown_waits_for_checkpoint_and_worker(tmp_path: Path) -> None:
    """Stopping a fake Slips process waits until its worker exits and it saves its state.

    Parameters:
        tmp_path: Folder for the fake slips.py and its marker files.
    """
    _factory = ModuleFactory()
    slips_script = tmp_path / "slips.py"
    marker = tmp_path / "ready.json"
    saved = tmp_path / "saved"
    slips_script.write_text('''"""A fake Slips process used to test stopping."""
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
    """Stop the child, then save the state and exit."""
    os.kill(child_pid, signal.SIGTERM)
    os.waitpid(child_pid, 0)
    Path(sys.argv[2]).write_text("saved")
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
Path(sys.argv[1]).write_text(json.dumps({"child": child_pid}))
while True:
    signal.pause()
''')
    process = subprocess.Popen([sys.executable, str(slips_script), str(marker), str(saved)])
    child_pid = None
    try:
        deadline = time.monotonic() + 10
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        child_pid = json.loads(marker.read_text())["child"]
        instance = control.get_verified_instance(psutil.Process(process.pid), slips_script)
        assert instance is not None
        assert control.get_verified_instance(psutil.Process(child_pid), slips_script) is None
        assert [item.pid for item in control.list_instances(slips_script)] == [process.pid]
        assert control.stop_instances([instance], slips_script, timeout=5) == 0
        assert saved.read_text() == "saved"
        assert process.wait(timeout=5) == 0
        assert not psutil.pid_exists(child_pid)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        if child_pid and psutil.pid_exists(child_pid):
            psutil.Process(child_pid).terminate()
