"""List, stop and restart running Slips instances, without opening their databases."""

import argparse
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from types import SimpleNamespace

import psutil

from slips_files.common.parsers.arg_parser import (
    create_instance_parser,
    create_launch_parser,
    create_web_server_parser,
)

RESTART_STOP_TIMEOUT_SECONDS = 300
NOT_SET = "—"
WEB_SERVER_MODULE = "modules.web_interface.server"


def _get_option_spellings(parser: argparse.ArgumentParser) -> SimpleNamespace:
    """Map each option of a parser to all the ways it can be typed.

    For example, the daemon option maps to ("-D", "--daemon").

    Parameters:
        parser: Parser that defines the options.

    Returns:
        Namespace with one attribute per option, holding its spellings.
    """
    return SimpleNamespace(
        **{
            action.dest: tuple(action.option_strings)
            for action in parser._actions
            if action.option_strings
        }
    )


# ARGS.daemon is ("-D", "--daemon"), FLAG.daemon is "--daemon" and
# PREFIXES.stop is ("--stop=",).
ARGS = _get_option_spellings(create_launch_parser())
WEB_ARGS = _get_option_spellings(create_web_server_parser())
FLAG = SimpleNamespace(
    **{dest: names[-1] for dest, names in vars(ARGS).items()}
)
PREFIXES = SimpleNamespace(
    **{
        dest: tuple(f"{name}=" for name in names if name.startswith("--"))
        for dest, names in vars(ARGS).items()
    }
)
COMMAND_ARGS = {*ARGS.list_instances, *ARGS.stop, *ARGS.restart}
COMMAND_PREFIXES = PREFIXES.stop + PREFIXES.restart
MANAGEMENT_ARGS = COMMAND_ARGS | {
    *ARGS.stop_daemon,
    *ARGS.killall,
    *ARGS.help,
    *ARGS.version,
}


@dataclass(frozen=True)
class RunningInstance:
    """A running Slips process.

    The start time is stored next to the PID so we can tell if the PID was
    reused by another process later.
    """

    pid: int
    created: float
    arguments: tuple[str, ...]


def _get_slips_script_index(command: list[str]) -> int | None:
    """Find where slips.py is in a command line.

    Commands that only mention slips.py, like `python -c "..."` or
    `python -m ...`, don't count.

    Parameters:
        command: The process's command line, split into words.

    Returns:
        Position of slips.py in the command, or None if the command
        doesn't run slips.py.
    """
    if not command:
        return None
    if Path(command[0]).name == "slips.py":
        return 0
    if not re.fullmatch(
        r"(?:python|pypy)(?:\d+(?:\.\d+)*)?", Path(command[0]).name, re.I
    ):
        return None
    index = 1
    while index < len(command) and command[index].startswith("-"):
        flag = command[index]
        if flag == "--":
            index += 1
            break
        if not (
            re.fullmatch(r"-[bBdEiIOPqRsSuvx]+", flag)
            or flag.startswith(("-W", "-X", "--check-hash-based-pycs"))
        ):
            return None
        index += 2 if flag in {"-W", "-X", "--check-hash-based-pycs"} else 1
    return (
        index
        if index < len(command) and Path(command[index]).name == "slips.py"
        else None
    )


def get_slips_run_arguments(
    command: list[str], include_views: bool = False
) -> tuple[str, ...] | None:
    """Get the arguments of a command that starts a Slips run.

    Commands that only manage Slips (--stop, --list-instances, --help...)
    and commands unrelated to Slips return None.

    Parameters:
        command: The process's command line, split into words.
        include_views: Also accept runs that only open saved results.
            Needed when listing and stopping instances.

    Returns:
        The arguments after slips.py, or None if the command doesn't
        start a run.
    """
    position = _get_slips_script_index(command)
    if position is None:
        return None
    arguments = tuple(command[position + 1 :])
    if not include_views and any(
        arg in ARGS.view or arg.startswith(PREFIXES.view) for arg in arguments
    ):
        return None
    if any(
        arg in MANAGEMENT_ARGS or arg.startswith(COMMAND_PREFIXES)
        for arg in arguments
    ):
        return None
    return arguments


def get_verified_instance(
    process: psutil.Process, slips_script: Path
) -> RunningInstance | None:
    """Check that a process is a Slips instance started from this Slips folder.

    Parameters:
        process: The process to check.
        slips_script: Path of the slips.py in this Slips folder.

    Returns:
        The running instance, or None if the process is not Slips, runs
        the slips.py of another folder, is a worker of another Slips
        instance, is dead, or can't be inspected.
    """
    try:
        command = process.cmdline()
        position = _get_slips_script_index(command)
        arguments = get_slips_run_arguments(command, include_views=True)
        if position is None or arguments is None or process.pid == os.getpid():
            return None
        script = Path(command[position])
        if not script.is_absolute():
            script = Path(process.cwd()) / script
        if script.resolve() != slips_script.resolve():
            return None
        if process.status() in {psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD}:
            return None
        for parent in process.parents():
            try:
                parent_command = parent.cmdline()
                parent_position = _get_slips_script_index(parent_command)
                if parent_position is None:
                    continue
                parent_script = Path(parent_command[parent_position])
                if not parent_script.is_absolute():
                    parent_script = Path(parent.cwd()) / parent_script
                if parent_script.resolve() == slips_script.resolve():
                    return None
            except (psutil.Error, OSError):
                continue
        return RunningInstance(process.pid, process.create_time(), arguments)
    except (psutil.Error, OSError):
        return None


def is_daemon(arguments: tuple[str, ...]) -> bool:
    """Tell if the arguments ask for daemon mode (-D).

    Parameters:
        arguments: The arguments after slips.py.
    """
    return any(arg in ARGS.daemon for arg in arguments)


def list_instances(slips_script: Path) -> list[RunningInstance]:
    """Find the running Slips instances started from this Slips folder.

    Parameters:
        slips_script: Path of the slips.py in this Slips folder. Processes
            are matched on it, wherever they were started from.

    Returns:
        The instances sorted by PID, without the process running this
        command.
    """
    return sorted(
        (
            instance
            for process in psutil.process_iter()
            if (instance := get_verified_instance(process, slips_script))
            is not None
        ),
        key=lambda instance: instance.pid,
    )


def _get_argument_value(arguments: tuple[str, ...], *names: str) -> str:
    """Read the value of one option from the arguments of a run.

    Parameters:
        arguments: The arguments after slips.py.
        names: All spellings of the option, e.g. "-o" and "--output".

    Returns:
        The option's value, or a dash if the option wasn't given.
    """
    for index, argument in enumerate(arguments):
        for name in names:
            if argument == name and index + 1 < len(arguments):
                return arguments[index + 1]
            if argument.startswith(name + "="):
                return argument[len(name) + 1 :]
            if (
                len(name) == 2
                and argument.startswith(name)
                and argument != name
            ):
                return argument[len(name) :]
    return NOT_SET


def _get_web_server_candidates(
    main: psutil.Process, instance: RunningInstance
) -> tuple[list[psutil.Process], Path | None]:
    """Collect the processes that may be serving the web interface of a run.

    Parameters:
        main: The run's main process.
        instance: The run's main process and the arguments it was started with.

    Returns:
        The candidate processes, and the run's output directory (None if
        it wasn't given).
    """
    if _get_argument_value(instance.arguments, *ARGS.view) != NOT_SET:
        return [main], None
    candidates = main.children(recursive=True)
    output_arg = _get_argument_value(instance.arguments, *ARGS.output)
    if output_arg == NOT_SET:
        return candidates, None
    output = (Path(main.cwd()) / output_arg).resolve()
    # The process that started the web server may have exited while the
    # server keeps running, so look at all processes on the machine.
    candidates.extend(
        process
        for process in psutil.process_iter(["cmdline"])
        if WEB_SERVER_MODULE in (process.info["cmdline"] or [])
    )
    return candidates, output


def _is_web_server_of_instance(
    process: psutil.Process, instance: RunningInstance, output: Path | None
) -> bool:
    """Tell if a process is the web server that a Slips run started.

    Parameters:
        process: The process to check.
        instance: The run's main process.
        output: The run's output directory. If None, it isn't compared.

    Returns:
        True if the process is the web server, was started after the run,
        and serves the same output directory.
    """
    command = process.cmdline()
    runs_web_server = any(
        command[index : index + 2] == ["-m", WEB_SERVER_MODULE]
        for index in range(len(command) - 1)
    )
    if not runs_web_server or process.create_time() < instance.created:
        return False
    if output is None:
        return True
    destination = _get_argument_value(tuple(command), *WEB_ARGS.output_dir)
    return (Path(process.cwd()) / destination).resolve() == output


def _get_listening_tcp_ports(process: psutil.Process) -> set[int]:
    """Get the TCP ports a process is accepting connections on.

    Parameters:
        process: The process to inspect.
    """
    return {
        connection.laddr.port
        for connection in process.net_connections(kind="tcp")
        if connection.status == psutil.CONN_LISTEN and connection.laddr
    }


def _get_web_ports_of_instance(instance: RunningInstance) -> list[int]:
    """Find the ports where the web interface of a Slips run is listening.

    Parameters:
        instance: The run's main process and the arguments it was started with.

    Returns:
        The open web ports in order. Empty if there are none or the
        processes can't be inspected.
    """
    try:
        main = psutil.Process(instance.pid)
        if main.create_time() != instance.created:
            return []
        candidates, output = _get_web_server_candidates(main, instance)
    except (psutil.Error, OSError):
        return []

    ports: set[int] = set()
    inspected: set[int] = set()
    for process in candidates:
        if process.pid in inspected:
            continue
        inspected.add(process.pid)
        try:
            if process.pid == main.pid or _is_web_server_of_instance(
                process, instance, output
            ):
                ports.update(_get_listening_tcp_ports(process))
        except (psutil.Error, OSError):
            continue
    return sorted(ports)


def _print_instances(instances: list[RunningInstance]) -> None:
    """Print a table of running instances so the user can pick one.

    Parameters:
        instances: The running Slips instances.
    """
    if not instances:
        print("No accessible running Slips instances.")
        return
    print("Running Slips instances:")
    print(f"{'PID':<9} {'MODE':<9} {'WEB PORT':<12} {'INPUT':<24} OUTPUT")
    for instance in instances:
        args = instance.arguments
        mode = "daemon" if is_daemon(args) else "normal"
        source = _get_argument_value(args, *ARGS.interface)
        if source == NOT_SET:
            source = _get_argument_value(args, *ARGS.filepath, *ARGS.growing)
        output = _get_argument_value(args, *ARGS.output)
        saved_output = _get_argument_value(args, *ARGS.view)
        if saved_output != NOT_SET:
            mode = "view-bg" if mode == "daemon" else "viewer"
            source = "saved results"
            output = saved_output
        ports = (
            ",".join(map(str, _get_web_ports_of_instance(instance))) or NOT_SET
        )
        print(f"{instance.pid:<9} {mode:<9} {ports:<12} {source:<24} {output}")


def _signal_instance_to_stop(
    instance: RunningInstance, slips_script: Path
) -> tuple[list[psutil.Process], bool]:
    """Ask one instance to shut down (SIGTERM), after checking again that
    it is still the same process.

    Parameters:
        instance: The instance to stop.
        slips_script: Path of the slips.py in this Slips folder.

    Returns:
        The instance and its workers (the processes to wait for), and
        whether the stop was refused. If the instance already exited,
        returns no processes and False.
    """
    try:
        process = psutil.Process(instance.pid)
        if (
            not process.is_running()
            or process.status() == psutil.STATUS_ZOMBIE
        ):
            return [], False
        if get_verified_instance(process, slips_script) != instance:
            print(
                f"PID {instance.pid} changed or cannot be verified; not stopped."
            )
            return [], True
        children = process.children(recursive=True)
        process.send_signal(signal.SIGTERM)
        print(
            f"Requested graceful shutdown of Slips PID {instance.pid}.",
            flush=True,
        )
        return [*children, process], False
    except psutil.NoSuchProcess:
        return [], False
    except psutil.AccessDenied:
        print(f"Permission denied for PID {instance.pid}; run as its owner.")
        return [], True


def _get_running_processes(
    processes: list[psutil.Process],
) -> list[psutil.Process]:
    """Keep only the processes that are still running.

    Parameters:
        processes: The processes that were asked to stop.

    Returns:
        The processes that are not gone or zombies. A process we're not
        allowed to inspect is assumed to be running.
    """
    running = []
    for process in processes:
        try:
            if process.is_running() and process.status() not in {
                psutil.STATUS_ZOMBIE,
                psutil.STATUS_DEAD,
            }:
                running.append(process)
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            running.append(process)
    return running


def _wait_for_processes_to_stop(
    processes: list[psutil.Process], timeout: float
) -> list[psutil.Process]:
    """Wait for processes to exit, printing progress every 10 seconds.

    Parameters:
        processes: The instances and workers that were asked to stop.
        timeout: Maximum seconds to wait for all of them together.

    Returns:
        The processes that are still running when the time is up.
    """
    alive = processes
    deadline = time.monotonic() + timeout
    remaining = timeout
    next_report = 10.0
    while True:
        alive = _get_running_processes(alive)
        if not alive or remaining <= 0:
            break
        interval = min(5.0, remaining)
        _, alive = psutil.wait_procs(alive, timeout=interval)
        if not alive:
            break
        remaining = min(
            remaining - interval, max(0.0, deadline - time.monotonic())
        )
        elapsed = timeout - remaining
        if elapsed >= next_report:
            pids = ", ".join(str(process.pid) for process in alive)
            print(
                f"Shutdown in progress ({elapsed:.0f}s); waiting for PID(s) {pids}. "
                "Waiting for workers to finish.",
                flush=True,
            )
            next_report = elapsed + 10
    return alive


def stop_instances(
    instances: list[RunningInstance], slips_script: Path, timeout: float = 45
) -> int:
    """Ask instances to shut down and wait for them to clean up.

    Nothing is force-killed.

    Parameters:
        instances: The instances to stop.
        slips_script: Path of the slips.py in this Slips folder.
        timeout: Maximum seconds to wait for all instances and their
            workers together.

    Returns:
        0 if everything stopped. 1 if a stop was refused (the process
        changed or permission was denied) or something is still running.
    """
    waiting: dict[int, psutil.Process] = {}
    failed = False
    for instance in instances:
        signaled, refused = _signal_instance_to_stop(instance, slips_script)
        waiting.update((process.pid, process) for process in signaled)
        failed = failed or refused
    if not waiting:
        return int(failed)
    alive = _wait_for_processes_to_stop(list(waiting.values()), timeout)
    if alive:
        pids = ", ".join(str(process.pid) for process in alive)
        print(
            f"Still stopping after {timeout:g}s: {pids}. Check the run's errors.log; no processes were force-killed."
        )
        return 1
    print("Selected Slips instances and their workers have stopped.")
    return int(failed)


def _restart_instance(instance: RunningInstance, slips_script: Path) -> int:
    """Stop a daemon completely, then start it again with the same arguments.

    Parameters:
        instance: The daemon to restart.
        slips_script: Path of the slips.py in this Slips folder.

    Returns:
        The exit code of the new launch, or 1 if reading the daemon,
        stopping it or starting it again failed.
    """
    if not is_daemon(instance.arguments):
        print(f"PID {instance.pid} is not a Slips daemon; not restarted.")
        return 1
    try:
        process = psutil.Process(instance.pid)
        if get_verified_instance(process, slips_script) != instance:
            print(
                f"PID {instance.pid} changed or cannot be verified; not restarted."
            )
            return 1
        command = process.cmdline()
        position = _get_slips_script_index(command)
        directory = process.cwd()
        # On macOS the command can show Python's base binary instead of the
        # virtualenv's, so use the Python that is running this command.
        command = [sys.executable, *command[1 if position else 0 :]]
    except (psutil.Error, OSError) as error:
        print(
            f"Cannot read the launch command for PID {instance.pid}: {error}"
        )
        return 1
    if (
        stop_instances(
            [instance], slips_script, timeout=RESTART_STOP_TIMEOUT_SECONDS
        )
        != 0
    ):
        print("Shutdown did not finish; no replacement daemon was started.")
        return 1
    print(
        f"Restarting Slips daemon with the arguments from PID {instance.pid}.",
        flush=True,
    )
    try:
        return subprocess.run(command, cwd=directory, check=False).returncode
    except OSError as error:
        print(f"Daemon stopped, but restarting failed: {error}")
        return 1


def _is_positive_pid(value: str) -> bool:
    """Tell if a command-line value is a valid PID (a number above zero).

    Parameters:
        value: The value given to --stop or --restart.
    """
    return value.isdecimal() and int(value) > 0


def _parse_instance_command(arguments: list[str]) -> argparse.Namespace:
    """Parse the arguments of a list, stop or restart command.

    Exits with an error message if the PID is invalid.

    Parameters:
        arguments: The command-line arguments, without the program name.

    Returns:
        The parsed options.
    """
    parser = create_instance_parser()
    options = parser.parse_args(arguments)
    if options.stop not in {None, "auto", "all"} and not _is_positive_pid(
        options.stop
    ):
        parser.error(f"{FLAG.stop} expects a positive PID or all")
    if options.restart not in {None, "auto"} and not _is_positive_pid(
        options.restart
    ):
        parser.error(f"{FLAG.restart} expects a positive daemon PID")
    return options


def _restart_selected_daemon(
    instances: list[RunningInstance], target: str, slips_script: Path
) -> int:
    """Restart the daemon that the user asked for.

    Parameters:
        instances: The running instances from this Slips folder.
        target: The daemon's PID, or "auto" to pick the only running daemon.
        slips_script: Path of the slips.py in this Slips folder.

    Returns:
        The exit code of the new launch, or 1 if there isn't exactly
        one matching daemon.
    """
    daemons = [
        instance
        for instance in instances
        if is_daemon(instance.arguments)
        and (target == "auto" or instance.pid == int(target))
    ]
    if not daemons:
        print(
            "No matching running Slips daemon from this Slips folder to restart."
        )
        return 1
    if len(daemons) > 1:
        print(f"More than one daemon is running. Use {FLAG.restart} PID.")
        return 1
    return _restart_instance(daemons[0], slips_script)


def _stop_selected_instances(
    instances: list[RunningInstance], target: str, slips_script: Path
) -> int:
    """Stop the instances that the user asked for.

    Parameters:
        instances: The running instances from this Slips folder.
        target: An instance's PID, "all", or "auto" to pick the only
            running instance.
        slips_script: Path of the slips.py in this Slips folder.

    Returns:
        0 if everything stopped. 1 if the target is unclear, not found,
        or didn't stop.
    """
    if not instances:
        return 0 if target in {"auto", "all"} else 1
    if target == "auto" and len(instances) > 1:
        print(
            f"More than one instance is running. Use {FLAG.stop} PID "
            f"or {FLAG.stop} all."
        )
        return 1
    selected = (
        instances
        if target in {"auto", "all"}
        else [
            instance for instance in instances if instance.pid == int(target)
        ]
    )
    if not selected:
        print(
            f"PID {target} is not an accessible Slips instance from this Slips folder."
        )
        return 1
    return stop_instances(selected, slips_script)


def handle_instance_command(arguments: list[str]) -> int | None:
    """Run the list, stop or restart command, if the user typed one.

    This runs before the config, logs and Redis are set up, so the
    commands work while other instances are running.

    Parameters:
        arguments: The command-line arguments, without the program name.

    Returns:
        The exit code, or None if this is a normal Slips run.
    """
    if any(arg in ARGS.stop_daemon for arg in arguments):
        argparse.ArgumentParser(prog="slips.py").error(
            f"{'/'.join(ARGS.stop_daemon)} was removed; "
            f"use {FLAG.stop} [PID|all] instead"
        )
    if not any(
        arg in COMMAND_ARGS or arg.startswith(COMMAND_PREFIXES)
        for arg in arguments
    ):
        return None
    options = _parse_instance_command(arguments)
    slips_script = Path(__file__).resolve().parents[2] / "slips.py"
    instances = list_instances(slips_script)
    _print_instances(instances)
    if options.list_instances:
        return 0
    if options.restart is not None:
        return _restart_selected_daemon(
            instances, options.restart, slips_script
        )
    return _stop_selected_instances(instances, options.stop, slips_script)
