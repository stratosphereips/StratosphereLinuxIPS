"""Find, stop and restart Slips runs without opening their databases."""

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


def option_spellings(parser: argparse.ArgumentParser) -> SimpleNamespace:
    """Name every option spelling of a parser by its attribute.

    Parameters:
        parser: Parser defining the options.

    Returns:
        Namespace mapping each option's attribute name to its spellings.
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
ARGS = option_spellings(create_launch_parser())
WEB_ARGS = option_spellings(create_web_server_parser())
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
    """Identify a main process by PID, creation time and capture arguments."""

    pid: int
    created: float
    arguments: tuple[str, ...]


def get_slips_script_index(command: list[str]) -> int | None:
    """Locate the executed Python script, excluding code strings and modules.

    Parameters:
        command: Process argument vector.

    Returns:
        Slips script position, or None for a different program.
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
    """Separate capture launches from management and unrelated commands.

    Parameters:
        command: Process argument vector.
        include_views: Include saved viewers for process discovery and stopping.

    Returns:
        Arguments following slips.py, or None when no capture is being run.
    """
    position = get_slips_script_index(command)
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
    process: psutil.Process, entrypoint: Path
) -> RunningInstance | None:
    """Verify a live main process executes this checkout's actual entry point.

    Parameters:
        process: Candidate process.
        entrypoint: Slips entry point for this checkout.

    Returns:
        Verified process identity, or None for another or inaccessible process.
    """
    try:
        command = process.cmdline()
        position = get_slips_script_index(command)
        arguments = get_slips_run_arguments(command, include_views=True)
        if position is None or arguments is None or process.pid == os.getpid():
            return None
        script = Path(command[position])
        if not script.is_absolute():
            script = Path(process.cwd()) / script
        if script.resolve() != entrypoint.resolve():
            return None
        if process.status() in {psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD}:
            return None
        for parent in process.parents():
            try:
                parent_command = parent.cmdline()
                parent_position = get_slips_script_index(parent_command)
                if parent_position is None:
                    continue
                parent_script = Path(parent_command[parent_position])
                if not parent_script.is_absolute():
                    parent_script = Path(parent.cwd()) / parent_script
                if parent_script.resolve() == entrypoint.resolve():
                    return None
            except (psutil.Error, OSError):
                continue
        return RunningInstance(process.pid, process.create_time(), arguments)
    except (psutil.Error, OSError):
        return None


def is_daemon(arguments: tuple[str, ...]) -> bool:
    """Tell whether a launch asked for daemon mode.

    Parameters:
        arguments: Arguments following slips.py.

    Returns:
        True when any daemon option spelling is present.
    """
    return any(arg in ARGS.daemon for arg in arguments)


def list_instances(entrypoint: Path) -> list[RunningInstance]:
    """Find accessible Slips main processes from one checkout.

    Parameters:
        entrypoint: Entry point to match independently of process working dirs.

    Returns:
        Verified instances in PID order, excluding this management command.
    """
    return sorted(
        (
            instance
            for process in psutil.process_iter()
            if (instance := get_verified_instance(process, entrypoint))
            is not None
        ),
        key=lambda instance: instance.pid,
    )


def get_argument_value(arguments: tuple[str, ...], *names: str) -> str:
    """Read an existing launch option for the instance listing.

    Parameters:
        arguments: Arguments following slips.py.
        names: Short and long spellings of one option.

    Returns:
        Option value, or a dash when it was omitted.
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


def get_web_server_candidates(
    main: psutil.Process, instance: RunningInstance
) -> tuple[list[psutil.Process], Path | None]:
    """Collect the processes that may serve the web pages of one Slips run.

    Parameters:
        main: Live main process of the run.
        instance: Main process identity and original launch arguments.

    Returns:
        Candidate processes, and the run's output dir when it was given.
    """
    if get_argument_value(instance.arguments, *ARGS.view) != NOT_SET:
        return [main], None
    candidates = main.children(recursive=True)
    output_arg = get_argument_value(instance.arguments, *ARGS.output)
    if output_arg == NOT_SET:
        return candidates, None
    output = (Path(main.cwd()) / output_arg).resolve()
    # The launcher may have exited while its page stays open.
    candidates.extend(
        process
        for process in psutil.process_iter(["cmdline"])
        if WEB_SERVER_MODULE in (process.info["cmdline"] or [])
    )
    return candidates, output


def is_web_server_of_instance(
    process: psutil.Process, instance: RunningInstance, output: Path | None
) -> bool:
    """Tell whether a process is the web server started for one Slips run.

    Parameters:
        process: Candidate process.
        instance: Main process identity of the run.
        output: Output dir of the run, or None to skip matching it.

    Returns:
        True for a web server started by this run for its output dir.
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
    destination = get_argument_value(tuple(command), *WEB_ARGS.output_dir)
    return (Path(process.cwd()) / destination).resolve() == output


def get_listening_tcp_ports(process: psutil.Process) -> set[int]:
    """Find the TCP ports a process is listening on.

    Parameters:
        process: Process to inspect.

    Returns:
        Local ports of its listening TCP sockets.
    """
    return {
        connection.laddr.port
        for connection in process.net_connections(kind="tcp")
        if connection.status == psutil.CONN_LISTEN and connection.laddr
    }


def get_web_ports_of_instance(instance: RunningInstance) -> list[int]:
    """Find HTTP ports actually listening for one verified Slips run.

    Parameters:
        instance: Main process identity and original launch arguments.

    Returns:
        Sorted open web ports, empty when absent or inaccessible.
    """
    try:
        main = psutil.Process(instance.pid)
        if main.create_time() != instance.created:
            return []
        candidates, output = get_web_server_candidates(main, instance)
    except (psutil.Error, OSError):
        return []

    ports: set[int] = set()
    inspected: set[int] = set()
    for process in candidates:
        if process.pid in inspected:
            continue
        inspected.add(process.pid)
        try:
            if process.pid == main.pid or is_web_server_of_instance(
                process, instance, output
            ):
                ports.update(get_listening_tcp_ports(process))
        except (psutil.Error, OSError):
            continue
    return sorted(ports)


def print_instances(instances: list[RunningInstance]) -> None:
    """Show enough launch information to select the intended capture.

    Parameters:
        instances: Verified main processes.
    """
    if not instances:
        print("No accessible running Slips instances.")
        return
    print("Running Slips instances:")
    print(f"{'PID':<9} {'MODE':<9} {'WEB PORT':<12} {'INPUT':<24} OUTPUT")
    for instance in instances:
        args = instance.arguments
        mode = "daemon" if is_daemon(args) else "normal"
        source = get_argument_value(args, *ARGS.interface)
        if source == NOT_SET:
            source = get_argument_value(args, *ARGS.filepath, *ARGS.growing)
        output = get_argument_value(args, *ARGS.output)
        saved_output = get_argument_value(args, *ARGS.view)
        if saved_output != NOT_SET:
            mode = "view-bg" if mode == "daemon" else "viewer"
            source = "saved results"
            output = saved_output
        ports = (
            ",".join(map(str, get_web_ports_of_instance(instance))) or NOT_SET
        )
        print(f"{instance.pid:<9} {mode:<9} {ports:<12} {source:<24} {output}")


def signal_instance_to_stop(
    instance: RunningInstance, entrypoint: Path
) -> tuple[list[psutil.Process], bool]:
    """Ask one main process to shut down, once it is verified again.

    Parameters:
        instance: Selected identity from discovery.
        entrypoint: Entry point required again immediately before signaling.

    Returns:
        The signaled main process with its workers, and whether the stop
        was refused. An already stopped run gives no processes and False.
    """
    try:
        process = psutil.Process(instance.pid)
        if (
            not process.is_running()
            or process.status() == psutil.STATUS_ZOMBIE
        ):
            return [], False
        if get_verified_instance(process, entrypoint) != instance:
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


def get_running_processes(
    processes: list[psutil.Process],
) -> list[psutil.Process]:
    """Keep the processes that are still executing.

    Parameters:
        processes: Processes that were asked to stop.

    Returns:
        Processes that are neither gone nor zombies. A process that
        cannot be inspected counts as running.
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


def wait_for_processes_to_stop(
    processes: list[psutil.Process], timeout: float
) -> list[psutil.Process]:
    """Wait for signaled processes to exit, reporting progress every 10s.

    Parameters:
        processes: Main processes and workers that were asked to stop.
        timeout: Maximum wait in seconds shared by all of them.

    Returns:
        Processes still running once the wait is over.
    """
    alive = processes
    deadline = time.monotonic() + timeout
    remaining = timeout
    next_report = 10.0
    while True:
        alive = get_running_processes(alive)
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
    instances: list[RunningInstance], entrypoint: Path, timeout: float = 45
) -> int:
    """Signal verified main processes and wait for their normal cleanup.

    Parameters:
        instances: Selected identities from discovery.
        entrypoint: Entry point required again immediately before signaling.
        timeout: Shared maximum wait in seconds for main processes and workers.

    Returns:
        Zero after complete shutdown; one for changed, denied or unfinished runs.
    """
    waiting: dict[int, psutil.Process] = {}
    failed = False
    for instance in instances:
        signaled, refused = signal_instance_to_stop(instance, entrypoint)
        waiting.update((process.pid, process) for process in signaled)
        failed = failed or refused
    if not waiting:
        return int(failed)
    alive = wait_for_processes_to_stop(list(waiting.values()), timeout)
    if alive:
        pids = ", ".join(str(process.pid) for process in alive)
        print(
            f"Still stopping after {timeout:g}s: {pids}. Check the run's errors.log; no processes were force-killed."
        )
        return 1
    print("Selected Slips instances and their workers have stopped.")
    return int(failed)


def restart_instance(instance: RunningInstance, entrypoint: Path) -> int:
    """Stop a verified daemon completely, then repeat its launch command.

    Parameters:
        instance: Selected daemon identity and original capture arguments.
        entrypoint: Entry point required before stopping the daemon.

    Returns:
        Launcher exit status, or one if inspection, shutdown or launch fails.
    """
    if not is_daemon(instance.arguments):
        print(f"PID {instance.pid} is not a Slips daemon; not restarted.")
        return 1
    try:
        process = psutil.Process(instance.pid)
        if get_verified_instance(process, entrypoint) != instance:
            print(
                f"PID {instance.pid} changed or cannot be verified; not restarted."
            )
            return 1
        command = process.cmdline()
        position = get_slips_script_index(command)
        directory = process.cwd()
        # macOS can expose Python's base binary instead of its virtualenv.
        command = [sys.executable, *command[1 if position else 0 :]]
    except (psutil.Error, OSError) as error:
        print(
            f"Cannot read the launch command for PID {instance.pid}: {error}"
        )
        return 1
    if (
        stop_instances(
            [instance], entrypoint, timeout=RESTART_STOP_TIMEOUT_SECONDS
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


def is_positive_pid(value: str) -> bool:
    """Tell whether a command-line value can be a PID.

    Parameters:
        value: Value given to a management option.

    Returns:
        True for a decimal number above zero.
    """
    return value.isdecimal() and int(value) > 0


def parse_instance_command(arguments: list[str]) -> argparse.Namespace:
    """Parse a management command, exiting on a malformed PID.

    Parameters:
        arguments: Command-line arguments without the executable name.

    Returns:
        Parsed management options.
    """
    parser = create_instance_parser()
    options = parser.parse_args(arguments)
    if options.stop not in {None, "auto", "all"} and not is_positive_pid(
        options.stop
    ):
        parser.error(f"{FLAG.stop} expects a positive PID or all")
    if options.restart not in {None, "auto"} and not is_positive_pid(
        options.restart
    ):
        parser.error(f"{FLAG.restart} expects a positive daemon PID")
    return options


def restart_selected_daemon(
    instances: list[RunningInstance], target: str, entrypoint: Path
) -> int:
    """Restart the one daemon a restart command points at.

    Parameters:
        instances: Verified instances from this checkout.
        target: Daemon PID, or "auto" for the only running daemon.
        entrypoint: Entry point required before stopping the daemon.

    Returns:
        Launcher exit status, or one when no single daemon matches.
    """
    daemons = [
        instance
        for instance in instances
        if is_daemon(instance.arguments)
        and (target == "auto" or instance.pid == int(target))
    ]
    if not daemons:
        print(
            "No matching running Slips daemon from this checkout to restart."
        )
        return 1
    if len(daemons) > 1:
        print(f"More than one daemon is running. Use {FLAG.restart} PID.")
        return 1
    return restart_instance(daemons[0], entrypoint)


def stop_selected_instances(
    instances: list[RunningInstance], target: str, entrypoint: Path
) -> int:
    """Stop the instances a stop command points at.

    Parameters:
        instances: Verified instances from this checkout.
        target: Instance PID, "all", or "auto" for the only running one.
        entrypoint: Entry point required again immediately before signaling.

    Returns:
        Zero after complete shutdown; one when the target is unclear,
        missing or did not stop.
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
            f"PID {target} is not an accessible Slips instance from this checkout."
        )
        return 1
    return stop_instances(selected, entrypoint)


def handle_instance_command(arguments: list[str]) -> int | None:
    """Handle management before capture, config, logs or Redis initialization.

    Parameters:
        arguments: Command-line arguments without the executable name.

    Returns:
        Management exit status, or None for a normal Slips invocation.
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
    options = parse_instance_command(arguments)
    entrypoint = Path(__file__).resolve().parents[2] / "slips.py"
    instances = list_instances(entrypoint)
    print_instances(instances)
    if options.list_instances:
        return 0
    if options.restart is not None:
        return restart_selected_daemon(instances, options.restart, entrypoint)
    return stop_selected_instances(instances, options.stop, entrypoint)
