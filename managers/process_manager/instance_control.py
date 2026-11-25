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

import psutil

RESTART_STOP_TIMEOUT_SECONDS = 300
WEB_SERVER_MODULE = "modules.web_interface.server"


@dataclass(frozen=True)
class RunningInstance:
    """Identify a main process by PID, creation time and capture arguments."""

    pid: int
    created: float
    arguments: tuple[str, ...]


def add_instance_arguments(parser: argparse.ArgumentParser) -> None:
    """Register instance commands in the full and lightweight CLI parsers.

    Parameters:
        parser: Parser receiving the management options.
    """
    commands = parser.add_mutually_exclusive_group()
    commands.add_argument(
        "--list-instances",
        action="store_true",
        help="List running Slips instances from this checkout without "
        "starting a capture or connecting to Redis.",
    )
    commands.add_argument(
        "--stop",
        nargs="?",
        const="auto",
        metavar="PID|all",
        help="Gracefully stop a Slips instance in any mode from this checkout. "
        "Omit PID when only one is running, or use all to stop every instance.",
    )
    commands.add_argument(
        "--restart",
        nargs="?",
        const="auto",
        metavar="PID",
        help="Stop a running daemon and relaunch it with its original "
        "arguments. Omit PID when only one daemon is running. Use the same "
        "Python environment that started it.",
    )


def script_position(command: list[str]) -> int | None:
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


def capture_arguments(
    command: list[str], include_views: bool = False
) -> tuple[str, ...] | None:
    """Separate capture launches from management and unrelated commands.

    Parameters:
        command: Process argument vector.
        include_views: Include saved viewers for process discovery and stopping.

    Returns:
        Arguments following slips.py, or None when no capture is being run.
    """
    position = script_position(command)
    if position is None:
        return None
    arguments = tuple(command[position + 1 :])
    if not include_views and any(
        arg == "--view" or arg.startswith("--view=") for arg in arguments
    ):
        return None
    if any(
        arg
        in {
            "--list-instances",
            "--stop",
            "--restart",
            "-S",
            "--stopdaemon",
            "-k",
            "--killall",
            "-h",
            "--help",
            "-V",
            "--version",
        }
        or arg.startswith(("--stop=", "--restart="))
        for arg in arguments
    ):
        return None
    return arguments


def inspect_instance(
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
        position = script_position(command)
        arguments = capture_arguments(command, include_views=True)
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
                parent_position = script_position(parent_command)
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
            if (instance := inspect_instance(process, entrypoint)) is not None
        ),
        key=lambda instance: instance.pid,
    )


def argument_value(arguments: tuple[str, ...], *names: str) -> str:
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
    return "—"


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
    if argument_value(instance.arguments, "--view") != "—":
        return [main], None
    candidates = main.children(recursive=True)
    output_arg = argument_value(instance.arguments, "-o", "--output")
    if output_arg == "—":
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
    destination = argument_value(tuple(command), "--output-dir")
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


def web_ports_for_instance(instance: RunningInstance) -> list[int]:
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
        print("No accessible running Slips instances from this checkout.")
        return
    print("Slips instances from this checkout:")
    print(f"{'PID':<9} {'MODE':<9} {'WEB PORT':<12} {'INPUT':<24} OUTPUT")
    for instance in instances:
        args = instance.arguments
        mode = "daemon" if {"-D", "--daemon"}.intersection(args) else "normal"
        source = argument_value(args, "-i", "--interface")
        if source == "—":
            source = argument_value(
                args, "-f", "--filepath", "-g", "--growing"
            )
        output = argument_value(args, "-o", "--output")
        saved_output = argument_value(args, "--view")
        if saved_output != "—":
            mode = "view-bg" if mode == "daemon" else "viewer"
            source = "saved results"
            output = saved_output
        ports = ",".join(map(str, web_ports_for_instance(instance))) or "—"
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
        if inspect_instance(process, entrypoint) != instance:
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
                "Waiting for workers and final state saving to finish.",
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
    if not {"-D", "--daemon"}.intersection(instance.arguments):
        print(f"PID {instance.pid} is not a Slips daemon; not restarted.")
        return 1
    try:
        process = psutil.Process(instance.pid)
        if inspect_instance(process, entrypoint) != instance:
            print(
                f"PID {instance.pid} changed or cannot be verified; not restarted."
            )
            return 1
        command = process.cmdline()
        position = script_position(command)
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
    parser = argparse.ArgumentParser(prog="slips.py", allow_abbrev=False)
    add_instance_arguments(parser)
    options = parser.parse_args(arguments)
    if options.stop not in {None, "auto", "all"} and not is_positive_pid(
        options.stop
    ):
        parser.error("--stop expects a positive PID or all")
    if options.restart not in {None, "auto"} and not is_positive_pid(
        options.restart
    ):
        parser.error("--restart expects a positive daemon PID")
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
        if {"-D", "--daemon"}.intersection(instance.arguments)
        and (target == "auto" or instance.pid == int(target))
    ]
    if not daemons:
        print(
            "No matching running Slips daemon from this checkout to restart."
        )
        return 1
    if len(daemons) > 1:
        print("More than one daemon is running. Use --restart PID.")
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
            "More than one instance is running. Use --stop PID or --stop all."
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
    if any(arg in {"-S", "--stopdaemon"} for arg in arguments):
        argparse.ArgumentParser(prog="slips.py").error(
            "-S/--stopdaemon was removed; use --stop [PID|all] instead"
        )
    if not any(
        arg in {"--list-instances", "--stop", "--restart"}
        or arg.startswith(("--stop=", "--restart="))
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
