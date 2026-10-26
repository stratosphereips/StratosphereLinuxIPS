"""Find and gracefully stop Slips runs without opening their databases."""

import argparse
import os
from pathlib import Path
import re
import signal
from dataclasses import dataclass

import psutil


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
    parser.add_argument(
        "--list-instances",
        action="store_true",
        help="List running Slips instances from this checkout without "
        "starting a capture or connecting to Redis.",
    )
    parser.add_argument(
        "--stop",
        nargs="?",
        const="auto",
        metavar="PID|all",
        help="Gracefully stop a Slips instance in any mode from this checkout. "
        "Omit PID when only one is running, or use all to stop every instance.",
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
        if position is None or process.pid == os.getpid():
            return None
        arguments = command[position + 1 :]
        if any(
            arg
            in {
                "--list-instances",
                "--stop",
                "-S",
                "--stopdaemon",
                "-k",
                "--killall",
                "-h",
                "--help",
                "-V",
                "--version",
            }
            or arg.startswith("--stop=")
            for arg in arguments
        ):
            return None
        script = Path(command[position])
        if not script.is_absolute():
            script = Path(process.cwd()) / script
        if script.resolve() != entrypoint.resolve():
            return None
        if process.status() in {psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD}:
            return None
        return RunningInstance(
            process.pid, process.create_time(), tuple(arguments)
        )
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


def print_instances(instances: list[RunningInstance]) -> None:
    """Show enough launch information to select the intended capture.

    Parameters:
        instances: Verified main processes.
    """
    if not instances:
        print("No accessible running Slips instances from this checkout.")
        return
    print("Slips instances from this checkout:")
    print(f"{'PID':<9} {'MODE':<9} {'INPUT':<24} OUTPUT")
    for instance in instances:
        args = instance.arguments
        mode = "daemon" if {"-D", "--daemon"}.intersection(args) else "normal"
        source = argument_value(args, "-i", "--interface")
        if source == "—":
            source = argument_value(
                args, "-f", "--filepath", "-g", "--growing"
            )
        output = argument_value(args, "-o", "--output")
        print(f"{instance.pid:<9} {mode:<9} {source:<24} {output}")


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
        try:
            process = psutil.Process(instance.pid)
            if (
                not process.is_running()
                or process.status() == psutil.STATUS_ZOMBIE
            ):
                continue
            if inspect_instance(process, entrypoint) != instance:
                print(
                    f"PID {instance.pid} changed or cannot be verified; not stopped."
                )
                failed = True
                continue
            children = process.children(recursive=True)
            process.send_signal(signal.SIGTERM)
            waiting.update((child.pid, child) for child in children)
            waiting[process.pid] = process
            print(
                f"Requested graceful shutdown of Slips PID {instance.pid}.",
                flush=True,
            )
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            print(
                f"Permission denied for PID {instance.pid}; run as its owner."
            )
            failed = True
    if waiting:
        _, alive = psutil.wait_procs(list(waiting.values()), timeout=timeout)
        if alive:
            pids = ", ".join(str(process.pid) for process in alive)
            print(
                f"Still stopping after {timeout:g}s: {pids}. Check the run's errors.log; no processes were force-killed."
            )
            failed = True
        else:
            print("Selected Slips instances and their workers have stopped.")
    return int(failed)


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
        arg in {"--list-instances", "--stop"} or arg.startswith("--stop=")
        for arg in arguments
    ):
        return None
    parser = argparse.ArgumentParser(prog="slips.py", allow_abbrev=False)
    add_instance_arguments(parser)
    options = parser.parse_args(arguments)
    if options.list_instances and options.stop is not None:
        parser.error("choose --list-instances or --stop")
    if options.stop not in {None, "auto", "all"}:
        if not options.stop.isdecimal() or int(options.stop) <= 0:
            parser.error("--stop expects a positive PID or all")
    entrypoint = Path(__file__).resolve().parents[2] / "slips.py"
    instances = list_instances(entrypoint)
    print_instances(instances)
    if options.list_instances:
        return 0
    if not instances:
        return 0 if options.stop in {"auto", "all"} else 1
    if options.stop == "auto" and len(instances) > 1:
        print(
            "More than one instance is running. Use --stop PID or --stop all."
        )
        return 1
    selected = (
        instances
        if options.stop in {"auto", "all"}
        else [
            instance
            for instance in instances
            if instance.pid == int(options.stop)
        ]
    )
    if not selected:
        print(
            f"PID {options.stop} is not an accessible Slips instance from this checkout."
        )
        return 1
    return stop_instances(selected, entrypoint)
