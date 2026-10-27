"""Reopen saved results with a private Redis server and no capture workers."""

import argparse
import contextlib
import errno
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import IO, Any

import redis
import psutil
import yaml

from managers.process_manager.instance_control import (
    argument_value,
    list_instances,
)
from slips_files.common.parsers.arg_parser import parse_web_port


def add_view_arguments(parser: argparse.ArgumentParser) -> None:
    """Register the saved-results option on a CLI parser.

    Parameters:
        parser: Parser receiving the option.
    """
    parser.add_argument(
        "--view",
        metavar="OUTPUT_FOLDER",
        help="Open a saved run's webpage without analyzing traffic again.",
    )


def validate_output(folder: str) -> Path:
    """Validate saved inputs and reject a folder still used by a capture.

    Parameters:
        folder: Output folder to reopen.

    Returns:
        Existing output path relative to the checkout.
    """
    output = Path(os.path.relpath(Path(folder).resolve()))
    for name in ("dump.rdb", "flows.sqlite"):
        path = output / "databases" / name
        if not path.is_file():
            raise ValueError(f"Cannot view this run: missing {path}")
    with sqlite3.connect(
        (output / "databases" / "flows.sqlite").resolve().as_uri()
        + "?mode=ro",
        uri=True,
    ) as connection:
        connection.execute("SELECT name FROM sqlite_master LIMIT 1").fetchone()
    for instance in list_instances(Path("slips.py")):
        if argument_value(instance.arguments, "--view") != "—":
            continue
        other = argument_value(instance.arguments, "-o", "--output")
        if other == "—":
            continue
        try:
            destination = Path(psutil.Process(instance.pid).cwd()) / other
        except psutil.Error:
            continue
        if output.resolve() == destination.resolve():
            raise ValueError(
                f"This folder is still used by Slips PID {instance.pid}. "
                "Use its existing webpage or stop that run first."
            )
    return output


def saved_host_profiles(output: Path, fallback: str) -> str:
    """Find host identities saved with this run before using shared identities.

    Parameters:
        output: Saved output folder.
        fallback: Current configuration's host database.

    Returns:
        Host database path for the viewer.
    """
    local = output / "permanent" / "host_profiles" / "hosts.sqlite"
    if local.is_file():
        return str(local)
    snapshots = sorted((output / "metadata").glob("*.yaml"))
    if snapshots:
        config = yaml.safe_load(snapshots[0].read_text()) or {}
        if not isinstance(config, dict):
            return fallback
        permanent = (config.get("parameters") or {}).get("permanent_dir")
        if permanent:
            path = Path(permanent) / "host_profiles" / "hosts.sqlite"
            if path.is_file():
                return os.path.relpath(path)
    return fallback


def stop_owned_redis(process: subprocess.Popen) -> None:
    """Reap only the Redis child created by this viewer, escalating if needed.

    Parameters:
        process: Owned Redis child with its creation identity retained by Popen.
    """
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def start_snapshot_redis(
    output: Path, runtime: Path, log: IO[str]
) -> tuple[subprocess.Popen, redis.Redis, int]:
    """Load a disposable snapshot copy without touching another Redis server.

    Parameters:
        output: Saved output folder containing the original snapshot.
        runtime: Private temporary directory for this viewer.
        log: Stream receiving Redis diagnostics.

    Returns:
        Owned process, authenticated client and assigned loopback port.
    """
    from slips_files.core.database.redis_db.redis_auth import (
        ensure_redis_password,
        get_redis_auth_conf_path,
    )

    binary = shutil.which("redis-server")
    if not binary:
        raise ValueError(
            "redis-server is required to open saved Slips results"
        )
    password = ensure_redis_password()
    shutil.copyfile(output / "databases" / "dump.rdb", runtime / "dump.rdb")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    process = subprocess.Popen(
        [
            binary,
            "--include",
            os.path.relpath(get_redis_auth_conf_path()),
            "--bind",
            "127.0.0.1",
            "--protected-mode",
            "yes",
            "--port",
            str(port),
            "--dir",
            str(runtime),
            "--dbfilename",
            "dump.rdb",
            "--save",
            "",
            "--appendonly",
            "no",
            "--daemonize",
            "no",
        ],
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    client = redis.Redis(
        host="127.0.0.1",
        port=port,
        password=password,
        decode_responses=True,
        socket_connect_timeout=1,
        socket_timeout=1,
    )
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ValueError(
                    "Cannot load dump.rdb; see web_interface/viewer.log"
                )
            try:
                if client.ping():
                    if client.info("server").get("process_id") != process.pid:
                        raise ValueError(
                            "Redis port was claimed by another process; try --view again"
                        )
                    if not client.hget("analysis", "output_dir"):
                        raise ValueError("dump.rdb has no Slips run identity")
                    # Only the private copy changes when a folder was moved.
                    client.hset("analysis", "output_dir", str(output))
                    client.delete("PIDs")
                    return process, client, port
            except redis.AuthenticationError:
                raise
            except (redis.ConnectionError, redis.BusyLoadingError):
                time.sleep(0.1)
        raise ValueError(
            "Loading dump.rdb timed out; see web_interface/viewer.log"
        )
    except BaseException:
        client.close()
        stop_owned_redis(process)
        raise


def bind_view_server(reader: Any, port: int, explicit: bool) -> Any:
    """Bind a local webpage, trying nearby ports when the default is occupied.

    Parameters:
        reader: Data reader tied to the restored snapshot.
        port: Preferred web port.
        explicit: Whether the user requires exactly this port.

    Returns:
        Bound Slips HTTP server, ready to serve requests.
    """
    from modules.web_interface.server import RequestHandler, SlipsHTTPServer

    for candidate in range(port, min(65536, port + (1 if explicit else 100))):
        try:
            return SlipsHTTPServer(
                ("127.0.0.1", candidate), RequestHandler, reader
            )
        except OSError as error:
            if error.errno != errno.EADDRINUSE:
                raise
    raise ValueError(f"Web port {port} is busy. Use --web-port <unused-port>.")


def run_viewer(
    options: argparse.Namespace, ready_fd: int | None = None
) -> int:
    """Serve saved results until interrupted and always clean up owned Redis.

    Parameters:
        options: Validated viewer CLI options.
        ready_fd: Optional pipe reporting background startup to the terminal.

    Returns:
        Zero on normal shutdown, or one when startup fails.
    """
    from modules.web_interface.server import RunDataReader
    from slips_files.common.log_rotation import RotatingTextLog, rotate_log
    from slips_files.common.parsers.config_parser import ConfigParser

    output = options.view
    conf = ConfigParser()
    web_dir = output / "web_interface"
    web_dir.mkdir(parents=True, exist_ok=True)
    policy = conf.detection_history_policy()
    rotate_log(web_dir / "viewer.log", policy)
    old_handlers = {}

    def interrupt(signum: int, frame: Any) -> None:
        """Interrupt viewer work on SIGTERM or Ctrl-C.

        Parameters:
            signum: Received shutdown signal.
            frame: Interrupted Python stack frame.
        """
        raise KeyboardInterrupt

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            old_handlers[signum] = signal.signal(signum, interrupt)
        with tempfile.TemporaryDirectory(
            prefix="view-", dir=web_dir
        ) as directory:
            with (web_dir / "viewer.log").open("a") as log:
                process, client, redis_port = start_snapshot_redis(
                    output, Path(directory), log
                )
                try:
                    host_profiles = saved_host_profiles(
                        output,
                        str(
                            Path(conf.permanent_dir())
                            / "host_profiles"
                            / "hosts.sqlite"
                        ),
                    )
                    reader = RunDataReader(
                        redis_port,
                        str(output),
                        host_profiles,
                        cache_redis_port=redis_port,
                        saved_view=True,
                    )
                    reader.validate_run_identity()
                    with bind_view_server(
                        reader,
                        options.web_port or conf.web_interface_port,
                        options.web_port is not None,
                    ) as server:
                        url = f"http://127.0.0.1:{server.server_port}/"
                        message = f"Saved results: {output}\nWebpage: {url}\nViewer PID: {os.getpid()}"
                        if ready_fd is not None:
                            os.write(
                                ready_fd,
                                json.dumps(
                                    {"status": 0, "message": message}
                                ).encode()
                                + b"\n",
                            )
                            os.close(ready_fd)
                            ready_fd = None
                        print(message, flush=True)
                        print(
                            "No capture or detection modules are running in this viewer. Ctrl-C or --stop PID closes it.",
                            flush=True,
                        )
                        stream = RotatingTextLog(
                            web_dir / "viewer.log", policy
                        )
                        with contextlib.redirect_stdout(
                            stream
                        ), contextlib.redirect_stderr(stream):
                            server.serve_forever(poll_interval=0.5)
                finally:
                    signal.signal(signal.SIGINT, signal.SIG_IGN)
                    signal.signal(signal.SIGTERM, signal.SIG_IGN)
                    client.close()
                    stop_owned_redis(process)
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, redis.RedisError, sqlite3.Error) as error:
        message = f"Cannot open saved results: {error}"
        if ready_fd is not None:
            with contextlib.suppress(BrokenPipeError):
                os.write(
                    ready_fd,
                    json.dumps({"status": 1, "message": message}).encode()
                    + b"\n",
                )
        print(message, file=sys.stderr, flush=True)
        return 1
    finally:
        if ready_fd is not None:
            os.close(ready_fd)
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
    return 0


def background_viewer(options: argparse.Namespace) -> int:
    """Detach a saved viewer and report readiness instead of assuming success.

    Parameters:
        options: Validated viewer options, including the output folder.

    Returns:
        Startup status reported by the detached child.
    """
    web_dir = options.view / "web_interface"
    web_dir.mkdir(parents=True, exist_ok=True)
    read_fd, write_fd = os.pipe()
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        os.setsid()
        with open(os.devnull, "r") as source, (web_dir / "viewer.log").open(
            "a"
        ) as log:
            os.dup2(source.fileno(), 0)
            os.dup2(log.fileno(), 1)
            os.dup2(log.fileno(), 2)
        try:
            status = run_viewer(options, write_fd)
        except BaseException:
            import traceback

            traceback.print_exc()
            status = 1
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(status)
    os.close(write_fd)
    try:
        pending = b""
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            readable, _, _ = select.select([read_fd], [], [], 1)
            if not readable:
                continue
            chunk = os.read(read_fd, 4096)
            if not chunk:
                break
            pending += chunk
            if b"\n" in pending:
                result = json.loads(pending.split(b"\n", 1)[0])
                print(result["message"], flush=True)
                return int(result["status"])
        print(
            f"Viewer did not finish starting. See {web_dir / 'viewer.log'}",
            file=sys.stderr,
        )
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        return 1
    except KeyboardInterrupt:
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        return 1
    finally:
        os.close(read_fd)


def handle_view_command(arguments: list[str]) -> int | None:
    """Handle --view before normal capture initialization can change output.

    Parameters:
        arguments: Command-line arguments without the executable name.

    Returns:
        Viewer exit status, or None for other Slips commands.
    """
    if not any(
        arg == "--view" or arg.startswith("--view=") for arg in arguments
    ):
        return None
    parser = argparse.ArgumentParser(prog="slips.py", allow_abbrev=False)
    add_view_arguments(parser)
    parser.add_argument("--web-port", type=parse_web_port)
    parser.add_argument("-c", "--config", default="config/slips.yaml")
    parser.add_argument("-D", "--daemon", action="store_true")
    options = parser.parse_args(arguments)
    try:
        options.view = validate_output(options.view)
        return (
            background_viewer(options)
            if options.daemon
            else run_viewer(options)
        )
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"Cannot open saved results: {error}", file=sys.stderr)
        return 1
