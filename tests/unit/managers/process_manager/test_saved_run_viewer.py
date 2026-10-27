"""Check saved-run startup, isolation and ownership-scoped cleanup."""

import argparse
import errno
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
from unittest.mock import Mock, patch

import pytest
import redis

from managers.process_manager import saved_run_viewer as viewer
from managers.process_manager import instance_control as control
from slips_files.common.parsers.arg_parser import ArgumentParser
from tests.module_factory import ModuleFactory


def saved_output(tmp_path: Path) -> Path:
    """Create minimal saved files without using a running analysis.

    Parameters:
        tmp_path: Temporary test directory.

    Returns:
        Folder with an SQLite database and dummy Redis snapshot.
    """
    output = tmp_path / "saved"
    databases = output / "databases"
    databases.mkdir(parents=True)
    (databases / "dump.rdb").write_bytes(b"original-snapshot")
    with sqlite3.connect(databases / "flows.sqlite") as connection:
        connection.execute("CREATE TABLE flows(uid TEXT)")
    return output


@pytest.mark.parametrize("missing", [None, "dump.rdb", "flows.sqlite"])
def test_validate_saved_files(tmp_path: Path, missing: str | None) -> None:
    """Fail before changing output when required saved files are absent."""
    _factory = ModuleFactory()
    output = saved_output(tmp_path)
    if missing:
        (output / "databases" / missing).unlink()
    with patch.object(viewer, "list_instances", return_value=[]):
        if missing:
            with pytest.raises(ValueError, match="missing"):
                viewer.validate_output(str(output))
        else:
            assert viewer.validate_output(str(output)).resolve() == output


@pytest.mark.parametrize("same,other_viewer", [(True, False), (False, False), (True, True)])
def test_reject_active_capture(tmp_path: Path, same: bool, other_viewer: bool) -> None:
    """Permit a separate capture or viewer while protecting the active folder."""
    _factory = ModuleFactory()
    output = saved_output(tmp_path)
    flag = "--view" if other_viewer else "-o"
    args = (flag, str(output if same else tmp_path / "live"))
    instance = control.RunningInstance(12345, 1.0, args)
    with patch.object(viewer, "list_instances", return_value=[instance]), patch.object(viewer.psutil, "Process") as process:
        process.return_value.cwd.return_value = str(Path.cwd())
        if same and not other_viewer:
            with pytest.raises(ValueError, match="still used"):
                viewer.validate_output(str(output))
        else:
            assert viewer.validate_output(str(output)).resolve() == output


@pytest.mark.parametrize("location", ["local", "snapshot", "fallback"])
def test_saved_host_profiles(tmp_path: Path, location: str) -> None:
    """Prefer identities belonging to the saved run over shared identities."""
    _factory = ModuleFactory()
    output = tmp_path / "saved"
    fallback = str(tmp_path / "shared" / "hosts.sqlite")
    expected = fallback
    if location != "fallback":
        permanent = output / "permanent" if location == "local" else tmp_path / "custom"
        hosts = permanent / "host_profiles" / "hosts.sqlite"
        hosts.parent.mkdir(parents=True)
        hosts.touch()
        expected = str(hosts) if location == "local" else os.path.relpath(hosts)
        if location == "snapshot":
            metadata = output / "metadata"
            metadata.mkdir(parents=True)
            (metadata / "slips.yaml").write_text(f"parameters:\n  permanent_dir: {permanent}\n")
    assert viewer.saved_host_profiles(output, fallback) == expected


@pytest.mark.parametrize("state", ["exited", "running", "stuck"])
def test_stop_owned_redis(state: str) -> None:
    """Reap only the owned child and force it down after a bounded grace period."""
    _factory = ModuleFactory()
    process = Mock()
    process.poll.return_value = 0 if state == "exited" else None
    if state == "stuck":
        process.wait.side_effect = [subprocess.TimeoutExpired("redis", 5), 0]
    viewer.stop_owned_redis(process)
    assert process.terminate.call_count == (state != "exited")
    assert process.kill.call_count == (state == "stuck")


@pytest.mark.parametrize("failure", [None, "exited", "missing_identity", "connect_error", "wrong_owner"])
def test_restore_is_private(tmp_path: Path, failure: str | None) -> None:
    """Load a copy with no persistence and clean up every failed restore."""
    _factory = ModuleFactory()
    output = saved_output(tmp_path)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    process = Mock(pid=12345)
    process.poll.return_value = 1 if failure == "exited" else None
    client = Mock()
    client.info.return_value = {"process_id": 54321 if failure == "wrong_owner" else process.pid}
    client.hget.return_value = None if failure == "missing_identity" else "old-location"
    if failure == "connect_error":
        client.ping.side_effect = redis.AuthenticationError("bad credentials")
    with patch("slips_files.core.database.redis_db.redis_auth.ensure_redis_password", return_value="test-secret"), patch("slips_files.core.database.redis_db.redis_auth.get_redis_auth_conf_path", return_value="permanent/test.conf"), patch.object(viewer.shutil, "which", return_value="redis-server"), patch.object(viewer.subprocess, "Popen", return_value=process) as launch, patch.object(viewer.redis, "Redis", return_value=client), patch.object(viewer, "stop_owned_redis") as stop:
        with (tmp_path / "redis.log").open("w") as log:
            if failure:
                with pytest.raises((ValueError, redis.RedisError)):
                    viewer.start_snapshot_redis(output, runtime, log)
                stop.assert_called_once_with(process)
                client.close.assert_called_once()
            else:
                actual_process, actual_client, port = viewer.start_snapshot_redis(output, runtime, log)
                assert actual_process is process and actual_client is client
                assert port != 6379
                client.hset.assert_called_once_with("analysis", "output_dir", str(output))
                client.delete.assert_called_once_with("PIDs")
                stop.assert_not_called()
    command = launch.call_args.args[0]
    assert command[command.index("--dir") + 1] == str(runtime)
    assert command[command.index("--save") + 1] == ""
    assert command[command.index("--appendonly") + 1] == "no"
    assert "test-secret" not in command
    assert (runtime / "dump.rdb").read_bytes() == b"original-snapshot"
    assert (output / "databases" / "dump.rdb").read_bytes() == b"original-snapshot"
    if failure == "connect_error":
        client.ping.assert_called_once()
    if failure == "wrong_owner":
        client.hset.assert_not_called()
        client.delete.assert_not_called()


@pytest.mark.parametrize("explicit", [False, True])
def test_web_port_conflict(explicit: bool) -> None:
    """Try a nearby port by default but honor an explicit port without replacing its owner."""
    _factory = ModuleFactory()
    reader = Mock()
    with patch("modules.web_interface.server.SlipsHTTPServer") as server:
        server.side_effect = [OSError(errno.EADDRINUSE, "busy"), Mock()]
        if explicit:
            with pytest.raises(ValueError, match="--web-port"):
                viewer.bind_view_server(reader, 55000, explicit)
            assert server.call_count == 1
        else:
            viewer.bind_view_server(reader, 55000, explicit)
            assert server.call_args_list[-1].args[0] == ("127.0.0.1", 55001)


@pytest.mark.parametrize("arguments", [
    ["--view", "saved", "-f", "capture.pcap"],
    ["--view", "saved", "--keep-history"],
    ["--view", "saved", "--web-port", "0"],
    ["--view", "saved", "--web-port", "65536"],
    ["--view"],
])
def test_reject_capture_options(arguments: list[str]) -> None:
    """Reject mixed capture commands before opening any saved files."""
    _factory = ModuleFactory()
    with patch.object(viewer, "validate_output") as validate:
        with pytest.raises(SystemExit) as error:
            viewer.handle_view_command(arguments)
    assert error.value.code == 2
    validate.assert_not_called()


@pytest.mark.parametrize("background", [False, True])
def test_view_cli_selection(tmp_path: Path, background: bool) -> None:
    """Route --view before capture setup and expose it in normal help."""
    _factory = ModuleFactory()
    arguments = ["--view", str(tmp_path), "--web-port", "55002"]
    if background:
        arguments.append("-D")
    with patch.object(viewer, "validate_output", return_value=tmp_path), patch.object(viewer, "run_viewer", return_value=0) as foreground, patch.object(viewer, "background_viewer", return_value=0) as daemon:
        assert viewer.handle_view_command(arguments) == 0
    selected = daemon if background else foreground
    selected.assert_called_once()
    assert selected.call_args.args[0].web_port == 55002
    with patch.object(sys, "argv", ["slips.py", "--view", str(tmp_path)]):
        assert ArgumentParser(add_help=False).parse_arguments().view == str(tmp_path)
    assert viewer.handle_view_command(["-i", "eth0"]) is None


@pytest.mark.parametrize("failure", [False, True])
def test_viewer_cleanup(tmp_path: Path, failure: bool) -> None:
    """Close the private server on Ctrl-C and on HTTP startup failure."""
    _factory = ModuleFactory()
    process, client = Mock(), Mock()
    reader = Mock()
    conf = Mock()
    conf.permanent_dir.return_value = "permanent"
    conf.detection_history_policy.return_value = {"enabled": False}
    server = Mock()
    server.server_port = 55001
    server.serve_forever.side_effect = KeyboardInterrupt
    context = Mock()
    context.__enter__ = Mock(return_value=server)
    context.__exit__ = Mock(return_value=False)
    with patch("slips_files.common.parsers.config_parser.ConfigParser", return_value=conf), patch("modules.web_interface.server.RunDataReader", return_value=reader) as create_reader, patch.object(viewer, "start_snapshot_redis", return_value=(process, client, 12345)), patch.object(viewer, "stop_owned_redis") as stop, patch.object(viewer, "bind_view_server", side_effect=ValueError("busy") if failure else None, return_value=context):
        status = viewer.run_viewer(argparse.Namespace(view=tmp_path, web_port=55001))
    assert status == int(failure)
    assert create_reader.call_args.kwargs == {"cache_redis_port": 12345, "saved_view": True}
    stop.assert_called_once_with(process)
    client.close.assert_called_once()
    assert not list((tmp_path / "web_interface").glob("view-*"))


@pytest.mark.parametrize("result", [0, 1, None])
def test_background_readiness(tmp_path: Path, result: int | None) -> None:
    """Report real child readiness and reap failed background startup."""
    _factory = ModuleFactory()
    payload = b"" if result is None else json.dumps({"status": result, "message": "viewer startup"}).encode() + b"\n"
    with patch.object(viewer.os, "fork", return_value=12345), patch.object(viewer.os, "pipe", return_value=(21, 22)), patch.object(viewer.os, "close"), patch.object(viewer.select, "select", return_value=([21], [], [])), patch.object(viewer.os, "read", return_value=payload), patch.object(viewer.os, "kill") as kill, patch.object(viewer.os, "waitpid"):
        assert viewer.background_viewer(argparse.Namespace(view=tmp_path)) == (1 if result is None else result)
    if result is None:
        kill.assert_called_once_with(12345, signal.SIGTERM)
    else:
        kill.assert_not_called()


@pytest.mark.parametrize("input_type", ["pcap", "interface", "stdin"])
def test_saved_live_clock(input_type: str) -> None:
    """Keep old live-run filters anchored to saved traffic instead of today.

    Parameters:
        input_type: Original saved analysis input type.
    """
    _factory = ModuleFactory()
    from modules.web_interface.server import RunDataReader

    reader = object.__new__(RunDataReader)
    reader.redis = Mock()
    reader.redis.hget.return_value = input_type
    reader.saved_view = True
    with patch("modules.web_interface.server.time.time", return_value=20000):
        assert reader._time_bounds({"range": ["live"]}, latest_event=7000) == (3400, 7000, "live")
    assert reader._current_network_start() is None
    assert reader._current_header_network() == {}
    assert reader._scoped_start({"network": ["current"]}, 3400) == 3400


@pytest.mark.parametrize("saved", [False, True])
def test_cache_connection_isolation(tmp_path: Path, saved: bool) -> None:
    """Use private DB 1 for saved viewers and preserve normal live cache defaults.

    Parameters:
        tmp_path: Isolated reader output.
        saved: Whether the cache should be private to the viewer.
    """
    _factory = ModuleFactory()
    from modules.web_interface.server import RunDataReader

    with patch("modules.web_interface.server.try_connect_with_and_without_password") as connect, patch.object(RunDataReader, "_detector_score_settings", return_value=("RATL", 5)), patch("modules.web_interface.server.initialize_history"):
        if saved:
            RunDataReader(12345, str(tmp_path), cache_redis_port=12345, saved_view=True)
        else:
            RunDataReader(12345, str(tmp_path))
    assert connect.call_args_list[0].kwargs["port"] == 12345
    assert connect.call_args_list[0].kwargs["db"] == 0
    assert connect.call_args_list[1].kwargs["port"] == (12345 if saved else 6379)
    assert connect.call_args_list[1].kwargs["db"] == 1
