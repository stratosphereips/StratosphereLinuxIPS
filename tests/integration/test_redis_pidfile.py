"""Verify real Redis startup writes and removes the correct PID files."""

import shutil
import time
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace
from typing import Callable
from unittest.mock import Mock

import pytest
import redis

from slips_files.core.database.redis_db.database import RedisDB
from tests.common_test_utils import start_test_redis_server
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("starter", ["slips", "test-helper"])
def test_redis_pidfiles_are_writable_and_isolated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    integration_port_factory: Callable[[str], int],
    starter: str,
) -> None:
    """Start two real servers without a system PID file or elevated privileges.

    Parameters:
        tmp_path: Isolated Redis configuration, log, and data directory.
        monkeypatch: Restore Redis class settings after the test.
        integration_port_factory: Allocate ports separate from running Slips.
        starter: Production config writer or integration-test startup helper.
    """
    factory = ModuleFactory()
    if shutil.which("redis-server") is None:
        pytest.skip("redis-server is required")
    auth = tmp_path / "redis-auth.conf"
    auth.write_text("")
    monkeypatch.setattr(RedisDB, "output_dir", str(tmp_path), raising=False)
    monkeypatch.setattr(RedisDB, "args", SimpleNamespace(save=False), raising=False)
    monkeypatch.setattr(RedisDB, "_options", {}, raising=False)
    monkeypatch.setattr(RedisDB, "_conf_file", "", raising=False)
    monkeypatch.setattr(RedisDB, "redis_port", 0, raising=False)
    monkeypatch.setattr(RedisDB, "printer", Mock(), raising=False)
    monkeypatch.setattr("slips_files.core.database.redis_db.database.ensure_redis_password", lambda: "unused")
    monkeypatch.setattr("slips_files.core.database.redis_db.database.get_redis_auth_conf_path", lambda: str(auth))
    assert factory.logger is not None
    clients = []
    pidfiles = []
    pids = []
    try:
        for index in range(2):
            port = integration_port_factory(f"pidfile-{starter}-{index}")
            client = redis.Redis(host="127.0.0.1", port=port, decode_responses=True,
                                 socket_connect_timeout=1, socket_timeout=1)
            clients.append(client)
            if starter == "slips":
                monkeypatch.setattr(RedisDB, "redis_port", port)
                RedisDB._setup_config_file()
                assert RedisDB._start_redis_server() is True
                assert RedisDB._confirm_redis_is_listening()[0] is True
            else:
                start_test_redis_server(port, tmp_path)
            assert client.ping() is True
            pid = client.info("server")["process_id"]
            pidfile = tmp_path / "redis" / f"redis-server-port-{port}.pid"
            assert int(pidfile.read_text().strip()) == pid
            assert client.config_get("pidfile")["pidfile"] == str(pidfile)
            log = tmp_path / "redis" / f"redis-server-port-{port}.log"
            assert "Failed to write PID file" not in log.read_text()
            client.set("pidfile-test", "running", ex=30)
            assert client.get("pidfile-test") == "running"
            pidfiles.append(pidfile)
            pids.append(pid)
        assert len(set(pids)) == len(set(pidfiles)) == 2
        assert all(path.exists() for path in pidfiles)
    finally:
        for client in clients:
            with suppress(redis.exceptions.RedisError):
                client.shutdown(nosave=True)
            client.close()
    deadline = time.monotonic() + 2
    while any(path.exists() for path in pidfiles) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert all(not path.exists() for path in pidfiles)
