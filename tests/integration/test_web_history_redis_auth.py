"""Verify web history collection against real protected and legacy Redis servers."""

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable
from unittest.mock import Mock, patch

import pytest
import redis

from modules.web_interface.history import connect_history
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "server_password,client_password,succeeds",
    [
        (None, "history-client-test", True),
        ("history-server-test", "history-server-test", True),
        ("history-server-test", "incorrect-history-test", False),
    ],
)
def test_history_collection_negotiates_redis_authentication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    integration_port_factory: Callable[[str], int],
    server_password: str | None,
    client_password: str,
    succeeds: bool,
) -> None:
    """Keep collection working without accepting incorrect server credentials.

    Parameters:
        tmp_path: Isolated Redis data, configuration and web history.
        monkeypatch: Restore credential lookup after each test.
        integration_port_factory: Allocate a port away from running analyses.
        server_password: Required password, or None for a legacy Redis server.
        client_password: Persistent Slips credential offered by the collector.
        succeeds: Whether collection should start and complete repeated batches.
    """
    factory = ModuleFactory()
    module = factory.create_web_interface_obj()
    executable = shutil.which("redis-server")
    if not executable:
        pytest.skip("redis-server is required")
    port = integration_port_factory("history-auth")
    config = tmp_path / "redis.conf"
    config.write_text(
        f'bind 127.0.0.1\nport {port}\nsave ""\nappendonly no\n'
        f"dir {json.dumps(str(tmp_path))}\n"
        + (f"requirepass {server_password}\n" if server_password else "")
    )
    config.chmod(0o600)
    control = redis.Redis(
        host="127.0.0.1",
        port=port,
        password=server_password,
        decode_responses=True,
        socket_connect_timeout=1,
        socket_timeout=1,
    )
    process = subprocess.Popen(
        [executable, str(config)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                control.ping()
                break
            except redis.ConnectionError:
                if process.poll() is not None or time.monotonic() >= deadline:
                    pytest.fail("Isolated history Redis did not start")
                time.sleep(0.02)
        output = tmp_path / "run"
        control.hset(
            "analysis",
            mapping={"input_type": "pcap", "output_dir": str(output)},
        )
        control.zadd("profiles", {"profile_192.0.2.10": time.time()})
        control.hset("profile_192.0.2.10", "host_name", "history-host")
        monkeypatch.setattr(
            "slips_files.core.database.redis_db.redis_auth.ensure_redis_password",
            lambda: client_password,
        )
        module.parent_output_dir = str(output)
        module.redis_port = port
        module.ppid = os.getpid()
        module.conf.web_interface_bind = "localhost"
        module.conf.permanent_dir.return_value = str(tmp_path / "permanent")
        module.args.interface = None
        module.args.access_point = None
        module.server_process = Mock(pid=12345)
        module.history_stop = Mock()
        module.history_stop.is_set.side_effect = [False, False, False, True]
        with (
            patch.object(module, "_replace_stale_server", return_value=True),
            patch.object(module, "_start_server"),
            patch.object(
                module,
                "get_module_specific_output_path",
                side_effect=lambda name: str(output / "web_interface" / name),
            ),
            patch("modules.web_interface.web_interface.utils.start_thread"),
            patch(
                "modules.web_interface.web_interface.utils.drop_root_privs_permanently"
            ),
        ):
            if not succeeds:
                with pytest.raises(redis.AuthenticationError):
                    module.pre_main()
                assert module.history_collector is None
                return
            assert module.pre_main() is False
            module._collect_history()
        assert module.history_stop.wait.call_count == 3
        assert not any(
            "History collector error:" in str(call)
            for call in module.print.call_args_list
        )
        assert module.history_collector.redis.hget(
            "analysis", "output_dir"
        ) == str(output)
        with connect_history(
            module.history_collector.history_path, read_only=True
        ) as history:
            assert (
                history.execute(
                    "SELECT COUNT(*) FROM runtime_metrics_1s"
                ).fetchone()[0]
                > 0
            )
            row = history.execute(
                "SELECT data FROM host_snapshots WHERE ip='192.0.2.10'"
            ).fetchone()
            assert json.loads(row[0])["hostname"] == "history-host"
    finally:
        if module.server_log:
            module.server_log.close()
        if module.history_collector:
            module.history_collector.redis.close()
        control.close()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
