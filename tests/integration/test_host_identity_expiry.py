"""Expire real Redis profiles and verify durable identity outside the web UI."""

import json
from pathlib import Path
import shutil
import socket
import subprocess
import time
from types import SimpleNamespace
from typing import Iterator
from unittest.mock import Mock

import pytest
import redis

from modules.web_interface.history import HistoryCollector, connect_history
from modules.web_interface.server import RunDataReader
from slips_files.core.database.database_manager import DBManager
from slips_files.core.database.redis_db.constants import Constants
from slips_files.core.database.redis_db.database import RedisDB
from slips_files.core.database.sqlite_db.host_profiles import HostProfileStore
from slips_files.core.structures.evidence import ProfileID
from tests.module_factory import ModuleFactory


@pytest.fixture
def identity_redis(tmp_path: Path) -> Iterator[redis.Redis]:
    """Own a temporary Redis without accessing a running Slips instance.

    Parameters:
        tmp_path: Redis logs and ephemeral data directory.

    Yields:
        Independent Redis client on a dynamically allocated loopback port.
    """
    executable = shutil.which("redis-server")
    if not executable:
        pytest.skip("redis-server is required for actual expiry coverage")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    process = subprocess.Popen(
        [
            executable,
            "--bind",
            "127.0.0.1",
            "--port",
            str(port),
            "--save",
            "",
            "--appendonly",
            "no",
            "--dir",
            str(tmp_path),
            "--logfile",
            str(tmp_path / "identity-redis.log"),
        ]
    )
    client = redis.Redis(
        host="127.0.0.1", port=port, decode_responses=True, socket_timeout=1
    )
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                client.ping()
                break
            except redis.ConnectionError:
                if process.poll() is not None or time.monotonic() >= deadline:
                    pytest.fail("Temporary identity Redis did not start")
                time.sleep(0.02)
        yield client
    finally:
        client.close()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_real_cache_expiry_keeps_core_alert_names_and_saved_snapshots(
    tmp_path: Path, identity_redis: redis.Redis
) -> None:
    """Keep core formatting, snapshots and UI labels after real key expiry.

    Parameters:
        tmp_path: Independent run and permanent identity store.
        identity_redis: Disposable real Redis, separate from production.
    """
    factory = ModuleFactory()
    state = {
        "interface": "en0",
        "connected": True,
        "local_network": "192.168.1.0/24",
        "gateway_mac": "aa:bb:cc:dd:ee:01",
    }
    path = tmp_path / "permanent" / "host_profiles" / "hosts.sqlite"
    store = HostProfileStore(path, "first-run", lambda _: state, ["en0"])
    store.observe_flow(
        SimpleNamespace(
            type_="dhcp",
            interface="en0",
            starttime=100,
            saddr="192.168.1.128",
            daddr="192.168.1.1",
            smac="00:08:9b:d1:04:d2",
            host_name="elhuevito.local",
        )
    )
    rdb = object.__new__(RedisDB)
    rdb.r = identity_redis
    rdb.constants = Constants()
    rdb.extended_ttl = 1
    rdb.set_profileid_field(
        "profile_192.168.1.128", "host_name", "elhuevito.local"
    )
    ttl = identity_redis.pttl("profile_192.168.1.128")
    rdb.set_profileid_field("profile_192.168.1.128", "threat_level", "high")
    assert 0 < identity_redis.pttl("profile_192.168.1.128") <= ttl
    identity_redis.hset("network_states", "en0", json.dumps(state))
    identity_redis.zadd("profiles", {"profile_192.168.1.128": 100})
    identity_redis.hset(
        "analysis", mapping={"input_type": "interface", "interface": "en0"}
    )
    db = object.__new__(DBManager)
    db.rdb = rdb
    db.conf = Mock()
    db.conf.permanent_dir.return_value = str(tmp_path / "permanent")
    db.all_interfaces = ["en0"]
    db.output_dir = str(tmp_path / "run")
    db.main_pid = 123
    assert (
        db.get_hostname_from_profile("profile_192.168.1.128")
        == "elhuevito.local"
    )
    deadline = time.monotonic() + 3
    while identity_redis.exists("profile_192.168.1.128"):
        assert time.monotonic() < deadline
        time.sleep(0.02)
    assert rdb.get_hostname_from_profile("profile_192.168.1.128") is None
    assert (
        db.get_hostname_from_profile("profile_192.168.1.128")
        == "elhuevito.local"
    )
    formatter = factory.create_evidence_formatter_obj()
    formatter.db = db
    assert "elhuevito.local" in formatter.get_printable_profile_info(
        SimpleNamespace(profile=ProfileID(ip="192.168.1.128"))
    )
    assert not identity_redis.exists("profile_192.168.1.128")
    # Ordinary traffic recreates the profile without repeating its old DHCP name.
    rdb.set_profileid_field("profile_192.168.1.128", "threat_level", "high")
    history = tmp_path / "run" / "web_interface" / "history.sqlite"
    collector = HistoryCollector(
        db.output_dir,
        history,
        identity_redis,
        db.main_pid,
        host_profiles_path=path,
    )
    assert collector.snapshot_hosts() == 1
    assert collector.snapshot_hosts() == 1
    with connect_history(history, read_only=True) as connection:
        saved = json.loads(
            connection.execute(
                "SELECT data FROM host_snapshots WHERE ip='192.168.1.128'"
            ).fetchone()[0]
        )
    assert saved["hostname"] == "elhuevito.local"
    assert saved["mac"] == "00:08:9b:d1:04:d2"
    reader = RunDataReader.__new__(RunDataReader)
    reader.redis = identity_redis
    reader.cache = identity_redis
    reader.output_dir = Path(db.output_dir)
    reader.host_profiles_path = path
    reader.history_path = history
    assert (
        reader.host_names({"ip": ["192.168.1.128"]})["names"]["192.168.1.128"][
            "name"
        ]
        == "elhuevito.local"
    )
