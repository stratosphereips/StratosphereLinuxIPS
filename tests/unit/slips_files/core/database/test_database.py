# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import (
    Mock,
    call,
    patch,
)
from pathlib import Path
from typing import Any

import redis
import json
import os
import pytest

from slips_files.core.flows.zeek import Conn
from slips_files.core.database.database_manager import DBManager
from slips_files.core.database.redis_db.database import RedisDB
from tests.module_factory import ModuleFactory


@pytest.fixture(autouse=True)
def ensure_redis_options(monkeypatch: Any) -> None:
    """
    Ensure Redis options exist when ModuleFactory skips config generation.

    Parameters:
        monkeypatch: Pytest fixture used to patch RedisDB class state.

    Return value:
        None.
    """
    monkeypatch.setattr(RedisDB, "_options", {}, raising=False)


# random values for testing
profileid = "profile_192.168.1.1"
twid = "timewindow1"
test_ip = "192.168.1.1"
flow = Conn(
    starttime="1601998398.945854",
    uid="1234",
    saddr=test_ip,
    daddr="8.8.8.8",
    dur=5,
    proto="TCP",
    appproto="dhcp",
    sport=80,
    dport=88,
    spkts=20,
    dpkts=20,
    sbytes=20,
    dbytes=20,
    state="",
    history="",
    smac="Established",
    dmac="",
    interface="eth0",
)


def test_set_info_for_domains():
    """tests set_info_for_domains, setNewDomain and get_domain_data"""
    db = ModuleFactory().create_db_manager_obj(6379, flush_db=True)
    domain = "www.google.com"
    domain_data = {"threatintelligence": "sample data"}
    db.set_info_for_domains(domain, domain_data)

    stored_data = db.get_domain_data(domain)
    assert "threatintelligence" in stored_data
    assert stored_data["threatintelligence"] == "sample data"


def test_subscribe():
    db = ModuleFactory().create_db_manager_obj(6379, flush_db=True)
    # invalid channel
    assert db.subscribe("invalid_channel") is False
    # valid channel, shoud return a pubsub object
    assert isinstance(db.subscribe("new_flow"), redis.client.PubSub)


def test_profile_moddule_labels():
    """tests set and get_profile_module_label"""
    db = ModuleFactory().create_db_manager_obj(6379, flush_db=True)
    module_label = "malicious"
    module_name = "test"
    db.set_module_label_for_profile(profileid, module_name, module_label)
    labels = db.get_modules_labels_of_a_profile(profileid)
    assert "test" in labels
    assert labels["test"] == "malicious"


def test_add_mac_addr_with_new_ipv4():
    """
    adding an ipv4 to no cached ip
    """
    db = ModuleFactory().create_db_manager_obj(6379, flush_db=True)
    ipv4 = "192.168.1.5"
    profileid_ipv4 = f"profile_{ipv4}"
    mac_addr = "00:00:5e:00:53:af"

    db.rdb.is_gw_mac = Mock(return_value=False)
    db.rdb._should_associate_this_mac_with_this_ip = Mock(return_value=True)
    db.r.hget = Mock()
    db.r.hset = Mock()
    db.r.hmget = Mock(return_value=[None])

    # simulate adding a new MAC and IPv4 address
    assert db.add_mac_addr_to_profile(profileid_ipv4, mac_addr, "eth0") is True

    # Ensure the IP is associated in the 'MAC' hash
    db.r.hmget.assert_called_with("MAC", mac_addr)
    db.r.hset.assert_any_call("MAC", mac_addr, json.dumps([ipv4]))


def test_add_mac_addr_with_existing_ipv4():
    """
    adding an ipv4 to a cached ipv4
    """
    db = ModuleFactory().create_db_manager_obj(6379, flush_db=True)
    ipv4 = "192.168.1.5"
    mac_addr = "00:00:5e:00:53:af"
    db.rdb.is_gw_mac = Mock(return_value=False)
    db.rdb._should_associate_this_mac_with_this_ip = Mock(return_value=True)
    db.r.hget = Mock()
    db.r.hset = Mock()
    db.r.hmget = Mock(return_value=[json.dumps([ipv4])])

    new_profile = "profile_192.168.1.6"

    # try to add a new profile with the same MAC but another IPv4 address
    assert db.add_mac_addr_to_profile(new_profile, mac_addr, "eth0") is False


def test_add_mac_addr_with_ipv6_association():
    """
    adding an ipv6 to a cached ipv4
    """
    db = ModuleFactory().create_db_manager_obj(6379, flush_db=True)
    ipv4 = "192.168.1.5"
    profile_ipv4 = "profile_192.168.1.5"
    mac_addr = "00:00:5e:00:53:af"

    # mock existing entry with ipv6
    db.rdb.is_gw_mac = Mock(return_value=False)
    db.rdb._should_associate_this_mac_with_this_ip = Mock(return_value=True)
    db.rdb.update_mac_of_profile = Mock()
    db.r.hmget = Mock(return_value=[json.dumps([ipv4])])
    db.r.hset = Mock()
    db.r.hget = Mock()

    ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    profile_ipv6 = f"profile_{ipv6}"
    # try to associate an ipv6 with the same MAC address
    assert db.add_mac_addr_to_profile(profile_ipv6, mac_addr, "eth0")

    expected_calls = [
        call(profile_ipv4, mac_addr),  # call with the ipv4 profileid
        call(profile_ipv6, mac_addr),  # call with the ipv6 profileid
    ]
    db.rdb.update_mac_of_profile.assert_has_calls(
        expected_calls, any_order=True
    )


def test_get_the_other_ip_version():
    db = ModuleFactory().create_db_manager_obj(6379, flush_db=True)
    profileid_ipv4 = "profile_192.168.250.250"
    ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

    db.rdb.get_the_other_ip_version = Mock(return_value=ipv6)

    other_ip = db.get_the_other_ip_version(profileid_ipv4)

    db.rdb.get_the_other_ip_version.assert_called_once_with(profileid_ipv4)
    assert other_ip == ipv6


def test_is_tor_node():
    """Test the DB manager Tor node lookup wrapper."""
    db = ModuleFactory().create_db_manager_obj(6379, flush_db=True)
    original_is_tor_node = db.rdb.is_tor_node
    db.rdb.is_tor_node = Mock(return_value=True)

    try:
        assert db.is_tor_node("185.220.101.1") is True
        db.rdb.is_tor_node.assert_called_once_with("185.220.101.1")
    finally:
        db.rdb.is_tor_node = original_is_tor_node


def test_redis_db_is_tor_node():
    """Test the Redis Tor nodes set membership lookup."""
    db = ModuleFactory().create_db_manager_obj(6379, flush_db=True)
    db.rdb.rcache.sismember = Mock(return_value=1)

    assert db.rdb.is_tor_node("185.220.101.1") is True
    db.rdb.rcache.sismember.assert_called_once_with(
        db.rdb.constants.TOR_NODES, "185.220.101.1"
    )


def test_store_official_dns_server():
    """Test storing detected DNS servers in Redis."""
    db = ModuleFactory().create_db_manager_obj(6379, flush_db=True)

    db.store_official_dns_server("192.168.1.53")
    db.store_official_dns_server("fd00::53")

    assert db.is_official_dns_server("192.168.1.53") is True
    assert db.is_official_dns_server("fd00::53") is True
    assert db.is_official_dns_server("not-an-ip") is False


def test_setup_config_file_uses_isolated_path_and_preserves_save(
    tmp_path, monkeypatch
):
    template = tmp_path / "redis.conf.template"
    template.write_text(
        'daemonize yes\nsave ""\nappendonly no\n', encoding="utf-8"
    )

    monkeypatch.setattr(RedisDB, "_conf_file_template", str(template))
    monkeypatch.setattr(RedisDB, "output_dir", tmp_path, raising=False)
    monkeypatch.setattr(RedisDB, "redis_port", 6379, raising=False)
    monkeypatch.setattr(RedisDB, "args", Mock(save=False), raising=False)

    RedisDB._setup_config_file()

    expected_conf = (
        tmp_path / "redis" / f"redis-server-port-{RedisDB.redis_port}.conf"
    )
    assert RedisDB._conf_file == str(expected_conf)

    conf_contents = expected_conf.read_text(encoding="utf-8").splitlines()
    assert 'save ""' in conf_contents
    assert f"dir {tmp_path / 'databases'}" in conf_contents
    assert "dbfilename dump.rdb" in conf_contents
    assert (
        f"logfile {tmp_path / 'redis' / f'redis-server-port-{RedisDB.redis_port}.log'}"
        in conf_contents
    )


def test_setup_config_file_enables_autosave_when_save_enabled(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Test Redis autosave options are set when save is enabled."""
    template = tmp_path / "redis.conf.template"
    template.write_text(
        'daemonize yes\nsave ""\nappendonly no\n', encoding="utf-8"
    )

    monkeypatch.setattr(RedisDB, "_conf_file_template", str(template))
    monkeypatch.setattr(RedisDB, "output_dir", tmp_path, raising=False)
    monkeypatch.setattr(RedisDB, "redis_port", 6379, raising=False)
    monkeypatch.setattr(RedisDB, "args", Mock(save=True), raising=False)

    RedisDB._setup_config_file()

    expected_conf = (
        tmp_path / "redis" / f"redis-server-port-{RedisDB.redis_port}.conf"
    )
    conf_contents = expected_conf.read_text(encoding="utf-8").splitlines()

    assert "save 30 500" in conf_contents
    assert "appendonly yes" in conf_contents
    assert f"dir {tmp_path / 'databases'}" in conf_contents
    assert "dbfilename dump.rdb" in conf_contents


def test_setup_config_file_uses_absolute_redis_paths(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Test generated Redis configs use absolute paths for dir and logfile."""
    template = tmp_path / "redis.conf.template"
    template.write_text(
        'daemonize yes\nsave ""\nappendonly no\n', encoding="utf-8"
    )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(RedisDB, "_conf_file_template", str(template))
    monkeypatch.setattr(
        RedisDB, "output_dir", "relative-output", raising=False
    )
    monkeypatch.setattr(RedisDB, "redis_port", 6379, raising=False)
    monkeypatch.setattr(RedisDB, "args", Mock(save=False), raising=False)

    RedisDB._setup_config_file()

    expected_logfile = (
        tmp_path / "relative-output" / "redis" / "redis-server-port-6379.log"
    )
    expected_dir = tmp_path / "relative-output" / "databases"
    conf_contents = (
        Path(RedisDB._conf_file).read_text(encoding="utf-8").splitlines()
    )

    assert f"logfile {expected_logfile}" in conf_contents
    assert f"dir {expected_dir}" in conf_contents
    assert expected_logfile.parent.exists()


def test_save_points_redis_at_backup_path(tmp_path: Path) -> None:
    """Test save writes the Redis RDB to the backup path."""
    db = object.__new__(RedisDB)
    backup_file = tmp_path / "databases" / "dump"
    redis_dump = backup_file.parent / "dump.rdb"
    backup_file.parent.mkdir()
    redis_dump.write_text("redis dump", encoding="utf-8")
    db.r = Mock()
    db.r.config_get.side_effect = [
        {"dir": str(backup_file.parent)},
        {"dbfilename": "dump.rdb"},
    ]
    db._save_rdb_with_redis_cli = Mock(return_value=True)
    db.print = Mock()

    assert db.save(str(backup_file)) is True

    db._save_rdb_with_redis_cli.assert_called_once_with(
        str(backup_file.parent / "dump.rdb")
    )
    db.r.save.assert_not_called()
    assert redis_dump.read_text(encoding="utf-8") == "redis dump"
    db.print.assert_not_called()


def test_save_copies_dump_from_configured_redis_dir(tmp_path: Path) -> None:
    """Test save copies the RDB if Redis reports a different dump path."""
    db = object.__new__(RedisDB)
    redis_dir = tmp_path / "redis-data"
    redis_dir.mkdir()
    redis_dump = redis_dir / "custom.rdb"
    redis_dump.write_text("redis dump", encoding="utf-8")
    backup_file = tmp_path / "databases" / "dump"
    backup_file.parent.mkdir()
    db.r = Mock()
    db.r.config_get.side_effect = [
        {"dir": str(redis_dir)},
        {"dbfilename": "custom.rdb"},
    ]
    db._save_rdb_with_redis_cli = Mock(return_value=False)
    db.print = Mock()

    assert db.save(str(backup_file)) is True

    db._save_rdb_with_redis_cli.assert_called_once_with(
        str(backup_file.parent / "dump.rdb")
    )
    db.r.save.assert_called_once()
    assert (backup_file.parent / "dump.rdb").read_text(
        encoding="utf-8"
    ) == "redis dump"
    assert not redis_dump.exists()
    db.print.assert_not_called()


def test_save_keeps_dump_when_redis_already_saved_to_backup_path(
    tmp_path: Path,
) -> None:
    """Test save does not delete the target RDB when Redis writes there."""
    db = object.__new__(RedisDB)
    backup_file = tmp_path / "databases" / "dump"
    backup_file.parent.mkdir()
    redis_dump = backup_file.parent / "dump.rdb"
    redis_dump.write_text("redis dump", encoding="utf-8")
    db.r = Mock()
    db.r.config_get.side_effect = [
        {"dir": str(backup_file.parent)},
        {"dbfilename": "dump.rdb"},
    ]
    db._save_rdb_with_redis_cli = Mock(return_value=False)
    db.print = Mock()

    assert db.save(str(backup_file)) is True

    db._save_rdb_with_redis_cli.assert_called_once_with(
        str(backup_file.parent / "dump.rdb")
    )
    db.r.save.assert_called_once()
    assert redis_dump.read_text(encoding="utf-8") == "redis dump"
    db.print.assert_not_called()


def test_save_rdb_with_redis_cli_writes_requested_file(tmp_path: Path) -> None:
    """Test redis-cli RDB export reports success when the file is created."""
    db = object.__new__(RedisDB)
    db.redis_port = 6379
    backup_rdb = tmp_path / "dump.rdb"

    def create_rdb_file(*args: Any, **kwargs: Any) -> Mock:
        backup_rdb.write_text("redis dump", encoding="utf-8")
        return Mock(returncode=0)

    with patch("subprocess.run", side_effect=create_rdb_file) as mock_run:
        assert db._save_rdb_with_redis_cli(str(backup_rdb)) is True

    mock_run.assert_called_once()


def test_init_p2p_trust_db_uses_permanent_dir(tmp_path, monkeypatch):
    db = ModuleFactory().create_db_manager_obj(6379)
    monkeypatch.chdir(tmp_path)
    db.init_p2p_trust_db = DBManager.init_p2p_trust_db.__get__(db, DBManager)
    monkeypatch.setattr(
        "slips_files.core.database.database_manager.get_this_filepath_inside_permanent_dir",
        lambda filename: os.path.join("persistent_state", filename),
    )

    db_path = db.init_p2p_trust_db()

    assert db_path == os.path.join(
        "persistent_state", "p2p_trust_runtime", "trustdb.db"
    )
    assert os.path.isdir(os.path.join("persistent_state", "p2p_trust_runtime"))
