# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
Unit tests for DBManager and the RedisDB wiring behind it.

Isolation model:
- every pytest process (each xdist worker, or the single serial process)
  starts its own redis-server on a free port and kills it at the end.
- RedisDB keeps its connection and its per-port singleton cache on the
  class, so every test gets a fresh instance and the class state is
  restored afterwards.
- the shared cache db (port 6379, db 1) is redirected to the private
  server, so no test touches a redis that other tests or files use.
"""

import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
)
from unittest.mock import (
    MagicMock,
    Mock,
    patch,
)

import pytest
import redis

from slips_files.core.database.database_manager import DBManager
from slips_files.core.database.redis_db.database import RedisDB
from slips_files.core.structures.evidence import (
    Attacker,
    Direction,
    Evidence,
    EvidenceType,
    IoCType,
    ProfileID,
    ThreatLevel,
    TimeWindow,
)
from slips_files.core.structures.flow_attributes import Protocol
from slips_files.core.structures.risk_weights import RiskWeight
from tests.module_factory import ModuleFactory

REDIS_DB_MODULE = "slips_files.core.database.redis_db.database"
REDIS_AUTH_MODULE = "slips_files.core.database.redis_db.redis_auth"
DB_MANAGER_MODULE = "slips_files.core.database.database_manager"
LOCALHOST = "127.0.0.1"
TEST_REDIS_PASSWORD = "unit-test-password"
PROFILEID = "profile_192.168.1.10"
TWID = "timewindow1"
MAC_ADDR = "00:00:5e:00:53:af"
_MISSING = object()


def _free_port() -> int:
    """
    Ask the kernel for a free TCP port on localhost.

    Return value:
        A port number that was free at the time of the call.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((LOCALHOST, 0))
        return sock.getsockname()[1]


def _wait_for_redis(
    port: int, process: subprocess.Popen, timeout: float = 10.0
) -> bool:
    """
    Poll a redis-server until it answers PING or exits.

    Parameters:
        port: Port the server was started on.
        process: The redis-server process.
        timeout: Seconds to wait before giving up.

    Return value:
        True when the server answered, False when it died or timed out.
    """
    client = redis.StrictRedis(
        host=LOCALHOST, port=port, socket_connect_timeout=0.5
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            if client.ping():
                return True
        except redis.RedisError:
            time.sleep(0.05)
    return False


def _restore_class_state(cls: type, before: Dict[str, Any]) -> None:
    """
    Put a class' own attributes back to a previous snapshot.

    Parameters:
        cls: The class to restore.
        before: Snapshot taken with dict(vars(cls)).
    """
    for name in list(vars(cls)):
        if name.startswith("__"):
            continue
        if name not in before:
            delattr(cls, name)
    for name, value in before.items():
        if name.startswith("__"):
            continue
        if vars(cls).get(name, _MISSING) is not value:
            setattr(cls, name, value)


@pytest.fixture(scope="session")
def redis_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[int]:
    """
    Start one private redis-server for this pytest process.

    Parameters:
        tmp_path_factory: Pytest factory used for the server's work dir.

    Return value:
        The port the private server listens on.
    """
    if not shutil.which("redis-server"):
        pytest.fail("redis-server is not installed, the db tests need it")

    workdir = tmp_path_factory.mktemp("redis")
    process: Optional[subprocess.Popen] = None
    log = None
    for _ in range(5):
        port = _free_port()
        log = open(workdir / f"redis-{port}.log", "wb")
        process = subprocess.Popen(
            [
                "redis-server",
                "--port",
                str(port),
                "--bind",
                LOCALHOST,
                "--daemonize",
                "no",
                "--save",
                "",
                "--appendonly",
                "no",
                "--dir",
                str(workdir),
                "--loglevel",
                "warning",
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        if _wait_for_redis(port, process):
            break
        process.kill()
        process.wait()
        log.close()
    else:
        pytest.fail("could not start a private redis-server for the tests")

    try:
        yield port
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        log.close()


@pytest.fixture(autouse=True)
def fresh_redis_db_class() -> Iterator[None]:
    """
    Give every test a clean RedisDB class and undo its class-level writes.

    RedisDB stores r, rcache, redis_port, instances and more on the class,
    so a test that connects to one port silently repoints every other
    cached instance. this runs before and after each test, including the
    ones that never touch redis.
    """
    before = dict(vars(RedisDB))
    RedisDB.instances = {}
    try:
        yield
    finally:
        _restore_class_state(RedisDB, before)


@pytest.fixture
def private_redis(
    redis_server: int, monkeypatch: pytest.MonkeyPatch
) -> Iterator[int]:
    """
    Point both RedisDB connections (r and rcache) at the private server
    and start the test from an empty db.

    Parameters:
        redis_server: Port of this process' private redis-server.
        monkeypatch: Pytest fixture used to stub the password lookup.

    Return value:
        The private server's port.
    """
    original_connect = RedisDB.__dict__["_connect"]
    connect = original_connect.__func__

    def connect_to_private_server(port: int, db: int) -> redis.StrictRedis:
        return connect(redis_server, db)

    RedisDB._connect = staticmethod(connect_to_private_server)
    # the private server has no password. keep the tests away from the
    # user's persistent redis_auth.conf
    monkeypatch.setattr(
        f"{REDIS_AUTH_MODULE}.ensure_redis_password",
        lambda: TEST_REDIS_PASSWORD,
    )
    monkeypatch.setattr(
        f"{REDIS_DB_MODULE}.ensure_redis_password",
        lambda: TEST_REDIS_PASSWORD,
    )
    redis.StrictRedis(host=LOCALHOST, port=redis_server).flushall()
    try:
        yield redis_server
    finally:
        RedisDB._connect = original_connect


def _create_db(port: int, tmp_path: Path, **kwargs: Any) -> DBManager:
    """
    Create a DBManager connected to the private redis-server.

    Parameters:
        port: Private redis-server port.
        tmp_path: Per-test dir used as the slips output dir.
        kwargs: Extra arguments for ModuleFactory.create_db_manager_obj.

    Return value:
        A DBManager with redis started and sqlite disabled.
    """
    return ModuleFactory().create_db_manager_obj(
        port,
        output_dir=str(tmp_path / "output"),
        flush_db=True,
        start_redis_server=False,
        **kwargs,
    )


@pytest.fixture
def db(private_redis: int, tmp_path: Path) -> Iterator[DBManager]:
    """
    DBManager connected to the private redis-server.

    Parameters:
        private_redis: Port of the private redis-server.
        tmp_path: Per-test dir used as the slips output dir.

    Return value:
        A ready DBManager.
    """
    db = _create_db(private_redis, tmp_path)
    yield db
    db.close_sqlite()


def _make_evidence(
    evidence_type: EvidenceType = EvidenceType.CONNECTION_WITHOUT_DNS,
    attacker_ip: str = "192.168.1.10",
    uids: Optional[List[str]] = None,
    **overrides: Any,
) -> Evidence:
    """
    Build a valid Evidence object for the tests.

    Parameters:
        evidence_type: Type of the evidence.
        attacker_ip: IP of the attacker, also used as the profile.
        uids: Flow uids causing the evidence.
        overrides: Any Evidence field to override.

    Return value:
        The Evidence object.
    """
    fields = dict(
        evidence_type=evidence_type,
        description="unit test evidence",
        attacker=Attacker(
            direction=Direction.SRC,
            ioc_type=IoCType.IP,
            value=attacker_ip,
        ),
        threat_level=ThreatLevel.MEDIUM,
        profile=ProfileID(ip=attacker_ip),
        timewindow=TimeWindow(number=1),
        uid=uids or ["flow-1"],
        timestamp="2024/01/01 10:00:00.000000+0000",
        confidence=0.8,
    )
    fields.update(overrides)
    return Evidence(**fields)


def _mark_redis_as_owned_by(db: DBManager, output_dir: str) -> None:
    """
    Make redis advertise the given output dir as the current run's.

    Parameters:
        db: DBManager connected to the private server.
        output_dir: Output dir to store.
    """
    db.set_input_metadata({db.constants.ANALYSIS_OUTPUT_DIR: output_dir})
    db.store_pid("main", db.main_pid)


def _sqlite_mock() -> MagicMock:
    """
    Sqlite stand-in that whitelists nothing.

    Return value:
        A MagicMock with the sqlite methods set_evidence relies on.
    """
    sqlite = MagicMock()
    sqlite.is_evidence_whitelisted.return_value = False
    sqlite.get_whitelisted_evidence_ids_in_tw.return_value = set()
    return sqlite


def _wait_until_subscribed(client: redis.StrictRedis, channel: str) -> None:
    """
    Block until redis reports a subscriber on the channel.

    Parameters:
        client: Connection to the private server.
        channel: Channel name.
    """
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if client.pubsub_numsub(channel)[0][1] >= 1:
            return
        time.sleep(0.01)
    pytest.fail(f"no subscriber showed up on {channel}")


# --------------------------------------------------------------------------
# connection and singleton behaviour
# --------------------------------------------------------------------------


def test_db_manager_connects_to_the_requested_port(
    db: DBManager, private_redis: int
) -> None:
    assert db.get_used_redis_port() == private_redis
    assert int(db.r.config_get("port")["port"]) == private_redis
    # the cache connection is redirected to the private server too
    assert int(db.rdb.rcache.config_get("port")["port"]) == private_redis


def test_redis_db_is_a_singleton_per_port(
    db: DBManager, private_redis: int, tmp_path: Path
) -> None:
    other = _create_db(private_redis, tmp_path / "other")
    assert other.rdb is db.rdb
    assert RedisDB.instances == {private_redis: db.rdb}


def test_new_redis_db_sets_the_initial_run_state(db: DBManager) -> None:
    assert db.get_slips_internal_time() == "0"
    assert float(db.get_slips_start_time()) > 0
    assert db.will_slips_have_new_incoming_flows() is True
    assert db.get_current_timewindow() is None


@pytest.mark.parametrize("run", [1, 2])
def test_each_test_starts_from_an_empty_redis(db: DBManager, run: int) -> None:
    """Both runs write a key, so whichever runs second proves the flush."""
    assert db.r.exists("leftover") == 0
    assert db.rdb.rcache.dbsize() == 0

    db.r.set("leftover", run)
    db.rdb.rcache.set("leftover", run)


# --------------------------------------------------------------------------
# DBManager is a facade: it must forward args and kwargs untouched
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method_name, args",
    [
        (
            "get_uids_for_vertical_portscan",
            (PROFILEID, TWID, Protocol.TCP, "8.8.8.8"),
        ),
        (
            "get_uids_for_horizontal_portscan",
            (PROFILEID, TWID, Protocol.TCP, 80),
        ),
        ("try_claim_alert_generation", (PROFILEID, TWID)),
        ("release_alert_claim", (PROFILEID, TWID)),
        ("get_the_other_ip_version", (PROFILEID,)),
        ("is_tor_node", ("185.220.101.1",)),
        ("store_official_dns_server", ("192.168.1.53",)),
        ("set_info_for_domains", ("example.com", {"ti": "feed"})),
        ("set_module_label_for_profile", (PROFILEID, "rnn", "malicious")),
        ("add_mac_addr_to_profile", (PROFILEID, MAC_ADDR, "eth0")),
        ("get_available_llm_backends", ()),
        ("incr_current_timewindow", ()),
    ],
)
def test_db_manager_forwards_calls_to_redis_db(
    db: DBManager,
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    args: tuple,
) -> None:
    forwarded = Mock(return_value="redis-result")
    monkeypatch.setattr(db.rdb, method_name, forwarded)

    assert getattr(db, method_name)(*args, extra="kw") == "redis-result"

    forwarded.assert_called_once_with(*args, extra="kw")


# --------------------------------------------------------------------------
# portscan uids
# --------------------------------------------------------------------------


def test_get_uids_for_vertical_portscan_returns_uids_in_time_order(
    db: DBManager,
) -> None:
    key = f"{PROFILEID}_{TWID}:tcp:not_estab:8.8.8.8:uids"
    db.r.zadd(key, {"uid-late": 30, "uid-early": 10, "uid-mid": 20})

    uids = db.get_uids_for_vertical_portscan(
        PROFILEID, TWID, Protocol.TCP, "8.8.8.8"
    )

    assert uids == ["uid-early", "uid-mid", "uid-late"]
    assert (
        db.get_uids_for_vertical_portscan(
            PROFILEID, TWID, Protocol.UDP, "8.8.8.8"
        )
        == []
    )


def test_get_uids_for_horizontal_portscan_returns_uids_in_time_order(
    db: DBManager,
) -> None:
    key = f"{PROFILEID}_{TWID}:udp:not_estab:dstport:53:uids"
    db.r.zadd(key, {"uid-b": 2, "uid-a": 1})

    uids = db.get_uids_for_horizontal_portscan(
        PROFILEID, TWID, Protocol.UDP, 53
    )

    assert uids == ["uid-a", "uid-b"]
    assert (
        db.get_uids_for_horizontal_portscan(PROFILEID, TWID, Protocol.UDP, 80)
        == []
    )


# --------------------------------------------------------------------------
# alert claims
# --------------------------------------------------------------------------


def test_alert_claim_is_won_once_until_released(db: DBManager) -> None:
    assert db.try_claim_alert_generation(PROFILEID, TWID) is True
    assert db.try_claim_alert_generation(PROFILEID, TWID) is False
    # another timewindow is a separate claim
    assert db.try_claim_alert_generation(PROFILEID, "timewindow2") is True

    db.release_alert_claim(PROFILEID, TWID)

    assert db.try_claim_alert_generation(PROFILEID, TWID) is True


def test_release_alert_claim_without_a_claim_is_a_noop(
    db: DBManager,
) -> None:
    db.release_alert_claim(PROFILEID, TWID)
    assert db.try_claim_alert_generation(PROFILEID, TWID) is True


# --------------------------------------------------------------------------
# domain info (cache db)
# --------------------------------------------------------------------------


def test_set_info_for_domains_stores_data_for_a_new_domain(
    db: DBManager,
) -> None:
    db.set_info_for_domains("www.google.com", {"threatintelligence": "feed"})

    assert db.get_domain_data("www.google.com") == {
        "threatintelligence": "feed"
    }
    assert db.get_domain_data("unknown.example") is False


def test_set_info_for_domains_adds_new_keys_and_leaves_old_ones(
    db: DBManager,
) -> None:
    db.set_info_for_domains("example.com", {"ti": "old"})

    # default mode is "leave": the existing key keeps its value
    db.set_info_for_domains("example.com", {"ti": "new"})
    assert db.get_domain_data("example.com") == {"ti": "old"}

    db.set_info_for_domains("example.com", {"geocountry": "CZ"})
    assert db.get_domain_data("example.com") == {
        "ti": "old",
        "geocountry": "CZ",
    }


def test_set_info_for_domains_overwrite_and_add_modes(db: DBManager) -> None:
    db.set_info_for_domains("example.com", {"IPs": ["1.1.1.1"]})

    db.set_info_for_domains("example.com", {"IPs": ["2.2.2.2"]}, mode="add")
    assert sorted(db.get_domain_data("example.com")["IPs"]) == [
        "1.1.1.1",
        "2.2.2.2",
    ]

    db.set_info_for_domains(
        "example.com", {"IPs": ["3.3.3.3"]}, mode="overwrite"
    )
    assert db.get_domain_data("example.com")["IPs"] == ["3.3.3.3"]


# --------------------------------------------------------------------------
# module labels
# --------------------------------------------------------------------------


def test_module_labels_of_a_profile(db: DBManager) -> None:
    assert db.get_modules_labels_of_a_profile(PROFILEID) == {}

    db.set_module_label_for_profile(PROFILEID, "rnn", "malicious")
    db.set_module_label_for_profile(PROFILEID, "flowalerts", "benign")
    assert db.get_modules_labels_of_a_profile(PROFILEID) == {
        "rnn": "malicious",
        "flowalerts": "benign",
    }

    # same module again overwrites its label only
    db.set_module_label_for_profile(PROFILEID, "rnn", "benign")
    assert db.get_modules_labels_of_a_profile(PROFILEID) == {
        "rnn": "benign",
        "flowalerts": "benign",
    }
    assert db.get_modules_labels_of_a_profile("profile_10.0.0.1") == {}


# --------------------------------------------------------------------------
# official dns servers and tor nodes
# --------------------------------------------------------------------------


@pytest.mark.parametrize("server", ["192.168.1.53", "fd00::53"])
def test_store_official_dns_server_accepts_valid_ips(
    db: DBManager, server: str
) -> None:
    db.store_official_dns_server(server)

    assert db.is_official_dns_server(server) is True
    assert db.is_official_dns_server("192.168.1.54") is False


@pytest.mark.parametrize("server", ["not-an-ip", "", "dns.google"])
def test_store_official_dns_server_ignores_invalid_values(
    db: DBManager, server: str
) -> None:
    db.store_official_dns_server(server)

    assert db.is_official_dns_server(server) is False
    assert db.r.scard(db.constants.OFFICIAL_DNS_SERVERS) == 0


def test_store_tor_nodes_and_is_tor_node(db: DBManager) -> None:
    db.store_tor_nodes({"185.220.101.1", "185.220.101.2"})

    assert db.is_tor_node("185.220.101.1") is True
    assert db.is_tor_node("185.220.101.2") is True
    assert db.is_tor_node("8.8.8.8") is False


def test_store_tor_nodes_ignores_an_empty_set(db: DBManager) -> None:
    db.store_tor_nodes(set())

    assert db.rdb.rcache.exists(db.constants.TOR_NODES) == 0


# --------------------------------------------------------------------------
# tranco whitelist (cache db)
# --------------------------------------------------------------------------


def test_tranco_whitelist_keeps_order_and_applies_limit(
    db: DBManager,
) -> None:
    db.store_tranco_whitelisted_domains(
        ["example.com", "google.com", "github.com"], limit=2
    )

    assert db.get_tranco_top_domains() == ["example.com", "google.com"]
    assert db.get_tranco_top_domains(limit=1) == ["example.com"]
    assert db.is_whitelisted_tranco_domain("google.com") is True
    assert db.is_whitelisted_tranco_domain("github.com") is False


def test_tranco_whitelist_without_limit_stores_everything(
    db: DBManager,
) -> None:
    domains = ["example.com", "google.com", "github.com"]
    db.store_tranco_whitelisted_domains(domains)

    assert db.get_tranco_top_domains() == domains
    assert db.get_tranco_top_domains(limit=0) == domains


def test_tranco_whitelist_replaces_the_previous_list(db: DBManager) -> None:
    db.store_tranco_whitelisted_domains(["old.com"])

    db.store_tranco_whitelisted_domains(["new.com"])
    assert db.get_tranco_top_domains() == ["new.com"]
    assert db.is_whitelisted_tranco_domain("old.com") is False

    db.store_tranco_whitelisted_domains([])
    assert db.get_tranco_top_domains() == []


def test_tranco_whitelist_with_a_non_positive_limit_keeps_old_data(
    db: DBManager,
) -> None:
    db.store_tranco_whitelisted_domains(["old.com"])

    db.store_tranco_whitelisted_domains(["new.com"], limit=0)

    assert db.get_tranco_top_domains() == ["old.com"]


@pytest.mark.parametrize(
    "lookup, expected",
    [
        (lambda db: db.get_tranco_top_domains(), []),
        (lambda db: db.is_whitelisted_tranco_domain("example.com"), False),
    ],
)
def test_tranco_reads_discard_a_legacy_cache_key_type(
    db: DBManager, lookup: Callable[[DBManager], Any], expected: Any
) -> None:
    key = db.constants.TRANCO_WHITELISTED_DOMAINS
    db.rdb.rcache.set(key, "legacy-string-value")

    assert lookup(db) == expected
    assert db.rdb.rcache.exists(key) == 0


# --------------------------------------------------------------------------
# llm backends registry
# --------------------------------------------------------------------------

EMPTY_LLM_REGISTRY = {"default_backend": "", "backends": {}}


def test_get_available_llm_backends_when_unset(db: DBManager) -> None:
    assert db.get_available_llm_backends() == EMPTY_LLM_REGISTRY


def test_set_and_get_available_llm_backends_roundtrip(db: DBManager) -> None:
    registry = {
        "default_backend": "local_qwen",
        "backends": {
            "local_qwen": {"provider": "ollama", "model": "qwen2.5:3b"},
            "openai_default": {"provider": "openai", "model": "gpt-4o-mini"},
        },
    }

    db.set_available_llm_backends(registry)

    assert db.get_available_llm_backends() == registry


@pytest.mark.parametrize(
    "registry, expected",
    [
        # backends missing a provider or a model are dropped, and a
        # default pointing at a dropped backend is cleared
        (
            {
                "default_backend": "broken",
                "backends": {
                    "broken": {"provider": "ollama"},
                    " ok ": {"provider": " ollama ", "model": " m "},
                    "": {"provider": "x", "model": "y"},
                    "not-a-dict": "x",
                },
            },
            {
                "default_backend": "",
                "backends": {"ok": {"provider": "ollama", "model": "m"}},
            },
        ),
        ({"default_backend": "x"}, EMPTY_LLM_REGISTRY),
        ("not a dict", EMPTY_LLM_REGISTRY),
        (None, EMPTY_LLM_REGISTRY),
    ],
)
def test_set_available_llm_backends_normalizes_the_registry(
    db: DBManager, registry: Any, expected: dict
) -> None:
    db.set_available_llm_backends(registry)

    assert db.get_available_llm_backends() == expected


def test_get_available_llm_backends_with_corrupt_json(db: DBManager) -> None:
    db.r.set(db.constants.AVAILABLE_LLM_BACKENDS, "{not json")

    assert db.get_available_llm_backends() == EMPTY_LLM_REGISTRY


# --------------------------------------------------------------------------
# current timewindow
# --------------------------------------------------------------------------


def test_incr_current_timewindow_counts_up(db: DBManager) -> None:
    db.incr_current_timewindow()
    assert db.get_current_timewindow() == "1"

    db.incr_current_timewindow()
    assert db.get_current_timewindow() == "2"


def test_incr_current_timewindow_resets_the_max_seen_risk_weight(
    db: DBManager,
) -> None:
    db.rdb._set_max_seen_risk_weight(PROFILEID, RiskWeight.HIGH)
    assert db.rdb.get_max_seen_risk_weight() == {
        "risk_weight": RiskWeight.HIGH,
        "profile": PROFILEID,
    }

    db.incr_current_timewindow()

    assert db.rdb.get_max_seen_risk_weight() == {
        "risk_weight": RiskWeight.LOW,
        "profile": "",
    }


# --------------------------------------------------------------------------
# mac addresses
# --------------------------------------------------------------------------


def test_add_mac_addr_to_profile_with_a_new_ipv4(db: DBManager) -> None:
    assert db.add_mac_addr_to_profile(PROFILEID, MAC_ADDR, "eth0") is True

    assert json.loads(db.r.hget(db.constants.MAC, MAC_ADDR)) == [
        "192.168.1.10"
    ]
    assert db.get_mac_addr_from_profile(PROFILEID) == MAC_ADDR


def test_add_mac_addr_to_profile_with_the_same_ip_again(
    db: DBManager,
) -> None:
    db.add_mac_addr_to_profile(PROFILEID, MAC_ADDR, "eth0")

    assert db.add_mac_addr_to_profile(PROFILEID, MAC_ADDR, "eth0") is False


def test_add_mac_addr_to_profile_refuses_two_ipv4s_with_one_mac(
    db: DBManager,
) -> None:
    db.add_mac_addr_to_profile(PROFILEID, MAC_ADDR, "eth0")

    other = "profile_192.168.1.11"
    assert db.add_mac_addr_to_profile(other, MAC_ADDR, "eth0") is False

    assert json.loads(db.r.hget(db.constants.MAC, MAC_ADDR)) == [
        "192.168.1.10"
    ]
    assert db.get_mac_addr_from_profile(other) is None


def test_add_mac_addr_to_profile_links_an_ipv6_to_the_ipv4(
    db: DBManager,
) -> None:
    ipv6 = "2001:db8:85a3::8a2e:370:7334"
    profile_ipv6 = f"profile_{ipv6}"
    db.add_mac_addr_to_profile(PROFILEID, MAC_ADDR, "eth0")

    assert db.add_mac_addr_to_profile(profile_ipv6, MAC_ADDR, "eth0") is True

    assert set(json.loads(db.r.hget(db.constants.MAC, MAC_ADDR))) == {
        "192.168.1.10",
        ipv6,
    }
    assert db.get_mac_addr_from_profile(profile_ipv6) == MAC_ADDR
    assert json.loads(db.get_ipv4_from_profile(profile_ipv6)) == [
        "192.168.1.10"
    ]
    assert json.loads(db.get_ipv6_from_profile(PROFILEID)) == [ipv6]
    assert json.loads(db.get_the_other_ip_version(PROFILEID)) == [ipv6]
    assert json.loads(db.get_the_other_ip_version(profile_ipv6)) == [
        "192.168.1.10"
    ]


def test_add_mac_addr_to_profile_links_an_ipv4_to_the_ipv6(
    db: DBManager,
) -> None:
    ipv6 = "2001:db8:85a3::8a2e:370:7334"
    profile_ipv6 = f"profile_{ipv6}"
    db.add_mac_addr_to_profile(profile_ipv6, MAC_ADDR, "eth0")

    assert db.add_mac_addr_to_profile(PROFILEID, MAC_ADDR, "eth0") is True

    assert json.loads(db.get_ipv6_from_profile(PROFILEID)) == [ipv6]
    assert json.loads(db.get_ipv4_from_profile(profile_ipv6)) == [
        "192.168.1.10"
    ]


def test_add_mac_addr_to_profile_allows_many_ipv6s_per_mac(
    db: DBManager,
) -> None:
    first = "2001:db8::1"
    second = "2001:db8::2"
    db.add_mac_addr_to_profile(f"profile_{first}", MAC_ADDR, "eth0")

    assert (
        db.add_mac_addr_to_profile(f"profile_{second}", MAC_ADDR, "eth0")
        is True
    )

    assert set(json.loads(db.r.hget(db.constants.MAC, MAC_ADDR))) == {
        first,
        second,
    }
    assert second in json.loads(db.get_ipv6_from_profile(f"profile_{first}"))
    assert first in json.loads(db.get_ipv6_from_profile(f"profile_{second}"))


@pytest.mark.parametrize(
    "profileid, mac_addr",
    [
        # 0.0.0.0 never gets a mac
        ("profile_0.0.0.0", MAC_ADDR),
        # no mac at all
        (PROFILEID, ""),
        # profiles created from a mac address instead of an ip
        (f"profile_{MAC_ADDR}", MAC_ADDR),
    ],
)
def test_add_mac_addr_to_profile_skips_unusable_input(
    db: DBManager, profileid: str, mac_addr: str
) -> None:
    assert db.add_mac_addr_to_profile(profileid, mac_addr, "eth0") is False
    assert db.r.exists(db.constants.MAC) == 0


def test_add_mac_addr_to_profile_skips_the_gateway_ip(db: DBManager) -> None:
    db.set_default_gateway("IP", "192.168.1.1", "eth0")

    assert (
        db.add_mac_addr_to_profile("profile_192.168.1.1", MAC_ADDR, "eth0")
        is False
    )


def test_mac_seen_with_a_public_ip_becomes_the_gateway_mac(
    db: DBManager,
) -> None:
    assert db.add_mac_addr_to_profile("profile_8.8.8.8", MAC_ADDR, "eth0")

    assert db.get_gateway_mac("eth0") == MAC_ADDR
    # the gateway mac is never assigned to a local ip afterwards
    assert db.add_mac_addr_to_profile(PROFILEID, MAC_ADDR, "eth0") is False


@pytest.mark.parametrize(
    "profileid",
    [PROFILEID, "profile_2001:db8::1", "profile_not-an-ip"],
)
def test_get_the_other_ip_version_without_a_link(
    db: DBManager, profileid: str
) -> None:
    assert not db.get_the_other_ip_version(profileid)


# --------------------------------------------------------------------------
# mac vendors
# --------------------------------------------------------------------------


@pytest.fixture
def offline_mac_vendor_lookup(mocker) -> Mock:
    """
    Stub the offline OUI lookup DBManager falls back to.

    Parameters:
        mocker: pytest-mock fixture.

    Return value:
        The Mock standing in for utils.get_mac_vendor_from_mac_addr.
    """
    return mocker.patch(
        f"{DB_MANAGER_MODULE}.utils.get_mac_vendor_from_mac_addr",
        return_value="Samsung Electronics Co.,Ltd",
    )


def test_get_mac_vendor_from_profile_prefers_the_cached_vendor(
    db: DBManager, offline_mac_vendor_lookup: Mock
) -> None:
    db.rdb.update_mac_of_profile(PROFILEID, MAC_ADDR)
    db.set_mac_vendor_to_profile(PROFILEID, MAC_ADDR, "Cached Vendor")

    assert db.get_mac_vendor_from_profile(PROFILEID) == "Cached Vendor"
    offline_mac_vendor_lookup.assert_not_called()


def test_get_mac_vendor_from_profile_without_a_mac(
    db: DBManager, offline_mac_vendor_lookup: Mock
) -> None:
    assert db.get_mac_vendor_from_profile(PROFILEID) is None
    offline_mac_vendor_lookup.assert_not_called()


def test_get_mac_vendor_from_profile_falls_back_to_the_offline_db(
    db: DBManager, offline_mac_vendor_lookup: Mock
) -> None:
    db.rdb.update_mac_of_profile(PROFILEID, MAC_ADDR)

    vendor = db.get_mac_vendor_from_profile(PROFILEID)

    assert vendor == "Samsung Electronics Co.,Ltd"
    offline_mac_vendor_lookup.assert_called_once_with(MAC_ADDR)
    # the result is cached in the profile for next time
    assert db.rdb.get_mac_vendor_from_profile(PROFILEID) == vendor
    assert db.get_mac_vendor_from_profile(PROFILEID) == vendor
    offline_mac_vendor_lookup.assert_called_once()


def test_get_mac_vendor_from_profile_when_the_offline_db_has_no_match(
    db: DBManager, offline_mac_vendor_lookup: Mock
) -> None:
    db.rdb.update_mac_of_profile(PROFILEID, MAC_ADDR)
    offline_mac_vendor_lookup.return_value = None

    assert db.get_mac_vendor_from_profile(PROFILEID) is None
    assert db.rdb.get_mac_vendor_from_profile(PROFILEID) is None


def test_get_mac_vendor_from_profile_when_the_offline_db_is_unreadable(
    db: DBManager, offline_mac_vendor_lookup: Mock
) -> None:
    db.rdb.update_mac_of_profile(PROFILEID, MAC_ADDR)
    offline_mac_vendor_lookup.side_effect = OSError("no such file")

    assert db.get_mac_vendor_from_profile(PROFILEID) is None


# --------------------------------------------------------------------------
# pub/sub
# --------------------------------------------------------------------------


def test_subscribe_rejects_unknown_channels(db: DBManager) -> None:
    assert db.subscribe("invalid_channel") is False


@pytest.mark.parametrize(
    "msg, expected_payload",
    [
        # json msgs get the version added to them
        (json.dumps({"flow": "data"}), {"flow": "data"}),
        # plain text msgs get wrapped
        ("stop_slips", {"text": "stop_slips"}),
    ],
)
def test_publish_and_subscribe_roundtrip(
    db: DBManager, msg: str, expected_payload: dict
) -> None:
    pubsub = db.subscribe("new_flow")
    assert isinstance(pubsub, redis.client.PubSub)
    _wait_until_subscribed(db.r, "new_flow")

    db.publish("new_flow", msg)

    message = None
    deadline = time.monotonic() + 5
    while message is None and time.monotonic() < deadline:
        message = pubsub.get_message(timeout=0.1)
        # redis-py sends the subscribe confirmation first. the db passes
        # ignore_subscribe_messages to subscribe(), where redis-py reads it
        # as a channel name, so the confirmation is not filtered for us
        if message and message["type"] != "message":
            message = None
    db.unsubscribe(pubsub)

    assert message is not None
    assert message["channel"] == "new_flow"
    payload = json.loads(message["data"])
    # every published msg carries the slips version
    assert payload.pop("version")
    assert payload == expected_payload
    assert db.get_msgs_published_in_channel("new_flow") == "1"


def test_unsubscribe_accepts_none(db: DBManager) -> None:
    db.unsubscribe(None)


# --------------------------------------------------------------------------
# run ownership
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "redis_output, caller_output, expected",
    [
        ("output/run/", "output/run", True),
        ("output/run", "output/run/", True),
        ("output/old-run", "output/new-run", False),
        (None, "output/new-run", False),
        ("", "output/new-run", False),
    ],
)
def test_belongs_to_run(
    db: DBManager,
    redis_output: Optional[str],
    caller_output: str,
    expected: bool,
) -> None:
    if redis_output is not None:
        _mark_redis_as_owned_by(db, redis_output)

    assert db.rdb.belongs_to_run(caller_output) is expected


# --------------------------------------------------------------------------
# set_evidence
# --------------------------------------------------------------------------


def test_set_evidence_stores_the_evidence_and_updates_the_threat_level(
    db: DBManager,
) -> None:
    _mark_redis_as_owned_by(db, db.output_dir)
    db.sqlite = _sqlite_mock()
    db.source_module = "conn_analyzer"
    evidence = _make_evidence()

    assert db.set_evidence(evidence) is True

    stored = db.get_twid_evidence(
        str(evidence.profile), str(evidence.timewindow)
    )
    assert set(stored) == {evidence.id}
    stored_evidence = json.loads(stored[evidence.id])
    assert stored_evidence["source_module"] == "conn_analyzer"
    assert stored_evidence["interface"] == "default"
    assert evidence.source_module == "conn_analyzer"
    db.sqlite.add_evidence.assert_called_once_with(evidence)
    assert db.get_evidence_number() == "1"
    # the attacker's profile gets the evidence's threat level
    assert db.r.hget(PROFILEID, db.constants.THREAT_LEVEL) == "medium"
    assert db.get_ip_info("192.168.1.10", "score") == 0.5
    assert db.get_ip_info("192.168.1.10", "confidence") == 0.8


def test_set_evidence_keeps_the_module_set_by_the_evidence(
    db: DBManager,
) -> None:
    _mark_redis_as_owned_by(db, db.output_dir)
    db.sqlite = _sqlite_mock()
    db.source_module = "conn_analyzer"
    evidence = _make_evidence(source_module="arp")

    assert db.set_evidence(evidence) is True

    assert evidence.source_module == "arp"


def test_set_evidence_ignores_a_duplicate(db: DBManager) -> None:
    _mark_redis_as_owned_by(db, db.output_dir)
    db.sqlite = _sqlite_mock()
    evidence = _make_evidence()

    assert db.set_evidence(evidence) is True
    assert db.set_evidence(evidence) is False

    db.sqlite.add_evidence.assert_called_once()
    assert db.get_evidence_number() == "1"


def test_set_evidence_refuses_when_redis_belongs_to_another_run(
    db: DBManager,
) -> None:
    _mark_redis_as_owned_by(db, "some/other/run")
    db.sqlite = _sqlite_mock()
    evidence = _make_evidence()

    assert db.set_evidence(evidence) is False

    assert db.get_twid_evidence(PROFILEID, TWID) == {}
    db.sqlite.add_evidence.assert_not_called()


def test_set_evidence_refuses_when_redis_has_no_run_yet(
    db: DBManager,
) -> None:
    db.sqlite = _sqlite_mock()

    assert db.set_evidence(_make_evidence()) is False


def test_set_evidence_skips_disabled_detections(
    private_redis: int, tmp_path: Path
) -> None:
    db = _create_db(
        private_redis,
        tmp_path,
        disabled_detections=[EvidenceType.CONNECTION_WITHOUT_DNS],
    )
    _mark_redis_as_owned_by(db, db.output_dir)
    db.sqlite = _sqlite_mock()
    evidence = _make_evidence(EvidenceType.CONNECTION_WITHOUT_DNS)

    assert db.set_evidence(evidence) is None

    assert db.get_twid_evidence(PROFILEID, TWID) == {}
    db.sqlite.add_evidence.assert_not_called()


def test_set_evidence_skips_whitelisted_evidence(db: DBManager) -> None:
    _mark_redis_as_owned_by(db, db.output_dir)
    db.sqlite = _sqlite_mock()
    db.sqlite.is_evidence_whitelisted.return_value = True
    evidence = _make_evidence()

    assert db.set_evidence(evidence) is False

    db.sqlite.is_evidence_whitelisted.assert_called_once_with(evidence.id)
    assert db.get_twid_evidence(PROFILEID, TWID) == {}


@pytest.mark.parametrize(
    "evidence_type",
    [EvidenceType.VERTICAL_PORT_SCAN, EvidenceType.HORIZONTAL_PORT_SCAN],
)
def test_set_evidence_keeps_at_most_20_uids_for_portscans(
    db: DBManager, evidence_type: EvidenceType
) -> None:
    _mark_redis_as_owned_by(db, db.output_dir)
    db.sqlite = _sqlite_mock()
    uids = [f"uid-{i}" for i in range(25)]
    evidence = _make_evidence(evidence_type, uids=uids)

    assert db.set_evidence(evidence) is True

    assert len(evidence.uid) == 20
    assert set(evidence.uid) <= set(uids)


def test_set_evidence_caps_the_confidence_at_1(db: DBManager) -> None:
    _mark_redis_as_owned_by(db, db.output_dir)
    db.sqlite = _sqlite_mock()
    evidence = _make_evidence()
    # bypass the dataclass validation on purpose
    evidence.confidence = 3

    assert db.set_evidence(evidence) is True

    assert evidence.confidence == 1
    assert db.get_ip_info("192.168.1.10", "confidence") == 1


# --------------------------------------------------------------------------
# get_twid_evidence filters whitelisted evidence out
# --------------------------------------------------------------------------


def test_get_twid_evidence_drops_whitelisted_ids(db: DBManager) -> None:
    _mark_redis_as_owned_by(db, db.output_dir)
    db.sqlite = _sqlite_mock()
    kept = _make_evidence()
    whitelisted = _make_evidence(EvidenceType.ARP_SCAN)
    db.set_evidence(kept)
    db.set_evidence(whitelisted)
    db.sqlite.get_whitelisted_evidence_ids_in_tw.return_value = {
        whitelisted.id
    }

    evidence = db.get_twid_evidence(PROFILEID, TWID)

    assert set(evidence) == {kept.id}
    db.sqlite.get_whitelisted_evidence_ids_in_tw.assert_called_once_with(
        "192.168.1.10", TWID
    )


def test_get_twid_evidence_without_evidence_skips_sqlite(
    db: DBManager,
) -> None:
    db.sqlite = _sqlite_mock()

    assert db.get_twid_evidence(PROFILEID, TWID) == {}

    db.sqlite.get_whitelisted_evidence_ids_in_tw.assert_not_called()


# --------------------------------------------------------------------------
# threat levels
# --------------------------------------------------------------------------


def test_update_threat_level_writes_redis_and_the_trust_db(
    db: DBManager,
) -> None:
    db.trust_db = Mock()

    db.update_threat_level(PROFILEID, "high", 0.9)

    db.trust_db.insert_slips_score.assert_called_once_with(
        "192.168.1.10", 0.8, 0.9
    )
    assert db.r.hget(PROFILEID, db.constants.THREAT_LEVEL) == "high"
    assert db.get_ip_info("192.168.1.10", "score") == 0.8
    assert db.get_ip_info("192.168.1.10", "confidence") == 0.9


def test_update_threat_level_keeps_the_max_score_seen(db: DBManager) -> None:
    db.update_threat_level(PROFILEID, "high", 0.9)

    db.update_threat_level(PROFILEID, "low", 0.1)

    assert db.r.hget(PROFILEID, db.constants.THREAT_LEVEL) == "low"
    assert db.get_ip_info("192.168.1.10", "score") == 0.8
    assert db.get_ip_info("192.168.1.10", "confidence") == 0.1


def test_update_threat_level_without_a_trust_db(db: DBManager) -> None:
    assert db.trust_db is None

    db.update_threat_level(PROFILEID, "critical", 1)

    assert db.get_ip_info("192.168.1.10", "score") == 1


# --------------------------------------------------------------------------
# sqlite side storages owned by the DBManager
# --------------------------------------------------------------------------


def test_get_generated_regexes_and_count(
    db: DBManager, tmp_path: Path
) -> None:
    db.conf.regex_generator_store_dir = Mock(
        return_value=str(tmp_path / "regex_generator")
    )
    db.conf.regex_generator_seed_benign_samples = Mock(return_value=False)
    record = {
        "regex_type": "dns_domain",
        "regex": r"^xqz[a-z0-9]{8,12}\.invalid$",
        "regex_hash": "hash-1",
        "status": "accepted",
        "rejection_reason": None,
        "matched_benign_value": None,
        "backend_alias": "local_qwen",
        "provider": "ollama",
        "model": "qwen2.5:3b",
        "temperature": 1.2,
        "prompt_version": "regex-generator-v1",
        "request_id": "req-1",
        "created_at": 1.0,
    }

    storage = db._get_regex_generator_storage()
    storage.store_generated_regex(record)

    # the storage is created once and reused
    assert db._get_regex_generator_storage() is storage
    regexes = db.get_generated_regexes("dns_domain")
    assert len(regexes) == 1
    assert {k: regexes[0][k] for k in record} == record
    assert db.get_generated_regexes_count("dns_domain") == 1
    assert db.get_generated_regexes("uri") == []
    assert db.get_generated_regexes_count("uri") == 0


def test_init_p2p_trust_db_uses_the_permanent_dir(
    db: DBManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    permanent_dir = tmp_path / "permanent"
    monkeypatch.setattr(
        f"{DB_MANAGER_MODULE}.get_this_filepath_inside_permanent_dir",
        lambda filename: str(permanent_dir / filename),
    )

    db_path = DBManager.init_p2p_trust_db(db)

    assert db_path == str(permanent_dir / "p2p_trust_runtime" / "trustdb.db")
    assert (permanent_dir / "p2p_trust_runtime").is_dir()
    assert db.get_p2p_trust_dir() == str(permanent_dir / "p2p_trust_runtime")


def test_close_all_dbs_closes_every_backend(
    db: DBManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(db.rdb, "r", Mock())
    monkeypatch.setattr(db.rdb, "rcache", Mock())
    db.sqlite = Mock()
    db.trust_db = Mock()
    db.regex_generator_storage = Mock()
    db.t_cell_storage = Mock()

    db.close_all_dbs()

    db.rdb.r.close.assert_called_once()
    db.rdb.rcache.close.assert_called_once()
    db.sqlite.close.assert_called_once()
    db.trust_db.close.assert_called_once()
    db.regex_generator_storage.close.assert_called_once()
    db.t_cell_storage.close.assert_called_once()


def test_close_sqlite_tolerates_missing_backends(db: DBManager) -> None:
    assert db.sqlite is None
    db.close_sqlite()


# --------------------------------------------------------------------------
# redis config file generation (no redis needed)
# --------------------------------------------------------------------------


@pytest.fixture
def redis_conf_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Dict[str, Any]:
    """
    Prepare RedisDB class state for _setup_config_file.

    Parameters:
        tmp_path: Per-test dir holding the template and the output dir.
        monkeypatch: Pytest fixture used to stub the auth helpers.

    Return value:
        Paths the tests assert on.
    """
    template = tmp_path / "redis.conf.template"
    template.write_text(
        'daemonize yes\nsave ""\nappendonly no\n', encoding="utf-8"
    )
    auth_conf = tmp_path / "redis_auth.conf"
    monkeypatch.setattr(
        f"{REDIS_DB_MODULE}.ensure_redis_password",
        lambda: TEST_REDIS_PASSWORD,
    )
    monkeypatch.setattr(
        f"{REDIS_DB_MODULE}.get_redis_auth_conf_path", lambda: str(auth_conf)
    )
    RedisDB._conf_file_template = str(template)
    RedisDB.output_dir = tmp_path / "output"
    RedisDB.redis_port = 6379
    RedisDB.args = Mock(save=False)
    return {
        "output_dir": tmp_path / "output",
        "auth_conf": auth_conf,
        "conf": tmp_path / "output" / "redis" / "redis-server-port-6379.conf",
    }


def test_setup_config_file_writes_a_per_port_conf(
    redis_conf_setup: Dict[str, Any],
) -> None:
    RedisDB._setup_config_file()

    conf = redis_conf_setup["conf"]
    output_dir = redis_conf_setup["output_dir"]
    assert RedisDB._conf_file == str(conf)
    lines = conf.read_text(encoding="utf-8").splitlines()
    # the auth include must come first so the template can't override it
    assert lines[0] == f"include {redis_conf_setup['auth_conf']}"
    assert 'save ""' in lines
    assert "appendonly no" in lines
    assert f"dir {output_dir / 'databases'}" in lines
    assert "dbfilename dump.rdb" in lines
    assert (
        f"logfile {output_dir / 'redis' / 'redis-server-port-6379.log'}"
        in lines
    )
    # requirepass never lands in the per-run conf
    assert not any(line.startswith("requirepass") for line in lines)


def test_setup_config_file_enables_autosave_when_save_is_requested(
    redis_conf_setup: Dict[str, Any],
) -> None:
    RedisDB.args = Mock(save=True)

    RedisDB._setup_config_file()

    lines = redis_conf_setup["conf"].read_text(encoding="utf-8").splitlines()
    assert "save 30 500" in lines
    assert "appendonly yes" in lines
    assert 'save ""' not in lines


def test_setup_config_file_uses_absolute_paths(
    redis_conf_setup: Dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    RedisDB.output_dir = "relative-output"

    RedisDB._setup_config_file()

    lines = Path(RedisDB._conf_file).read_text(encoding="utf-8").splitlines()
    logfile = (
        tmp_path / "relative-output" / "redis" / "redis-server-port-6379.log"
    )
    assert f"logfile {logfile}" in lines
    assert f"dir {tmp_path / 'relative-output' / 'databases'}" in lines
    assert logfile.parent.exists()


# --------------------------------------------------------------------------
# starting the redis server (no redis needed)
# --------------------------------------------------------------------------


@pytest.fixture
def redis_start_setup(tmp_path: Path) -> Mock:
    """
    Prepare RedisDB class state for _start_redis_server.

    Parameters:
        tmp_path: Per-test dir holding a conf file.

    Return value:
        The printer Mock the code logs the command to.
    """
    conf_file = tmp_path / "redis server.conf"
    conf_file.write_text("port 6379\n", encoding="utf-8")
    RedisDB._conf_file = str(conf_file)
    RedisDB._options = {"logfile": str(tmp_path / "redis" / "server.log")}
    RedisDB.redis_port = 6379
    RedisDB.printer = Mock()
    return RedisDB.printer


def _redis_process(returncode: int) -> Mock:
    """
    Fake redis-server process.

    Parameters:
        returncode: Exit code the fake process reports.

    Return value:
        A Mock that behaves like subprocess.Popen's result.
    """
    process = Mock(returncode=returncode)
    process.communicate.return_value = (b"", b"bind: address in use")
    return process


def test_start_redis_server_logs_the_command_to_logfiles_only(
    redis_start_setup: Mock, tmp_path: Path
) -> None:
    with patch(
        f"{REDIS_DB_MODULE}.subprocess.Popen", return_value=_redis_process(0)
    ) as popen:
        assert RedisDB._start_redis_server() is True

    redis_start_setup.print.assert_called_once_with(
        f"Redis command: redis-server '{tmp_path / 'redis server.conf'}' "
        "--port 6379 --bind 127.0.0.1 --daemonize yes",
        log_to_logfiles_only=True,
    )
    popen.assert_called_once()
    # the log dir is created ahead of redis
    assert (tmp_path / "redis").is_dir()


def test_start_redis_server_accepts_a_server_already_on_the_port(
    redis_start_setup: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        f"{REDIS_DB_MODULE}.utils.is_port_in_use", lambda port: True
    )
    with patch(
        f"{REDIS_DB_MODULE}.subprocess.Popen", return_value=_redis_process(1)
    ):
        assert RedisDB._start_redis_server() is True


def test_start_redis_server_raises_when_redis_fails_to_start(
    redis_start_setup: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        f"{REDIS_DB_MODULE}.utils.is_port_in_use", lambda port: False
    )
    with (
        patch(
            f"{REDIS_DB_MODULE}.subprocess.Popen",
            return_value=_redis_process(1),
        ),
        pytest.raises(RuntimeError, match="address in use"),
    ):
        RedisDB._start_redis_server()


# --------------------------------------------------------------------------
# saving the db to disk (no redis needed)
# --------------------------------------------------------------------------


def _detached_redis_db(redis_dir: Path, dbfilename: str) -> RedisDB:
    """
    RedisDB without a connection, with a mocked redis client.

    Parameters:
        redis_dir: Dir the fake redis reports as its dump dir.
        dbfilename: Dump file name the fake redis reports.

    Return value:
        A RedisDB whose r, print and redis-cli helper are Mocks.
    """
    db = object.__new__(RedisDB)
    db.r = Mock()
    db.r.config_get.side_effect = lambda option: {
        "dir": {"dir": str(redis_dir)},
        "dbfilename": {"dbfilename": dbfilename},
    }[option]
    db._save_rdb_with_redis_cli = Mock(return_value=False)
    db.print = Mock()
    return db


def test_save_prefers_redis_cli(tmp_path: Path) -> None:
    backup_dir = tmp_path / "databases"
    db = _detached_redis_db(backup_dir, "dump.rdb")
    db._save_rdb_with_redis_cli.return_value = True

    assert db.save(str(backup_dir / "dump")) is True

    db._save_rdb_with_redis_cli.assert_called_once_with(
        str(backup_dir / "dump.rdb")
    )
    db.r.save.assert_not_called()
    assert backup_dir.is_dir()


def test_save_copies_the_dump_from_the_redis_dir(tmp_path: Path) -> None:
    redis_dir = tmp_path / "redis-data"
    redis_dir.mkdir()
    (redis_dir / "custom.rdb").write_text("redis dump", encoding="utf-8")
    backup_dir = tmp_path / "databases"
    db = _detached_redis_db(redis_dir, "custom.rdb")

    assert db.save(str(backup_dir / "dump")) is True

    db.r.save.assert_called_once()
    assert (backup_dir / "dump.rdb").read_text(encoding="utf-8") == (
        "redis dump"
    )
    assert not (redis_dir / "custom.rdb").exists()
    db.print.assert_not_called()


def test_save_keeps_the_dump_when_redis_wrote_it_in_place(
    tmp_path: Path,
) -> None:
    backup_dir = tmp_path / "databases"
    backup_dir.mkdir()
    (backup_dir / "dump.rdb").write_text("redis dump", encoding="utf-8")
    db = _detached_redis_db(backup_dir, "dump.rdb")

    assert db.save(str(backup_dir / "dump")) is True

    db.r.save.assert_called_once()
    assert (backup_dir / "dump.rdb").read_text(encoding="utf-8") == (
        "redis dump"
    )


def test_save_reports_a_failed_save_command(tmp_path: Path) -> None:
    db = _detached_redis_db(tmp_path, "dump.rdb")
    db.r.save.side_effect = redis.RedisError("read-only replica")

    assert db.save(str(tmp_path / "databases" / "dump")) is False

    db.print.assert_called_once()
    assert "SAVE command failed" in db.print.call_args.args[0]


def test_save_reports_a_missing_dump(tmp_path: Path) -> None:
    db = _detached_redis_db(tmp_path / "nowhere", "dump.rdb")

    assert db.save(str(tmp_path / "databases" / "dump")) is False

    db.print.assert_called_once()
    assert "Cannot find the redis database" in db.print.call_args.args[0]


def test_save_rdb_with_redis_cli_succeeds_when_the_file_appears(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        f"{REDIS_DB_MODULE}.ensure_redis_password",
        lambda: TEST_REDIS_PASSWORD,
    )
    db = object.__new__(RedisDB)
    db.redis_port = 6379
    backup_rdb = tmp_path / "dump.rdb"

    def create_rdb_file(*args: Any, **kwargs: Any) -> Mock:
        backup_rdb.write_text("redis dump", encoding="utf-8")
        return Mock(returncode=0, stderr=b"")

    with patch(
        f"{REDIS_DB_MODULE}.subprocess.run", side_effect=create_rdb_file
    ) as run:
        assert db._save_rdb_with_redis_cli(str(backup_rdb)) is True

    run.assert_called_once()
    command = run.call_args.args[0]
    assert command[:5] == ["redis-cli", "-h", LOCALHOST, "-p", "6379"]
    assert command[-2:] == ["--rdb", str(backup_rdb)]
    # the password travels in the env, never in the command line
    assert run.call_args.kwargs["env"]["REDISCLI_AUTH"] == TEST_REDIS_PASSWORD
    assert TEST_REDIS_PASSWORD not in command


def test_save_rdb_with_redis_cli_fails_when_no_file_appears(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        f"{REDIS_DB_MODULE}.ensure_redis_password",
        lambda: TEST_REDIS_PASSWORD,
    )
    db = object.__new__(RedisDB)
    db.redis_port = 6379

    with patch(
        f"{REDIS_DB_MODULE}.subprocess.run",
        return_value=Mock(returncode=0, stderr=b""),
    ):
        assert db._save_rdb_with_redis_cli(str(tmp_path / "dump.rdb")) is False


def test_save_rdb_with_redis_cli_retries_without_a_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        f"{REDIS_DB_MODULE}.ensure_redis_password",
        lambda: TEST_REDIS_PASSWORD,
    )
    db = object.__new__(RedisDB)
    db.redis_port = 6379
    backup_rdb = tmp_path / "dump.rdb"
    auth_error = Mock(
        returncode=1,
        stderr=(
            b"AUTH failed: called without any password configured "
            b"for the default user"
        ),
    )

    def retry_without_auth(*args: Any, **kwargs: Any) -> Mock:
        backup_rdb.write_text("redis dump", encoding="utf-8")
        return Mock(returncode=0, stderr=b"")

    with patch(
        f"{REDIS_DB_MODULE}.subprocess.run",
        side_effect=[auth_error, retry_without_auth()],
    ) as run:
        assert db._save_rdb_with_redis_cli(str(backup_rdb)) is True

    assert run.call_count == 2
    assert "env" in run.call_args_list[0].kwargs
    assert "env" not in run.call_args_list[1].kwargs


# Tests added by the native Slips work (PR 2141).
@pytest.fixture(autouse=True)
def ensure_redis_options(fresh_redis_db_class: None) -> None:
    """
    Ensure Redis options exist when ModuleFactory skips config generation.

    Parameters:
        fresh_redis_db_class: Restores the RedisDB class state afterwards.
    """
    RedisDB._options = {}


@pytest.mark.parametrize("cached,expected", [
    ('["104.244.40.0/21"]', ["104.244.40.0/21"]),
    ('["2400:6680::/32"]', ["2400:6680::/32"]),
    (None, None), ("", None), ("not-json", None), ('{"104": []}', None),
    ('[42]', None), ('[]', []),
])
def test_org_ranges_use_shared_cache(cached: str | None, expected: list[str] | None) -> None:
    """Read decoded organization networks from cache rather than run DB 0.

    Parameters:
        cached: Serialized cache result, including missing or malformed values.
        expected: Network list supplied to organization membership checks.
    """
    _factory = ModuleFactory()
    db = object.__new__(RedisDB)
    db.r = Mock()
    db.rcache = Mock()
    db.rcache.hget.return_value = cached
    assert db.is_ip_in_org_cidrs("twitter", "104") == expected
    db.rcache.hget.assert_called_once_with("twitter_IPs", "104")
    db.r.hget.assert_not_called()


def test_set_evidence_publishes_after_sqlite_commit() -> None:
    """A fast whitelist consumer must always find the durable evidence row."""
    db = ModuleFactory().create_db_manager_obj(6379)
    db.rdb.belongs_to_run = Mock(return_value=True)
    db.rdb.set_evidence = Mock(return_value=True)
    db.rdb.publish_evidence_added = Mock()
    db.sqlite = Mock()
    db.sqlite.is_evidence_whitelisted = Mock(return_value=False)
    db._get_evidence_interface = Mock(return_value="en0")
    db.update_threat_level = Mock()
    evidence = Mock(
        evidence_type=EvidenceType.ARP_SCAN,
        source_module="arp",
        uid=["arp-flow"],
        attacker=Mock(profile="profile_192.168.1.185"),
        threat_level="low",
        confidence=0.8,
    )
    persisted = False

    def persist(_evidence: object) -> None:
        """Record when the SQLite insert has completed.

        Parameters:
            _evidence: Evidence being written.
        """
        nonlocal persisted
        persisted = True

    def consume(_evidence: object) -> None:
        """Simulate a subscriber processing the event immediately.

        Parameters:
            _evidence: Evidence being consumed.
        """
        assert persisted, "evidence was published before its SQLite row"

    db.sqlite.add_evidence.side_effect = persist
    db.rdb.publish_evidence_added.side_effect = consume

    assert db.set_evidence(evidence) is True
    db.rdb.set_evidence.assert_called_once_with(evidence, notify=False)
    db.sqlite.add_evidence.assert_called_once_with(evidence)
    db.rdb.publish_evidence_added.assert_called_once_with(evidence)


@pytest.mark.parametrize("owner", [None, "output/a-slips-run"])
def test_factory_refuses_a_redis_run_owner(owner: str | None) -> None:
    """Refuse an owned database before its constructor can write test values.

    Parameters:
        owner: Existing Slips run identity or a Redis instance reserved for tests.
    """
    factory = ModuleFactory()
    client = Mock()
    client.hget.return_value = owner
    with patch("slips_files.common.slips_utils.utils.is_port_in_use", return_value=True), patch("slips_files.core.database.redis_db.redis_auth.try_connect_with_and_without_password", return_value=client), patch("slips_files.core.database.database_manager.DBManager") as constructor:
        if owner:
            with pytest.raises(RuntimeError, match="Refusing unit-test writes"):
                factory.create_db_manager_obj(6379)
            constructor.assert_not_called()
        else:
            factory._assert_redis_has_no_run_owner(6379)
        client.close.assert_called_once()


def test_factory_allows_an_unused_redis_port() -> None:
    """Allow a new isolated server without treating refused connections as ownership."""
    factory = ModuleFactory()
    with patch("slips_files.common.slips_utils.utils.is_port_in_use", return_value=False), patch("slips_files.core.database.redis_db.redis_auth.try_connect_with_and_without_password") as connect:
        factory._assert_redis_has_no_run_owner(65000)
    connect.assert_not_called()


@pytest.mark.parametrize("failure", [redis.exceptions.ConnectionError, redis.exceptions.TimeoutError])
def test_factory_refuses_unverified_redis_ownership(failure: type[Exception]) -> None:
    """Fail closed if an existing server's run ownership cannot be checked.

    Parameters:
        failure: Connection loss or timeout while checking the occupied port.
    """
    factory = ModuleFactory()
    with patch("slips_files.common.slips_utils.utils.is_port_in_use", return_value=True), patch("slips_files.core.database.redis_db.redis_auth.try_connect_with_and_without_password", side_effect=failure("connection lost")):
        with pytest.raises(RuntimeError, match="Cannot verify ownership"):
            factory._assert_redis_has_no_run_owner(65000)


@pytest.mark.parametrize("add_version", [True, False])
def test_publish_preserves_external_protocol_version(
    add_version: bool,
) -> None:
    """Allow protocol adapters to preserve their external wire version.

    Parameters:
        add_version: Whether publishing should add Slips's version metadata.
    """
    db = ModuleFactory().create_redis_publisher_obj()
    payload = json.dumps({"type": "tl2nl_alert", "version": 1, "data": {}})
    db.publish("iris_internal", payload, add_version=add_version)
    sent = json.loads(db.r.publish.call_args.args[1])
    expected = Path("VERSION").read_text().strip() if add_version else 1
    assert sent["version"] == expected
