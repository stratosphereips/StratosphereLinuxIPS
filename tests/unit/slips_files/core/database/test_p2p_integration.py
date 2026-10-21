"""Check P2P integration without opening the running Slips Redis."""

import os
import shutil
import socket
import subprocess
import time
from typing import Any, Iterator

import redis
from pathlib import Path
from unittest.mock import Mock

import pytest

from slips_files.core.database.database_manager import DBManager
from slips_files.core.database.redis_db.database import RedisDB
from slips_files.core.database.redis_db.constants import Constants
from slips_files.core.structures.evidence import EvidenceType
from tests.module_factory import ModuleFactory


def mock_p2p_database(factory: ModuleFactory) -> DBManager:
    """Build a facade with explicit mocks and no network connections.

    Parameters:
        factory: Test object factory providing the logger.

    Returns:
        Database manager ready for evidence integration tests.
    """
    db = object.__new__(DBManager)
    db.rdb = Mock()
    db.sqlite = Mock()
    db.trust_db = None
    db.conf = Mock()
    db.conf.disabled_detections.return_value = []
    db.output_dir = "output/p2p-unit"
    db.main_pid = 12345
    db.printer = factory.logger
    return db


@pytest.fixture
def isolated_redis(tmp_path: Path) -> Iterator[redis.Redis]:
    """Start and clean up an independent loopback Redis for one test.

    Parameters:
        tmp_path: Isolated configuration and log directory.

    Yields:
        Client connected exclusively to the child Redis process.
    """
    executable = shutil.which("redis-server")
    if not executable:
        pytest.skip("redis-server is required for the isolated storage test")
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
            str(tmp_path / "redis.log"),
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
                    pytest.fail("Isolated Redis failed to start")
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


def test_slips_own_connection_registry_uses_exact_tuple_and_ttl() -> None:
    """Bound self-generated flow marks and separate retained Redis runs."""
    _module_factory = ModuleFactory()
    db = object.__new__(RedisDB)
    db.r = Mock()
    db.constants = Constants()

    db.record_slips_own_connection(
        123, "tcp", "192.0.2.10", 51234, "198.51.100.43", 43
    )

    key = "slips:own_connection:123:" "tcp|192.0.2.10|51234|198.51.100.43|43"
    source_key = "slips:own_sources:123"
    pipe = db.r.pipeline.return_value
    pipe.set.assert_called_once_with(key, "1", ex=3600)
    pipe.sadd.assert_called_once_with(source_key, "192.0.2.10")
    pipe.expire.assert_called_once_with(source_key, 3600)
    pipe.execute.assert_called_once()

    db.r.sismember.return_value = 1
    db.r.exists.return_value = 1
    assert db.is_slips_own_source_ip(123, "192.0.2.10")
    assert db.is_slips_own_connection(
        123, "TCP", "192.0.2.10", 51234, "198.51.100.43", 43
    )
    db.r.exists.assert_called_once_with(key)


def test_set_evidence_publishes_after_sqlite_commit() -> None:
    """A fast whitelist consumer must always find the durable evidence row."""
    factory = ModuleFactory()
    db = mock_p2p_database(factory)
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


@pytest.mark.parametrize(
    "evidence_type",
    [EvidenceType.P2P_REPORT, EvidenceType.MALICIOUS_IP_FROM_P2P_NETWORK],
)
def test_peer_evidence_does_not_change_local_reputation(
    evidence_type: EvidenceType,
) -> None:
    """A peer's finding cannot become Slips's own score for trust decisions.

    Parameters:
        evidence_type: Peer-derived evidence category.
    """
    factory = ModuleFactory()
    db = mock_p2p_database(factory)
    db.rdb.belongs_to_run = Mock(return_value=True)
    db.rdb.set_evidence = Mock(return_value=True)
    db.rdb.publish_evidence_added = Mock()
    db.sqlite = Mock()
    db.sqlite.is_evidence_whitelisted = Mock(return_value=False)
    db._get_evidence_interface = Mock(return_value="en0")
    db.update_threat_level = Mock()
    evidence = Mock(
        evidence_type=evidence_type,
        source_module="p2p_trust",
        uid=[],
        attacker=Mock(profile="profile_192.0.2.10"),
        threat_level="critical",
        confidence=1.0,
    )

    assert db.set_evidence(evidence) is True
    db.sqlite.add_evidence.assert_called_once_with(evidence)
    db.update_threat_level.assert_not_called()


@pytest.mark.parametrize("has_peer_evidence", [False, True])
def test_alert_promotes_only_local_evidence_to_local_reputation(
    has_peer_evidence: bool,
) -> None:
    """Mixed or peer-only alerts retain the actual first-hand local score.

    Parameters:
        has_peer_evidence: Whether the alert includes a peer-derived finding.
    """
    factory = ModuleFactory()
    db = mock_p2p_database(factory)
    db.sqlite = Mock()
    db.rdb.set_alert = Mock()
    db.rdb.get_flows_causing_evidence = Mock(return_value=[])
    db.set_flow_label = Mock()
    db.update_threat_level = Mock()
    alert = Mock(profile="profile_192.0.2.10")
    evidence_type = (
        EvidenceType.P2P_REPORT if has_peer_evidence else EvidenceType.ARP_SCAN
    )

    db.set_alert(alert, {"evidence-1": Mock(evidence_type=evidence_type)})

    if has_peer_evidence:
        db.update_threat_level.assert_not_called()
    else:
        db.update_threat_level.assert_called_once_with(
            "profile_192.0.2.10", "critical", 1
        )


def test_local_reputation_uses_slips_current_score() -> None:
    """Share the same accumulated local threat value held by Slips."""
    factory = ModuleFactory()
    db = mock_p2p_database(factory)
    db.trust_db = Mock()
    db.rdb.update_threat_level = Mock(return_value=None)
    db.rdb.get_ip_info = Mock(return_value=0.8)

    db.update_threat_level("profile_192.0.2.10", "low", 0.6)

    db.trust_db.insert_slips_score.assert_called_once_with(
        "192.0.2.10", 0.8, 0.6
    )


@pytest.mark.parametrize("previous_score", [0, 0.8])
def test_informational_observation_preserves_peer_assessment(
    previous_score: float,
) -> None:
    """Informational observations cannot assert benignness or alter trust.

    Parameters:
        previous_score: Redis's historical score before the observation.
    """
    factory = ModuleFactory()
    db = mock_p2p_database(factory)
    db.trust_db = Mock()
    db.rdb.update_threat_level = Mock()
    db.rdb.get_ip_info = Mock(return_value=previous_score)

    db.update_threat_level("profile_192.0.2.10", "info", 1)

    db.rdb.update_threat_level.assert_called_once()
    db.trust_db.insert_slips_score.assert_not_called()


def test_replace_network_state_clears_old_network_settings(
    isolated_redis: redis.Redis,
) -> None:
    """A Wi-Fi switch replaces the subnet, gateway, host IP, and DNS."""
    factory = ModuleFactory()
    db = mock_p2p_database(factory)
    db.rdb = object.__new__(RedisDB)
    db.rdb.r = isolated_redis
    db.rdb.constants = Constants()
    db.rdb.default_ttl = 3600
    first = {
        "host_ip": "192.168.1.20",
        "local_network": "192.168.1.0/24",
        "gateway_ip": "192.168.1.1",
        "gateway_mac": "aa:bb:cc:dd:ee:ff",
        "dns_servers": ["192.168.1.53"],
        "version": 1,
    }
    second = {
        "host_ip": "10.0.0.25",
        "local_network": "10.0.0.0/24",
        "gateway_ip": "10.0.0.1",
        "gateway_mac": "11:22:33:44:55:66",
        "dns_servers": ["10.0.0.53"],
        "version": 2,
    }

    db.replace_network_state("wlan0", first)
    db.store_official_dns_server("192.168.1.54")
    db.replace_network_state("wlan0", second)

    assert db.get_network_state("wlan0") == second
    assert db.get_host_ip("wlan0") == "10.0.0.25"
    assert db.get_local_network("wlan0") == "10.0.0.0/24"
    assert db.get_gateway_ip("wlan0") == "10.0.0.1"
    assert db.get_gateway_mac("wlan0") == "11:22:33:44:55:66"
    assert db.is_official_dns_server("10.0.0.53") is True
    assert db.is_official_dns_server("192.168.1.53") is False
    assert db.is_official_dns_server("192.168.1.54") is False

    db.replace_network_state(
        "wlan0",
        {
            **second,
            "host_ip": "",
            "local_network": "",
            "gateway_ip": "",
            "gateway_mac": "",
            "dns_servers": [],
            "version": 3,
        },
    )
    assert db.get_host_ip("wlan0") is None
    assert db.get_local_network("wlan0") is None
    assert db.get_gateway_ip("wlan0") is None
    assert db.is_official_dns_server("10.0.0.53") is False


def test_backup_db_moves_wal_sidecars(tmp_path: Path) -> None:
    """Keep the WAL and shared-memory files with a backed-up trust DB.

    Parameters:
        tmp_path: Temporary directory for SQLite files.
    """
    factory = ModuleFactory()
    db = mock_p2p_database(factory)
    db_path = tmp_path / "trustdb.db"
    for suffix in ("", "-wal", "-shm"):
        (tmp_path / f"trustdb.db{suffix}").write_bytes(b"old")

    DBManager.backup_db(db, str(db_path))

    assert not db_path.exists()
    assert not (tmp_path / "trustdb.db-wal").exists()
    assert not (tmp_path / "trustdb.db-shm").exists()
    backups = list(tmp_path.glob("trustdb.db.*.bak"))
    assert len(backups) == 1
    for suffix in ("", "-wal", "-shm"):
        assert (tmp_path / f"{backups[0].name}{suffix}").read_bytes() == b"old"


def test_init_p2p_trust_db_backs_up_malformed_db_once(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Skip the write check after a malformed trust DB was moved aside.

    Parameters:
        tmp_path: Temporary directory for the trust database.
        monkeypatch: Replaces the permanent directory and database probes.
    """
    factory = ModuleFactory()
    db = mock_p2p_database(factory)
    monkeypatch.setattr(
        "slips_files.core.database.database_manager.get_this_filepath_inside_permanent_dir",
        lambda filename: str(tmp_path / filename),
    )
    db_path = tmp_path / "p2p_trust_runtime" / "trustdb.db"
    db_path.parent.mkdir()
    db_path.write_bytes(b"malformed")
    db.is_db_malformed = Mock(return_value=True)
    db.has_write_access_to_sqlite = Mock(return_value=False)
    db.backup_db = Mock(side_effect=lambda path: os.remove(path))

    assert DBManager.init_p2p_trust_db(db) == str(db_path)
    db.backup_db.assert_called_once_with(str(db_path))
    db.has_write_access_to_sqlite.assert_not_called()
