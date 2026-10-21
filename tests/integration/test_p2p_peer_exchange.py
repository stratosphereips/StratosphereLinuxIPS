"""Exchange real typed reports between two isolated local Pigeon daemons."""

import base64
import json
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import time
from typing import Iterator
from unittest.mock import Mock

import pytest
import redis

from modules.p2p_trust.p2p_trust import Trust
from modules.p2p_trust.trust.report_validation import ReportValidator
from modules.p2p_trust.trust.trustdb import TrustDB
from modules.p2p_trust.utils.go_director import GoDirector
from modules.p2p_trust.utils.utils import (
    send_blame_to_go,
    send_evaluation_to_go,
)
from tests.module_factory import ModuleFactory
from tests.unit.slips_files.core.database import (
    test_p2p_integration as isolated_storage,
)


@pytest.fixture
def peer_redis(tmp_path: Path) -> Iterator[redis.Redis]:
    """Reuse the independent Redis fixture for real wire exchanges.

    Parameters:
        tmp_path: Isolated Redis directory.

    Yields:
        Client owned exclusively by this test.
    """
    yield from isolated_storage.isolated_redis.__wrapped__(tmp_path)


@pytest.fixture(scope="module")
def pigeon_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the exact Pigeon revision selected by this branch.

    Parameters:
        tmp_path_factory: Isolated binary output directory provider.

    Returns:
        Native executable for loopback-only integration tests.
    """
    compiler = shutil.which("go")
    if compiler is None:
        pytest.skip("Go is required for real Pigeon exchange tests")
    binary = tmp_path_factory.mktemp("pigeon-wire") / "p2p4slips"
    subprocess.run(
        [
            compiler,
            "-C",
            "p2p4slips",
            "build",
            "-buildvcs=false",
            "-o",
            str(binary),
            ".",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    return binary


def free_tcp_port() -> int:
    """Reserve an available loopback listener number.

    Returns:
        Unoccupied TCP port for a temporary peer.
    """
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@pytest.mark.parametrize("message_type", ["report", "blame"])
def test_real_peer_exchange_preserves_provenance_and_reaches_python(
    tmp_path: Path,
    pigeon_binary: Path,
    peer_redis: redis.Redis,
    message_type: str,
) -> None:
    """Authenticate peers, exchange typed evidence and store it in Python.

    Parameters:
        tmp_path: Temporary keys, logs and validation state.
        pigeon_binary: Executable built from the pinned submodule.
        peer_redis: Independent Redis with an unused loopback port.
        message_type: Reputation report or blame to send through the real wire.
    """
    factory = ModuleFactory()
    group = f"slips-test-{tmp_path.name}"
    redis_port = peer_redis.connection_pool.connection_kwargs["port"]
    subscribers = peer_redis.pubsub(ignore_subscribe_messages=True)
    subscribers.subscribe("wire_gopy_b")
    processes: list[subprocess.Popen] = []
    logs = []
    database = None
    try:
        peer_ids = []
        ports = [free_tcp_port(), free_tcp_port()]
        for index, name in enumerate(("a", "b")):
            directory = tmp_path / name
            directory.mkdir()
            log_path = directory / "peer.log"
            log = log_path.open("w")
            logs.append(log)
            command = [
                str(pigeon_binary),
                "-host",
                "127.0.0.1",
                "-port",
                str(ports[index]),
                "-rendezvous",
                group,
                "-key-file",
                str(directory / "peer.keys"),
                "-redis-db",
                f"127.0.0.1:{redis_port}",
                "-redis-auth-conf",
                "",
                "-redis-channel-pygo",
                f"wire_pygo_{name}",
                "-redis-channel-gopy",
                f"wire_gopy_{name}",
                "-slips-version",
                "wire-test",
            ]
            if index:
                command += [
                    "-bootstrap-peers",
                    f"/ip4/127.0.0.1/tcp/{ports[0]}/p2p/{peer_ids[0]}",
                ]
            process = subprocess.Popen(
                command, cwd=directory, stdout=log, stderr=subprocess.STDOUT
            )
            processes.append(process)
            deadline = time.monotonic() + 15
            while True:
                assert process.poll() is None, log_path.read_text()
                match = re.search(r"/p2p/([A-Za-z0-9]+)", log_path.read_text())
                if match:
                    peer_ids.append(match.group(1))
                    break
                assert time.monotonic() < deadline, log_path.read_text()
                time.sleep(0.02)
        deadline = time.monotonic() + 15
        while True:
            peer_logs = [
                (tmp_path / name / "peer.log").read_text()
                for name in ("a", "b")
            ]
            ready = all(
                "New peer says hello to me" in log
                or "PeerOld response ok" in log
                for log in peer_logs
            )
            if ready and peer_redis.smembers("p2p:connections"):
                break
            assert time.monotonic() < deadline, "\n".join(peer_logs)
            time.sleep(0.02)
        provenance = [
            {
                "evidence_type": "ARP_SCAN",
                "module": "arp",
                "rule_version": "wire-v1",
                "method": "HEURISTIC",
                "family": "network_discovery",
                "observed_at": time.time(),
                "evidence_id": "wire-local",
            }
        ]
        sender = Mock()
        sender.publish.side_effect = peer_redis.publish
        if message_type == "report":
            send_evaluation_to_go(
                "192.0.2.99",
                0.8,
                0.9,
                peer_ids[1],
                "wire_pygo_a",
                sender,
                provenance,
            )
        else:
            send_blame_to_go(
                "192.0.2.99", 0.8, 0.9, "wire_pygo_a", sender, provenance
            )
        received = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            event = subscribers.get_message(timeout=0.5)
            if not event:
                continue
            envelope = json.loads(event["data"])
            if envelope.get("message_type") != "go_data":
                continue
            inner = json.loads(
                base64.b64decode(envelope["message_contents"]["message"])
            )
            if inner.get("message_type") == message_type:
                received = envelope
                break
        assert received is not None, "\n".join(
            (tmp_path / name / "peer.log").read_text() for name in ("a", "b")
        )
        assert inner["evaluation"]["provenance"] == provenance
        assert received["message_contents"]["reporter"] == peer_ids[0]
        trust = Trust.__new__(Trust)
        trust.slips_version = "wire-test"
        trust.gopy_channel = "wire_gopy_b"
        trust.unversioned_channels = frozenset({"wire_gopy_b"})
        assert trust.is_msg_version_compatible(
            {"data": json.dumps(received)}, "wire_gopy_b"
        )
        database = TrustDB(
            factory.logger, str(tmp_path / "trust.sqlite"), 12345
        )
        receiver = Mock()
        receiver.get_tw_of_ts.return_value = ("timewindow1", 0)
        blame = Mock()
        director = GoDirector(
            factory.logger,
            database,
            receiver,
            "IPsInfo",
            blame_evaluator=blame,
            report_validation=ReportValidator(tmp_path / "validation.sqlite"),
            network_identity=lambda: "gateway:wire-test",
        )
        director.handle_gopy_data(received)
        row = database.conn.execute(
            "SELECT reporter_peerid,score,confidence FROM reports WHERE reported_key='192.0.2.99'"
        ).fetchone()
        assert row == (peer_ids[0], 0.8, 0.9)
        evidence = receiver.set_evidence.call_args.args[0]
        assert evidence.peer_report["provenance"] == provenance
        assert evidence.peer_report["network_id"] == "gateway:wire-test"
        assert blame.call_count == (1 if message_type == "blame" else 0)
    finally:
        if database is not None:
            database.close()
        subscribers.close()
        for process in reversed(processes):
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for log in logs:
            log.close()
