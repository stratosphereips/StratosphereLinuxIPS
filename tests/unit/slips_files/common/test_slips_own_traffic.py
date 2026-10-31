"""Check exact attribution of sockets opened by Slips modules."""

import socket
from types import SimpleNamespace
from unittest.mock import Mock

from slips_files.common.slips_own_traffic import (
    SlipsTrafficTracker,
    TrackedSocket,
)
from tests.module_factory import ModuleFactory


def test_tracker_records_exact_external_socket_and_skips_loopback() -> None:
    """Keep a WHOIS-like tuple without marking Redis loopback traffic."""
    _module_factory = ModuleFactory()
    tracker = SlipsTrafficTracker()
    sock = SimpleNamespace(
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        getpeername=lambda: ("198.51.100.43", 43),
        getsockname=lambda: ("192.0.2.10", 51234),
    )
    tracker.record(sock, ("198.51.100.43", 43))
    tracker.record(sock, ("198.51.100.43", 43))
    db = Mock(main_pid=123)
    tracker.attach(db)

    db.record_slips_own_connection.assert_called_once_with(
        123, "tcp", "192.0.2.10", 51234, "198.51.100.43", 43
    )
    sock.getpeername = lambda: ("127.0.0.1", 6379)
    tracker.record(sock, ("127.0.0.1", 6379))
    db.record_slips_own_connection.assert_called_once()


def test_tracker_restores_socket_constructor() -> None:
    """Keep socket interception inside one child module's lifetime."""
    _module_factory = ModuleFactory()
    original = socket.socket
    tracker = SlipsTrafficTracker()
    try:
        tracker.install()
        assert socket.socket is TrackedSocket
    finally:
        tracker.stop()

    assert socket.socket is original
