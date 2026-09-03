"""Tests for exact authenticated P2P connection state."""

import pytest

from slips_files.core.database.redis_db.constants import Constants
from slips_files.core.database.redis_db.p2p_handler import P2PHandler
from tests.module_factory import ModuleFactory


class FakeRedis:
    """Minimal Redis test double for expiring P2P tuple records."""

    def __init__(self) -> None:
        """Initialize string and set storage."""
        self.values = {}
        self.sets = {}

    def sadd(self, key, value) -> None:
        """Add one set member."""
        self.sets.setdefault(key, set()).add(value)

    def smembers(self, key):
        """Return set members."""
        return set(self.sets.get(key, set()))

    def srem(self, key, value) -> None:
        """Remove one set member."""
        self.sets.setdefault(key, set()).discard(value)

    def set(self, key, value, **_kwargs) -> None:
        """Store one value while accepting Redis expiry arguments."""
        self.values[key] = value

    def get(self, key):
        """Return one stored value."""
        return self.values.get(key)

    def delete(self, key) -> None:
        """Delete one stored value."""
        self.values.pop(key, None)


def make_handler() -> P2PHandler:
    """Create a P2P handler with isolated fake Redis storage.

    Returns:
        P2P handler ready for registry tests.
    """
    _module_factory = ModuleFactory()
    handler = P2PHandler()
    handler.r = FakeRedis()
    handler.constants = Constants
    return handler


def connection(**overrides) -> dict:
    """Build an authenticated connection record.

    Parameters:
        overrides: Fields to replace in the default record.

    Returns:
        Exact authenticated P2P TCP connection record.
    """
    record = {
        "peer_id": "peer-a",
        "protocol": "tcp",
        "local_ip": "192.0.2.10",
        "local_port": "6668",
        "remote_ip": "198.51.100.20",
        "remote_port": "43123",
        "authenticated": True,
        "connected": True,
    }
    record.update(overrides)
    return record


def flow(**overrides) -> dict:
    """Build a parsed TCP flow dictionary.

    Parameters:
        overrides: Fields to replace in the default flow.

    Returns:
        Parsed flow endpoint fields.
    """
    record = {
        "proto": "tcp",
        "saddr": "198.51.100.20",
        "sport": "43123",
        "daddr": "192.0.2.10",
        "dport": "6668",
    }
    record.update(overrides)
    return record


@pytest.mark.parametrize("reverse", [False, True])
def test_authenticated_tuple_matches_both_flow_directions(
    reverse: bool,
) -> None:
    """Match only a stored authenticated tuple in either flow direction."""
    handler = make_handler()
    handler.store_authenticated_p2p_connection(
        "connection-a", connection(), 30
    )
    candidate = flow()
    if reverse:
        candidate = {
            "proto": "tcp",
            "saddr": candidate["daddr"],
            "sport": candidate["dport"],
            "daddr": candidate["saddr"],
            "dport": candidate["sport"],
        }

    assert handler.is_authenticated_p2p_flow(candidate) is True


def test_failed_handshake_and_unrelated_peer_traffic_do_not_match() -> None:
    """Do not exempt failed handshakes or unrelated traffic from a peer."""
    handler = make_handler()
    handler.store_authenticated_p2p_connection(
        "connection-a", connection(), 30
    )

    assert handler.is_authenticated_p2p_flow(flow(dport="443")) is False
    handler.remove_authenticated_p2p_connection("connection-a")
    assert handler.is_authenticated_p2p_flow(flow()) is False


def test_reconnect_with_changed_port_replaces_exact_matching_tuple() -> None:
    """Match a reconnect's new port without exempting its old tuple."""
    handler = make_handler()
    handler.store_authenticated_p2p_connection(
        "old", connection(remote_port="43123"), 30
    )
    handler.remove_authenticated_p2p_connection("old")
    handler.store_authenticated_p2p_connection(
        "new", connection(remote_port="51000"), 30
    )

    assert handler.is_authenticated_p2p_flow(flow(sport="43123")) is False
    assert handler.is_authenticated_p2p_flow(flow(sport="51000")) is True


def test_expired_tuple_is_pruned_from_live_index() -> None:
    """Treat a missing TTL record as offline and prune its stale index member."""
    handler = make_handler()
    handler.store_authenticated_p2p_connection("expired", connection(), 30)
    handler.r.delete(f"{Constants.P2P_ACTIVE_CONNECTION_PREFIX}expired")

    assert handler.get_authenticated_p2p_connections() == []
    assert handler.r.smembers(Constants.P2P_ACTIVE_CONNECTIONS) == set()


def test_recent_authenticated_tuple_covers_post_disconnect_flow_only() -> None:
    """Use the grace registry for flow classification, never live status."""
    handler = make_handler()
    handler.store_authenticated_p2p_connection(
        "recent", connection(connected=False), 3, active=False
    )

    assert handler.get_authenticated_p2p_connections() == []
    assert handler.is_authenticated_p2p_flow(flow()) is True
    assert (
        handler.is_authenticated_p2p_flow(flow(), include_recent=False)
        is False
    )
