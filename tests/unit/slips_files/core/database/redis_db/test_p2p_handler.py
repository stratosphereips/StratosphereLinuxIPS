"""Tests for matching flows against known P2P connections."""

import json
import time

import pytest

from slips_files.core.database.redis_db.constants import Constants
from slips_files.core.database.redis_db.p2p_handler import P2PHandler
from tests.module_factory import ModuleFactory


class FakePipeline:
    """Minimal pipeline test double queuing calls against a FakeRedis."""

    def __init__(self, redis: "FakeRedis") -> None:
        """Bind this pipeline to the FakeRedis it queues calls against."""
        self.redis = redis
        self.calls = []

    def __enter__(self) -> "FakePipeline":
        """Support use as a context manager, like the real redis pipeline."""
        return self

    def __exit__(self, *_exc_info) -> None:
        """No cleanup needed; calls are only applied on execute()."""
        return None

    def sismember(self, key, value) -> "FakePipeline":
        """Queue one sismember check."""
        self.calls.append(("sismember", key, value))
        return self

    def srem(self, key, value) -> "FakePipeline":
        """Queue one set-member removal."""
        self.calls.append(("srem", key, value))
        return self

    def zrem(self, key, value) -> "FakePipeline":
        """Queue one sorted-set-member removal."""
        self.calls.append(("zrem", key, value))
        return self

    def execute(self) -> list:
        """Run every queued call and return the results in order."""
        return [getattr(self.redis, name)(*args) for name, *args in self.calls]


class FakeRedis:
    """Minimal Redis test double backed by a set of connection entries."""

    def __init__(self) -> None:
        """Initialize set, string, and sorted-set storage."""
        self.sets = {}
        self.values = {}
        self.zsets = {}

    def sadd(self, key, value) -> None:
        """Add one set member."""
        self.sets.setdefault(key, set()).add(value)

    def srem(self, key, value) -> None:
        """Remove one set member."""
        self.sets.setdefault(key, set()).discard(value)

    def sismember(self, key, value) -> bool:
        """Check whether a value is a member of a set."""
        return value in self.sets.get(key, set())

    def smembers(self, key):
        """Return set members."""
        return set(self.sets.get(key, set()))

    def set(self, key, value, **_kwargs) -> None:
        """Store one value, accepting Redis expiry keyword arguments."""
        self.values[key] = value

    def get(self, key):
        """Return one stored value."""
        return self.values.get(key)

    def delete(self, key) -> None:
        """Delete one stored value."""
        self.values.pop(key, None)

    def zadd(self, key, mapping) -> None:
        """Add {member: score} entries to a sorted set."""
        self.zsets.setdefault(key, {}).update(mapping)

    def zrem(self, key, value) -> None:
        """Remove one sorted-set member."""
        self.zsets.setdefault(key, {}).pop(value, None)

    def zrangebyscore(self, key, min_score, max_score) -> list:
        """Return members scored within [min_score, max_score]."""
        min_score = float("-inf") if min_score == "-inf" else min_score
        max_score = float("inf") if max_score == "+inf" else max_score
        return [
            member
            for member, score in self.zsets.get(key, {}).items()
            if min_score <= score <= max_score
        ]

    def pipeline(self, transaction: bool = True) -> FakePipeline:
        """Return a pipeline queuing calls against this fake Redis."""
        self.pipeline_calls = getattr(self, "pipeline_calls", 0) + 1
        return FakePipeline(self)


def make_handler() -> P2PHandler:
    """Create a P2P handler with isolated fake Redis storage.

    Returns:
        P2P handler ready for connection-matching tests.
    """
    _module_factory = ModuleFactory()
    handler = P2PHandler()
    handler.r = FakeRedis()
    handler.constants = Constants
    return handler


def store_connection(
    handler: P2PHandler,
    proto="tcp",
    local_ip="192.0.2.10",
    local_port="6668",
    remote_ip="198.51.100.20",
    remote_port="43123",
) -> None:
    """Store one connection entry the way the Go peer daemon would.

    Parameters:
        handler: P2P handler under test.
        proto: Transport protocol.
        local_ip: Local endpoint IP.
        local_port: Local endpoint port.
        remote_ip: Remote endpoint IP.
        remote_port: Remote endpoint port.
    """
    entry = f"{proto}|{local_ip}|{local_port}|{remote_ip}|{remote_port}"
    handler.r.sadd(Constants.P2P_CONNECTIONS, entry)


@pytest.mark.parametrize("reverse", [False, True])
def test_connection_matches_both_flow_directions(reverse: bool) -> None:
    """Match a stored connection tuple in either flow direction."""
    handler = make_handler()
    store_connection(handler)

    if reverse:
        args = ("192.0.2.10", "6668", "198.51.100.20", "43123", "tcp")
    else:
        args = ("198.51.100.20", "43123", "192.0.2.10", "6668", "tcp")

    assert handler.is_p2p_related_flow(*args) is True


def test_unrelated_traffic_does_not_match() -> None:
    """Do not match traffic that isn't a stored P2P connection."""
    handler = make_handler()
    store_connection(handler)

    assert (
        handler.is_p2p_related_flow(
            "198.51.100.20", "43123", "192.0.2.10", "443", "tcp"
        )
        is False
    )


def test_removed_connection_no_longer_matches() -> None:
    """Stop matching a connection once it's removed."""
    handler = make_handler()
    store_connection(handler)
    handler.r.srem(
        Constants.P2P_CONNECTIONS,
        "tcp|192.0.2.10|6668|198.51.100.20|43123",
    )

    assert (
        handler.is_p2p_related_flow(
            "198.51.100.20", "43123", "192.0.2.10", "6668", "tcp"
        )
        is False
    )


def test_reconnect_with_changed_port_replaces_matching_tuple() -> None:
    """Match a reconnect's new port, not its stale old one."""
    handler = make_handler()
    store_connection(handler, remote_port="43123")
    handler.r.srem(
        Constants.P2P_CONNECTIONS,
        "tcp|192.0.2.10|6668|198.51.100.20|43123",
    )
    store_connection(handler, remote_port="51000")

    assert (
        handler.is_p2p_related_flow(
            "198.51.100.20", "43123", "192.0.2.10", "6668", "tcp"
        )
        is False
    )
    assert (
        handler.is_p2p_related_flow(
            "198.51.100.20", "51000", "192.0.2.10", "6668", "tcp"
        )
        is True
    )


def test_batch_matches_one_round_trip_for_many_flows() -> None:
    """Check many flows in one pipelined call, same results as one-by-one."""
    handler = make_handler()
    store_connection(handler)

    flows = [
        # matches, forward direction
        ("198.51.100.20", "43123", "192.0.2.10", "6668", "tcp"),
        # matches, reverse direction
        ("192.0.2.10", "6668", "198.51.100.20", "43123", "tcp"),
        # does not match
        ("198.51.100.20", "43123", "192.0.2.10", "443", "tcp"),
    ]

    results = handler.is_p2p_related_flow_batch(flows)

    assert results == [True, True, False]
    # one pipelined round trip for all 3 flows, not one round trip each
    assert handler.r.pipeline_calls == 1


def test_batch_empty_input_returns_empty_list() -> None:
    """An empty flow list needs no redis round trip and returns []."""
    handler = make_handler()
    assert handler.is_p2p_related_flow_batch([]) == []


def test_stored_authenticated_connection_is_readable_by_web_interface() -> (
    None
):
    """The web interface reads live connections via the active registry."""
    handler = make_handler()
    connection = {
        "peer_id": "peer-a",
        "protocol": "tcp",
        "local_ip": "192.0.2.10",
        "local_port": "6668",
        "remote_ip": "198.51.100.20",
        "remote_port": "43123",
        "connected": True,
        "authenticated": True,
    }

    handler.store_authenticated_p2p_connection(
        "connection-a", connection, ttl=300
    )

    assert handler.r.smembers(Constants.P2P_ACTIVE_CONNECTIONS) == {
        "connection-a"
    }
    stored = json.loads(
        handler.r.get(f"{Constants.P2P_ACTIVE_CONNECTION_PREFIX}connection-a")
    )
    assert stored == connection


def test_removed_authenticated_connection_drops_from_registry() -> None:
    """Disconnecting a peer removes it from the live registry."""
    handler = make_handler()
    handler.store_authenticated_p2p_connection(
        "connection-a", {"authenticated": True}, ttl=300
    )

    handler.remove_authenticated_p2p_connection("connection-a")

    assert handler.r.smembers(Constants.P2P_ACTIVE_CONNECTIONS) == set()
    assert (
        handler.r.get(f"{Constants.P2P_ACTIVE_CONNECTION_PREFIX}connection-a")
        is None
    )


def test_removing_a_connection_also_stops_it_matching_flows() -> None:
    """A disconnect clears the flow-matching entry too, not just the UI one.

    Guards against the go daemon's disconnect notification getting lost
    (e.g. a crash) leaving a stale tuple that would otherwise match flows
    forever.
    """
    handler = make_handler()
    store_connection(handler)
    handler.store_authenticated_p2p_connection(
        "tcp|192.0.2.10|6668|198.51.100.20|43123",
        {"authenticated": True},
        ttl=300,
    )

    handler.remove_authenticated_p2p_connection(
        "tcp|192.0.2.10|6668|198.51.100.20|43123"
    )

    assert (
        handler.is_p2p_related_flow(
            "198.51.100.20", "43123", "192.0.2.10", "6668", "tcp"
        )
        is False
    )


def test_prune_stale_p2p_connections_drops_entries_with_no_heartbeat() -> None:
    """A connection whose heartbeat has gone quiet is pruned as stale."""
    handler = make_handler()
    store_connection(handler, remote_port="43123")
    store_connection(handler, remote_port="51000")
    handler.r.zsets[Constants.P2P_CONNECTIONS_LAST_SEEN] = {
        "tcp|192.0.2.10|6668|198.51.100.20|43123": 0,
        "tcp|192.0.2.10|6668|198.51.100.20|51000": time.time(),
    }

    handler.del_stale_p2p_connections(max_age=600)

    assert handler.r.smembers(Constants.P2P_CONNECTIONS) == {
        "tcp|192.0.2.10|6668|198.51.100.20|51000"
    }
    assert Constants.P2P_CONNECTIONS_LAST_SEEN in handler.r.zsets
    assert (
        "tcp|192.0.2.10|6668|198.51.100.20|43123"
        not in handler.r.zsets[Constants.P2P_CONNECTIONS_LAST_SEEN]
    )


def test_prune_stale_p2p_connections_no_stale_entries_is_a_noop() -> None:
    """Nothing to prune shouldn't touch redis at all."""
    handler = make_handler()
    store_connection(handler)

    handler.del_stale_p2p_connections(max_age=600)

    assert handler.r.smembers(Constants.P2P_CONNECTIONS) == {
        "tcp|192.0.2.10|6668|198.51.100.20|43123"
    }
