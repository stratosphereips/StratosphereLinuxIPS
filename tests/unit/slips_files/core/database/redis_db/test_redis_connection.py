"""Tests for Redis transport recovery."""

from unittest.mock import Mock, patch

import pytest
import redis

from tests.module_factory import ModuleFactory


def test_pubsub_disconnect_does_not_log_through_dead_redis() -> None:
    """Retry without recursively calling Redis or growing the backoff."""
    factory = ModuleFactory()
    database = factory.create_redis_publisher_obj()
    database.print = Mock()
    database.connection_retry = 0
    database.backoff = 0.1
    database.max_retries = 3
    channel = Mock()
    channel.get_message.side_effect = redis.exceptions.ConnectionError(
        "server closed"
    )

    with patch(
        "slips_files.core.database.redis_db.database.time.sleep"
    ) as sleep:
        assert database.get_message(channel) is None
        assert database.get_message(channel) is None
        with pytest.raises(RuntimeError, match="Redis unavailable"):
            database.get_message(channel)

    database.print.assert_called_once()
    database.r.get.assert_not_called()
    database.r.set.assert_not_called()
    sleep.assert_any_call(0.1)
    assert database.backoff <= 2.0


def test_pubsub_recovery_resets_retry_state() -> None:
    """A restored Redis connection starts future outages with fresh retries."""
    factory = ModuleFactory()
    database = factory.create_redis_publisher_obj()
    database.print = factory.logger
    database.connection_retry = 2
    database.backoff = 2.0
    channel = Mock()
    channel.get_message.return_value = None

    assert database.get_message(channel) is None
    assert database.connection_retry == 0
    assert database.backoff == 0.1
