"""Tests for Redis transport recovery."""

from unittest.mock import Mock, patch

import pytest
import redis

from slips_files.core.database.redis_db.constants import Constants
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("worker_flag,interface,gateway,expected", [
    (False, "eth0", "b6:49:9f:96:b2:d4", True),
    (True, "wlan0", "00:11:22:33:44:55", False),
    (False, "eth0", None, False),
])
def test_gateway_mac_uses_shared_interface_state(worker_flag: bool, interface: str, gateway: str | None, expected: bool) -> None:
    """Honor gateway discovery by other workers and separate interfaces."""
    database = ModuleFactory().create_redis_publisher_obj()
    database._gateway_MAC_found = worker_flag
    database.get_gateway_mac = Mock(return_value=gateway)

    assert database._is_gw_mac("B6:49:9F:96:B2:D4", interface) is expected
    database.get_gateway_mac.assert_called_once_with(interface)


@pytest.mark.parametrize("ip,mac,existing,expected", [
    ("147.32.82.228", "b6:49:9f:96:b2:d4", None, True),
    ("147.32.82.228", "b6:49:9f:96:b2:d4", "00:11:22:33:44:55", False),
    ("172.18.0.8", "b6:49:9f:96:b2:d4", None, False),
    ("224.0.0.1", "01:00:5e:00:00:01", None, False),
    ("147.32.82.228", "", None, False),
    ("not-an-ip", "b6:49:9f:96:b2:d4", None, False),
])
def test_gateway_inference_keeps_existing_route(ip: str, mac: str, existing: str | None, expected: bool) -> None:
    """Learn a missing router without overwriting another worker's route."""
    database = ModuleFactory().create_redis_publisher_obj()
    database.constants = Constants()
    database._gateway_MAC_found = True
    database.get_gateway_mac = Mock(return_value=existing)
    database.set_default_gateway = Mock()

    assert database._determine_gw_mac(ip, mac, "eth0") is expected
    if expected:
        database.set_default_gateway.assert_called_once_with("MAC", mac, "eth0")
    else:
        database.set_default_gateway.assert_not_called()


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
