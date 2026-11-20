"""Tests for asynchronous permanent host profiling."""

import time
from unittest.mock import Mock, patch

import pytest
import redis

from tests.module_factory import ModuleFactory


def mock_cached_identity(
    module: object, hostname: str | None, ip_info: dict
) -> None:
    """Make the mocked database return one cached identity for every IP.

    Parameters:
        module: Module whose database manager is mocked.
        hostname: Hostname stored in the Redis profile.
        ip_info: IP info fields stored in Redis.
    """
    module.db.get_cached_hostname_from_profile.return_value = hostname
    module.db.get_ip_info.side_effect = lambda ip, info_type: ip_info.get(
        info_type
    )


@pytest.mark.parametrize(
    "ip,ip_info,requested",
    [
        ("8.8.8.8", {}, True),
        ("8.8.8.8", {"reverse_dns": "dns.google"}, False),
        ("8.8.8.8", {"reverse_dns_lookup": {"retry_after": 2000}}, False),
        ("8.8.8.8", {"reverse_dns_lookup": {"retry_after": 999}}, True),
        ("192.168.1.20", {}, True),
        ("ff02::fb", {}, False),
        ("255.255.255.255", {}, False),
        ("0.0.0.0", {}, False),
    ],
)
def test_host_profile_requests_missing_endpoint_names(
    ip: str, ip_info: dict, requested: bool
) -> None:
    """Enrich destination-only hosts without repeating recent failed lookups.

    Parameters:
        ip: Observed endpoint.
        ip_info: Cached name and lookup result.
        requested: Whether an asynchronous lookup should be requested.
    """
    module = ModuleFactory().create_host_profile_obj()
    with patch(
        "modules.host_profile.host_profile.time.time", return_value=1000
    ):
        module._request_missing_hostname_lookup(ip, ip_info)
    assert module.db.set_new_ip.call_count == int(requested)


@pytest.mark.parametrize(
    "processed_flows_count,batch_duration,expected_pause",
    [
        (0, 0.0, 1.0),
        (0, 5.0, 1.0),
        (64, 0.01, 0.25),
        (64, 0.5, 2.0),
    ],
)
def test_pause_after_batch_follows_the_work_done(
    processed_flows_count: int, batch_duration: float, expected_pause: float
) -> None:
    """Rest longer after slow batches, and a fixed time when idle.

    Parameters:
        processed_flows_count: Flows handled by the last batch.
        batch_duration: Seconds the last batch took.
        expected_pause: Seconds the module should rest.
    """
    module = ModuleFactory().create_host_profile_obj()
    assert (
        module._get_pause_after_batch(processed_flows_count, batch_duration)
        == expected_pause
    )


def test_host_profile_idle_wait_does_not_touch_multiprocessing_event() -> None:
    """Avoid the macOS condition-lock assertion after worker shutdown."""
    module = ModuleFactory().create_host_profile_obj()
    module.process_batch = Mock(return_value=0)
    module.termination_event.is_set.return_value = False
    module.termination_event.wait.side_effect = AssertionError(
        "must acquire() condition before using wait()"
    )

    with patch("modules.host_profile.host_profile.time.sleep") as sleep:
        assert module.main() is False

    assert sleep.call_count == 4
    sleep.assert_any_call(0.25)
    module.termination_event.wait.assert_not_called()

    module.termination_event.is_set.side_effect = [False, True]
    with patch("modules.host_profile.host_profile.time.sleep") as sleep:
        assert module.main() is False
    sleep.assert_called_once_with(0.25)


def test_host_profile_processes_bounded_batches_without_profiler_writes() -> (
    None
):
    """Catch up from run SQLite in batches and persist identity clues."""
    module = ModuleFactory().create_host_profile_obj()
    module.MAX_FLOWS_PER_TABLE_PER_BATCH = 2
    module._enrich_queued_ips = Mock()
    conn_flow = {"type_": "conn", "saddr": "10.0.0.2", "daddr": "8.8.8.8"}
    http_flow = {**conn_flow, "type_": "http", "host": "example.org"}
    stored_flows = {
        "flows": [(1, conn_flow), (2, conn_flow), (3, conn_flow)],
        "altflows": [(1, http_flow), (2, {})],
    }

    def get_flows_after_rowid(table: str, last_rowid: int, max_flows: int):
        return [
            flow_row
            for flow_row in stored_flows[table]
            if flow_row[0] > last_rowid
        ][:max_flows]

    module.db.get_flows_after_rowid.side_effect = get_flows_after_rowid
    saved_batches = []
    module.db.save_host_identity_from_flows.side_effect = (
        lambda flows: saved_batches.append([vars(flow) for flow in flows])
    )

    assert module.process_batch() == 4
    assert module.last_processed_rowid_of_table == {"flows": 2, "altflows": 2}
    assert module.process_batch() == 1
    assert module.process_batch() == 0
    assert module.last_processed_rowid_of_table == {"flows": 3, "altflows": 2}
    # the unparsable flow is skipped, but still counted as processed
    assert saved_batches == [
        [conn_flow, conn_flow, http_flow],
        [conn_flow],
    ]
    assert module._ips_awaiting_enrichment == {"10.0.0.2", "8.8.8.8"}


def test_failed_save_does_not_skip_the_flow_batch() -> None:
    """Read the same flows again after the permanent store rejects them."""
    module = ModuleFactory().create_host_profile_obj()
    module.db.get_flows_after_rowid.return_value = [(7, {"saddr": "10.0.0.2"})]
    module.db.save_host_identity_from_flows.side_effect = RuntimeError

    with pytest.raises(RuntimeError):
        module.process_batch()

    assert module.last_processed_rowid_of_table == {"flows": 0, "altflows": 0}


def test_host_profile_enriches_ips_from_cached_identity() -> None:
    """Persist cached names and threat sources only when they change."""
    module = ModuleFactory().create_host_profile_obj()
    module._ips_awaiting_enrichment.add("8.8.8.8")
    ip_info = {
        "reverse_dns": "dns.google",
        "threatintelligence": {"source": ["feed-one"]},
    }
    mock_cached_identity(module, "dns.google", ip_info)

    module._enrich_queued_ips()

    module.db.save_host_identity_from_ip_info.assert_called_once_with(
        "8.8.8.8", ip_info
    )
    module.db.save_hostname_of_profile.assert_called_once_with(
        "dns.google", "profile_8.8.8.8"
    )
    module.db.get_cached_hostname_from_profile.assert_called_once_with(
        "profile_8.8.8.8"
    )
    assert module._ips_awaiting_enrichment == set()

    module._last_enrichment_time_of_ip["8.8.8.8"] = time.monotonic() - 301
    ip_info["threatintelligence"] = {"source": ["feed-two"]}
    module._enrich_queued_ips()
    assert module.db.save_host_identity_from_ip_info.call_count == 2
    assert module.db.save_host_identity_from_ip_info.call_args.args[1][
        "threatintelligence"
    ] == {"source": ["feed-two"]}

    module._last_enrichment_time_of_ip["8.8.8.8"] = time.monotonic() - 301
    module._enrich_queued_ips()
    assert module.db.save_host_identity_from_ip_info.call_count == 2


def test_enrichment_is_limited_to_one_small_batch_per_iteration() -> None:
    """Leave the rest of a long queue for the next iterations."""
    module = ModuleFactory().create_host_profile_obj()
    module.ENRICHMENT_BATCH_SIZE = 2
    module._ips_awaiting_enrichment.update({"8.8.8.8", "1.1.1.1", "9.9.9.9"})
    mock_cached_identity(module, None, {})

    module._enrich_queued_ips()

    assert len(module._ips_awaiting_enrichment) == 1
    assert len(module._last_enrichment_time_of_ip) == 2


def test_failed_redis_read_keeps_ips_queued() -> None:
    """Retry an address later when Redis can't be read right now."""
    module = ModuleFactory().create_host_profile_obj()
    module._ips_awaiting_enrichment.add("8.8.8.8")
    module.db.get_cached_hostname_from_profile.side_effect = (
        redis.exceptions.ConnectionError
    )

    module._enrich_queued_ips()

    assert module._ips_awaiting_enrichment == {"8.8.8.8"}
    module.db.save_host_identity_from_ip_info.assert_not_called()
    module.db.set_new_ip.assert_not_called()


def test_enrichment_history_stays_bounded() -> None:
    """Forget the enrichment history once it tracks too many addresses."""
    module = ModuleFactory().create_host_profile_obj()
    module.MAX_TRACKED_IPS = 1
    module._last_enrichment_time_of_ip = {"8.8.8.8": 1.0, "1.1.1.1": 2.0}
    module._last_enrichment_signature_of_ip = {"8.8.8.8": 1, "1.1.1.1": 2}

    module._forget_enrichment_history_if_too_big()

    assert module._last_enrichment_time_of_ip == {}
    assert module._last_enrichment_signature_of_ip == {}


def test_destination_only_host_requests_enrichment_from_background_batch() -> (
    None
):
    """Request a name when flow endpoints exist without profiling metadata."""
    module = ModuleFactory().create_host_profile_obj()
    mock_cached_identity(module, None, {})
    module._queue_ips_for_enrichment(
        [(1, {"daddr": "8.8.8.8", "saddr": "not-an-ip"})]
    )
    assert module._ips_awaiting_enrichment == {"8.8.8.8"}
    module._enrich_queued_ips()
    module.db.set_new_ip.assert_called_once_with("8.8.8.8")
    module._enrich_queued_ips()
    module.db.set_new_ip.assert_called_once_with("8.8.8.8")


def test_shutdown_flushes_pending_flows_until_none_are_left() -> None:
    """Persist the flows still waiting when Slips stops."""
    module = ModuleFactory().create_host_profile_obj()
    module.process_batch = Mock(side_effect=[64, 3, 0])

    module.shutdown_gracefully()

    assert module.process_batch.call_count == 3
