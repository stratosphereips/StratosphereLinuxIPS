# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for modules/ip_info/host_info.py"""

import time
from unittest.mock import AsyncMock, Mock, patch

import pytest
import redis

from tests.module_factory import ModuleFactory

HOST_INFO = "modules.ip_info.host_info"


def mock_cached_identity(
    host_info: object, hostname: str | None, ip_info: dict
) -> None:
    """Make the mocked database return one cached identity for every IP.

    Parameters:
        host_info: Helper whose database manager is mocked.
        hostname: Hostname stored in the Redis profile.
        ip_info: IP info fields stored in Redis.
    """
    host_info.db.get_cached_hostname_from_profile.return_value = hostname
    host_info.db.get_ip_info.side_effect = lambda ip, info_type: ip_info.get(
        info_type
    )


async def run_now(func, *args):
    """Stand in for the module's executor helper, without a thread.

    Parameters:
        func: Blocking callable the helper wants to run.
        args: Positional arguments for the callable.

    Returns:
        Callable result.
    """
    return func(*args)


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
def test_host_info_requests_missing_endpoint_names(
    ip: str, ip_info: dict, requested: bool
) -> None:
    """Enrich destination-only hosts without repeating recent failed lookups.

    Parameters:
        ip: Observed endpoint.
        ip_info: Cached name and lookup result.
        requested: Whether an asynchronous lookup should be requested.
    """
    host_info = ModuleFactory().create_ip_info_obj().host_info
    with patch(f"{HOST_INFO}.time.time", return_value=1000):
        host_info._request_missing_hostname_lookup(ip, ip_info)
    assert host_info.db.set_new_ip.call_count == int(requested)


@pytest.mark.parametrize(
    "archived_flows_count,batch_duration,expected_pause",
    [
        (0, 0.0, 1.0),
        (0, 5.0, 1.0),
        (64, 0.01, 0.25),
        (64, 0.5, 2.0),
    ],
)
def test_pause_after_batch_follows_the_work_done(
    archived_flows_count: int, batch_duration: float, expected_pause: float
) -> None:
    """Rest longer after slow batches, and a fixed time when idle.

    Parameters:
        archived_flows_count: Flows handled by the last batch.
        batch_duration: Seconds the last batch took.
        expected_pause: Seconds the helper should rest.
    """
    host_info = ModuleFactory().create_ip_info_obj().host_info
    assert (
        host_info._get_pause_after_batch(archived_flows_count, batch_duration)
        == expected_pause
    )


def test_host_info_processes_bounded_batches_without_profiler_writes() -> None:
    """Catch up from run SQLite in batches and persist identity clues."""
    host_info = ModuleFactory().create_ip_info_obj().host_info
    host_info.MAX_FLOWS_PER_TABLE_PER_BATCH = 2
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

    host_info.db.get_flows_after_rowid.side_effect = get_flows_after_rowid
    saved_batches = []
    host_info.db.save_host_identity_from_flows.side_effect = (
        lambda flows: saved_batches.append([vars(flow) for flow in flows])
    )

    assert host_info._archive_new_flows() == 4
    assert host_info.last_processed_rowid_of_table == {
        "flows": 2,
        "altflows": 2,
    }
    assert host_info._archive_new_flows() == 1
    assert host_info._archive_new_flows() == 0
    assert host_info.last_processed_rowid_of_table == {
        "flows": 3,
        "altflows": 2,
    }
    # the unparsable flow is skipped, but still counted as processed
    assert saved_batches == [
        [conn_flow, conn_flow, http_flow],
        [conn_flow],
    ]
    assert host_info._ips_awaiting_enrichment == {"10.0.0.2", "8.8.8.8"}


def test_failed_save_does_not_skip_the_flow_batch() -> None:
    """Read the same flows again after the permanent store rejects them."""
    host_info = ModuleFactory().create_ip_info_obj().host_info
    host_info.db.get_flows_after_rowid.return_value = [
        (7, {"saddr": "10.0.0.2"})
    ]
    host_info.db.save_host_identity_from_flows.side_effect = RuntimeError

    with pytest.raises(RuntimeError):
        host_info._archive_new_flows()

    assert host_info.last_processed_rowid_of_table == {
        "flows": 0,
        "altflows": 0,
    }


def test_host_info_enriches_ips_from_cached_identity() -> None:
    """Persist cached names and threat sources only when they change."""
    host_info = ModuleFactory().create_ip_info_obj().host_info
    host_info._ips_awaiting_enrichment.add("8.8.8.8")
    ip_info = {
        "reverse_dns": "dns.google",
        "threatintelligence": {"source": ["feed-one"]},
    }
    mock_cached_identity(host_info, "dns.google", ip_info)

    host_info._enrich_queued_ips()

    host_info.db.save_host_identity_from_ip_info.assert_called_once_with(
        "8.8.8.8", ip_info
    )
    host_info.db.save_hostname_of_profile.assert_called_once_with(
        "dns.google", "profile_8.8.8.8"
    )
    host_info.db.get_cached_hostname_from_profile.assert_called_once_with(
        "profile_8.8.8.8"
    )
    assert host_info._ips_awaiting_enrichment == set()

    host_info._last_enrichment_time_of_ip["8.8.8.8"] = time.monotonic() - 301
    ip_info["threatintelligence"] = {"source": ["feed-two"]}
    host_info._requeue_ips_due_for_refresh()
    host_info._enrich_queued_ips()
    assert host_info.db.save_host_identity_from_ip_info.call_count == 2
    assert host_info.db.save_host_identity_from_ip_info.call_args.args[1][
        "threatintelligence"
    ] == {"source": ["feed-two"]}

    host_info._last_enrichment_time_of_ip["8.8.8.8"] = time.monotonic() - 301
    host_info._requeue_ips_due_for_refresh()
    host_info._enrich_queued_ips()
    assert host_info.db.save_host_identity_from_ip_info.call_count == 2


def test_enrichment_is_limited_to_one_small_batch_per_iteration() -> None:
    """Leave the rest of a long queue for the next iterations."""
    host_info = ModuleFactory().create_ip_info_obj().host_info
    host_info.ENRICHMENT_BATCH_SIZE = 2
    host_info._ips_awaiting_enrichment.update(
        {"8.8.8.8", "1.1.1.1", "9.9.9.9"}
    )
    mock_cached_identity(host_info, None, {})

    host_info._enrich_queued_ips()

    assert len(host_info._ips_awaiting_enrichment) == 1
    assert len(host_info._last_enrichment_time_of_ip) == 2


def test_failed_redis_read_keeps_ips_queued() -> None:
    """Retry an address later when Redis can't be read right now."""
    host_info = ModuleFactory().create_ip_info_obj().host_info
    host_info._ips_awaiting_enrichment.add("8.8.8.8")
    host_info.db.get_cached_hostname_from_profile.side_effect = (
        redis.exceptions.ConnectionError
    )

    host_info._enrich_queued_ips()

    assert host_info._ips_awaiting_enrichment == {"8.8.8.8"}
    host_info.db.save_host_identity_from_ip_info.assert_not_called()
    host_info.db.set_new_ip.assert_not_called()


def test_new_ip_is_queued_on_a_freshly_booted_machine() -> None:
    """Queue a never enriched address even when the monotonic clock is low."""
    host_info = ModuleFactory().create_ip_info_obj().host_info
    with patch(f"{HOST_INFO}.time.monotonic", return_value=10.0):
        host_info._queue_ips_for_enrichment([(1, {"daddr": "8.8.8.8"})])
    assert host_info._ips_awaiting_enrichment == {"8.8.8.8"}


def test_enrichment_history_stays_bounded() -> None:
    """Forget the enrichment history once it tracks too many addresses."""
    host_info = ModuleFactory().create_ip_info_obj().host_info
    host_info.MAX_TRACKED_IPS = 1
    host_info._last_enrichment_time_of_ip = {"8.8.8.8": 1.0, "1.1.1.1": 2.0}
    host_info._last_enrichment_signature_of_ip = {"8.8.8.8": 1, "1.1.1.1": 2}

    host_info._forget_enrichment_history_if_too_big()

    assert host_info._last_enrichment_time_of_ip == {}
    assert host_info._last_enrichment_signature_of_ip == {}


def test_destination_only_host_requests_enrichment_from_background_batch() -> (
    None
):
    """Request a name when flow endpoints exist without profiling metadata."""
    host_info = ModuleFactory().create_ip_info_obj().host_info
    mock_cached_identity(host_info, None, {})
    host_info._queue_ips_for_enrichment(
        [(1, {"daddr": "8.8.8.8", "saddr": "not-an-ip"})]
    )
    assert host_info._ips_awaiting_enrichment == {"8.8.8.8"}
    host_info._enrich_queued_ips()
    host_info.db.set_new_ip.assert_called_once_with("8.8.8.8")
    host_info._enrich_queued_ips()
    host_info.db.set_new_ip.assert_called_once_with("8.8.8.8")


def test_archive_batch_runs_every_step_once_in_order() -> None:
    """Archive, refresh, enrich and prune in that order, each batch."""
    host_info = ModuleFactory().create_ip_info_obj().host_info
    batch_steps = Mock()
    batch_steps._archive_new_flows.return_value = 5
    step_names = [
        "_archive_new_flows",
        "_requeue_ips_due_for_refresh",
        "_enrich_queued_ips",
        "_forget_enrichment_history_if_too_big",
    ]
    for step_name in step_names:
        setattr(host_info, step_name, getattr(batch_steps, step_name))

    assert host_info.archive_batch() == 5

    assert [call[0] for call in batch_steps.mock_calls] == step_names


@pytest.mark.parametrize(
    "flow,expected_ips",
    [
        ({"saddr": "10.0.0.2", "daddr": "8.8.8.8"}, ["10.0.0.2", "8.8.8.8"]),
        ({"saddr": "not-an-ip", "daddr": "ff02::fb"}, ["ff02::fb"]),
        ({"saddr": None}, []),
        ({}, []),
    ],
)
def test_get_ips_of_flow_keeps_valid_addresses_only(
    flow: dict, expected_ips: list[str]
) -> None:
    """Skip missing and malformed addresses of a flow.

    Parameters:
        flow: Parsed flow row.
        expected_ips: Addresses that should be picked from it.
    """
    host_info = ModuleFactory().create_ip_info_obj().host_info
    assert host_info._get_ips_of_flow(flow) == expected_ips


@pytest.mark.parametrize(
    "queued_ips,seconds_since_enrichment,expected_queue",
    [
        (set(), 301, {"8.8.8.8"}),
        (set(), 10, set()),
        ({"1.1.1.1"}, 301, {"1.1.1.1"}),
    ],
)
def test_stale_ips_are_requeued_only_when_the_queue_is_empty(
    queued_ips: set[str],
    seconds_since_enrichment: int,
    expected_queue: set[str],
) -> None:
    """Refresh old addresses, but let newly seen ones go first.

    Parameters:
        queued_ips: Addresses already waiting for enrichment.
        seconds_since_enrichment: Age of the known address' enrichment.
        expected_queue: Queue after the refresh step.
    """
    host_info = ModuleFactory().create_ip_info_obj().host_info
    host_info._ips_awaiting_enrichment = queued_ips
    host_info._last_enrichment_time_of_ip["8.8.8.8"] = (
        time.monotonic() - seconds_since_enrichment
    )

    host_info._requeue_ips_due_for_refresh()

    assert host_info._ips_awaiting_enrichment == expected_queue


@pytest.mark.parametrize(
    "hostname,ip_info,other_hostname,other_ip_info,same_signature",
    [
        ("dns.google", {"asn": "x"}, "dns.google", {"asn": "x"}, True),
        ("dns.google", {"asn": "x"}, "dns.google", {"asn": "y"}, False),
        ("dns.google", {}, None, {}, False),
        (None, {"untracked": 1}, None, {"untracked": 2}, True),
    ],
)
def test_identity_signature_changes_with_tracked_values_only(
    hostname: str | None,
    ip_info: dict,
    other_hostname: str | None,
    other_ip_info: dict,
    same_signature: bool,
) -> None:
    """Tell changed identities apart, ignoring fields that aren't saved.

    Parameters:
        hostname: Hostname of the first identity.
        ip_info: IP info of the first identity.
        other_hostname: Hostname of the second identity.
        other_ip_info: IP info of the second identity.
        same_signature: Whether both should give the same signature.
    """
    host_info = ModuleFactory().create_ip_info_obj().host_info
    signatures_match = host_info._get_identity_signature(
        hostname, ip_info
    ) == host_info._get_identity_signature(other_hostname, other_ip_info)
    assert signatures_match is same_signature


@pytest.mark.parametrize(
    "is_batch_claimed,seconds_until_next_batch,expected_claim",
    [
        (False, -1, True),
        (False, 30, False),
        (True, -1, False),
    ],
)
def test_batch_is_claimed_only_when_rested_and_free(
    is_batch_claimed: bool,
    seconds_until_next_batch: int,
    expected_claim: bool,
) -> None:
    """Start a batch only after the rest, and never two at once.

    Parameters:
        is_batch_claimed: Whether a batch is already running.
        seconds_until_next_batch: Rest left before the next batch.
        expected_claim: Whether the caller may start a batch.
    """
    host_info = ModuleFactory().create_ip_info_obj().host_info
    host_info._is_batch_claimed = is_batch_claimed
    host_info._next_batch_time = time.monotonic() + seconds_until_next_batch

    assert host_info.claim_due_batch() is expected_claim
    # a granted claim blocks the next one until its batch ends
    assert host_info.claim_due_batch() is False


@pytest.mark.parametrize(
    "archived_flows_count,expected_pause",
    [
        (0, 1.0),
        (64, 0.25),
    ],
)
async def test_finished_batch_rests_before_the_next_one(
    archived_flows_count: int, expected_pause: float
) -> None:
    """Keep the pacing by delaying the next claim instead of sleeping.

    Parameters:
        archived_flows_count: Flows handled by the batch.
        expected_pause: Rest the helper should take afterwards.
    """
    host_info = ModuleFactory().create_ip_info_obj().host_info
    host_info.archive_batch = Mock(return_value=archived_flows_count)
    assert host_info.claim_due_batch() is True

    with patch(f"{HOST_INFO}.time.monotonic", return_value=500.0):
        await host_info.archive_batch_async(run_now)

    host_info.archive_batch.assert_called_once_with()
    assert host_info._next_batch_time == 500.0 + expected_pause
    assert host_info._is_batch_claimed is False


async def test_failed_batch_rests_longer_and_frees_the_claim() -> None:
    """Retry a broken batch later, without flooding the log meanwhile."""
    host_info = ModuleFactory().create_ip_info_obj().host_info
    host_info.archive_batch = Mock(side_effect=RuntimeError)
    assert host_info.claim_due_batch() is True

    with patch(f"{HOST_INFO}.time.monotonic", return_value=500.0):
        with pytest.raises(RuntimeError):
            await host_info.archive_batch_async(run_now)

    assert host_info._next_batch_time == 560.0
    assert host_info._is_batch_claimed is False


async def test_batch_is_handed_to_the_executor_helper() -> None:
    """Never run the blocking batch on the event loop itself."""
    host_info = ModuleFactory().create_ip_info_obj().host_info
    run_in_executor = AsyncMock(return_value=0)

    await host_info.archive_batch_async(run_in_executor)

    run_in_executor.assert_awaited_once_with(host_info.archive_batch)


async def test_shutdown_flushes_pending_flows_until_none_are_left() -> None:
    """Persist the flows still waiting when Slips stops."""
    host_info = ModuleFactory().create_ip_info_obj().host_info
    host_info.archive_batch = Mock(side_effect=[64, 3, 0])

    await host_info.flush_async(run_now)

    assert host_info.archive_batch.call_count == 3


async def test_shutdown_flush_gives_up_after_its_deadline() -> None:
    """Don't hold Slips' shutdown for a backlog that keeps coming."""
    host_info = ModuleFactory().create_ip_info_obj().host_info
    host_info.SHUTDOWN_FLUSH_SECONDS = 0
    host_info.archive_batch = Mock(return_value=64)

    await host_info.flush_async(run_now)

    host_info.archive_batch.assert_not_called()
