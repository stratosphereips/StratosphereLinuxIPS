# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for modules/ip_info/host_info.py"""

import time
from unittest.mock import AsyncMock, Mock, patch

import pytest
import redis

from tests.module_factory import ModuleFactory

ARCHIVER = "modules.ip_info.host_info"


def mock_cached_identity(
    archiver: object, hostname: str | None, ip_info: dict
) -> None:
    """Make the mocked database return one cached identity for every IP.

    Parameters:
        archiver: Archiver whose database manager is mocked.
        hostname: Hostname stored in the Redis profile.
        ip_info: IP info fields stored in Redis.
    """
    archiver.db.get_cached_hostname_from_profile.return_value = hostname
    archiver.db.get_ip_info.side_effect = lambda ip, info_type: ip_info.get(
        info_type
    )


async def run_now(func, *args):
    """Stand in for the module's executor helper, without a thread.

    Parameters:
        func: Blocking callable the archiver wants to run.
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
def test_archiver_requests_missing_endpoint_names(
    ip: str, ip_info: dict, requested: bool
) -> None:
    """Enrich destination-only hosts without repeating recent failed lookups.

    Parameters:
        ip: Observed endpoint.
        ip_info: Cached name and lookup result.
        requested: Whether an asynchronous lookup should be requested.
    """
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    with patch(f"{ARCHIVER}.time.time", return_value=1000):
        archiver._request_missing_hostname_lookup(ip, ip_info)
    assert archiver.db.set_new_ip.call_count == int(requested)


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
        expected_pause: Seconds the archiver should rest.
    """
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    assert (
        archiver._get_pause_after_batch(archived_flows_count, batch_duration)
        == expected_pause
    )


def test_archiver_processes_bounded_batches_without_profiler_writes() -> None:
    """Catch up from run SQLite in batches and persist identity clues."""
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    archiver.MAX_FLOWS_PER_TABLE_PER_BATCH = 2
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

    archiver.db.get_flows_after_rowid.side_effect = get_flows_after_rowid
    saved_batches = []
    archiver.db.save_host_identity_from_flows.side_effect = (
        lambda flows: saved_batches.append([vars(flow) for flow in flows])
    )

    assert archiver._archive_new_flows() == 4
    assert archiver.last_processed_rowid_of_table == {
        "flows": 2,
        "altflows": 2,
    }
    assert archiver._archive_new_flows() == 1
    assert archiver._archive_new_flows() == 0
    assert archiver.last_processed_rowid_of_table == {
        "flows": 3,
        "altflows": 2,
    }
    # the unparsable flow is skipped, but still counted as processed
    assert saved_batches == [
        [conn_flow, conn_flow, http_flow],
        [conn_flow],
    ]
    assert archiver._ips_awaiting_enrichment == {"10.0.0.2", "8.8.8.8"}


def test_failed_save_does_not_skip_the_flow_batch() -> None:
    """Read the same flows again after the permanent store rejects them."""
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    archiver.db.get_flows_after_rowid.return_value = [
        (7, {"saddr": "10.0.0.2"})
    ]
    archiver.db.save_host_identity_from_flows.side_effect = RuntimeError

    with pytest.raises(RuntimeError):
        archiver._archive_new_flows()

    assert archiver.last_processed_rowid_of_table == {
        "flows": 0,
        "altflows": 0,
    }


def test_archiver_enriches_ips_from_cached_identity() -> None:
    """Persist cached names and threat sources only when they change."""
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    archiver._ips_awaiting_enrichment.add("8.8.8.8")
    ip_info = {
        "reverse_dns": "dns.google",
        "threatintelligence": {"source": ["feed-one"]},
    }
    mock_cached_identity(archiver, "dns.google", ip_info)

    archiver._enrich_queued_ips()

    archiver.db.save_host_identity_from_ip_info.assert_called_once_with(
        "8.8.8.8", ip_info
    )
    archiver.db.save_hostname_of_profile.assert_called_once_with(
        "dns.google", "profile_8.8.8.8"
    )
    archiver.db.get_cached_hostname_from_profile.assert_called_once_with(
        "profile_8.8.8.8"
    )
    assert archiver._ips_awaiting_enrichment == set()

    archiver._last_enrichment_time_of_ip["8.8.8.8"] = time.monotonic() - 301
    ip_info["threatintelligence"] = {"source": ["feed-two"]}
    archiver._requeue_ips_due_for_refresh()
    archiver._enrich_queued_ips()
    assert archiver.db.save_host_identity_from_ip_info.call_count == 2
    assert archiver.db.save_host_identity_from_ip_info.call_args.args[1][
        "threatintelligence"
    ] == {"source": ["feed-two"]}

    archiver._last_enrichment_time_of_ip["8.8.8.8"] = time.monotonic() - 301
    archiver._requeue_ips_due_for_refresh()
    archiver._enrich_queued_ips()
    assert archiver.db.save_host_identity_from_ip_info.call_count == 2


def test_enrichment_is_limited_to_one_small_batch_per_iteration() -> None:
    """Leave the rest of a long queue for the next iterations."""
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    archiver.ENRICHMENT_BATCH_SIZE = 2
    archiver._ips_awaiting_enrichment.update(
        {"8.8.8.8", "1.1.1.1", "9.9.9.9"}
    )
    mock_cached_identity(archiver, None, {})

    archiver._enrich_queued_ips()

    assert len(archiver._ips_awaiting_enrichment) == 1
    assert len(archiver._last_enrichment_time_of_ip) == 2


def test_failed_redis_read_keeps_ips_queued() -> None:
    """Retry an address later when Redis can't be read right now."""
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    archiver._ips_awaiting_enrichment.add("8.8.8.8")
    archiver.db.get_cached_hostname_from_profile.side_effect = (
        redis.exceptions.ConnectionError
    )

    archiver._enrich_queued_ips()

    assert archiver._ips_awaiting_enrichment == {"8.8.8.8"}
    archiver.db.save_host_identity_from_ip_info.assert_not_called()
    archiver.db.set_new_ip.assert_not_called()


def test_enrichment_history_stays_bounded() -> None:
    """Forget the enrichment history once it tracks too many addresses."""
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    archiver.MAX_TRACKED_IPS = 1
    archiver._last_enrichment_time_of_ip = {"8.8.8.8": 1.0, "1.1.1.1": 2.0}
    archiver._last_enrichment_signature_of_ip = {"8.8.8.8": 1, "1.1.1.1": 2}

    archiver._forget_enrichment_history_if_too_big()

    assert archiver._last_enrichment_time_of_ip == {}
    assert archiver._last_enrichment_signature_of_ip == {}


def test_destination_only_host_requests_enrichment_from_background_batch() -> (
    None
):
    """Request a name when flow endpoints exist without profiling metadata."""
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    mock_cached_identity(archiver, None, {})
    archiver._queue_ips_for_enrichment(
        [(1, {"daddr": "8.8.8.8", "saddr": "not-an-ip"})]
    )
    assert archiver._ips_awaiting_enrichment == {"8.8.8.8"}
    archiver._enrich_queued_ips()
    archiver.db.set_new_ip.assert_called_once_with("8.8.8.8")
    archiver._enrich_queued_ips()
    archiver.db.set_new_ip.assert_called_once_with("8.8.8.8")


def test_archive_batch_runs_every_step_once_in_order() -> None:
    """Archive, refresh, enrich and prune in that order, each batch."""
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    batch_steps = Mock()
    batch_steps._archive_new_flows.return_value = 5
    step_names = [
        "_archive_new_flows",
        "_requeue_ips_due_for_refresh",
        "_enrich_queued_ips",
        "_forget_enrichment_history_if_too_big",
    ]
    for step_name in step_names:
        setattr(archiver, step_name, getattr(batch_steps, step_name))

    assert archiver.archive_batch() == 5

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
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    assert archiver._get_ips_of_flow(flow) == expected_ips


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
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    archiver._ips_awaiting_enrichment = queued_ips
    archiver._last_enrichment_time_of_ip["8.8.8.8"] = (
        time.monotonic() - seconds_since_enrichment
    )

    archiver._requeue_ips_due_for_refresh()

    assert archiver._ips_awaiting_enrichment == expected_queue


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
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    signatures_match = archiver._get_identity_signature(
        hostname, ip_info
    ) == archiver._get_identity_signature(other_hostname, other_ip_info)
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
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    archiver._is_batch_claimed = is_batch_claimed
    archiver._next_batch_time = time.monotonic() + seconds_until_next_batch

    assert archiver.claim_due_batch() is expected_claim
    # a granted claim blocks the next one until its batch ends
    assert archiver.claim_due_batch() is False


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
        expected_pause: Rest the archiver should take afterwards.
    """
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    archiver.archive_batch = Mock(return_value=archived_flows_count)
    assert archiver.claim_due_batch() is True

    with patch(f"{ARCHIVER}.time.monotonic", return_value=500.0):
        await archiver.archive_batch_async(run_now)

    archiver.archive_batch.assert_called_once_with()
    assert archiver._next_batch_time == 500.0 + expected_pause
    assert archiver._is_batch_claimed is False


async def test_failed_batch_rests_longer_and_frees_the_claim() -> None:
    """Retry a broken batch later, without flooding the log meanwhile."""
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    archiver.archive_batch = Mock(side_effect=RuntimeError)
    assert archiver.claim_due_batch() is True

    with patch(f"{ARCHIVER}.time.monotonic", return_value=500.0):
        with pytest.raises(RuntimeError):
            await archiver.archive_batch_async(run_now)

    assert archiver._next_batch_time == 560.0
    assert archiver._is_batch_claimed is False


async def test_batch_is_handed_to_the_executor_helper() -> None:
    """Never run the blocking batch on the event loop itself."""
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    run_in_executor = AsyncMock(return_value=0)

    await archiver.archive_batch_async(run_in_executor)

    run_in_executor.assert_awaited_once_with(archiver.archive_batch)


async def test_shutdown_flushes_pending_flows_until_none_are_left() -> None:
    """Persist the flows still waiting when Slips stops."""
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    archiver.archive_batch = Mock(side_effect=[64, 3, 0])

    await archiver.flush_async(run_now)

    assert archiver.archive_batch.call_count == 3


async def test_shutdown_flush_gives_up_after_its_deadline() -> None:
    """Don't hold Slips' shutdown for a backlog that keeps coming."""
    archiver = ModuleFactory().create_ip_info_obj().host_identity_archiver
    archiver.SHUTDOWN_FLUSH_SECONDS = 0
    archiver.archive_batch = Mock(return_value=64)

    await archiver.flush_async(run_now)

    archiver.archive_batch.assert_not_called()
