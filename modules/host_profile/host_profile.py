# SPDX-License-Identifier: GPL-2.0-only
"""Archive host identity from completed run flows off the profiler path."""

import ipaddress
import time
from types import SimpleNamespace
from typing import Any

import redis

from slips_files.common.abstracts.imodule import IModule

# rowid of a stored flow, and the flow itself
FlowRow = tuple[int, dict[str, Any]]


class HostProfile(IModule):
    """Persist a bounded number of host observations each iteration."""

    name = "host_profile"
    description = "Archives host names and identity clues across runs"
    authors = ["Sebastian Garcia"]
    FLOW_TABLES = ("flows", "altflows")
    MAX_FLOWS_PER_TABLE_PER_BATCH = 64
    ENRICHMENT_BATCH_SIZE = 16
    ENRICHMENT_INTERVAL_SECONDS = 300
    MAX_TRACKED_IPS = 4096
    IP_INFO_FIELDS = (
        "reverse_dns",
        "asn",
        "geocountry",
        "SNI",
        "threatintelligence",
        "reverse_dns_lookup",
    )
    # how long main() rests between batches
    IDLE_PAUSE_SECONDS = 1.0
    MIN_PAUSE_SECONDS = 0.25
    REST_TO_WORK_RATIO = 4
    STOP_CHECK_INTERVAL_SECONDS = 0.25
    SHUTDOWN_FLUSH_SECONDS = 2.0

    def init(self) -> None:
        """Initialize only inexpensive counters before modules start."""
        self.last_processed_rowid_of_table: dict[str, int] = {
            table: 0 for table in self.FLOW_TABLES
        }
        self._ips_awaiting_enrichment: set[str] = set()
        self._last_enrichment_time_of_ip: dict[str, float] = {}
        self._last_enrichment_signature_of_ip: dict[str, int] = {}

    def subscribe_to_channels(self) -> None:
        """Read completed SQLite rows instead of subscribing to every flow."""
        self.channels = {}

    def _read_new_flows(self) -> dict[str, list[FlowRow]]:
        """Read a bounded batch of unprocessed flows from each flow table.

        Returns:
            New flow rows of each table, oldest first.
        """
        return {
            table: self.db.get_flows_after_rowid(
                table, last_processed_rowid, self.MAX_FLOWS_PER_TABLE_PER_BATCH
            )
            for table, last_processed_rowid in (
                self.last_processed_rowid_of_table.items()
            )
        }

    def _mark_flows_as_processed(
        self, new_flows_of_table: dict[str, list[FlowRow]]
    ) -> None:
        """Remember the last flow handled in each table.

        The next batch starts right after it, so no flow is read twice.

        Parameters:
            new_flows_of_table: Flow rows that were just saved, per table.
        """
        for table, flow_rows in new_flows_of_table.items():
            if flow_rows:
                last_rowid, _ = flow_rows[-1]
                self.last_processed_rowid_of_table[table] = last_rowid

    def _was_enriched_recently(self, ip: str, now: float) -> bool:
        """Check whether an address is too fresh to be enriched again.

        Parameters:
            ip: Address seen in a flow.
            now: Current monotonic time.

        Returns:
            Whether the address was enriched in the last few minutes.
        """
        seconds_since_enrichment = now - self._last_enrichment_time_of_ip.get(
            ip, 0
        )
        return seconds_since_enrichment < self.ENRICHMENT_INTERVAL_SECONDS

    def _get_ips_of_flow(self, flow: dict[str, Any]) -> list[str]:
        """Pick the source and destination addresses out of a flow.

        Flows without a usable address, like ARP or broken rows, give
        nothing.

        Parameters:
            flow: Parsed flow row.

        Returns:
            The valid IP addresses of the flow.
        """
        ips = []
        for address_field in ("saddr", "daddr"):
            ip = str(flow.get(address_field) or "")
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            ips.append(ip)
        return ips

    def _queue_ips_for_enrichment(self, flow_rows: list[FlowRow]) -> None:
        """Queue the addresses of a flow batch for eventual Redis enrichment.

        The queue is capped, addresses that don't fit are picked up when
        they are seen again.

        Parameters:
            flow_rows: Parsed flow rows from the current batch.
        """
        now = time.monotonic()
        for _, flow in flow_rows:
            for ip in self._get_ips_of_flow(flow):
                if self._was_enriched_recently(ip, now):
                    continue
                if len(self._ips_awaiting_enrichment) < self.MAX_TRACKED_IPS:
                    self._ips_awaiting_enrichment.add(ip)

    def _requeue_ips_due_for_refresh(self) -> None:
        """Queue known addresses whose last enrichment is now too old.

        Names and threat intelligence can change long after an address was
        first seen, so each address is checked again every few minutes.
        Newly seen addresses go first, so nothing is re-queued while some
        are still waiting.
        """
        if self._ips_awaiting_enrichment:
            return
        now = time.monotonic()
        for ip in self._last_enrichment_time_of_ip:
            if not self._was_enriched_recently(ip, now):
                self._ips_awaiting_enrichment.add(ip)
            if (
                len(self._ips_awaiting_enrichment)
                >= self.ENRICHMENT_BATCH_SIZE
            ):
                break

    def _pop_ips_to_enrich(self) -> list[str]:
        """Take the next small group of addresses out of the queue.

        Returns:
            At most one enrichment batch of addresses.
        """
        batch_size = min(
            len(self._ips_awaiting_enrichment), self.ENRICHMENT_BATCH_SIZE
        )
        return [self._ips_awaiting_enrichment.pop() for _ in range(batch_size)]

    def _read_cached_identity_of_ip(
        self, ip: str
    ) -> tuple[str | None, dict[str, Any]]:
        """Read what the other modules have learned about an address so far.

        Parameters:
            ip: Address being enriched.

        Returns:
            Hostname of the address' profile, and its known IP info fields.
        """
        cached_hostname = self.db.get_cached_hostname_from_profile(
            f"profile_{ip}"
        )
        ip_info = {}
        for info_type in self.IP_INFO_FIELDS:
            info = self.db.get_ip_info(ip, info_type)
            if info is not None:
                ip_info[info_type] = info
        return cached_hostname, ip_info

    def _get_identity_signature(
        self, cached_hostname: str | None, ip_info: dict[str, Any]
    ) -> int:
        """Sum up the cached identity of an address in one number.

        Comparing it with the last saved one tells whether anything
        changed, without keeping every value in memory.

        Parameters:
            cached_hostname: Hostname of the address' profile, if known.
            ip_info: Known IP info fields of the address.

        Returns:
            Hash of the hostname and the IP info fields.
        """
        return hash(
            (
                str(cached_hostname),
                *(str(ip_info.get(field)) for field in self.IP_INFO_FIELDS),
            )
        )

    def _save_cached_identity_of_ip(
        self, ip: str, cached_hostname: str | None, ip_info: dict[str, Any]
    ) -> None:
        """Persist the cached identity of an address, if it changed.

        The signature of the last saved values is kept in memory, so
        unchanged addresses cost no database write.

        Parameters:
            ip: Address being enriched.
            cached_hostname: Hostname of the address' profile, if known.
            ip_info: Known IP info fields of the address.
        """
        identity_signature = self._get_identity_signature(
            cached_hostname, ip_info
        )
        if identity_signature == self._last_enrichment_signature_of_ip.get(ip):
            return
        if ip_info:
            self.db.save_host_identity_from_ip_info(ip, ip_info)
        if cached_hostname:
            self.db.save_hostname_of_profile(
                str(cached_hostname), f"profile_{ip}"
            )
        self._last_enrichment_signature_of_ip[ip] = identity_signature

    def _forget_enrichment_history_if_too_big(self) -> None:
        """Keep the in-memory enrichment history bounded.

        Forgetting it only costs one extra enrichment per address.
        """
        if len(self._last_enrichment_time_of_ip) > self.MAX_TRACKED_IPS:
            self._last_enrichment_time_of_ip.clear()
            self._last_enrichment_signature_of_ip.clear()

    def _enrich_queued_ips(self) -> None:
        """Save names and threat context of a small group of queued IPs."""
        ips_to_enrich = self._pop_ips_to_enrich()
        for position, ip in enumerate(ips_to_enrich):
            try:
                cached_hostname, ip_info = self._read_cached_identity_of_ip(ip)
            except redis.exceptions.RedisError:
                # put the unread addresses back, to retry in the next batch
                self._ips_awaiting_enrichment.update(ips_to_enrich[position:])
                return
            self._request_missing_hostname_lookup(ip, ip_info)
            self._save_cached_identity_of_ip(ip, cached_hostname, ip_info)
            self._last_enrichment_time_of_ip[ip] = time.monotonic()

    def _request_missing_hostname_lookup(
        self, ip: str, ip_info: dict[str, Any]
    ) -> None:
        """Request missing names for destination-only hosts and retry failures.

        Parameters:
            ip: Observed source or destination address.
            ip_info: Cached enrichment, including the previous lookup result.
        """
        address = ipaddress.ip_address(ip)
        if (
            address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        ):
            return
        if ip_info.get("reverse_dns"):
            return
        previous_lookup = ip_info.get("reverse_dns_lookup")
        if (
            isinstance(previous_lookup, dict)
            and previous_lookup.get("retry_after", 0) > time.time()
        ):
            return
        self.db.set_new_ip(ip)

    def _archive_new_flows(self) -> int:
        """Persist and checkpoint one bounded flow batch outside the profiler.

        Returns:
            Number of flow rows archived in this iteration.
        """
        new_flows_of_table = self._read_new_flows()
        new_flow_rows = [
            flow_row
            for flow_rows in new_flows_of_table.values()
            for flow_row in flow_rows
        ]
        if new_flow_rows:
            self.db.save_host_identity_from_flows(
                SimpleNamespace(**flow) for _, flow in new_flow_rows if flow
            )
            self._queue_ips_for_enrichment(new_flow_rows)
            self._mark_flows_as_processed(new_flows_of_table)
        return len(new_flow_rows)

    def _get_pause_after_batch(
        self, processed_flows_count: int, batch_duration: float
    ) -> float:
        """Decide how long to rest before reading the next batch.

        With no new flows, wait a full second for some to arrive.
        Otherwise rest four times as long as the batch took. That keeps
        this module at about a fifth of one CPU core even with a long
        backlog, so the modules that detect attacks aren't slowed down.

        Parameters:
            processed_flows_count: Flows handled by the batch that just ended.
            batch_duration: Seconds that batch took.

        Returns:
            Seconds to rest.
        """
        if not processed_flows_count:
            return self.IDLE_PAUSE_SECONDS
        return max(
            self.MIN_PAUSE_SECONDS, batch_duration * self.REST_TO_WORK_RATIO
        )

    def _sleep_unless_stopping(self, pause_seconds: float) -> None:
        """Rest in short steps, so a stop request is noticed quickly.

        Event.wait() can lose its condition lock after a worker is
        force-stopped on macOS, so the stop flag is checked between short
        sleeps instead.

        Parameters:
            pause_seconds: Total time to rest.
        """
        remaining_seconds = pause_seconds
        while remaining_seconds > 0 and not self.termination_event.is_set():
            sleep_step = min(
                remaining_seconds, self.STOP_CHECK_INTERVAL_SECONDS
            )
            time.sleep(sleep_step)
            remaining_seconds -= sleep_step

    def main(self) -> bool:
        """Process one batch, then rest so the backlog never hogs the CPU.

        Returns:
            False to keep the background module running.
        """
        batch_started_at = time.monotonic()
        archived_flows_count = self._archive_new_flows()
        self._requeue_ips_due_for_refresh()
        self._enrich_queued_ips()
        self._forget_enrichment_history_if_too_big()
        batch_duration = time.monotonic() - batch_started_at
        self._sleep_unless_stopping(
            self._get_pause_after_batch(archived_flows_count, batch_duration)
        )
        return False

    def shutdown_gracefully(self) -> None:
        """Give pending observations a short bounded chance to persist."""
        flush_deadline = time.monotonic() + self.SHUTDOWN_FLUSH_SECONDS
        while time.monotonic() < flush_deadline:
            archived_flows_count = self._archive_new_flows()
            self._enrich_queued_ips()
            if not archived_flows_count:
                break
