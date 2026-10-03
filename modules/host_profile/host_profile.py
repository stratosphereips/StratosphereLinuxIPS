# SPDX-License-Identifier: GPL-2.0-only
"""Archive host identity from completed run flows off the profiler path."""

import ipaddress
import json
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from slips_files.common.abstracts.imodule import IModule
from slips_files.common.slips_utils import utils
from slips_files.core.database.sqlite_db.host_profiles import HostProfileStore


class HostProfile(IModule):
    """Persist a bounded number of host observations each iteration."""

    name = "host_profile"
    description = "Archives host names and identity clues across runs"
    authors = ["Sebastian Garcia"]
    BATCH_SIZE = 64
    ENRICHMENT_BATCH_SIZE = 16
    ENRICHMENT_INTERVAL_SECONDS = 300
    CACHE_LIMIT = 4096
    IP_INFO_FIELDS = (
        "reverse_dns",
        "asn",
        "geocountry",
        "SNI",
        "threatintelligence",
    )

    def init(self) -> None:
        """Initialize only inexpensive counters before modules start."""
        self.flow_rowid = 0
        self.altflow_rowid = 0
        self.store: HostProfileStore | None = None
        self._pending_ips: set[str] = set()
        self._enriched_at: dict[str, float] = {}
        self._enrichment_signatures: dict[str, int] = {}
        self.flows_path = (
            Path(self.parent_output_dir) / "databases" / "flows.sqlite"
        )

    def subscribe_to_channels(self) -> None:
        """Read completed SQLite rows instead of subscribing to every flow."""
        self.channels = {}

    def pre_main(self) -> bool:
        """Open the permanent store after core startup has completed.

        Returns:
            False when initialization succeeds.
        """
        self.store = HostProfileStore(
            Path(self.conf.permanent_dir()) / "host_profiles" / "hosts.sqlite",
            f"{self.parent_output_dir}:{self.ppid}",
            self.db.rdb.get_network_state,
            utils.get_all_interfaces(self.args),
        )
        return False

    def _read_rows(
        self,
    ) -> tuple[
        list[tuple[int, dict[str, Any]]], list[tuple[int, dict[str, Any]]]
    ]:
        """Read a bounded batch from each immutable flow stream.

        Returns:
            Network and protocol flow rows with their SQLite row IDs.
        """
        if not self.flows_path.exists():
            return [], []
        try:
            with sqlite3.connect(
                f"file:{self.flows_path}?mode=ro", uri=True, timeout=0.2
            ) as connection:
                batches = []
                for table, last_rowid in (
                    ("flows", self.flow_rowid),
                    ("altflows", self.altflow_rowid),
                ):
                    rows = connection.execute(
                        f"SELECT rowid, flow FROM {table} WHERE rowid > ? "
                        "ORDER BY rowid LIMIT ?",
                        (last_rowid, self.BATCH_SIZE),
                    ).fetchall()
                    batch = []
                    for rowid, serialized in rows:
                        try:
                            flow = json.loads(serialized)
                        except (TypeError, ValueError):
                            flow = {}
                        if not isinstance(flow, dict):
                            flow = {}
                        batch.append((int(rowid), flow))
                    batches.append(batch)
                return batches[0], batches[1]
        except sqlite3.Error:
            return [], []

    def _remember_ips(self, rows: list[tuple[int, dict[str, Any]]]) -> None:
        """Queue a small number of addresses for eventual Redis enrichment.

        Parameters:
            rows: Parsed flow rows from the current batch.
        """
        now = time.monotonic()
        for _, flow in rows:
            for key in ("saddr", "daddr"):
                ip = str(flow.get(key) or "")
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if (
                    now - self._enriched_at.get(ip, 0)
                    < self.ENRICHMENT_INTERVAL_SECONDS
                ):
                    continue
                if len(self._pending_ips) < self.CACHE_LIMIT:
                    self._pending_ips.add(ip)

    def _enrich_hosts(self) -> None:
        """Read a small Redis batch for names and cached threat context."""
        if not self.store:
            return
        if not self._pending_ips:
            now = time.monotonic()
            for ip, last in self._enriched_at.items():
                if now - last >= self.ENRICHMENT_INTERVAL_SECONDS:
                    self._pending_ips.add(ip)
                if len(self._pending_ips) >= self.ENRICHMENT_BATCH_SIZE:
                    break
        if not self._pending_ips:
            return
        ips = [
            self._pending_ips.pop()
            for _ in range(
                min(len(self._pending_ips), self.ENRICHMENT_BATCH_SIZE)
            )
        ]
        cache = self.db.rdb.rcache.pipeline(transaction=False)
        names = self.db.rdb.r.pipeline(transaction=False)
        for ip in ips:
            names.hget(f"profile_{ip}", "host_name")
            for field in self.IP_INFO_FIELDS:
                cache.hget(f"IPsInfo:{field}", ip)
        try:
            hostnames = names.execute()
            values = cache.execute()
        except Exception:
            self._pending_ips.update(ips)
            return
        for index, ip in enumerate(ips):
            fields = {}
            raw_values = []
            for offset, field in enumerate(self.IP_INFO_FIELDS):
                value = values[index * len(self.IP_INFO_FIELDS) + offset]
                raw_values.append(value)
                if value is None:
                    continue
                try:
                    fields[field] = json.loads(value)
                except (TypeError, ValueError):
                    fields[field] = value
            signature = hash(
                (str(hostnames[index]), *(str(value) for value in raw_values))
            )
            if signature != self._enrichment_signatures.get(ip):
                if fields:
                    self.store.observe_ip_info(ip, fields)
                if hostnames[index]:
                    self.store.observe_hostname(
                        str(hostnames[index]), f"profile_{ip}"
                    )
                self._enrichment_signatures[ip] = signature
            self._enriched_at[ip] = time.monotonic()
        if len(self._enriched_at) > self.CACHE_LIMIT:
            self._enriched_at.clear()
            self._enrichment_signatures.clear()

    def process_batch(self) -> int:
        """Persist and checkpoint one bounded batch outside the profiler.

        Returns:
            Number of rows processed in this iteration.
        """
        flows, altflows = self._read_rows()
        rows = flows + altflows
        if rows and self.store:
            self.store.observe_flows(
                SimpleNamespace(**flow) for _, flow in rows if flow
            )
            self._remember_ips(rows)
            if flows:
                self.flow_rowid = flows[-1][0]
            if altflows:
                self.altflow_rowid = altflows[-1][0]
        self._enrich_hosts()
        return len(rows)

    def main(self) -> bool:
        """Process one batch, yielding CPU when the backlog is empty.

        Returns:
            False to keep the background module running.
        """
        started = time.monotonic()
        count = self.process_batch()
        elapsed = time.monotonic() - started
        self.termination_event.wait(max(0.25, elapsed * 4) if count else 1.0)
        return False

    def shutdown_gracefully(self) -> None:
        """Give pending observations a short bounded chance to persist."""
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if not self.process_batch():
                break
