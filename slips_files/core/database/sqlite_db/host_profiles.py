# SPDX-License-Identifier: GPL-2.0-only
"""Keep durable, network-scoped identity clues for observed hosts."""

import ipaddress
import json
import os
import re
import sqlite3
import time
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any, Callable, Collection, Iterable, Iterator, Sequence

from slips_files.common.abstracts.isqlite import ISQLite
from slips_files.common.network_context import network_state_at
from slips_files.common.printer import Printer
from slips_files.common.slips_utils import utils
from slips_files.core.output import Output

MAX_FACTS_PER_KIND = 200
MAX_VALUE_LENGTH = 2048
# how long to wait before writing the same seen-host record or MAC again
REPEATED_WRITE_INTERVAL_SECONDS = 60
NETWORK_STATE_CACHE_SECONDS = 5
MAX_RECENT_MACS = 4096
MAX_RECENT_HOST_SEEN = 10000
# sqlite limits how many "?" one query can hold
MAX_IPS_PER_QUERY = 200
MAX_IPS_PER_TRIAGE_QUERY = 300
MAX_MDNS_BINDINGS_PER_FLOW = 64
PUBLIC_NETWORK_ID = "public"
# where the store lives inside the permanent directory
HOST_PROFILES_DB_SUBPATH = Path("host_profiles") / "hosts.sqlite"

TABLE_SCHEMAS = {
    "hosts": (
        "network_id TEXT NOT NULL, ip TEXT NOT NULL, "
        "network_label TEXT NOT NULL, first_seen REAL NOT NULL, "
        "last_seen REAL NOT NULL, "
        "PRIMARY KEY (network_id, ip)"
    ),
    "host_observations": (
        "network_id TEXT NOT NULL, ip TEXT NOT NULL, "
        "first_seen REAL NOT NULL, last_seen REAL NOT NULL, "
        "PRIMARY KEY(network_id, ip)"
    ),
    "host_endpoint_observations": (
        "network_id TEXT NOT NULL, ip TEXT NOT NULL, "
        "first_seen REAL NOT NULL, last_seen REAL NOT NULL, "
        "PRIMARY KEY(network_id, ip)"
    ),
    "facts": (
        "network_id TEXT NOT NULL, ip TEXT NOT NULL, "
        "kind TEXT NOT NULL, value TEXT NOT NULL, "
        "first_seen REAL NOT NULL, last_seen REAL NOT NULL, "
        "observations INTEGER NOT NULL DEFAULT 1, "
        "PRIMARY KEY (network_id, ip, kind, value)"
    ),
    "network_names": "network_id TEXT PRIMARY KEY, name TEXT NOT NULL",
    "host_annotations": (
        "network_id TEXT NOT NULL, ip TEXT NOT NULL, "
        "name TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', "
        "updated_at REAL NOT NULL, PRIMARY KEY (network_id, ip)"
    ),
    "device_annotations": (
        "mac TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', "
        "note TEXT NOT NULL DEFAULT '', updated_at REAL NOT NULL"
    ),
    "host_annotation_devices": (
        "network_id TEXT NOT NULL, ip TEXT NOT NULL, mac TEXT NOT NULL, "
        "PRIMARY KEY(network_id, ip)"
    ),
    "mdns_annotations": (
        "mdns_name TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', "
        "note TEXT NOT NULL DEFAULT '', updated_at REAL NOT NULL"
    ),
    "mdns_identity_annotations": (
        "mdns_name TEXT PRIMARY KEY, network_id TEXT NOT NULL, "
        "ip TEXT NOT NULL, name TEXT NOT NULL, note TEXT NOT NULL, "
        "updated_at REAL NOT NULL"
    ),
    "host_triage": (
        "subject TEXT PRIMARY KEY, status TEXT NOT NULL, "
        "labels TEXT NOT NULL, updated_at REAL NOT NULL"
    ),
}
INDEX_QUERIES = (
    "CREATE INDEX IF NOT EXISTS host_endpoint_ip_idx "
    "ON host_endpoint_observations(ip, first_seen, last_seen)",
    "CREATE INDEX IF NOT EXISTS facts_host_idx "
    "ON facts(network_id, ip, kind, last_seen DESC)",
    "CREATE INDEX IF NOT EXISTS facts_mac_lookup_idx "
    "ON facts(kind,value,network_id,ip)",
    "CREATE INDEX IF NOT EXISTS facts_ip_kind_idx "
    "ON facts(ip,kind,last_seen DESC)",
    "CREATE INDEX IF NOT EXISTS hosts_ip_seen_idx "
    "ON hosts(ip,last_seen DESC)",
)

# newest MAC of the host row aliased as "h"
LATEST_MAC_OF_HOST_SQL = (
    "(SELECT lower(f.value) FROM facts f WHERE f.network_id=h.network_id "
    "AND f.ip=h.ip AND f.kind='mac' "
    "ORDER BY f.last_seen DESC LIMIT 1)"
)
# MAC that owned the address when the annotation aliased as "a" was saved
MAC_WHEN_ANNOTATED_SQL = (
    "(SELECT lower(f.value) FROM facts f JOIN host_annotations saved "
    "ON saved.network_id=f.network_id AND saved.ip=f.ip "
    "WHERE f.network_id=a.network_id AND f.ip=a.ip AND f.kind='mac' "
    "AND f.first_seen<=saved.updated_at "
    "ORDER BY MIN(f.last_seen, saved.updated_at) DESC, "
    "f.first_seen DESC LIMIT 1)"
)
MAC_OF_ANNOTATION_SQL = (
    "COALESCE((SELECT d.mac FROM host_annotation_devices d WHERE "
    "d.network_id=a.network_id AND d.ip=a.ip), " + MAC_WHEN_ANNOTATED_SQL + ")"
)
IDENTITY_FACTS_SQL = (
    "SELECT network_id,ip,kind,value,first_seen,last_seen FROM facts "
    "WHERE {condition} "
    "AND kind IN ('mac','hostname','mdns_hostname','reverse_dns') "
    "ORDER BY last_seen DESC,first_seen DESC"
)
# the higher the number, the more we trust a name of this kind
NAME_KIND_PRIORITY = {"hostname": 3, "mdns_hostname": 2, "reverse_dns": 1}
NAME_KIND_LABELS = {
    "hostname": "Hostname",
    "mdns_hostname": "mDNS",
    "reverse_dns": "rDNS",
}
NO_NAME_CANDIDATE = (0, 0, "", "")

ProfileKey = tuple[str, str]
NameCandidate = tuple[int, float, str, str]


class HostProfileStore(ISQLite):
    """Persist seen hosts and distinct identity clues across Slips runs."""

    name = "host_profiles"

    def __init__(
        self,
        logger: Output,
        db_path: Path,
        main_pid: int,
        run_name: str,
        network_state_lookup: Callable[[str], dict[str, Any] | None],
        interfaces: list[str],
    ) -> None:
        """Create the shared store and remember how to identify live networks.

        Parameters:
            logger: Output queue used to report failed queries.
            db_path: SQLite path in the configured permanent directory.
            main_pid: PID of slips.py, used to name the cross-process lock.
            run_name: Output directory used to isolate unknown local networks.
            network_state_lookup: Lookup for a monitored interface's current
                state.
            interfaces: Monitored interface names.
        """
        self.printer = Printer(logger, self.name)
        self.db_path = db_path
        self.run_name = run_name
        self.network_state_lookup = network_state_lookup
        self.interfaces = interfaces
        self._network_state_cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._recent_host_seen: dict[ProfileKey, float] = {}
        self._recent_macs: dict[ProfileKey, tuple[str, float]] = {}
        self._create_private_db_dir()
        super().__init__(self.name, main_pid, str(db_path))
        with self.conn_lock:
            # lets readers use column names instead of positions
            self.conn.row_factory = sqlite3.Row
        self._init_tables()
        self._restrict_access_to_slips_user(self.db_path, 0o600)

    def _create_private_db_dir(self) -> None:
        """Create the store's directory, readable by the Slips user only.

        Host names and notes are private, so other users of this machine
        shouldn't be able to list or read them.
        """
        db_dir = self.db_path.parent
        db_dir.mkdir(parents=True, exist_ok=True)
        self._restrict_access_to_slips_user(db_dir, 0o700)

    @staticmethod
    def _restrict_access_to_slips_user(path: Path, mode: int) -> None:
        """Give a path to the owner of the Slips directory and lock it down.

        Slips often starts as root and drops privileges later, so anything
        root creates here must be handed to the user that owns the Slips
        directory, or the unprivileged modules lose access to it.

        Parameters:
            path: File or directory of the store.
            mode: Permission bits to set, e.g. 0o600.
        """
        try:
            if os.geteuid() == 0:
                slips_dir_owner = Path.cwd().stat()
                os.chown(path, slips_dir_owner.st_uid, slips_dir_owner.st_gid)
            path.chmod(mode)
        except PermissionError:
            # another user created it, and already locked it down
            pass

    def _init_tables(self) -> None:
        """Create any missing table or index.

        Runs on every start, so a store created by an older Slips gains
        the tables added since.
        """
        for table_name, schema in TABLE_SCHEMAS.items():
            self.create_table(table_name, schema)
        for index_query in INDEX_QUERIES:
            self.execute(index_query)

    @contextmanager
    def _open_write_transaction(self) -> Iterator[sqlite3.Cursor]:
        """Group several statements into one commit.

        execute() commits after each statement, and every commit syncs the
        disk. A batch of flows needs hundreds of statements, and a host
        review must be saved fully or not at all, so both run in one
        transaction here. It takes the same locks as execute(), in the
        same order. Never call execute() or select() inside it, they wait
        for the lock this already holds.

        BEGIN IMMEDIATE takes the write lock up front, so the reads done
        before the first write can't go stale.

        Returns:
            Cursor of the open transaction. It commits when the block
            ends, and rolls back when the block raises.
        """
        with self.conn_lock:
            with self._acquire_flock():
                cursor = self.conn.cursor()
                try:
                    cursor.execute("BEGIN IMMEDIATE")
                    yield cursor
                    self.conn.commit()
                except BaseException:
                    self.conn.rollback()
                    # the rolled back rows were never saved, so a retry
                    # must not be skipped as a repeated write
                    self._recent_host_seen.clear()
                    self._recent_macs.clear()
                    raise

    def _fetch_rows(
        self, query: str, params: Sequence[Any] = ()
    ) -> list[sqlite3.Row]:
        """Run one read query and return all its rows.

        Parameters:
            query: SELECT statement.
            params: Values for the query's placeholders.

        Returns:
            Matching rows, or an empty list when the query failed.
            execute() already logged the failure.
        """
        cursor = self.execute(query, params)
        if cursor is None:
            return []
        return self.fetchall(cursor)

    @staticmethod
    def _make_placeholders(values: Collection[Any]) -> str:
        """Build the "?,?,?" part of an SQL IN clause.

        Parameters:
            values: Values the query will bind.

        Returns:
            One question mark per value, comma separated.
        """
        return ",".join("?" for _ in values)

    @staticmethod
    def build_network_id(network_state: dict[str, Any], run_name: str) -> str:
        """Identify a network by router MAC or isolate it to one run.

        Parameters:
            network_state: Current interface settings.
            run_name: Run identifier for networks without a known router.

        Returns:
            Network identity suitable for storing a user-provided name.
        """
        gateway_mac = (
            str(network_state.get("gateway_mac") or "").strip().lower()
        )
        if gateway_mac:
            return f"gateway:{gateway_mac}"
        return f"run:{run_name}" if run_name else ""

    def get_network_names(self, network_ids: Iterable[str]) -> dict[str, str]:
        """Read user-provided names for a bounded set of networks.

        Parameters:
            network_ids: Network identities to look up.

        Returns:
            Saved names indexed by network identity.
        """
        unique_network_ids = list(
            dict.fromkeys(
                network_id for network_id in network_ids if network_id
            )
        )
        if not unique_network_ids:
            return {}
        name_rows = self.select(
            "network_names",
            columns="network_id, name",
            condition=(
                f"network_id IN "
                f"({self._make_placeholders(unique_network_ids)})"
            ),
            params=unique_network_ids,
        )
        return {
            name_row["network_id"]: name_row["name"]
            for name_row in name_rows or []
        }

    def get_network_of_observation(
        self, ip: str, observed_at: float
    ) -> dict[str, str]:
        """Resolve the saved network for an address at an event timestamp.

        Parameters:
            ip: Host address associated with the detection.
            observed_at: Detection time as a Unix timestamp.

        Returns:
            Network identity and display name, or an explicit unknown label.
        """
        unknown_network = {
            "network_id": "",
            "network_name": "",
            "network_label": "Unknown network (not recorded)",
        }
        try:
            address = ipaddress.ip_address(ip)
            observation_time = float(observed_at)
        except (TypeError, ValueError):
            return unknown_network
        if address.is_global:
            return {
                "network_id": PUBLIC_NETWORK_ID,
                "network_name": "",
                "network_label": "Public internet",
            }
        observation_rows = self._fetch_rows(
            "SELECT o.network_id, COALESCE(h.network_label,'') "
            "AS network_label, o.first_seen, o.last_seen, n.name "
            "FROM host_endpoint_observations o "
            "LEFT JOIN hosts h ON h.network_id=o.network_id AND h.ip=o.ip "
            "LEFT JOIN network_names n ON n.network_id=o.network_id "
            "WHERE o.ip=?",
            (str(address),),
        )
        rows_at_observation_time = [
            observation_row
            for observation_row in observation_rows
            if observation_row["first_seen"]
            <= observation_time
            <= observation_row["last_seen"]
        ]
        matching_network_ids = {
            str(observation_row["network_id"])
            for observation_row in rows_at_observation_time
        }
        if len(matching_network_ids) > 1:
            return {
                "network_id": ",".join(sorted(matching_network_ids)),
                "network_name": "",
                "network_label": "Multiple networks",
            }
        if not matching_network_ids:
            return unknown_network
        matching_row = rows_at_observation_time[0]
        network_name = str(matching_row["name"] or "")
        return {
            "network_id": str(matching_row["network_id"]),
            "network_name": network_name,
            "network_label": network_name
            or str(matching_row["network_label"])
            or f"Captured network · {matching_row['network_id']}",
        }

    def set_network_name(self, network_id: str, name: str) -> None:
        """Save or clear one network name in the permanent database.

        Parameters:
            network_id: Router or run-scoped network identity.
            name: User-provided display name, or empty to clear it.
        """
        if name:
            self.execute(
                "INSERT INTO network_names VALUES (?, ?) "
                "ON CONFLICT(network_id) DO UPDATE SET name=excluded.name",
                (network_id, name),
            )
        else:
            self.delete("network_names", "network_id=?", (network_id,))

    def has_network_profile(self, ip: str, network_id: str) -> bool:
        """Check whether a host was recorded under one network identity.

        Parameters:
            ip: Host address shown in the web interface.
            network_id: Network identity selected for naming.

        Returns:
            Whether the exact host-network pair exists.
        """
        try:
            normalized_ip = str(ipaddress.ip_address(ip))
        except ValueError:
            return False
        host_row = self.select(
            "hosts",
            columns="1",
            condition="network_id=? AND ip=?",
            params=(network_id, normalized_ip),
            limit=1,
        )
        return host_row is not None

    def _get_latest_mac_of_host(
        self, transaction_cursor: sqlite3.Cursor, network_id: str, ip: str
    ) -> str:
        """Read the newest usable MAC seen for one host profile.

        Parameters:
            transaction_cursor: Cursor of the open write transaction.
            network_id: Network the host belongs to.
            ip: Normalized host address.

        Returns:
            Normalized MAC, or an empty string when none is usable.
        """
        mac_row = transaction_cursor.execute(
            "SELECT value FROM facts WHERE network_id=? AND ip=? "
            "AND kind='mac' ORDER BY last_seen DESC LIMIT 1",
            (network_id, ip),
        ).fetchone()
        return self._normalize_unicast_mac(mac_row["value"] if mac_row else "")

    def _get_latest_stable_mdns_name_of_host(
        self, transaction_cursor: sqlite3.Cursor, network_id: str, ip: str
    ) -> str:
        """Read the newest mDNS name that identifies one host profile.

        Parameters:
            transaction_cursor: Cursor of the open write transaction.
            network_id: Network the host belongs to.
            ip: Normalized host address.

        Returns:
            Stable mDNS hostname, or an empty string when there is none.
        """
        mdns_rows = transaction_cursor.execute(
            "SELECT value FROM facts WHERE network_id=? AND ip=? "
            "AND kind='mdns_hostname' ORDER BY last_seen DESC",
            (network_id, ip),
        ).fetchall()
        for mdns_row in mdns_rows:
            stable_mdns_name = self._get_stable_mdns_name(mdns_row["value"])
            if stable_mdns_name:
                return stable_mdns_name
        return ""

    def set_host_annotation(
        self,
        ip: str,
        network_id: str,
        name: str,
        note: str,
        status: str | None = None,
        labels: list[str] | None = None,
    ) -> None:
        """Persist a user name and note for a host and its known device MAC.

        Everything is saved in one transaction, so a failed write never
        leaves half a review behind.

        Parameters:
            ip: Host IP address.
            network_id: Network identity already associated with this host.
            name: User name, or empty to clear it.
            note: User note, or empty to clear it.
            status: Optional review mark saved in the same transaction.
            labels: Optional custom labels saved with the mark.
        """
        normalized_ip = str(ipaddress.ip_address(ip))
        updated_at = time.time()
        with self._open_write_transaction() as transaction_cursor:
            device_mac = self._get_latest_mac_of_host(
                transaction_cursor, network_id, normalized_ip
            )
            stable_mdns_name = self._get_latest_stable_mdns_name_of_host(
                transaction_cursor, network_id, normalized_ip
            )
            if name or note:
                transaction_cursor.execute(
                    "INSERT INTO host_annotations VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(network_id, ip) DO UPDATE SET "
                    "name=excluded.name, note=excluded.note, "
                    "updated_at=excluded.updated_at",
                    (network_id, normalized_ip, name, note, updated_at),
                )
            else:
                transaction_cursor.execute(
                    "DELETE FROM host_annotations WHERE network_id=? AND ip=?",
                    (network_id, normalized_ip),
                )
            if device_mac and network_id != PUBLIC_NETWORK_ID:
                transaction_cursor.execute(
                    "INSERT INTO host_annotation_devices VALUES (?, ?, ?) "
                    "ON CONFLICT(network_id, ip) DO UPDATE SET "
                    "mac=excluded.mac",
                    (network_id, normalized_ip, device_mac),
                )
                transaction_cursor.execute(
                    "INSERT INTO device_annotations VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(mac) DO UPDATE SET name=excluded.name, "
                    "note=excluded.note, updated_at=excluded.updated_at",
                    (device_mac, name, note, updated_at),
                )
            if stable_mdns_name and not device_mac:
                transaction_cursor.execute(
                    "INSERT INTO mdns_identity_annotations "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(mdns_name) DO UPDATE SET name=excluded.name, "
                    "note=excluded.note, network_id=excluded.network_id, "
                    "ip=excluded.ip, updated_at=excluded.updated_at",
                    (
                        stable_mdns_name,
                        network_id,
                        normalized_ip,
                        name,
                        note,
                        updated_at,
                    ),
                )
            if status is not None:
                self._save_host_triage(
                    transaction_cursor,
                    normalized_ip,
                    network_id,
                    status,
                    labels or [],
                )

    def set_host_triage(
        self, ip: str, network_id: str, status: str, labels: list[str]
    ) -> None:
        """Persist review marks for a verified device or an exact host profile.

        Parameters:
            ip: Selected host address.
            network_id: Network to which the host belongs.
            status: Review workflow mark, or empty to clear it.
            labels: User-defined labels for the host.
        """
        with self._open_write_transaction() as transaction_cursor:
            self._save_host_triage(
                transaction_cursor, ip, network_id, status, labels
            )

    def _save_host_triage(
        self,
        transaction_cursor: sqlite3.Cursor,
        ip: str,
        network_id: str,
        status: str,
        labels: list[str],
    ) -> None:
        """Write review marks using the caller's transaction.

        Lets set_host_annotation() save the name, note and marks together.

        Parameters:
            transaction_cursor: Cursor of the open write transaction.
            ip: Selected host address.
            network_id: Network to which the host belongs.
            status: Review workflow mark, or empty to clear it.
            labels: User-defined labels for the host.
        """
        device_mac = self._get_latest_mac_of_host(
            transaction_cursor, network_id, ip
        )
        triage_subject = (
            f"mac:{device_mac}"
            if device_mac and network_id.startswith("gateway:")
            else f"host:{network_id}:{ip}"
        )
        transaction_cursor.execute(
            "INSERT INTO host_triage VALUES (?, ?, ?, ?) "
            "ON CONFLICT(subject) DO UPDATE SET status=excluded.status, "
            "labels=excluded.labels, updated_at=excluded.updated_at",
            (triage_subject, status, json.dumps(labels), time.time()),
        )

    def get_triage_of_profiles(
        self, ips: Iterable[str]
    ) -> dict[ProfileKey, dict[str, Any]]:
        """Read the review marks of every network profile of the given IPs.

        Parameters:
            ips: Addresses to resolve, including device member addresses.

        Returns:
            Effective status and labels indexed by network and address.
        """
        unique_ips = list(dict.fromkeys(ips))
        if not unique_ips:
            return {}
        triage_of_subject = {
            triage_row["subject"]: {
                "status": triage_row["status"],
                "labels": json.loads(triage_row["labels"]),
            }
            for triage_row in self._fetch_rows(
                "SELECT subject, status, labels FROM host_triage"
            )
        }
        triage_of_profile: dict[ProfileKey, dict[str, Any]] = {}
        for batch_start in range(0, len(unique_ips), MAX_IPS_PER_TRIAGE_QUERY):
            ip_batch = unique_ips[
                batch_start : batch_start + MAX_IPS_PER_TRIAGE_QUERY
            ]
            host_rows = self._fetch_rows(
                "SELECT h.network_id, h.ip, (SELECT value FROM facts f "
                "WHERE f.network_id=h.network_id AND f.ip=h.ip "
                "AND f.kind='mac' ORDER BY f.last_seen DESC LIMIT 1) AS mac "
                "FROM hosts h "
                f"WHERE h.ip IN ({self._make_placeholders(ip_batch)}) "
                "ORDER BY h.last_seen DESC",
                ip_batch,
            )
            for host_row in host_rows:
                network_id, ip = host_row["network_id"], host_row["ip"]
                device_mac = self._normalize_unicast_mac(host_row["mac"])
                device_subject = (
                    f"mac:{device_mac}"
                    if device_mac and network_id.startswith("gateway:")
                    else ""
                )
                triage = triage_of_subject.get(
                    device_subject,
                    triage_of_subject.get(f"host:{network_id}:{ip}"),
                )
                triage_of_profile[(network_id, ip)] = triage or {
                    "status": "",
                    "labels": [],
                }
        return triage_of_profile

    def get_last_observation_times(
        self, network_ids: Iterable[str]
    ) -> dict[str, float]:
        """Read seen hosts on selected networks without refreshing them.

        Parameters:
            network_ids: Verified networks and the current run fallback.

        Returns:
            Latest actual observation timestamp for each address.
        """
        unique_network_ids = list(
            dict.fromkeys(
                network_id for network_id in network_ids if network_id
            )
        )
        if not unique_network_ids:
            return {}
        observation_rows = self._fetch_rows(
            "SELECT ip, MAX(last_seen) AS last_seen "
            "FROM host_endpoint_observations WHERE network_id IN "
            f"({self._make_placeholders(unique_network_ids)}) GROUP BY ip",
            unique_network_ids,
        )
        return {
            str(observation_row["ip"]): float(observation_row["last_seen"])
            for observation_row in observation_rows
        }

    def get_triage_of_ips(
        self, ips: Iterable[str]
    ) -> dict[str, dict[str, Any]]:
        """Read the most recent review mark for each displayed host.

        Parameters:
            ips: Addresses in the inventory.

        Returns:
            Review status and labels indexed by address.
        """
        triage_of_ip: dict[str, dict[str, Any]] = {}
        for (_, ip), triage in self.get_triage_of_profiles(ips).items():
            triage_of_ip.setdefault(ip, triage)
        return triage_of_ip

    @staticmethod
    def _get_stable_mdns_name(observed_name: str | None) -> str:
        """Select a device mDNS hostname, excluding services and random IDs.

        Parameters:
            observed_name: Observed mDNS name.

        Returns:
            Canonical hostname, or an empty string when it is unsuitable.
        """
        mdns_name = str(observed_name or "").strip().lower().rstrip(".")
        hostname_match = re.fullmatch(
            r"([a-z0-9][a-z0-9-]{0,62})\.local", mdns_name
        )
        if not hostname_match:
            return ""
        host_label = hostname_match.group(1)
        is_random_uuid = re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}",
            host_label,
        )
        if is_random_uuid:
            return ""
        return mdns_name

    @staticmethod
    def _normalize_unicast_mac(observed_mac: str | None) -> str:
        """Accept a specific unicast MAC for matching one device.

        Parameters:
            observed_mac: MAC address stored with a host profile.

        Returns:
            Normalized MAC, or an empty string for an unusable address.
        """
        mac = str(observed_mac or "").strip().lower()
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            return ""
        is_group_address = int(mac[:2], 16) & 1
        if mac == "00:00:00:00:00:00" or is_group_address:
            return ""
        return mac

    def _get_stable_mdns_name_of_profiles(
        self, ips: list[str]
    ) -> dict[ProfileKey, str]:
        """Find the newest stable mDNS name of each profile of the given IPs.

        Parameters:
            ips: Addresses whose profiles are being named.

        Returns:
            Stable mDNS hostname indexed by network identity and IP.
        """
        mdns_name_of_profile: dict[ProfileKey, str] = {}
        for mdns_row in self._fetch_rows(
            "SELECT network_id, ip, value FROM facts "
            "WHERE kind='mdns_hostname' "
            f"AND ip IN ({self._make_placeholders(ips)}) "
            "ORDER BY last_seen DESC",
            ips,
        ):
            stable_mdns_name = self._get_stable_mdns_name(mdns_row["value"])
            if stable_mdns_name:
                mdns_name_of_profile.setdefault(
                    (mdns_row["network_id"], mdns_row["ip"]), stable_mdns_name
                )
        return mdns_name_of_profile

    def _get_annotations_saved_by_mdns_name(
        self, mdns_names: set[str]
    ) -> dict[str, dict[str, str]]:
        """Read annotations that were saved for a device without a MAC.

        Parameters:
            mdns_names: Stable mDNS hostnames of the displayed profiles.

        Returns:
            Name and note indexed by mDNS hostname.
        """
        annotation_of_mdns_name: dict[str, dict[str, str]] = {}
        for annotation_row in self._fetch_rows(
            "SELECT m.mdns_name, m.name, m.note, (SELECT value FROM facts f "
            "WHERE f.network_id=m.network_id AND f.ip=m.ip "
            "AND f.kind='mac' ORDER BY f.last_seen DESC LIMIT 1) "
            "AS source_mac FROM mdns_identity_annotations m "
            f"WHERE mdns_name IN ({self._make_placeholders(mdns_names)})",
            tuple(mdns_names),
        ):
            if self._normalize_unicast_mac(annotation_row["source_mac"]):
                # the device has a MAC now, so its MAC annotation wins
                continue
            annotation_of_mdns_name[annotation_row["mdns_name"]] = {
                "name": annotation_row["name"] or "",
                "note": annotation_row["note"] or "",
            }
        return annotation_of_mdns_name

    def _get_host_annotations_matching_mdns_names(
        self, mdns_names: set[str]
    ) -> dict[str, dict[str, str]]:
        """Read host annotations of MAC-less hosts that share an mDNS name.

        Covers annotations saved before mDNS names were stored on their own.

        Parameters:
            mdns_names: Stable mDNS hostnames of the displayed profiles.

        Returns:
            Newest name and note indexed by mDNS hostname.
        """
        annotation_of_mdns_name: dict[str, dict[str, str]] = {}
        for annotation_row in self._fetch_rows(
            f"SELECT a.name, a.note, f.value, {MAC_OF_ANNOTATION_SQL} "
            "AS source_mac FROM host_annotations a "
            "JOIN facts f ON f.network_id=a.network_id AND f.ip=a.ip "
            "AND f.kind='mdns_hostname' WHERE (a.name!='' OR a.note!='') "
            f"AND f.value IN ({self._make_placeholders(mdns_names)}) "
            "ORDER BY a.updated_at DESC, f.last_seen DESC",
            tuple(mdns_names),
        ):
            stable_mdns_name = self._get_stable_mdns_name(
                annotation_row["value"]
            )
            if stable_mdns_name and not self._normalize_unicast_mac(
                annotation_row["source_mac"]
            ):
                annotation_of_mdns_name.setdefault(
                    stable_mdns_name,
                    {
                        "name": annotation_row["name"] or "",
                        "note": annotation_row["note"] or "",
                    },
                )
        return annotation_of_mdns_name

    def _get_device_annotations(
        self, macs: set[str]
    ) -> dict[str, dict[str, str]]:
        """Read the annotations saved for the given device MACs.

        Parameters:
            macs: Usable MACs of the displayed profiles.

        Returns:
            Name and note indexed by MAC.
        """
        return {
            device_row["mac"]: {
                "name": device_row["name"] or "",
                "note": device_row["note"] or "",
            }
            for device_row in self._fetch_rows(
                "SELECT mac, name, note FROM device_annotations"
            )
            if device_row["mac"] in macs
        }

    def _get_host_annotations_matching_macs(
        self, macs: set[str]
    ) -> dict[str, dict[str, str]]:
        """Read host annotations whose address was owned by one of the MACs.

        Covers annotations saved before device MACs were stored on their own.

        Parameters:
            macs: Usable MACs of the displayed profiles.

        Returns:
            Newest name and note indexed by MAC.
        """
        annotation_of_mac: dict[str, dict[str, str]] = {}
        for annotation_row in self._fetch_rows(
            f"SELECT a.name, a.note, {MAC_OF_ANNOTATION_SQL} AS mac "
            "FROM host_annotations a WHERE a.network_id!='public' "
            "ORDER BY a.updated_at DESC"
        ):
            annotation_mac = self._normalize_unicast_mac(annotation_row["mac"])
            if annotation_mac in macs and (
                annotation_row["name"] or annotation_row["note"]
            ):
                annotation_of_mac.setdefault(
                    annotation_mac,
                    {
                        "name": annotation_row["name"] or "",
                        "note": annotation_row["note"] or "",
                    },
                )
        return annotation_of_mac

    def _resolve_annotations(
        self, ips: Iterable[str]
    ) -> dict[ProfileKey, dict[str, str]]:
        """Resolve profile names by device MAC, then exact host profile.

        Parameters:
            ips: IP addresses whose network profiles are being displayed.

        Returns:
            Effective annotations indexed by network identity and IP.
        """
        unique_ips = list(dict.fromkeys(ips))
        if not unique_ips:
            return {}
        host_rows = self._fetch_rows(
            "SELECT h.network_id, h.ip, a.name, a.note, "
            f"{LATEST_MAC_OF_HOST_SQL} AS mac, "
            f"{MAC_OF_ANNOTATION_SQL} AS annotation_mac FROM hosts h "
            "LEFT JOIN host_annotations a ON a.network_id=h.network_id "
            "AND a.ip=h.ip "
            f"WHERE h.ip IN ({self._make_placeholders(unique_ips)}) "
            "ORDER BY h.last_seen DESC",
            unique_ips,
        )
        local_macs = {
            self._normalize_unicast_mac(host_row["mac"])
            for host_row in host_rows
            if host_row["network_id"] != PUBLIC_NETWORK_ID
        } - {""}
        mdns_name_of_profile = self._get_stable_mdns_name_of_profiles(
            unique_ips
        )
        mdns_names = set(mdns_name_of_profile.values())
        annotations_saved_by_mdns_name: dict[str, dict[str, str]] = {}
        host_annotations_by_mdns_name: dict[str, dict[str, str]] = {}
        if mdns_names:
            annotations_saved_by_mdns_name = (
                self._get_annotations_saved_by_mdns_name(mdns_names)
            )
            host_annotations_by_mdns_name = (
                self._get_host_annotations_matching_mdns_names(mdns_names)
            )
        device_annotations = self._get_device_annotations(local_macs)
        host_annotations_by_mac = self._get_host_annotations_matching_macs(
            local_macs
        )

        annotation_of_profile: dict[ProfileKey, dict[str, str]] = {}
        for host_row in host_rows:
            network_id, ip = host_row["network_id"], host_row["ip"]
            name, note = host_row["name"], host_row["note"]
            is_local = network_id != PUBLIC_NETWORK_ID
            current_mac = (
                self._normalize_unicast_mac(host_row["mac"])
                if is_local
                else ""
            )
            annotation_mac = (
                self._normalize_unicast_mac(host_row["annotation_mac"])
                if is_local
                else ""
            )
            if annotation_mac and annotation_mac != current_mac:
                # the address belongs to another device now
                name = note = ""
            host_annotation = {"name": name or "", "note": note or ""}
            mdns_name = mdns_name_of_profile.get((network_id, ip), "")
            if current_mac in device_annotations:
                annotation = device_annotations[current_mac]
            elif name or note:
                annotation = host_annotation
            elif (
                not current_mac and mdns_name in annotations_saved_by_mdns_name
            ):
                annotation = annotations_saved_by_mdns_name[mdns_name]
            elif (
                not current_mac and mdns_name in host_annotations_by_mdns_name
            ):
                annotation = host_annotations_by_mdns_name[mdns_name]
            else:
                annotation = host_annotations_by_mac.get(
                    current_mac, host_annotation
                )
            annotation_of_profile[(network_id, ip)] = annotation
        return annotation_of_profile

    def get_hostname_of_profile(
        self,
        profileid: str,
        network_states: Iterable[dict[str, Any]],
        current_mac: str | None = None,
        cached_name: str | None = None,
    ) -> str | None:
        """Read a durable hostname for core consumers in their capture context.

        Parameters:
            profileid: Slips profile containing the endpoint address.
            network_states: Current settings of the monitored interfaces.
            current_mac: Optional cached hardware address to check ownership.
            cached_name: Fresh cache value used when durable ownership
                permits it.

        Returns:
            Learned name for this network/device, or None if unverified.
        """
        try:
            address = ipaddress.ip_address(profileid.removeprefix("profile_"))
        except (AttributeError, ValueError):
            return None
        ip = str(address)
        current_network_ids = []
        for network_state in network_states:
            if (
                not isinstance(network_state, dict)
                or network_state.get("connected") is False
            ):
                continue
            try:
                local_network = ipaddress.ip_network(
                    network_state.get("local_network", ""), strict=False
                )
            except ValueError:
                local_network = None
            if address.is_link_local or (
                local_network and address in local_network
            ):
                current_network_ids.append(
                    self.build_network_id(network_state, self.run_name)
                )
        current_network_ids.append(f"run:{self.run_name}")
        identity = self.get_identities_of_ips(
            [ip], current_network_ids, {ip: current_mac or ""}
        ).get(ip, {})
        if identity:
            return identity.get("name") or None
        is_known_on_another_network = bool(self.get_identities_of_ips([ip]))
        if is_known_on_another_network:
            # the cached name may belong to that other network's device
            return None
        return cached_name or None

    def _select_preferred_profile_of_ips(
        self, ip_batch: list[str], rank_of_network: dict[str, int]
    ) -> dict[str, ProfileKey]:
        """Pick the one network profile that best describes each address.

        Parameters:
            ip_batch: Addresses being resolved.
            rank_of_network: Preferred networks, the lowest rank wins. Empty
                selects the most recently seen profile.

        Returns:
            Chosen network identity and IP, indexed by address. Addresses
            with no profile on a preferred or public network are left out.
        """
        host_rows = self._fetch_rows(
            "SELECT h.network_id,h.ip,h.last_seen,"
            "o.last_seen AS endpoint_seen "
            "FROM hosts h LEFT JOIN host_endpoint_observations o "
            "ON o.network_id=h.network_id AND o.ip=h.ip "
            f"WHERE h.ip IN ({self._make_placeholders(ip_batch)}) "
            "ORDER BY h.last_seen DESC",
            ip_batch,
        )
        host_rows = sorted(
            host_rows,
            key=lambda host_row: (
                rank_of_network.get(
                    host_row["network_id"], len(rank_of_network)
                ),
                host_row["endpoint_seen"] is None,
                -float(host_row["endpoint_seen"] or host_row["last_seen"]),
            ),
        )
        profile_of_ip: dict[str, ProfileKey] = {}
        for host_row in host_rows:
            network_id = host_row["network_id"]
            if (
                rank_of_network
                and network_id not in rank_of_network
                and network_id != PUBLIC_NETWORK_ID
            ):
                continue
            profile_of_ip.setdefault(
                host_row["ip"], (network_id, host_row["ip"])
            )
        return profile_of_ip

    def _get_identity_facts_of_ips(
        self, ip_batch: list[str]
    ) -> dict[ProfileKey, list[sqlite3.Row]]:
        """Read the MACs and names of every profile of the given addresses.

        Parameters:
            ip_batch: Addresses being resolved.

        Returns:
            Fact rows, newest first, indexed by network identity and IP.
        """
        facts_of_profile: dict[ProfileKey, list[sqlite3.Row]] = {}
        for fact_row in self._fetch_rows(
            IDENTITY_FACTS_SQL.format(
                condition=f"ip IN ({self._make_placeholders(ip_batch)})"
            ),
            ip_batch,
        ):
            facts_of_profile.setdefault(
                (fact_row["network_id"], fact_row["ip"]), []
            ).append(fact_row)
        return facts_of_profile

    def _get_current_mac_of_ips(
        self,
        profile_of_ip: dict[str, ProfileKey],
        facts_of_profile: dict[ProfileKey, list[sqlite3.Row]],
        live_mac_of_ip: dict[str, str],
    ) -> tuple[dict[str, str], set[str]]:
        """Decide which device owns each address right now.

        Parameters:
            profile_of_ip: Chosen profile of each address.
            facts_of_profile: Stored facts of those profiles.
            live_mac_of_ip: MACs seen in the running capture, they win over
                the stored ones.

        Returns:
            The MAC of each address, and the addresses whose live MAC
            differs from the stored one.
        """
        mac_of_ip: dict[str, str] = {}
        ips_with_mac_conflict: set[str] = set()
        for ip, profile_key in profile_of_ip.items():
            stored_mac = next(
                (
                    self._normalize_unicast_mac(fact_row["value"])
                    for fact_row in facts_of_profile.get(profile_key, [])
                    if fact_row["kind"] == "mac"
                ),
                "",
            )
            live_mac = self._normalize_unicast_mac(live_mac_of_ip.get(ip))
            if live_mac and stored_mac and live_mac != stored_mac:
                ips_with_mac_conflict.add(ip)
            mac_of_ip[ip] = live_mac or stored_mac
        return mac_of_ip, ips_with_mac_conflict

    def _add_facts_of_profiles_sharing_macs(
        self,
        facts_of_profile: dict[ProfileKey, list[sqlite3.Row]],
        macs: list[str],
    ) -> None:
        """Load the facts of other addresses used by the same devices.

        A device keeps its MAC when its address changes, so a name learned
        on an old address still belongs to it.

        Parameters:
            facts_of_profile: Facts loaded so far, extended in place.
            macs: MACs of the addresses being resolved.
        """
        if not macs:
            return
        profiles_sharing_macs = self._fetch_rows(
            "SELECT DISTINCT network_id,ip FROM facts "
            f"WHERE kind='mac' AND value IN ({self._make_placeholders(macs)}) "
            "AND network_id!='public'",
            macs,
        )
        profiles_not_loaded = [
            (profile_row["network_id"], profile_row["ip"])
            for profile_row in profiles_sharing_macs
            if (profile_row["network_id"], profile_row["ip"])
            not in facts_of_profile
        ]
        for batch_start in range(
            0, len(profiles_not_loaded), MAX_IPS_PER_QUERY
        ):
            profile_batch = profiles_not_loaded[
                batch_start : batch_start + MAX_IPS_PER_QUERY
            ]
            pair_placeholders = ",".join("(?,?)" for _ in profile_batch)
            for fact_row in self._fetch_rows(
                IDENTITY_FACTS_SQL.format(
                    condition=f"(network_id,ip) IN ({pair_placeholders})"
                ),
                [
                    key_part
                    for profile_key in profile_batch
                    for key_part in profile_key
                ],
            ):
                facts_of_profile.setdefault(
                    (fact_row["network_id"], fact_row["ip"]), []
                ).append(fact_row)

    def _collect_name_candidates(
        self, facts_of_profile: dict[ProfileKey, list[sqlite3.Row]]
    ) -> tuple[
        dict[str, set[str]],
        dict[str, list[NameCandidate]],
        dict[ProfileKey, list[NameCandidate]],
    ]:
        """Sort every learned name by the device or profile it belongs to.

        A name belongs to a MAC only when exactly one MAC used the address
        while the name was seen. Profiles that never had a MAC keep their
        names to themselves.

        Parameters:
            facts_of_profile: MAC and name facts of the loaded profiles.

        Returns:
            Every MAC ever seen on each IP, name candidates of each MAC,
            and name candidates of each MAC-less profile.
        """
        macs_seen_on_ip: dict[str, set[str]] = {}
        candidates_of_mac: dict[str, list[NameCandidate]] = {}
        candidates_of_profile: dict[ProfileKey, list[NameCandidate]] = {}
        for profile_key, fact_rows in facts_of_profile.items():
            network_id, ip = profile_key
            mac_rows = [
                fact_row
                for fact_row in fact_rows
                if fact_row["kind"] == "mac"
                and self._normalize_unicast_mac(fact_row["value"])
            ]
            macs_seen_on_ip.setdefault(ip, set()).update(
                self._normalize_unicast_mac(mac_row["value"])
                for mac_row in mac_rows
            )
            for fact_row in fact_rows:
                fact_kind = fact_row["kind"]
                if fact_kind not in NAME_KIND_PRIORITY:
                    continue
                name = str(fact_row["value"] or "").strip()
                if fact_kind == "mdns_hostname":
                    name = self._get_stable_mdns_name(name)
                if not name:
                    continue
                name_candidate = (
                    NAME_KIND_PRIORITY[fact_kind],
                    float(fact_row["last_seen"]),
                    name,
                    NAME_KIND_LABELS[fact_kind],
                )
                owner_macs = {
                    self._normalize_unicast_mac(mac_row["value"])
                    for mac_row in mac_rows
                    if mac_row["first_seen"] <= fact_row["last_seen"]
                    and mac_row["last_seen"] >= fact_row["first_seen"]
                }
                if not owner_macs:
                    owner_macs = {
                        self._normalize_unicast_mac(mac_row["value"])
                        for mac_row in mac_rows
                        if mac_row["first_seen"] <= fact_row["last_seen"]
                    }
                if len(owner_macs) == 1 and network_id != PUBLIC_NETWORK_ID:
                    candidates_of_mac.setdefault(
                        next(iter(owner_macs)), []
                    ).append(name_candidate)
                if not mac_rows:
                    candidates_of_profile.setdefault(profile_key, []).append(
                        name_candidate
                    )
        return macs_seen_on_ip, candidates_of_mac, candidates_of_profile

    def _get_identities_of_ip_batch(
        self,
        ip_batch: list[str],
        rank_of_network: dict[str, int],
        live_mac_of_ip: dict[str, str],
    ) -> dict[str, dict[str, Any]]:
        """Resolve the identity of a group of addresses small enough to query.

        Parameters:
            ip_batch: Addresses being resolved.
            rank_of_network: Preferred networks, the lowest rank wins.
            live_mac_of_ip: MACs seen in the running capture.

        Returns:
            Names, sources and verified MACs indexed by address.
        """
        profile_of_ip = self._select_preferred_profile_of_ips(
            ip_batch, rank_of_network
        )
        if not profile_of_ip:
            return {}
        facts_of_profile = self._get_identity_facts_of_ips(ip_batch)
        mac_of_ip, ips_with_mac_conflict = self._get_current_mac_of_ips(
            profile_of_ip, facts_of_profile, live_mac_of_ip
        )
        self._add_facts_of_profiles_sharing_macs(
            facts_of_profile, sorted(set(mac_of_ip.values()) - {""})
        )
        macs_seen_on_ip, candidates_of_mac, candidates_of_profile = (
            self._collect_name_candidates(facts_of_profile)
        )
        identity_of_ip: dict[str, dict[str, Any]] = {}
        for ip, profile_key in profile_of_ip.items():
            network_id = profile_key[0]
            device_mac = (
                mac_of_ip[ip] if network_id != PUBLIC_NETWORK_ID else ""
            )
            name_candidates = (
                candidates_of_mac.get(device_mac, [])
                if device_mac
                else candidates_of_profile.get(profile_key, [])
            )
            best_candidate = (
                max(name_candidates, default=NO_NAME_CANDIDATE)
                if ip not in ips_with_mac_conflict
                else NO_NAME_CANDIDATE
            )
            _, _, name, name_source = best_candidate
            identity_of_ip[ip] = {
                "name": name,
                "source": name_source,
                "mac": device_mac,
            }
            other_macs_seen_on_ip = macs_seen_on_ip.get(ip, set()) - {
                device_mac
            }
            if device_mac and other_macs_seen_on_ip:
                identity_of_ip[ip]["identity_changed"] = True
        return identity_of_ip

    def get_identities_of_ips(
        self,
        ips: Iterable[str],
        network_ids: Iterable[str] = (),
        current_macs: dict[str, str] | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Recover learned device names from durable, scoped identity facts.

        Parameters:
            ips: Addresses whose displayed identity is being resolved.
            network_ids: Preferred capture networks; empty selects recent
                history.
            current_macs: Live MACs that override historical address
                ownership.

        Returns:
            Names, sources and verified MACs indexed by requested address.
        """
        unique_ips = list(dict.fromkeys(ips))
        if not unique_ips:
            return {}
        preferred_network_ids = list(
            dict.fromkeys(
                network_id for network_id in network_ids if network_id
            )
        )
        rank_of_network = {
            network_id: rank
            for rank, network_id in enumerate(preferred_network_ids)
        }
        identity_of_ip: dict[str, dict[str, Any]] = {}
        for batch_start in range(0, len(unique_ips), MAX_IPS_PER_QUERY):
            identity_of_ip.update(
                self._get_identities_of_ip_batch(
                    unique_ips[batch_start : batch_start + MAX_IPS_PER_QUERY],
                    rank_of_network,
                    current_macs or {},
                )
            )
        return identity_of_ip

    def get_annotations_of_ips(
        self, ips: Iterable[str], network_ids: Iterable[str] = ()
    ) -> dict[str, dict[str, str]]:
        """Read each displayed device's effective saved annotation.

        Parameters:
            ips: IP addresses displayed in the current view.
            network_ids: Selected capture networks; empty includes all
                history.

        Returns:
            User names and notes indexed by IP address.
        """
        annotation_of_profile = self._resolve_annotations(ips)
        rank_of_network = {
            network_id: rank
            for rank, network_id in enumerate(network_ids)
            if network_id
        }
        profiles_by_preference = (
            sorted(
                annotation_of_profile.items(),
                key=lambda profile_annotation: rank_of_network.get(
                    profile_annotation[0][0], len(rank_of_network)
                ),
            )
            if rank_of_network
            else annotation_of_profile.items()
        )
        annotation_of_ip: dict[str, dict[str, str]] = {}
        for (network_id, ip), annotation in profiles_by_preference:
            if (
                rank_of_network
                and network_id not in rank_of_network
                and network_id != PUBLIC_NETWORK_ID
            ):
                continue
            annotation_of_ip.setdefault(ip, annotation)
        return annotation_of_ip

    def _get_cached_network_state(self, interface: str) -> dict[str, Any]:
        """Read a recent network state for an interface.

        The state is cached for a few seconds, so a batch of flows doesn't
        ask Redis once per flow.

        Parameters:
            interface: Interface name from a flow or run configuration.

        Returns:
            Current network settings, or an empty dictionary.
        """
        if interface in self.interfaces:
            monitored_interface = interface
        elif len(self.interfaces) == 1:
            monitored_interface = self.interfaces[0]
        else:
            return {}
        now = time.monotonic()
        cached_entry = self._network_state_cache.get(monitored_interface)
        if cached_entry:
            cached_at, cached_network_state = cached_entry
            if now - cached_at < NETWORK_STATE_CACHE_SECONDS:
                return cached_network_state
        network_state = self.network_state_lookup(monitored_interface) or {}
        self._network_state_cache[monitored_interface] = (now, network_state)
        return network_state

    @staticmethod
    def _get_network_state_at(
        network_state: dict[str, Any], observed_at: float, flow: Any = None
    ) -> dict[str, Any]:
        """Select capture settings at packet time when replaying retained flows.

        Parameters:
            network_state: Current cached interface settings and bounded
                history.
            observed_at: Packet observation time.
            flow: Optional endpoints and hardware addresses for polling gaps.

        Returns:
            Recorded settings, or an unidentified network if history is
            missing.
        """
        return network_state_at(network_state, observed_at, flow) or {}

    def _get_network_identity_of_ip(
        self,
        ip: str,
        interface: str,
        network_state: dict[str, Any] | None = None,
    ) -> tuple[str, str, str] | None:
        """Find a safe public or network-specific key for an IP.

        Parameters:
            ip: Candidate host address.
            interface: Interface on which it was observed.
            network_state: Optional capture settings at the packet's
                timestamp.

        Returns:
            Normalized IP, network key, and display label when valid.
        """
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if (
            address.is_multicast
            or address.is_unspecified
            or address.is_loopback
        ):
            return None
        normalized_ip = str(address)
        if address.is_global:
            return normalized_ip, PUBLIC_NETWORK_ID, "Public internet"
        if network_state is None:
            network_state = self._get_cached_network_state(interface)
        try:
            local_network = ipaddress.ip_network(
                network_state.get("local_network", ""), strict=False
            )
        except ValueError:
            local_network = None
        gateway_mac = str(network_state.get("gateway_mac") or "").lower()
        if local_network and address in local_network and gateway_mac:
            return (
                normalized_ip,
                self.build_network_id(network_state, self.run_name),
                f"{local_network} · router {gateway_mac}",
            )
        if address.version == 6 and address.is_link_local and gateway_mac:
            link_interface = network_state.get("interface") or interface
            return (
                normalized_ip,
                self.build_network_id(network_state, self.run_name),
                f"Link-local on {link_interface} · router {gateway_mac}",
            )
        return (
            normalized_ip,
            self.build_network_id({}, self.run_name),
            f"Unidentified network · {self.run_name}",
        )

    def _drop_empty_and_repeated_facts(
        self,
        profile_key: ProfileKey,
        facts: list[tuple[str, str]],
        now: float,
    ) -> tuple[list[tuple[str, str]], str]:
        """Keep only the facts worth a database write.

        A MAC is seen in every flow of a host, so the same MAC is only
        written once per minute.

        Parameters:
            profile_key: Network identity and IP the facts describe.
            facts: Kind and value pairs learned from one observation.
            now: Monotonic time of the observation.

        Returns:
            The facts to save, and the MAC among them if there is one.
        """
        facts_to_save = []
        mac_to_save = ""
        for fact_kind, fact_value in facts:
            if not isinstance(fact_value, str) or not fact_value.strip():
                continue
            if fact_kind == "mac":
                fact_value = self._normalize_unicast_mac(fact_value)
                if not fact_value:
                    continue
                recent_mac, recent_mac_saved_at = self._recent_macs.get(
                    profile_key, ("", 0)
                )
                if (
                    recent_mac == fact_value
                    and now - recent_mac_saved_at
                    < REPEATED_WRITE_INTERVAL_SECONDS
                ):
                    continue
                mac_to_save = fact_value
            facts_to_save.append(
                (fact_kind, fact_value.strip()[:MAX_VALUE_LENGTH])
            )
        return facts_to_save, mac_to_save

    @staticmethod
    def _upsert_fact(
        transaction_cursor: sqlite3.Cursor,
        profile_key: ProfileKey,
        fact_kind: str,
        fact_value: str,
        observed_at: float,
    ) -> None:
        """Save one fact, unless the host already has too many of its kind.

        The limit stops a host that keeps changing e.g. its SNI from
        growing the store forever.

        Parameters:
            transaction_cursor: Cursor of the open write transaction.
            profile_key: Network identity and IP the fact describes.
            fact_kind: Type of the clue, e.g. "mac" or "hostname".
            fact_value: The clue itself.
            observed_at: Observation timestamp.
        """
        network_id, ip = profile_key
        is_known_fact = transaction_cursor.execute(
            "SELECT 1 FROM facts WHERE network_id=? AND ip=? "
            "AND kind=? AND value=?",
            (network_id, ip, fact_kind, fact_value),
        ).fetchone()
        if not is_known_fact:
            facts_of_this_kind = transaction_cursor.execute(
                "SELECT COUNT(*) FROM facts WHERE network_id=? "
                "AND ip=? AND kind=?",
                (network_id, ip, fact_kind),
            ).fetchone()[0]
            if facts_of_this_kind >= MAX_FACTS_PER_KIND:
                return
        transaction_cursor.execute(
            "INSERT INTO facts VALUES (?, ?, ?, ?, ?, ?, 1) "
            "ON CONFLICT(network_id, ip, kind, value) DO UPDATE SET "
            "first_seen=MIN(first_seen, excluded.first_seen), "
            "last_seen=MAX(last_seen, excluded.last_seen), "
            "observations=observations+1",
            (network_id, ip, fact_kind, fact_value, observed_at, observed_at),
        )

    def _save_host_facts(
        self,
        ip: str,
        interface: str,
        observed_at: float,
        facts: list[tuple[str, str]],
        observed_traffic: bool = False,
        from_packet: bool = False,
        capture_network_state: dict[str, Any] | None = None,
        transaction_cursor: sqlite3.Cursor | None = None,
    ) -> None:
        """Upsert a seen host and bounded distinct facts in one transaction.

        Parameters:
            ip: Observed host IP.
            interface: Capture interface.
            observed_at: Observation timestamp.
            facts: Kind and value pairs learned from this observation.
            observed_traffic: Whether a parsed packet flow caused the
                host-seen record.
            from_packet: Use capture-time settings for DNS-advertised
                metadata.
            capture_network_state: Already selected packet-time network
                settings.
            transaction_cursor: Cursor of the caller's open transaction.
                A new transaction is opened when it's missing.
        """
        network_state = self._resolve_network_state_for_host_seen(
            interface,
            observed_at,
            observed_traffic or from_packet,
            capture_network_state,
        )
        network_identity = self._get_network_identity_of_ip(
            ip, interface, network_state
        )
        if network_identity is None:
            return
        normalized_ip, network_id, network_label = network_identity
        profile_key = (network_id, normalized_ip)
        now = time.monotonic()
        seconds_since_host_last_seen = now - self._recent_host_seen.get(
            profile_key, 0
        )
        if (
            observed_traffic
            and seconds_since_host_last_seen >= REPEATED_WRITE_INTERVAL_SECONDS
        ):
            facts = self._add_own_mac_fact(facts, normalized_ip, network_state)
        facts_to_save, mac_to_save = self._drop_empty_and_repeated_facts(
            profile_key, facts, now
        )
        capture_network_id, capture_host_seen_key = (
            self._build_capture_host_seen_key(network_state, normalized_ip)
        )
        should_save_endpoint_observation = (
            observed_traffic
            and now - self._recent_host_seen.get(capture_host_seen_key, 0)
            >= REPEATED_WRITE_INTERVAL_SECONDS
        )
        if (
            not facts_to_save
            and not should_save_endpoint_observation
            and seconds_since_host_last_seen < REPEATED_WRITE_INTERVAL_SECONDS
        ):
            return
        transaction = (
            nullcontext(transaction_cursor)
            if transaction_cursor is not None
            else self._open_write_transaction()
        )
        with transaction as cursor:
            # ip info and hostnames arrive without a packet
            is_metadata_update = not observed_traffic and not from_packet
            network_id, network_label, should_save_host = (
                self._resolve_host_network_for_host_seen(
                    cursor,
                    network_id,
                    network_label,
                    normalized_ip,
                    is_metadata_update,
                )
            )
            profile_key = (network_id, normalized_ip)
            if should_save_endpoint_observation:
                self._upsert_endpoint_observation(
                    cursor, capture_network_id, normalized_ip, observed_at
                )
            if should_save_host:
                self._upsert_host(
                    cursor, profile_key, network_label, observed_at
                )
            for fact_kind, fact_value in dict.fromkeys(facts_to_save):
                self._upsert_fact(
                    cursor, profile_key, fact_kind, fact_value, observed_at
                )
        self._remember_host_seen(
            profile_key,
            (
                capture_host_seen_key
                if should_save_endpoint_observation
                else None
            ),
            mac_to_save,
            now,
        )

    def _resolve_network_state_for_host_seen(
        self,
        interface: str,
        observed_at: float,
        is_packet_time: bool,
        capture_network_state: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Pick the network settings a seen host should be judged against.

        A caller that already selected the packet-time settings wins.
        Otherwise packet-driven host-seen events use the settings that were
        active at the packet timestamp, and metadata-only updates use
        the current settings of the interface.

        Parameters:
            interface: Capture interface.
            observed_at: Observation timestamp.
            is_packet_time: Whether a packet caused the host-seen event.
            capture_network_state: Already selected packet-time network
                settings, or None.

        Returns:
            The network settings to use for this host-seen event.
        """
        if capture_network_state is not None:
            return capture_network_state
        network_state = self._get_cached_network_state(interface)
        if is_packet_time:
            return self._get_network_state_at(network_state, observed_at)
        return network_state

    def _add_own_mac_fact(
        self,
        facts: list[tuple[str, str]],
        normalized_ip: str,
        network_state: dict[str, Any],
    ) -> list[tuple[str, str]]:
        """Attach the capture host's own MAC when the seen host is its own IP.

        Packets sent by the capture host carry its MAC, but the parsed
        flow doesn't, so the MAC is taken from the interface settings.

        Parameters:
            facts: Kind and value pairs learned from this observation.
            normalized_ip: Observed host IP.
            network_state: Network settings at the time of the host-seen event.

        Returns:
            The facts, plus a "mac" fact when the IP belongs to the
            capture host and its MAC is a usable unicast address.
        """
        own_ips = {
            own_address.get("ip")
            for own_address in network_state.get("addresses", [])
        }
        if network_state.get("host_ip"):
            own_ips.add(network_state["host_ip"])
        if normalized_ip not in own_ips:
            return facts
        own_mac = self._normalize_unicast_mac(network_state.get("mac"))
        if not own_mac:
            return facts
        return [*facts, ("mac", own_mac)]

    def _build_capture_host_seen_key(
        self, network_state: dict[str, Any], normalized_ip: str
    ) -> tuple[str, ProfileKey]:
        """Build the throttle key for endpoint observations of this capture.

        The key changes whenever the capture network settings change,
        so a host is recorded once per network configuration it was
        seen under.

        Parameters:
            network_state: Network settings at the time of the host-seen event.
            normalized_ip: Observed host IP.

        Returns:
            The capture network id, and the key used to throttle
            repeated endpoint observation writes.
        """
        capture_network_id = self.build_network_id(
            network_state, self.run_name
        )
        capture_host_seen_key = (
            f"capture:{capture_network_id}:"
            f"{network_state.get('changed_at', '')}",
            normalized_ip,
        )
        return capture_network_id, capture_host_seen_key

    def _resolve_host_network_for_host_seen(
        self,
        cursor: sqlite3.Cursor,
        network_id: str,
        network_label: str,
        normalized_ip: str,
        is_metadata_update: bool,
    ) -> tuple[str, str, bool]:
        """Decide which network a host row belongs to and if it needs saving.

        A packet proves the host is on the network, so the row is always
        saved there. Metadata alone (ip info, hostnames) doesn't, so an
        unknown host is kept under this run's "unidentified" network
        instead of being invented on the real one. Public hosts aren't
        tied to a local network, so they're always saved.

        Parameters:
            cursor: Cursor of the open write transaction.
            network_id: Network the seen host resolved to.
            network_label: Human readable name of that network.
            normalized_ip: Observed host IP.
            is_metadata_update: Whether it came without a packet.

        Returns:
            The network id and label to save under, and whether the
            host row should be written.
        """
        if not is_metadata_update or network_id == PUBLIC_NETWORK_ID:
            return network_id, network_label, True
        if self._is_host_known_on_network(cursor, (network_id, normalized_ip)):
            return network_id, network_label, False
        unidentified_network_id = self.build_network_id({}, self.run_name)
        unidentified_label = f"Unidentified network · {self.run_name}"
        should_save_host = not self._is_host_known_on_network(
            cursor, (unidentified_network_id, normalized_ip)
        )
        return unidentified_network_id, unidentified_label, should_save_host

    @staticmethod
    def _is_host_known_on_network(
        cursor: sqlite3.Cursor, profile_key: ProfileKey
    ) -> bool:
        """Check whether a host row already exists for this network and IP.

        Parameters:
            cursor: Cursor of the open write transaction.
            profile_key: Network identity and IP to look up.

        Returns:
            True when the host row exists.
        """
        return bool(
            cursor.execute(
                "SELECT 1 FROM hosts WHERE network_id=? AND ip=?",
                profile_key,
            ).fetchone()
        )

    @staticmethod
    def _upsert_endpoint_observation(
        cursor: sqlite3.Cursor,
        capture_network_id: str,
        normalized_ip: str,
        observed_at: float,
    ) -> None:
        """Record that an IP was seen as a traffic endpoint of this capture.

        Parameters:
            cursor: Cursor of the open write transaction.
            capture_network_id: Network id of the capture itself.
            normalized_ip: Observed host IP.
            observed_at: Observation timestamp.
        """
        cursor.execute(
            "INSERT INTO host_endpoint_observations "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(network_id, ip) DO UPDATE SET "
            "first_seen=MIN(first_seen, excluded.first_seen), "
            "last_seen=MAX(last_seen, excluded.last_seen)",
            (capture_network_id, normalized_ip, observed_at, observed_at),
        )

    @staticmethod
    def _upsert_host(
        cursor: sqlite3.Cursor,
        profile_key: ProfileKey,
        network_label: str,
        observed_at: float,
    ) -> None:
        """Create the host row or widen its first/last seen window.

        Parameters:
            cursor: Cursor of the open write transaction.
            profile_key: Network identity and IP of the host.
            network_label: Human readable name of the network.
            observed_at: Observation timestamp.
        """
        network_id, normalized_ip = profile_key
        cursor.execute(
            "INSERT INTO hosts VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(network_id, ip) DO UPDATE SET "
            "network_label=excluded.network_label, "
            "first_seen=MIN(first_seen, excluded.first_seen), "
            "last_seen=MAX(last_seen, excluded.last_seen)",
            (
                network_id,
                normalized_ip,
                network_label,
                observed_at,
                observed_at,
            ),
        )

    def _remember_host_seen(
        self,
        profile_key: ProfileKey,
        capture_host_seen_key: ProfileKey | None,
        mac_to_save: str,
        now: float,
    ) -> None:
        """Update the in-memory throttles after a successful write.

        The caches are bounded by clearing them wholesale once they grow
        past their limit, which only costs a few extra writes later.

        Parameters:
            profile_key: Network identity and IP that was just saved.
            capture_host_seen_key: Endpoint observation key to refresh, or
                None when no endpoint observation was written.
            mac_to_save: MAC that was just saved, empty when none was.
            now: Monotonic time of the write.
        """
        self._recent_host_seen[profile_key] = now
        if mac_to_save:
            self._recent_macs[profile_key] = (mac_to_save, now)
            if len(self._recent_macs) > MAX_RECENT_MACS:
                self._recent_macs.clear()
        if capture_host_seen_key is not None:
            self._recent_host_seen[capture_host_seen_key] = now
        if len(self._recent_host_seen) > MAX_RECENT_HOST_SEEN:
            self._recent_host_seen.clear()

    @staticmethod
    def _get_local_link_mac(
        ip: str,
        observed_mac: str,
        network_state: dict[str, Any],
        is_arp_binding: bool = False,
    ) -> str:
        """Accept an endpoint MAC only when the address belongs to this link.

        Parameters:
            ip: Endpoint address.
            observed_mac: Ethernet or ARP hardware address.
            network_state: Capture settings at the packet timestamp.
            is_arp_binding: Whether the ARP payload explicitly binds the
                address.

        Returns:
            Usable local MAC, or an empty string for routed or invalid
            addresses.
        """
        mac = HostProfileStore._normalize_unicast_mac(observed_mac)
        if not mac:
            return ""
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return ""
        if (
            address.is_global
            or address.is_multicast
            or address.is_unspecified
            or address.is_loopback
        ):
            return ""
        own_ips = {
            own_address.get("ip")
            for own_address in network_state.get("addresses", [])
        }
        own_ips.add(network_state.get("host_ip"))
        own_mac = HostProfileStore._normalize_unicast_mac(
            network_state.get("mac")
        )
        if str(address) in own_ips and own_mac and mac != own_mac:
            return ""
        if is_arp_binding:
            return mac
        gateway_mac = HostProfileStore._normalize_unicast_mac(
            network_state.get("gateway_mac")
        )
        if mac == gateway_mac and str(address) != network_state.get(
            "gateway_ip"
        ):
            # a routed packet carries the router's MAC, not the host's
            return ""
        if address.is_link_local:
            return mac
        local_network_cidrs = [
            network_state.get("local_network", ""),
            *(
                own_address.get("network", "")
                for own_address in network_state.get("addresses", [])
            ),
        ]
        for local_network_cidr in local_network_cidrs:
            try:
                local_network = ipaddress.ip_network(
                    local_network_cidr, strict=False
                )
            except ValueError:
                continue
            if (
                address in local_network
                and address != local_network.broadcast_address
            ):
                return mac
        return ""

    @staticmethod
    def _get_observation_time_of_flow(flow: Any) -> float:
        """Read when a flow started, as a Unix timestamp.

        Parameters:
            flow: Parsed flow.

        Returns:
            Start time of the flow, or the current time when it's missing.
        """
        try:
            return float(
                utils.convert_ts_format(
                    getattr(flow, "starttime", None), "unixtimestamp"
                )
            )
        except (TypeError, ValueError, AttributeError):
            return time.time()

    def _get_endpoint_macs_of_flow(
        self,
        flow: Any,
        source_ip: str,
        destination_ip: str,
        capture_network_state: dict[str, Any],
    ) -> tuple[str, str]:
        """Read the MACs that a conn or ARP flow proves for its endpoints.

        Parameters:
            flow: Parsed conn or ARP flow.
            source_ip: Source address of the flow.
            destination_ip: Destination address of the flow.
            capture_network_state: Network settings at the packet timestamp.

        Returns:
            Source and destination MACs, each empty when it isn't a local
            device's.
        """
        is_arp = str(getattr(flow, "type_", "") or "").lower() == "arp"
        if is_arp:
            source_mac = str(
                getattr(flow, "src_hw", "") or getattr(flow, "smac", "") or ""
            )
            destination_mac = str(getattr(flow, "dst_hw", "") or "")
        else:
            source_mac = str(getattr(flow, "smac", "") or "")
            destination_mac = str(getattr(flow, "dmac", "") or "")
        return (
            self._get_local_link_mac(
                source_ip, source_mac, capture_network_state, is_arp
            ),
            self._get_local_link_mac(
                destination_ip, destination_mac, capture_network_state, is_arp
            ),
        )

    @staticmethod
    def _get_http_facts_of_flow(flow: Any) -> list[tuple[str, str]]:
        """Read the host and URL an HTTP flow reveals about its server.

        Parameters:
            flow: Parsed HTTP flow.

        Returns:
            Kind and value pairs for the destination host.
        """
        http_host = str(getattr(flow, "host", "") or "")
        uri = str(getattr(flow, "uri", "") or "")
        http_facts = [("http_host", http_host)]
        if uri.startswith(("http://", "https://")):
            http_facts.append(("url", uri))
        elif http_host and uri:
            url_path = uri if uri.startswith("/") else f"/{uri}"
            http_facts.append(("url", f"http://{http_host}{url_path}"))
        return http_facts

    def _save_names_from_dns_flow(
        self,
        flow: Any,
        interface: str,
        observed_at: float,
        capture_network_state: dict[str, Any],
        transaction_cursor: sqlite3.Cursor,
    ) -> None:
        """Store the names a DNS or mDNS flow gives to other addresses.

        Parameters:
            flow: Parsed DNS flow.
            interface: Capture interface.
            observed_at: Observation timestamp.
            capture_network_state: Network settings at the packet timestamp.
            transaction_cursor: Cursor of the open write transaction.
        """
        dns_query = str(getattr(flow, "query", "") or "")
        is_mdns = "5353" in {
            str(getattr(flow, "sport", "") or ""),
            str(getattr(flow, "dport", "") or ""),
        }
        if is_mdns:
            mdns_bindings = getattr(flow, "mdns_bindings", []) or []
            if isinstance(mdns_bindings, str):
                mdns_bindings = mdns_bindings.split(",")
            for mdns_binding in mdns_bindings[:MAX_MDNS_BINDINGS_PER_FLOW]:
                owner_name, separator, bound_ip = str(mdns_binding).partition(
                    "|"
                )
                stable_mdns_name = self._get_stable_mdns_name(owner_name)
                if separator and stable_mdns_name:
                    self._save_host_facts(
                        bound_ip,
                        interface,
                        observed_at,
                        [("mdns_hostname", stable_mdns_name)],
                        from_packet=True,
                        capture_network_state=capture_network_state,
                        transaction_cursor=transaction_cursor,
                    )
        for dns_answer in getattr(flow, "answers", []) or []:
            if isinstance(dns_answer, dict):
                dns_answer = (
                    dns_answer.get("rdata") or dns_answer.get("data") or ""
                )
            self._save_host_facts(
                str(dns_answer),
                interface,
                observed_at,
                [] if is_mdns else [("dns_name", dns_query)],
                from_packet=True,
                capture_network_state=capture_network_state,
                transaction_cursor=transaction_cursor,
            )

    def _save_identity_from_flow(
        self, flow: Any, transaction_cursor: sqlite3.Cursor
    ) -> None:
        """Store both endpoints and names learned from one parsed flow.

        Parameters:
            flow: Conn, DNS, HTTP, TLS, DHCP, or other parsed flow.
            transaction_cursor: Cursor of the open write transaction.
        """
        interface = str(getattr(flow, "interface", "") or "")
        observed_at = self._get_observation_time_of_flow(flow)
        source_ip = str(getattr(flow, "saddr", "") or "")
        destination_ip = str(getattr(flow, "daddr", "") or "")
        flow_type = str(getattr(flow, "type_", "") or "").lower()
        capture_network_state = self._get_network_state_at(
            self._get_cached_network_state(interface), observed_at, flow
        )
        # -------------------------------------------
        source_facts: list[tuple[str, str]] = []
        destination_facts: list[tuple[str, str]] = []
        if flow_type in {"arp", "conn"}:
            source_mac, destination_mac = self._get_endpoint_macs_of_flow(
                flow, source_ip, destination_ip, capture_network_state
            )
            source_facts.append(("mac", source_mac))
            destination_facts.append(("mac", destination_mac))

        if flow_type == "dhcp":
            if self._get_network_identity_of_ip(source_ip, interface) is None:
                # a client asking for an address has no usable source yet
                source_ip = str(getattr(flow, "requested_addr", "") or "")
            source_facts.extend(
                [
                    ("hostname", str(getattr(flow, "host_name", "") or "")),
                    ("mac", str(getattr(flow, "smac", "") or "")),
                ]
            )

        elif flow_type == "http":
            destination_facts.extend(self._get_http_facts_of_flow(flow))
        elif flow_type in {"ssl", "tls"}:
            destination_facts.append(
                ("sni", str(getattr(flow, "server_name", "") or ""))
            )
        elif flow_type == "dns":
            self._save_names_from_dns_flow(
                flow,
                interface,
                observed_at,
                capture_network_state,
                transaction_cursor,
            )

        for endpoint_ip, endpoint_facts in (
            (source_ip, source_facts),
            (destination_ip, destination_facts),
        ):
            self._save_host_facts(
                endpoint_ip,
                interface,
                observed_at,
                endpoint_facts,
                observed_traffic=True,
                capture_network_state=capture_network_state,
                transaction_cursor=transaction_cursor,
            )

    def save_host_identity_from_flow(self, flow: Any) -> None:
        """Store both endpoints and names learned from one parsed flow.

        Parameters:
            flow: Conn, DNS, HTTP, TLS, DHCP, or other parsed flow.
        """
        with self._open_write_transaction() as transaction_cursor:
            self._save_identity_from_flow(flow, transaction_cursor)

    def save_host_identity_from_flows(self, flows: Iterable[Any]) -> None:
        """Persist one bounded flow batch in a single SQLite transaction.

        Parameters:
            flows: Parsed flow objects read by the host profile module.
        """
        with self._open_write_transaction() as transaction_cursor:
            for flow in flows:
                self._save_identity_from_flow(flow, transaction_cursor)

    def save_host_identity_from_ip_info(
        self, ip: str, ip_info: dict[str, Any]
    ) -> None:
        """Keep learned reverse DNS, SNI, and threat feed appearances.

        Parameters:
            ip: Address being enriched.
            ip_info: Redis IPInfo fields written by a Slips module.
        """
        try:
            is_public = ipaddress.ip_address(ip).is_global
        except ValueError:
            return
        facts: list[tuple[str, str]] = []
        reverse_dns = ip_info.get("reverse_dns")
        if reverse_dns:
            facts.append(("reverse_dns", str(reverse_dns)))
        asn = ip_info.get("asn")
        if isinstance(asn, dict):
            asn_description = " ".join(
                str(asn.get(asn_field, "") or "")
                for asn_field in ("number", "org")
            ).strip()
            facts.append(("asn", asn_description))
        country = ip_info.get("geocountry")
        is_real_country = country and str(country).strip().casefold() not in {
            "private",
            "unknown",
        }
        if is_public and is_real_country:
            facts.append(("country", str(country)))
        server_names = ip_info.get("SNI") or []
        if not isinstance(server_names, list):
            server_names = [server_names]
        for server_name in server_names:
            if isinstance(server_name, dict):
                facts.append(("sni", str(server_name.get("server_name", ""))))
        threat_intelligence = ip_info.get("threatintelligence") or {}
        if isinstance(threat_intelligence, dict):
            threat_feeds = threat_intelligence.get("source", [])
            if not isinstance(threat_feeds, list):
                threat_feeds = [threat_feeds]
            for threat_feed in threat_feeds:
                facts.append(("threat_feed", str(threat_feed)))
        if facts:
            self._save_host_facts(ip, "", time.time(), facts)

    def save_hostname_of_profile(self, hostname: str, profileid: str) -> None:
        """Persist a name learned through a host profile update.

        Parameters:
            hostname: Newly learned hostname.
            profileid: Profile identifier containing the host IP.
        """
        self._save_host_facts(
            profileid.removeprefix("profile_"),
            "",
            time.time(),
            [("hostname", hostname)],
        )

    def _get_endpoint_times_of_ip(
        self, ip: str, network_ids: list[str]
    ) -> dict[str, tuple[float, float]]:
        """Read when an address really sent or received traffic per network.

        Parameters:
            ip: Normalized host address.
            network_ids: Networks the address has a profile on.

        Returns:
            First and last time seen indexed by network identity.
        """
        return {
            str(observation_row["network_id"]): (
                float(observation_row["first_seen"]),
                float(observation_row["last_seen"]),
            )
            for observation_row in self._fetch_rows(
                "SELECT network_id, first_seen, last_seen "
                "FROM host_endpoint_observations WHERE ip=? "
                f"AND network_id IN ({self._make_placeholders(network_ids)})",
                (ip, *network_ids),
            )
        }

    def get_host_profiles(self, ip: str) -> list[dict[str, Any]]:
        """Read all network-separated profiles for one host address.

        Parameters:
            ip: Host address shown in the web interface.

        Returns:
            Profiles and their clues, newest network first.
        """
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return []
        normalized_ip = str(address)
        host_rows = self._fetch_rows(
            "SELECT * FROM hosts WHERE ip=? "
            "ORDER BY last_seen DESC LIMIT 50",
            (normalized_ip,),
        )
        if not host_rows:
            return []
        network_ids = [host_row["network_id"] for host_row in host_rows]
        network_names = self.get_network_names(network_ids)
        annotation_of_profile = self._resolve_annotations((normalized_ip,))
        endpoint_times_of_network = self._get_endpoint_times_of_ip(
            normalized_ip, network_ids
        )
        host_profiles = []
        for host_row in host_rows:
            network_id = host_row["network_id"]
            fact_rows = self._fetch_rows(
                "SELECT kind, value, first_seen, last_seen, observations "
                "FROM facts WHERE network_id=? AND ip=? "
                "ORDER BY last_seen DESC",
                (network_id, normalized_ip),
            )
            annotation = annotation_of_profile.get(
                (network_id, normalized_ip), {}
            )
            endpoint_first_seen, endpoint_last_seen = (
                endpoint_times_of_network.get(network_id, (None, None))
            )
            host_profiles.append(
                {
                    **dict(host_row),
                    "default_network_label": host_row["network_label"],
                    "network_name": network_names.get(network_id, ""),
                    "network_label": network_names.get(
                        network_id, host_row["network_label"]
                    ),
                    "user_name": annotation.get("name", ""),
                    "user_note": annotation.get("note", ""),
                    "endpoint_first_seen": endpoint_first_seen,
                    "endpoint_last_seen": endpoint_last_seen,
                    "facts": [
                        dict(fact_row)
                        for fact_row in fact_rows
                        if fact_row["kind"] != "country"
                        or (
                            address.is_global
                            and str(fact_row["value"]).strip().casefold()
                            not in {"private", "unknown"}
                        )
                    ],
                }
            )
        return host_profiles
