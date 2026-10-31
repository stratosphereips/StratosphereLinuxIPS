# SPDX-License-Identifier: GPL-2.0-only
"""Keep durable, network-scoped identity clues for observed hosts."""

import ipaddress
import json
import os
import re
import sqlite3
import time
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Callable, Iterable

from slips_files.common.slips_utils import utils
from slips_files.common.network_context import network_state_at

MAX_FACTS_PER_KIND = 200
MAX_VALUE_LENGTH = 2048


class HostProfileStore:
    """Persist host sightings and distinct identity clues across Slips runs."""

    def __init__(
        self,
        path: Path,
        run_name: str,
        network_lookup: Callable[[str], dict[str, Any] | None],
        interfaces: list[str],
    ) -> None:
        """Create the shared store and remember how to identify live networks.

        Parameters:
            path: SQLite path in the configured permanent directory.
            run_name: Output directory used to isolate unknown local networks.
            network_lookup: Lookup for a monitored interface's current state.
            interfaces: Monitored interface names.
        """
        self.path = path
        self.run_name = run_name
        self.network_lookup = network_lookup
        self.interfaces = interfaces
        self._network_cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._recent_sightings: dict[tuple[str, str], float] = {}
        self._recent_macs: dict[tuple[str, str], tuple[str, float]] = {}
        self._active_connection: sqlite3.Connection | None = None
        path.parent.mkdir(parents=True, exist_ok=True)
        if os.geteuid() == 0:
            owner = Path.cwd().stat()
            os.chown(path.parent, owner.st_uid, owner.st_gid)
        path.parent.chmod(0o700)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS hosts ("
                "network_id TEXT NOT NULL, ip TEXT NOT NULL, "
                "network_label TEXT NOT NULL, first_seen REAL NOT NULL, "
                "last_seen REAL NOT NULL, "
                "PRIMARY KEY (network_id, ip))"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS host_observations ("
                "network_id TEXT NOT NULL, ip TEXT NOT NULL, "
                "first_seen REAL NOT NULL, last_seen REAL NOT NULL, "
                "PRIMARY KEY(network_id, ip))"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS host_endpoint_observations ("
                "network_id TEXT NOT NULL, ip TEXT NOT NULL, "
                "first_seen REAL NOT NULL, last_seen REAL NOT NULL, "
                "PRIMARY KEY(network_id, ip))"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS host_endpoint_ip_idx "
                "ON host_endpoint_observations(ip, first_seen, last_seen)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS facts ("
                "network_id TEXT NOT NULL, ip TEXT NOT NULL, "
                "kind TEXT NOT NULL, value TEXT NOT NULL, "
                "first_seen REAL NOT NULL, last_seen REAL NOT NULL, "
                "observations INTEGER NOT NULL DEFAULT 1, "
                "PRIMARY KEY (network_id, ip, kind, value))"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS facts_host_idx "
                "ON facts(network_id, ip, kind, last_seen DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS facts_mac_lookup_idx ON facts(kind,value,network_id,ip)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS facts_ip_kind_idx ON facts(ip,kind,last_seen DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS hosts_ip_seen_idx ON hosts(ip,last_seen DESC)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS network_names ("
                "network_id TEXT PRIMARY KEY, name TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS host_annotations ("
                "network_id TEXT NOT NULL, ip TEXT NOT NULL, "
                "name TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', "
                "updated_at REAL NOT NULL, PRIMARY KEY (network_id, ip))"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS device_annotations ("
                "mac TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', "
                "note TEXT NOT NULL DEFAULT '', updated_at REAL NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS host_annotation_devices ("
                "network_id TEXT NOT NULL, ip TEXT NOT NULL, mac TEXT NOT NULL, "
                "PRIMARY KEY(network_id, ip))"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS mdns_annotations ("
                "mdns_name TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', "
                "note TEXT NOT NULL DEFAULT '', updated_at REAL NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS mdns_identity_annotations ("
                "mdns_name TEXT PRIMARY KEY, network_id TEXT NOT NULL, "
                "ip TEXT NOT NULL, name TEXT NOT NULL, note TEXT NOT NULL, "
                "updated_at REAL NOT NULL)"
            )
        if os.geteuid() == 0:
            os.chown(path, owner.st_uid, owner.st_gid)
        path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        """Open one transaction-safe connection to the shared SQLite file.

        Returns:
            Configured SQLite connection.
        """
        connection = sqlite3.connect(self.path, timeout=20)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def network_id_for_state(state: dict[str, Any], run_name: str) -> str:
        """Identify a network by router MAC or isolate it to one run.

        Parameters:
            state: Current interface settings.
            run_name: Run identifier for networks without a known router.

        Returns:
            Network identity suitable for storing a user-provided name.
        """
        gateway_mac = str(state.get("gateway_mac") or "").strip().lower()
        if gateway_mac:
            return f"gateway:{gateway_mac}"
        return f"run:{run_name}" if run_name else ""

    @staticmethod
    def _network_names_from_connection(
        connection: sqlite3.Connection, network_ids: Iterable[str]
    ) -> dict[str, str]:
        """Read selected names using an already open SQLite connection.

        Parameters:
            connection: Open host profile database connection.
            network_ids: Network identities to look up.

        Returns:
            Saved names indexed by network identity.
        """
        keys = list(dict.fromkeys(key for key in network_ids if key))
        if not keys:
            return {}
        placeholders = ",".join("?" for _ in keys)
        try:
            return {
                network_id: name
                for network_id, name in connection.execute(
                    "SELECT network_id, name FROM network_names "
                    f"WHERE network_id IN ({placeholders})",
                    keys,
                )
            }
        except sqlite3.OperationalError:
            return {}

    @staticmethod
    def network_names(
        path: Path, network_ids: Iterable[str]
    ) -> dict[str, str]:
        """Read user-provided names for a bounded set of networks.

        Parameters:
            path: Permanent host profile database.
            network_ids: Network identities to look up.

        Returns:
            Saved names indexed by network identity.
        """
        if not path.exists():
            return {}
        with sqlite3.connect(
            f"file:{path}?mode=ro", uri=True, timeout=1
        ) as connection:
            return HostProfileStore._network_names_from_connection(
                connection, network_ids
            )

    @staticmethod
    def network_for_observation(
        path: Path, ip: str, observed_at: float
    ) -> dict[str, str]:
        """Resolve the saved network for an address at an event timestamp.

        Parameters:
            path: Permanent host profile database path.
            ip: Host address associated with the detection.
            observed_at: Detection time as a Unix timestamp.

        Returns:
            Network identity and display name, or an explicit unknown label.
        """
        unknown = {
            "network_id": "",
            "network_name": "",
            "network_label": "Unknown network (not recorded)",
        }
        try:
            normalized_ip = str(ipaddress.ip_address(ip))
            timestamp = float(observed_at)
        except (TypeError, ValueError):
            return unknown
        if not path.exists():
            return unknown
        if ipaddress.ip_address(normalized_ip).is_global:
            return {
                "network_id": "public",
                "network_name": "",
                "network_label": "Public internet",
            }
        try:
            with sqlite3.connect(
                f"file:{path}?mode=ro", uri=True, timeout=5
            ) as connection:
                rows = connection.execute(
                    "SELECT o.network_id, COALESCE(h.network_label,''), "
                    "o.first_seen, o.last_seen, n.name "
                    "FROM host_endpoint_observations o "
                    "LEFT JOIN hosts h ON h.network_id=o.network_id AND h.ip=o.ip "
                    "LEFT JOIN network_names n ON n.network_id=o.network_id "
                    "WHERE o.ip=?",
                    (normalized_ip,),
                ).fetchall()
        except sqlite3.Error:
            return unknown
        matching = [row for row in rows if row[2] <= timestamp <= row[3]]
        network_ids = {str(row[0]) for row in matching}
        if len(network_ids) != 1:
            if len(network_ids) > 1:
                return {
                    "network_id": ",".join(sorted(network_ids)),
                    "network_name": "",
                    "network_label": "Multiple networks",
                }
            return unknown
        row = matching[0]
        network_name = str(row[4] or "")
        return {
            "network_id": str(row[0]),
            "network_name": network_name,
            "network_label": network_name
            or str(row[1])
            or f"Captured network · {row[0]}",
        }

    @staticmethod
    def set_network_name(path: Path, network_id: str, name: str) -> None:
        """Save or clear one network name in the permanent database.

        Parameters:
            path: Permanent host profile database.
            network_id: Router or run-scoped network identity.
            name: User-provided display name, or empty to clear it.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        path.parent.chmod(0o700)
        with sqlite3.connect(path, timeout=5) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS network_names ("
                "network_id TEXT PRIMARY KEY, name TEXT NOT NULL)"
            )
            if name:
                connection.execute(
                    "INSERT INTO network_names VALUES (?, ?) "
                    "ON CONFLICT(network_id) DO UPDATE SET name=excluded.name",
                    (network_id, name),
                )
            else:
                connection.execute(
                    "DELETE FROM network_names WHERE network_id=?",
                    (network_id,),
                )
        path.chmod(0o600)

    @staticmethod
    def has_network_profile(path: Path, ip: str, network_id: str) -> bool:
        """Check whether a host was recorded under one network identity.

        Parameters:
            path: Permanent host profile database.
            ip: Host address shown in the web interface.
            network_id: Network identity selected for naming.

        Returns:
            Whether the exact host-network pair exists.
        """
        try:
            normalized = str(ipaddress.ip_address(ip))
        except ValueError:
            return False
        if not path.exists():
            return False
        with sqlite3.connect(
            f"file:{path}?mode=ro", uri=True, timeout=1
        ) as connection:
            return (
                connection.execute(
                    "SELECT 1 FROM hosts WHERE network_id=? AND ip=? LIMIT 1",
                    (network_id, normalized),
                ).fetchone()
                is not None
            )

    @staticmethod
    def set_host_annotation(
        path: Path,
        ip: str,
        network_id: str,
        name: str,
        note: str,
        status: str | None = None,
        labels: list[str] | None = None,
    ) -> None:
        """Persist a user name and note for a host and its known device MAC.

        Parameters:
            path: Permanent host profile database.
            ip: Host IP address.
            network_id: Network identity already associated with this host.
            name: User name, or empty to clear it.
            note: User note, or empty to clear it.
            status: Optional review mark saved in the same transaction.
            labels: Optional custom labels saved with the mark.
        """
        normalized = str(ipaddress.ip_address(ip))
        with sqlite3.connect(path, timeout=5) as connection:
            mac_row = connection.execute(
                "SELECT value FROM facts WHERE network_id=? AND ip=? "
                "AND kind='mac' ORDER BY last_seen DESC LIMIT 1",
                (network_id, normalized),
            ).fetchone()
            mdns_rows = connection.execute(
                "SELECT value FROM facts WHERE network_id=? AND ip=? "
                "AND kind='mdns_hostname' ORDER BY last_seen DESC",
                (network_id, normalized),
            ).fetchall()
            mdns_name = next(
                (
                    stable
                    for (value,) in mdns_rows
                    if (stable := HostProfileStore._stable_mdns_name(value))
                ),
                "",
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS host_annotations ("
                "network_id TEXT NOT NULL, ip TEXT NOT NULL, "
                "name TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', "
                "updated_at REAL NOT NULL, PRIMARY KEY (network_id, ip))"
            )
            if name or note:
                connection.execute(
                    "INSERT INTO host_annotations VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(network_id, ip) DO UPDATE SET "
                    "name=excluded.name, note=excluded.note, "
                    "updated_at=excluded.updated_at",
                    (network_id, normalized, name, note, time.time()),
                )
            else:
                connection.execute(
                    "DELETE FROM host_annotations WHERE network_id=? AND ip=?",
                    (network_id, normalized),
                )
            mac = HostProfileStore._usable_mac(mac_row[0] if mac_row else "")
            if mac and network_id != "public":
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS host_annotation_devices ("
                    "network_id TEXT NOT NULL, ip TEXT NOT NULL, mac TEXT NOT NULL, "
                    "PRIMARY KEY(network_id, ip))"
                )
                connection.execute(
                    "INSERT INTO host_annotation_devices VALUES (?, ?, ?) "
                    "ON CONFLICT(network_id, ip) DO UPDATE SET mac=excluded.mac",
                    (network_id, normalized, mac),
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS device_annotations ("
                    "mac TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', "
                    "note TEXT NOT NULL DEFAULT '', updated_at REAL NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO device_annotations VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(mac) DO UPDATE SET name=excluded.name, "
                    "note=excluded.note, updated_at=excluded.updated_at",
                    (mac, name, note, time.time()),
                )
            if mdns_name and not mac:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS mdns_identity_annotations ("
                    "mdns_name TEXT PRIMARY KEY, network_id TEXT NOT NULL, "
                    "ip TEXT NOT NULL, name TEXT NOT NULL, note TEXT NOT NULL, "
                    "updated_at REAL NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO mdns_identity_annotations VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(mdns_name) DO UPDATE SET name=excluded.name, "
                    "note=excluded.note, network_id=excluded.network_id, "
                    "ip=excluded.ip, updated_at=excluded.updated_at",
                    (
                        mdns_name,
                        network_id,
                        normalized,
                        name,
                        note,
                        time.time(),
                    ),
                )

            if status is not None:
                HostProfileStore.set_host_triage(
                    path,
                    normalized,
                    network_id,
                    status,
                    labels or [],
                    connection,
                )

    @staticmethod
    def set_host_triage(
        path: Path,
        ip: str,
        network_id: str,
        status: str,
        labels: list[str],
        connection: sqlite3.Connection | None = None,
    ) -> None:
        """Persist review marks for a verified device or an exact host profile.

        Parameters:
            path: Permanent host database.
            ip: Selected host address.
            network_id: Network to which the host belongs.
            status: Review workflow mark, or empty to clear it.
            labels: User-defined labels for the host.
            connection: Optional caller transaction shared with name and note.
        """
        context = (
            nullcontext(connection)
            if connection is not None
            else sqlite3.connect(path, timeout=5)
        )
        with context as connection:
            mac_row = connection.execute(
                "SELECT value FROM facts WHERE network_id=? AND ip=? "
                "AND kind='mac' ORDER BY last_seen DESC LIMIT 1",
                (network_id, ip),
            ).fetchone()
            mac = HostProfileStore._usable_mac(mac_row[0] if mac_row else "")
            subject = (
                f"mac:{mac}"
                if mac and network_id.startswith("gateway:")
                else f"host:{network_id}:{ip}"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS host_triage (subject TEXT PRIMARY KEY, "
                "status TEXT NOT NULL, labels TEXT NOT NULL, updated_at REAL NOT NULL)"
            )
            connection.execute(
                "INSERT INTO host_triage VALUES (?, ?, ?, ?) "
                "ON CONFLICT(subject) DO UPDATE SET status=excluded.status, "
                "labels=excluded.labels, updated_at=excluded.updated_at",
                (subject, status, json.dumps(labels), time.time()),
            )

    @staticmethod
    def triage_for_profiles(
        path: Path, ips: Iterable[str]
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Read review marks without creating or migrating the permanent store.

        Parameters:
            path: Permanent host database.
            ips: Addresses to resolve, including device member addresses.

        Returns:
            Effective status and labels indexed by network and address.
        """
        keys = list(dict.fromkeys(ips))
        if not keys or not path.exists():
            return {}
        result: dict[tuple[str, str], dict[str, Any]] = {}
        with sqlite3.connect(
            f"file:{path}?mode=ro", uri=True, timeout=5
        ) as connection:
            try:
                marks = {
                    row[0]: {"status": row[1], "labels": json.loads(row[2])}
                    for row in connection.execute(
                        "SELECT subject, status, labels FROM host_triage"
                    )
                }
            except sqlite3.OperationalError:
                return {}
            for offset in range(0, len(keys), 300):
                batch = keys[offset : offset + 300]
                placeholders = ",".join("?" for _ in batch)
                rows = connection.execute(
                    "SELECT h.network_id, h.ip, (SELECT value FROM facts f "
                    "WHERE f.network_id=h.network_id AND f.ip=h.ip AND f.kind='mac' "
                    "ORDER BY f.last_seen DESC LIMIT 1) AS mac FROM hosts h "
                    f"WHERE h.ip IN ({placeholders}) ORDER BY h.last_seen DESC",
                    batch,
                )
                for network_id, ip, value in rows:
                    mac = HostProfileStore._usable_mac(value)
                    subject = (
                        f"mac:{mac}"
                        if mac and network_id.startswith("gateway:")
                        else ""
                    )
                    mark = marks.get(
                        subject, marks.get(f"host:{network_id}:{ip}")
                    )
                    result[(network_id, ip)] = mark or {
                        "status": "",
                        "labels": [],
                    }
        return result

    @staticmethod
    def observation_times(
        path: Path, network_ids: Iterable[str]
    ) -> dict[str, float]:
        """Read real sightings on selected networks without refreshing timestamps.

        Parameters:
            path: Permanent host database.
            network_ids: Verified networks and the current run fallback.

        Returns:
            Latest actual observation timestamp for each address.
        """
        keys = list(dict.fromkeys(key for key in network_ids if key))
        if not path.exists() or not keys:
            return {}
        try:
            with sqlite3.connect(
                f"file:{path}?mode=ro", uri=True, timeout=5
            ) as connection:
                marks = ",".join("?" for _ in keys)
                return {
                    str(ip): float(seen)
                    for ip, seen in connection.execute(
                        f"SELECT ip, MAX(last_seen) FROM host_endpoint_observations WHERE network_id IN ({marks}) GROUP BY ip",
                        keys,
                    )
                }
        except sqlite3.OperationalError:
            return {}

    @staticmethod
    def triage_for_ips(
        path: Path, ips: Iterable[str]
    ) -> dict[str, dict[str, Any]]:
        """Read the most recent review mark for each displayed host.

        Parameters:
            path: Permanent host database.
            ips: Addresses in the inventory.

        Returns:
            Review status and labels indexed by address.
        """
        result: dict[str, dict[str, Any]] = {}
        for (_, ip), mark in HostProfileStore.triage_for_profiles(
            path, ips
        ).items():
            result.setdefault(ip, mark)
        return result

    @staticmethod
    def _stable_mdns_name(value: str | None) -> str:
        """Select a device mDNS hostname, excluding services and random IDs.

        Parameters:
            value: Observed mDNS name.

        Returns:
            Canonical hostname, or an empty string when it is unsuitable.
        """
        name = str(value or "").strip().lower().rstrip(".")
        match = re.fullmatch(r"([a-z0-9][a-z0-9-]{0,62})\.local", name)
        if not match:
            return ""
        label = match.group(1)
        if re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}",
            label,
        ):
            return ""
        return name

    @staticmethod
    def _usable_mac(value: str | None) -> str:
        """Accept a specific unicast MAC for matching one device.

        Parameters:
            value: MAC address stored with a host profile.

        Returns:
            Normalized MAC, or an empty string for an unusable address.
        """
        mac = str(value or "").strip().lower()
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            return ""
        if mac == "00:00:00:00:00:00" or int(mac[:2], 16) & 1:
            return ""
        return mac

    @staticmethod
    def _resolved_annotations(
        connection: sqlite3.Connection, ips: Iterable[str]
    ) -> dict[tuple[str, str], dict[str, str]]:
        """Resolve profile names by device MAC, then exact host profile.

        Parameters:
            connection: Open permanent host database connection.
            ips: IP addresses whose network profiles are being displayed.

        Returns:
            Effective annotations indexed by network identity and IP.
        """
        keys = list(dict.fromkeys(ips))
        if not keys:
            return {}
        placeholders = ",".join("?" for _ in keys)
        mac_query = (
            "(SELECT lower(f.value) FROM facts f WHERE f.network_id=h.network_id "
            "AND f.ip=h.ip AND f.kind='mac' "
            "ORDER BY f.last_seen DESC LIMIT 1)"
        )
        historical_mac = (
            "(SELECT lower(f.value) FROM facts f JOIN host_annotations saved "
            "ON saved.network_id=f.network_id AND saved.ip=f.ip "
            "WHERE f.network_id=a.network_id AND f.ip=a.ip AND f.kind='mac' "
            "AND f.first_seen<=saved.updated_at "
            "ORDER BY MIN(f.last_seen, saved.updated_at) DESC, f.first_seen DESC LIMIT 1)"
        )
        has_bindings = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='host_annotation_devices'"
        ).fetchone()
        saved_mac = (
            "COALESCE((SELECT d.mac FROM host_annotation_devices d WHERE "
            "d.network_id=a.network_id AND d.ip=a.ip), " + historical_mac + ")"
            if has_bindings
            else historical_mac
        )
        try:
            rows = connection.execute(
                "SELECT h.network_id, h.ip, a.name, a.note, "
                f"{mac_query} AS mac, {saved_mac} AS annotation_mac FROM hosts h "
                "LEFT JOIN host_annotations a ON a.network_id=h.network_id "
                "AND a.ip=h.ip WHERE h.ip IN (" + placeholders + ") "
                "ORDER BY h.last_seen DESC",
                keys,
            ).fetchall()
        except sqlite3.OperationalError:
            return {}
        macs = {
            HostProfileStore._usable_mac(row[4])
            for row in rows
            if row[0] != "public"
        } - {""}
        mdns_by_host: dict[tuple[str, str], str] = {}
        for network_id, ip, value in connection.execute(
            "SELECT network_id, ip, value FROM facts WHERE kind='mdns_hostname' "
            "AND ip IN (" + placeholders + ") ORDER BY last_seen DESC",
            keys,
        ):
            stable = HostProfileStore._stable_mdns_name(value)
            if stable:
                mdns_by_host.setdefault((network_id, ip), stable)
        mdns_names = set(mdns_by_host.values())
        saved_mdns: dict[str, dict[str, str]] = {}
        if mdns_names:
            mdns_placeholders = ",".join("?" for _ in mdns_names)
            try:
                for mdns_name, name, note, source_mac in connection.execute(
                    "SELECT m.mdns_name, m.name, m.note, (SELECT value FROM facts f "
                    "WHERE f.network_id=m.network_id AND f.ip=m.ip AND f.kind='mac' "
                    "ORDER BY f.last_seen DESC LIMIT 1) FROM mdns_identity_annotations m "
                    "WHERE mdns_name IN (" + mdns_placeholders + ")",
                    tuple(mdns_names),
                ):
                    if HostProfileStore._usable_mac(source_mac):
                        continue
                    saved_mdns[mdns_name] = {
                        "name": name or "",
                        "note": note or "",
                    }
            except sqlite3.OperationalError:
                pass
        legacy_mdns: dict[str, dict[str, str]] = {}
        if mdns_names:
            for name, note, value, source_mac in connection.execute(
                f"SELECT a.name, a.note, f.value, {saved_mac} FROM host_annotations a "
                "JOIN facts f ON f.network_id=a.network_id AND f.ip=a.ip "
                "AND f.kind='mdns_hostname' WHERE (a.name!='' OR a.note!='') "
                f"AND f.value IN ({mdns_placeholders}) "
                "ORDER BY a.updated_at DESC, f.last_seen DESC",
                tuple(mdns_names),
            ):
                stable = HostProfileStore._stable_mdns_name(value)
                if stable and not HostProfileStore._usable_mac(source_mac):
                    legacy_mdns.setdefault(
                        stable, {"name": name or "", "note": note or ""}
                    )
        device_annotations: dict[str, dict[str, str]] = {}
        try:
            for mac, name, note in connection.execute(
                "SELECT mac, name, note FROM device_annotations"
            ):
                if mac in macs:
                    device_annotations[mac] = {
                        "name": name or "",
                        "note": note or "",
                    }
        except sqlite3.OperationalError:
            pass
        legacy_annotations: dict[str, dict[str, str]] = {}
        for name, note, mac in connection.execute(
            f"SELECT a.name, a.note, {saved_mac} AS mac "
            "FROM host_annotations a WHERE a.network_id!='public' "
            "ORDER BY a.updated_at DESC"
        ):
            mac = HostProfileStore._usable_mac(mac)
            if mac in macs and (name or note):
                legacy_annotations.setdefault(
                    mac, {"name": name or "", "note": note or ""}
                )
        resolved: dict[tuple[str, str], dict[str, str]] = {}
        for network_id, ip, name, note, mac, annotation_mac in rows:
            mac = (
                HostProfileStore._usable_mac(mac)
                if network_id != "public"
                else ""
            )
            annotation_mac = (
                HostProfileStore._usable_mac(annotation_mac)
                if network_id != "public"
                else ""
            )
            if annotation_mac and annotation_mac != mac:
                name = note = ""
            direct = {"name": name or "", "note": note or ""}
            mdns_name = mdns_by_host.get((network_id, ip), "")
            if mac in device_annotations:
                resolved[(network_id, ip)] = device_annotations[mac]
            elif name or note:
                resolved[(network_id, ip)] = direct
            elif not mac and mdns_name in saved_mdns:
                resolved[(network_id, ip)] = saved_mdns[mdns_name]
            elif not mac and mdns_name in legacy_mdns:
                resolved[(network_id, ip)] = legacy_mdns[mdns_name]
            else:
                resolved[(network_id, ip)] = legacy_annotations.get(
                    mac, direct
                )
        return resolved

    @staticmethod
    def hostname_for_profile(
        profileid: str,
        path: Path,
        network_states: Iterable[dict[str, Any]],
        run_name: str,
        current_mac: str | None = None,
        cached_name: str | None = None,
    ) -> str | None:
        """Read a durable hostname for core consumers in their capture context.

        Parameters:
            profileid: Slips profile containing the endpoint address.
            path: Shared permanent identity database.
            network_states: Current settings of the monitored interfaces.
            run_name: Fallback identity for this capture.
            current_mac: Optional cached hardware address to check ownership.
            cached_name: Fresh cache value used when durable ownership permits it.

        Returns:
            Learned name for this network/device, or None if unverified.
        """
        try:
            ip = str(ipaddress.ip_address(profileid.removeprefix("profile_")))
        except (AttributeError, ValueError):
            return None
        address = ipaddress.ip_address(ip)
        networks = []
        for state in network_states:
            if not isinstance(state, dict) or state.get("connected") is False:
                continue
            try:
                local = ipaddress.ip_network(
                    state.get("local_network", ""), strict=False
                )
            except ValueError:
                local = None
            if address.is_link_local or (local and address in local):
                networks.append(
                    HostProfileStore.network_id_for_state(state, run_name)
                )
        networks.append(f"run:{run_name}")
        try:
            identities = HostProfileStore.identities_for_ips(
                path, [ip], networks, {ip: current_mac or ""}
            )
            identity = identities.get(ip, {})
            if identity:
                if identity.get("name"):
                    return identity["name"]
                return None
            if path.exists() and HostProfileStore.identities_for_ips(
                path, [ip]
            ):
                return None
        except (OSError, sqlite3.Error):
            pass
        return cached_name or None

    @staticmethod
    def identities_for_ips(
        path: Path,
        ips: Iterable[str],
        network_ids: Iterable[str] = (),
        current_macs: dict[str, str] | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Recover learned device names from durable, scoped identity facts.

        Parameters:
            path: Permanent host database, opened without creating it.
            ips: Addresses whose displayed identity is being resolved.
            network_ids: Preferred capture networks; empty selects recent history.
            current_macs: Live MACs that override historical address ownership.

        Returns:
            Names, sources and verified MACs indexed by requested address.
        """
        keys = list(dict.fromkeys(ips))
        if not keys or not path.exists():
            return {}
        networks = list(dict.fromkeys(key for key in network_ids if key))
        preference = {key: index for index, key in enumerate(networks)}
        result: dict[str, dict[str, Any]] = {}
        priority = {"hostname": 3, "mdns_hostname": 2, "reverse_dns": 1}
        sources = {
            "hostname": "Hostname",
            "mdns_hostname": "mDNS",
            "reverse_dns": "rDNS",
        }
        with sqlite3.connect(
            f"file:{path}?mode=ro", uri=True, timeout=5
        ) as connection:
            connection.row_factory = sqlite3.Row
            for offset in range(0, len(keys), 200):
                batch = keys[offset : offset + 200]
                marks = ",".join("?" for _ in batch)
                try:
                    profiles = connection.execute(
                        "SELECT h.network_id,h.ip,h.last_seen,o.last_seen AS endpoint_seen "
                        "FROM hosts h LEFT JOIN host_endpoint_observations o "
                        "ON o.network_id=h.network_id AND o.ip=h.ip "
                        f"WHERE h.ip IN ({marks}) ORDER BY h.last_seen DESC",
                        batch,
                    ).fetchall()
                except sqlite3.OperationalError:
                    profiles = connection.execute(
                        "SELECT network_id,ip,last_seen,NULL AS endpoint_seen "
                        f"FROM hosts WHERE ip IN ({marks}) ORDER BY last_seen DESC",
                        batch,
                    ).fetchall()
                profiles = sorted(
                    profiles,
                    key=lambda row: (
                        preference.get(row["network_id"], len(preference)),
                        row["endpoint_seen"] is None,
                        -float(row["endpoint_seen"] or row["last_seen"]),
                    ),
                )
                selected = {}
                for row in profiles:
                    if (
                        preference
                        and row["network_id"] not in preference
                        and row["network_id"] != "public"
                    ):
                        continue
                    selected.setdefault(
                        row["ip"], (row["network_id"], row["ip"])
                    )
                if not selected:
                    continue
                facts = connection.execute(
                    "SELECT network_id,ip,kind,value,first_seen,last_seen FROM facts "
                    f"WHERE ip IN ({marks}) AND kind IN ('mac','hostname','mdns_hostname','reverse_dns') "
                    "ORDER BY last_seen DESC,first_seen DESC",
                    batch,
                ).fetchall()
                by_profile: dict[tuple[str, str], list[sqlite3.Row]] = {}
                for fact in facts:
                    by_profile.setdefault(
                        (fact["network_id"], fact["ip"]), []
                    ).append(fact)
                target_macs = {}
                conflicts = set()
                for ip, key in selected.items():
                    mac = next(
                        (
                            HostProfileStore._usable_mac(f["value"])
                            for f in by_profile.get(key, [])
                            if f["kind"] == "mac"
                        ),
                        "",
                    )
                    live_mac = HostProfileStore._usable_mac(
                        (current_macs or {}).get(ip)
                    )
                    if live_mac and mac and live_mac != mac:
                        conflicts.add(ip)
                    target_macs[ip] = live_mac or mac
                macs = sorted(set(target_macs.values()) - {""})
                if macs:
                    mac_marks = ",".join("?" for _ in macs)
                    aliases = connection.execute(
                        "SELECT DISTINCT network_id,ip FROM facts "
                        f"WHERE kind='mac' AND value IN ({mac_marks}) AND network_id!='public'",
                        macs,
                    ).fetchall()
                    missing = [
                        (row[0], row[1])
                        for row in aliases
                        if (row[0], row[1]) not in by_profile
                    ]
                    for start in range(0, len(missing), 200):
                        chunk = missing[start : start + 200]
                        pairs = ",".join("(?,?)" for _ in chunk)
                        extra = connection.execute(
                            "SELECT network_id,ip,kind,value,first_seen,last_seen FROM facts "
                            f"WHERE (network_id,ip) IN ({pairs}) "
                            "AND kind IN ('mac','hostname','mdns_hostname','reverse_dns') "
                            "ORDER BY last_seen DESC,first_seen DESC",
                            [value for pair in chunk for value in pair],
                        ).fetchall()
                        for fact in extra:
                            by_profile.setdefault(
                                (fact["network_id"], fact["ip"]), []
                            ).append(fact)
                previous_owners: dict[str, set[str]] = {}
                by_mac: dict[str, list[tuple[int, float, str, str]]] = {}
                direct: dict[
                    tuple[str, str], list[tuple[int, float, str, str]]
                ] = {}
                for key, values in by_profile.items():
                    hardware = [
                        f
                        for f in values
                        if f["kind"] == "mac"
                        and HostProfileStore._usable_mac(f["value"])
                    ]
                    previous_owners.setdefault(key[1], set()).update(
                        HostProfileStore._usable_mac(f["value"])
                        for f in hardware
                    )
                    for fact in values:
                        kind = fact["kind"]
                        if kind not in priority:
                            continue
                        name = str(fact["value"] or "").strip()
                        if kind == "mdns_hostname":
                            name = HostProfileStore._stable_mdns_name(name)
                        if not name:
                            continue
                        candidate = (
                            priority[kind],
                            float(fact["last_seen"]),
                            name,
                            sources[kind],
                        )
                        owners = {
                            HostProfileStore._usable_mac(mac["value"])
                            for mac in hardware
                            if mac["first_seen"] <= fact["last_seen"]
                            and mac["last_seen"] >= fact["first_seen"]
                        }
                        if not owners:
                            owners = {
                                HostProfileStore._usable_mac(mac["value"])
                                for mac in hardware
                                if mac["first_seen"] <= fact["last_seen"]
                            }
                        if len(owners) == 1 and key[0] != "public":
                            by_mac.setdefault(next(iter(owners)), []).append(
                                candidate
                            )
                        if not hardware:
                            direct.setdefault(key, []).append(candidate)
                for ip, key in selected.items():
                    mac = target_macs[ip] if key[0] != "public" else ""
                    candidates = (
                        by_mac.get(mac, []) if mac else direct.get(key, [])
                    )
                    best = (
                        max(candidates, default=(0, 0, "", ""))
                        if ip not in conflicts
                        else (0, 0, "", "")
                    )
                    result[ip] = {
                        "name": best[2],
                        "source": best[3],
                        "mac": mac,
                    }
                    if mac and previous_owners.get(ip, set()) - {mac}:
                        result[ip]["identity_changed"] = True
        return result

    @staticmethod
    def annotations_for_ips(
        path: Path, ips: Iterable[str], network_ids: Iterable[str] = ()
    ) -> dict[str, dict[str, str]]:
        """Read each displayed device's effective saved annotation.

        Parameters:
            path: Permanent host profile database.
            ips: IP addresses displayed in the current view.
            network_ids: Selected capture networks; empty includes all history.

        Returns:
            User names and notes indexed by IP address.
        """
        keys = list(dict.fromkeys(ips))
        if not keys or not path.exists():
            return {}
        with sqlite3.connect(
            f"file:{path}?mode=ro", uri=True, timeout=1
        ) as connection:
            rows = HostProfileStore._resolved_annotations(connection, keys)
        result: dict[str, dict[str, str]] = {}
        preference = {
            key: index for index, key in enumerate(network_ids) if key
        }
        ordered = (
            sorted(
                rows.items(),
                key=lambda row: preference.get(row[0][0], len(preference)),
            )
            if preference
            else rows.items()
        )
        for (network_id, ip), annotation in ordered:
            if (
                preference
                and network_id not in preference
                and network_id != "public"
            ):
                continue
            result.setdefault(ip, annotation)
        return result

    def _network_state(self, interface: str) -> dict[str, Any]:
        """Read a recent network state for an interface.

        Parameters:
            interface: Interface name from a flow or run configuration.

        Returns:
            Current network settings, or an empty dictionary.
        """
        name = (
            interface
            if interface in self.interfaces
            else (self.interfaces[0] if len(self.interfaces) == 1 else "")
        )
        if not name:
            return {}
        now = time.monotonic()
        cached = self._network_cache.get(name)
        if cached and now - cached[0] < 5:
            return cached[1]
        state = self.network_lookup(name) or {}
        self._network_cache[name] = (now, state)
        return state

    @staticmethod
    def _observation_network(
        state: dict[str, Any], observed_at: float, flow: Any = None
    ) -> dict[str, Any]:
        """Select capture settings at packet time when replaying retained flows.

        Parameters:
            state: Current cached interface settings and bounded history.
            observed_at: Packet observation time.
            flow: Optional endpoints and hardware addresses for polling gaps.

        Returns:
            Recorded settings, or an unidentified network if history is missing.
        """
        return network_state_at(state, observed_at, flow) or {}

    def _identity(
        self, ip: str, interface: str, state: dict[str, Any] | None = None
    ) -> tuple[str, str, str] | None:
        """Find a safe public or network-specific key for an IP.

        Parameters:
            ip: Candidate host address.
            interface: Interface on which it was observed.
            state: Optional capture settings at the packet's timestamp.

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
        normalized = str(address)
        if address.is_global:
            return normalized, "public", "Public internet"
        state = self._network_state(interface) if state is None else state
        try:
            network = ipaddress.ip_network(
                state.get("local_network", ""), strict=False
            )
        except ValueError:
            network = None
        if network and address in network and state.get("gateway_mac"):
            gateway_mac = str(state["gateway_mac"]).lower()
            return (
                normalized,
                self.network_id_for_state(state, self.run_name),
                f"{network} · router {gateway_mac}",
            )
        if (
            address.version == 6
            and address.is_link_local
            and state.get("gateway_mac")
        ):
            gateway_mac = str(state["gateway_mac"]).lower()
            return (
                normalized,
                self.network_id_for_state(state, self.run_name),
                f"Link-local on {state.get('interface') or interface} · router {gateway_mac}",
            )
        return (
            normalized,
            self.network_id_for_state({}, self.run_name),
            f"Unidentified network · {self.run_name}",
        )

    def _save(
        self,
        ip: str,
        interface: str,
        observed_at: float,
        facts: list[tuple[str, str]],
        observed_traffic: bool = False,
        from_packet: bool = False,
        capture_state: dict[str, Any] | None = None,
    ) -> None:
        """Upsert a sighting and bounded distinct facts in one transaction.

        Parameters:
            ip: Observed host IP.
            interface: Capture interface.
            observed_at: Observation timestamp.
            facts: Kind and value pairs learned from this observation.
            observed_traffic: Whether a parsed packet flow caused the sighting.
            from_packet: Use capture-time settings for DNS-advertised metadata.
            capture_state: Already selected packet-time network settings.
        """
        state = (
            self._network_state(interface)
            if capture_state is None
            else capture_state
        )
        if capture_state is None and (observed_traffic or from_packet):
            state = self._observation_network(state, observed_at)
        identity = self._identity(ip, interface, state)
        if identity is None:
            return
        normalized, network_id, network_label = identity
        key = (network_id, normalized)
        now = time.monotonic()
        own_ips = {item.get("ip") for item in state.get("addresses", [])}
        if state.get("host_ip"):
            own_ips.add(state["host_ip"])
        if (
            observed_traffic
            and normalized in own_ips
            and time.monotonic() - self._recent_sightings.get(key, 0) >= 60
            and (mac := self._usable_mac(state.get("mac")))
        ):
            facts = [*facts, ("mac", mac)]
        filtered = []
        saved_mac = ""
        for kind, value in facts:
            if not isinstance(value, str) or not value.strip():
                continue
            if kind == "mac":
                value = self._usable_mac(value)
                if not value:
                    continue
                previous_mac, saved_at = self._recent_macs.get(key, ("", 0))
                if previous_mac == value and now - saved_at < 60:
                    continue
                saved_mac = value
            filtered.append((kind, value.strip()[:MAX_VALUE_LENGTH]))
        capture_id = self.network_id_for_state(state, self.run_name)
        capture_key = (
            f"capture:{capture_id}:{state.get('changed_at', '')}",
            normalized,
        )
        save_observation = (
            observed_traffic
            and now - self._recent_sightings.get(capture_key, 0) >= 60
        )
        if (
            not filtered
            and not save_observation
            and now - self._recent_sightings.get(key, 0) < 60
        ):
            return
        context = (
            nullcontext(self._active_connection)
            if self._active_connection is not None
            else self._connect()
        )
        with context as connection:
            metadata_update = not observed_traffic and not from_packet
            write_host = not metadata_update or network_id == "public"
            if metadata_update and network_id != "public":
                existing_host = connection.execute(
                    "SELECT 1 FROM hosts WHERE network_id=? AND ip=?",
                    (network_id, normalized),
                ).fetchone()
                if not existing_host:
                    network_id = self.network_id_for_state({}, self.run_name)
                    network_label = f"Unidentified network · {self.run_name}"
                    key = (network_id, normalized)
                    write_host = not connection.execute(
                        "SELECT 1 FROM hosts WHERE network_id=? AND ip=?",
                        key,
                    ).fetchone()
            if save_observation:
                connection.execute(
                    "INSERT INTO host_endpoint_observations VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(network_id, ip) DO UPDATE SET "
                    "first_seen=MIN(first_seen, excluded.first_seen), "
                    "last_seen=MAX(last_seen, excluded.last_seen)",
                    (capture_id, normalized, observed_at, observed_at),
                )
            if write_host:
                connection.execute(
                    "INSERT INTO hosts VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(network_id, ip) DO UPDATE SET "
                    "network_label=excluded.network_label, "
                    "first_seen=MIN(first_seen, excluded.first_seen), "
                    "last_seen=MAX(last_seen, excluded.last_seen)",
                    (
                        network_id,
                        normalized,
                        network_label,
                        observed_at,
                        observed_at,
                    ),
                )
            for kind, value in dict.fromkeys(filtered):
                existing = connection.execute(
                    "SELECT 1 FROM facts WHERE network_id=? AND ip=? "
                    "AND kind=? AND value=?",
                    (network_id, normalized, kind, value),
                ).fetchone()
                if not existing:
                    count = connection.execute(
                        "SELECT COUNT(*) FROM facts WHERE network_id=? "
                        "AND ip=? AND kind=?",
                        (network_id, normalized, kind),
                    ).fetchone()[0]
                    if count >= MAX_FACTS_PER_KIND:
                        continue
                connection.execute(
                    "INSERT INTO facts VALUES (?, ?, ?, ?, ?, ?, 1) "
                    "ON CONFLICT(network_id, ip, kind, value) DO UPDATE SET "
                    "first_seen=MIN(first_seen, excluded.first_seen), "
                    "last_seen=MAX(last_seen, excluded.last_seen), "
                    "observations=observations+1",
                    (
                        network_id,
                        normalized,
                        kind,
                        value,
                        observed_at,
                        observed_at,
                    ),
                )
        self._recent_sightings[key] = now
        if saved_mac:
            self._recent_macs[key] = (saved_mac, now)
            if len(self._recent_macs) > 4096:
                self._recent_macs.clear()
        if save_observation:
            self._recent_sightings[capture_key] = now
        if len(self._recent_sightings) > 10000:
            self._recent_sightings.clear()

    @staticmethod
    def _local_link_mac(
        ip: str, value: str, state: dict[str, Any], arp: bool = False
    ) -> str:
        """Accept an endpoint MAC only when the address belongs to this link.

        Parameters:
            ip: Endpoint address.
            value: Ethernet or ARP hardware address.
            state: Capture settings at the packet timestamp.
            arp: Whether the ARP payload explicitly binds the address.

        Returns:
            Usable local MAC, or an empty string for routed or invalid addresses.
        """
        mac = HostProfileStore._usable_mac(value)
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
        own = {item.get("ip") for item in state.get("addresses", [])}
        own.add(state.get("host_ip"))
        own_mac = HostProfileStore._usable_mac(state.get("mac"))
        if str(address) in own and own_mac and mac != own_mac:
            return ""
        if arp:
            return mac
        if mac == HostProfileStore._usable_mac(
            state.get("gateway_mac")
        ) and str(address) != state.get("gateway_ip"):
            return ""
        if address.is_link_local:
            return mac
        networks = [
            state.get("local_network", ""),
            *(item.get("network", "") for item in state.get("addresses", [])),
        ]
        for value in networks:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                continue
            if address in network and address != network.broadcast_address:
                return mac
        return ""

    def observe_flow(self, flow: Any) -> None:
        """Store both endpoints and names learned from one parsed flow.

        Parameters:
            flow: Conn, DNS, HTTP, TLS, DHCP, or other parsed flow.
        """
        interface = str(getattr(flow, "interface", "") or "")
        try:
            observed_at = float(
                utils.convert_ts_format(
                    getattr(flow, "starttime", None), "unixtimestamp"
                )
            )
        except (TypeError, ValueError, AttributeError):
            observed_at = time.time()
        source = str(getattr(flow, "saddr", "") or "")
        target = str(getattr(flow, "daddr", "") or "")
        kind = str(getattr(flow, "type_", "") or "").lower()
        state = self._observation_network(
            self._network_state(interface), observed_at, flow
        )
        source_facts: list[tuple[str, str]] = []
        target_facts: list[tuple[str, str]] = []
        if kind in {"arp", "conn"}:
            if kind == "arp":
                source_mac = str(
                    getattr(flow, "src_hw", "")
                    or getattr(flow, "smac", "")
                    or ""
                )
                target_mac = str(getattr(flow, "dst_hw", "") or "")
            else:
                source_mac = str(getattr(flow, "smac", "") or "")
                target_mac = str(getattr(flow, "dmac", "") or "")
            source_mac = self._local_link_mac(
                source, source_mac, state, kind == "arp"
            )
            target_mac = self._local_link_mac(
                target, target_mac, state, kind == "arp"
            )
            source_facts.append(("mac", source_mac))
            target_facts.append(("mac", target_mac))
        if kind == "dhcp":
            if self._identity(source, interface) is None:
                source = str(getattr(flow, "requested_addr", "") or "")
            source_facts.extend(
                [
                    ("hostname", str(getattr(flow, "host_name", "") or "")),
                    ("mac", str(getattr(flow, "smac", "") or "")),
                ]
            )
        elif kind == "http":
            host = str(getattr(flow, "host", "") or "")
            uri = str(getattr(flow, "uri", "") or "")
            target_facts.append(("http_host", host))
            if uri.startswith(("http://", "https://")):
                target_facts.append(("url", uri))
            elif host and uri:
                path = uri if uri.startswith("/") else f"/{uri}"
                target_facts.append(("url", f"http://{host}{path}"))
        elif kind in {"ssl", "tls"}:
            target_facts.append(
                ("sni", str(getattr(flow, "server_name", "") or ""))
            )
        elif kind == "dns":
            query = str(getattr(flow, "query", "") or "")
            mdns = "5353" in {
                str(getattr(flow, "sport", "") or ""),
                str(getattr(flow, "dport", "") or ""),
            }
            if mdns:
                bindings = getattr(flow, "mdns_bindings", []) or []
                if isinstance(bindings, str):
                    bindings = bindings.split(",")
                for binding in bindings[:64]:
                    owner, separator, address = str(binding).partition("|")
                    if separator and (
                        hostname := self._stable_mdns_name(owner)
                    ):
                        self._save(
                            address,
                            interface,
                            observed_at,
                            [("mdns_hostname", hostname)],
                            from_packet=True,
                            capture_state=state,
                        )
            for answer in getattr(flow, "answers", []) or []:
                if isinstance(answer, dict):
                    answer = answer.get("rdata") or answer.get("data") or ""
                answer = str(answer)
                self._save(
                    answer,
                    interface,
                    observed_at,
                    [] if mdns else [("dns_name", query)],
                    from_packet=True,
                    capture_state=state,
                )
        self._save(
            source,
            interface,
            observed_at,
            source_facts,
            observed_traffic=True,
            capture_state=state,
        )
        self._save(
            target,
            interface,
            observed_at,
            target_facts,
            observed_traffic=True,
            capture_state=state,
        )

    def observe_flows(self, flows: Iterable[Any]) -> None:
        """Persist one bounded flow batch in a single SQLite transaction.

        Parameters:
            flows: Parsed flow objects read by the host profile module.
        """
        with self._connect() as connection:
            self._active_connection = connection
            try:
                for flow in flows:
                    self.observe_flow(flow)
            finally:
                self._active_connection = None

    def observe_ip_info(self, ip: str, to_store: dict[str, Any]) -> None:
        """Keep learned reverse DNS, SNI, and threat feed appearances.

        Parameters:
            ip: Address being enriched.
            to_store: Redis IPInfo fields written by a Slips module.
        """
        try:
            is_public = ipaddress.ip_address(ip).is_global
        except ValueError:
            return
        facts: list[tuple[str, str]] = []
        reverse_dns = to_store.get("reverse_dns")
        if reverse_dns:
            facts.append(("reverse_dns", str(reverse_dns)))
        asn = to_store.get("asn")
        if isinstance(asn, dict):
            description = " ".join(
                str(asn.get(field, "") or "") for field in ("number", "org")
            ).strip()
            facts.append(("asn", description))
        country = to_store.get("geocountry")
        if (
            is_public
            and country
            and str(country).strip().casefold()
            not in {
                "private",
                "unknown",
            }
        ):
            facts.append(("country", str(country)))
        sni = to_store.get("SNI") or []
        for item in sni if isinstance(sni, list) else [sni]:
            if isinstance(item, dict):
                facts.append(("sni", str(item.get("server_name", ""))))
        ti = to_store.get("threatintelligence") or {}
        if isinstance(ti, dict):
            sources = ti.get("source", [])
            for source in sources if isinstance(sources, list) else [sources]:
                facts.append(("threat_feed", str(source)))
        if facts:
            self._save(ip, "", time.time(), facts)

    def observe_hostname(self, hostname: str, profileid: str) -> None:
        """Persist a name learned through a host profile update.

        Parameters:
            hostname: Newly learned hostname.
            profileid: Profile identifier containing the host IP.
        """
        self._save(
            profileid.removeprefix("profile_"),
            "",
            time.time(),
            [("hostname", hostname)],
        )

    @staticmethod
    def read(path: Path, ip: str) -> list[dict[str, Any]]:
        """Read all network-separated profiles for one host address.

        Parameters:
            path: Permanent SQLite database path.
            ip: Host address shown in the web interface.

        Returns:
            Profiles and their clues, newest network first.
        """
        try:
            address = ipaddress.ip_address(ip)
            normalized = str(address)
        except ValueError:
            return []
        if not path.exists():
            return []
        with sqlite3.connect(
            f"file:{path}?mode=ro", uri=True, timeout=5
        ) as conn:
            conn.row_factory = sqlite3.Row
            hosts = conn.execute(
                "SELECT * FROM hosts WHERE ip=? "
                "ORDER BY last_seen DESC LIMIT 50",
                (normalized,),
            ).fetchall()
            names = HostProfileStore._network_names_from_connection(
                conn, (host["network_id"] for host in hosts)
            )
            annotations = HostProfileStore._resolved_annotations(
                conn, (normalized,)
            )
            endpoint_times: dict[str, tuple[float, float]] = {}
            try:
                network_ids = [host["network_id"] for host in hosts]
                marks = ",".join("?" for _ in network_ids)
                endpoint_times = {
                    str(network_id): (float(first), float(last))
                    for network_id, first, last in conn.execute(
                        "SELECT network_id, first_seen, last_seen "
                        "FROM host_endpoint_observations WHERE ip=? "
                        f"AND network_id IN ({marks})",
                        (normalized, *network_ids),
                    )
                }
            except sqlite3.OperationalError:
                pass
            profiles = []
            for host in hosts:
                facts = conn.execute(
                    "SELECT kind, value, first_seen, last_seen, observations "
                    "FROM facts WHERE network_id=? AND ip=? "
                    "ORDER BY last_seen DESC",
                    (host["network_id"], normalized),
                ).fetchall()
                profiles.append(
                    {
                        **dict(host),
                        "default_network_label": host["network_label"],
                        "network_name": names.get(host["network_id"], ""),
                        "network_label": names.get(
                            host["network_id"], host["network_label"]
                        ),
                        "user_name": annotations.get(
                            (host["network_id"], normalized), {}
                        ).get("name", ""),
                        "user_note": annotations.get(
                            (host["network_id"], normalized), {}
                        ).get("note", ""),
                        "endpoint_first_seen": endpoint_times.get(
                            host["network_id"], (None, None)
                        )[0],
                        "endpoint_last_seen": endpoint_times.get(
                            host["network_id"], (None, None)
                        )[1],
                        "facts": [
                            dict(fact)
                            for fact in facts
                            if fact["kind"] != "country"
                            or (
                                address.is_global
                                and str(fact["value"]).strip().casefold()
                                not in {"private", "unknown"}
                            )
                        ],
                    }
                )
            return profiles
