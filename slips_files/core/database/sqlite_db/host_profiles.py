# SPDX-License-Identifier: GPL-2.0-only
"""Keep durable, network-scoped identity clues for observed hosts."""

import ipaddress
import os
import re
import sqlite3
import time
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Callable, Iterable

from slips_files.common.slips_utils import utils

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
                "CREATE TABLE IF NOT EXISTS mdns_annotations ("
                "mdns_name TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', "
                "note TEXT NOT NULL DEFAULT '', updated_at REAL NOT NULL)"
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
        try:
            with sqlite3.connect(
                f"file:{path}?mode=ro", uri=True, timeout=5
            ) as connection:
                rows = connection.execute(
                    "SELECT h.network_id, h.network_label, h.first_seen, "
                    "h.last_seen, n.name FROM hosts h "
                    "LEFT JOIN network_names n ON n.network_id=h.network_id "
                    "WHERE h.ip=?",
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
            "network_label": network_name or str(row[1]),
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
        path: Path, ip: str, network_id: str, name: str, note: str
    ) -> None:
        """Persist a user name and note for a host and its known device MAC.

        Parameters:
            path: Permanent host profile database.
            ip: Host IP address.
            network_id: Network identity already associated with this host.
            name: User name, or empty to clear it.
            note: User note, or empty to clear it.
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
                "AND kind='mdns_name' ORDER BY last_seen DESC",
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
            if mac and network_id.startswith("gateway:"):
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
            if mdns_name:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS mdns_annotations ("
                    "mdns_name TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', "
                    "note TEXT NOT NULL DEFAULT '', updated_at REAL NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO mdns_annotations VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(mdns_name) DO UPDATE SET name=excluded.name, "
                    "note=excluded.note, updated_at=excluded.updated_at",
                    (mdns_name, name, note, time.time()),
                )

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
        try:
            rows = connection.execute(
                "SELECT h.network_id, h.ip, a.name, a.note, "
                f"{mac_query} AS mac FROM hosts h "
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
            if row[0].startswith("gateway:")
        } - {""}
        mdns_by_host: dict[tuple[str, str], str] = {}
        for network_id, ip, value in connection.execute(
            "SELECT network_id, ip, value FROM facts WHERE kind='mdns_name' "
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
                for mdns_name, name, note in connection.execute(
                    "SELECT mdns_name, name, note FROM mdns_annotations "
                    "WHERE mdns_name IN (" + mdns_placeholders + ")",
                    tuple(mdns_names),
                ):
                    saved_mdns[mdns_name] = {
                        "name": name or "",
                        "note": note or "",
                    }
            except sqlite3.OperationalError:
                pass
        legacy_mdns: dict[str, dict[str, str]] = {}
        for name, note, value in connection.execute(
            "SELECT a.name, a.note, f.value FROM host_annotations a "
            "JOIN facts f ON f.network_id=a.network_id AND f.ip=a.ip "
            "AND f.kind='mdns_name' WHERE a.name!='' OR a.note!='' "
            "ORDER BY a.updated_at DESC, f.last_seen DESC"
        ):
            stable = HostProfileStore._stable_mdns_name(value)
            if stable:
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
            "SELECT a.name, a.note, "
            "(SELECT lower(f.value) FROM facts f "
            "WHERE f.network_id=a.network_id AND f.ip=a.ip "
            "AND f.kind='mac' ORDER BY f.last_seen DESC LIMIT 1) AS mac "
            "FROM host_annotations a WHERE a.network_id LIKE 'gateway:%' "
            "ORDER BY a.updated_at DESC"
        ):
            mac = HostProfileStore._usable_mac(mac)
            if mac in macs and (name or note):
                legacy_annotations.setdefault(
                    mac, {"name": name or "", "note": note or ""}
                )
        resolved: dict[tuple[str, str], dict[str, str]] = {}
        for network_id, ip, name, note, mac in rows:
            mac = (
                HostProfileStore._usable_mac(mac)
                if network_id.startswith("gateway:")
                else ""
            )
            direct = {"name": name or "", "note": note or ""}
            mdns_name = mdns_by_host.get((network_id, ip), "")
            if mac in device_annotations:
                resolved[(network_id, ip)] = device_annotations[mac]
            elif name or note:
                resolved[(network_id, ip)] = direct
            elif mdns_name in saved_mdns:
                resolved[(network_id, ip)] = saved_mdns[mdns_name]
            elif mdns_name in legacy_mdns:
                resolved[(network_id, ip)] = legacy_mdns[mdns_name]
            else:
                resolved[(network_id, ip)] = legacy_annotations.get(
                    mac, direct
                )
        return resolved

    @staticmethod
    def annotations_for_ips(
        path: Path, ips: Iterable[str]
    ) -> dict[str, dict[str, str]]:
        """Read each displayed device's effective saved annotation.

        Parameters:
            path: Permanent host profile database.
            ips: IP addresses displayed in the current view.

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
        for (_, ip), annotation in rows.items():
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

    def _identity(
        self, ip: str, interface: str
    ) -> tuple[str, str, str] | None:
        """Find a safe public or network-specific key for an IP.

        Parameters:
            ip: Candidate host address.
            interface: Interface on which it was observed.

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
        state = self._network_state(interface)
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
    ) -> None:
        """Upsert a sighting and bounded distinct facts in one transaction.

        Parameters:
            ip: Observed host IP.
            interface: Capture interface.
            observed_at: Observation timestamp.
            facts: Kind and value pairs learned from this observation.
        """
        identity = self._identity(ip, interface)
        if identity is None:
            return
        normalized, network_id, network_label = identity
        key = (network_id, normalized)
        filtered = [
            (kind, value.strip()[:MAX_VALUE_LENGTH])
            for kind, value in facts
            if isinstance(value, str) and value.strip()
        ]
        now = time.monotonic()
        if not filtered and now - self._recent_sightings.get(key, 0) < 60:
            return
        context = (
            nullcontext(self._active_connection)
            if self._active_connection is not None
            else self._connect()
        )
        with context as connection:
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
        if len(self._recent_sightings) > 10000:
            self._recent_sightings.clear()

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
        source_facts: list[tuple[str, str]] = []
        target_facts: list[tuple[str, str]] = []
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
            port = str(getattr(flow, "dport", "") or "")
            answer_kind = "mdns_name" if port == "5353" else "dns_name"
            for answer in getattr(flow, "answers", []) or []:
                if isinstance(answer, dict):
                    answer = answer.get("rdata") or answer.get("data") or ""
                answer = str(answer)
                self._save(
                    answer, interface, observed_at, [(answer_kind, query)]
                )
        self._save(source, interface, observed_at, source_facts)
        self._save(target, interface, observed_at, target_facts)

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
