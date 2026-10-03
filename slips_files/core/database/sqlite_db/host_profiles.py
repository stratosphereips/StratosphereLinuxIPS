# SPDX-License-Identifier: GPL-2.0-only
"""Keep durable, network-scoped identity clues for observed hosts."""

import ipaddress
import os
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
                f"gateway:{gateway_mac}",
                f"{network} · router {gateway_mac}",
            )
        return (
            normalized,
            f"run:{self.run_name}",
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
