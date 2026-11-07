"""Filter web history by recorded network identity across separate visits."""

import math
import sqlite3
from bisect import bisect_right
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from modules.web_interface.history import network_connection_scope
from slips_files.core.database.sqlite_db.host_profiles import HostProfileStore

MAX_NETWORK_VISITS = 4096


def network_filtered(method: Callable[..., Any]) -> Callable[..., Any]:
    """Give one web request an independent network-scoped reader.

    Parameters:
        method: Reader endpoint accepting a query dictionary.

    Returns:
        Endpoint wrapper preserving unfiltered and saved-view behavior.
    """

    @wraps(method)
    def filtered(reader: Any, *args: Any, **kwargs: Any) -> Any:
        """Run an endpoint with its query's network context.

        Parameters:
            reader: Run data reader.
            args: Endpoint arguments.
            kwargs: Named endpoint arguments.

        Returns:
            Endpoint response.
        """
        query = kwargs.get("query")
        if query is None:
            query = next(
                (value for value in reversed(args) if isinstance(value, dict)),
                {},
            )
        if (
            isinstance(query, dict)
            and (
                query.get("network", [""])[0] in {"current", "connection"}
                or query.get("interface", [""])[0]
                or query.get("network_id", [""])[0]
                or query.get("range", [""])[0] == "connection"
            )
            and not getattr(reader, "_active_network_scope", None)
        ):
            reader = reader._for_network_scope(query)
        return method(reader, *args, **kwargs)

    return filtered


def network_visits(
    state: dict[str, Any],
    run_name: str,
    saved: dict[str, Any] | None = None,
) -> tuple[tuple[float, str], ...]:
    """Extract valid ordered network transitions from a bounded interface snapshot.

    Parameters:
        state: Current network and recent transition history.
        run_name: Identity fallback for networks without a router MAC.
        saved: Persisted uninterrupted connection checkpoint.

    Returns:
        Timestamp and network identity pairs, oldest first.
    """
    history = state.get("history", [])
    snapshots = (history[-10:] if isinstance(history, list) else []) + [state]
    checkpoint = network_connection_scope(state, saved)
    if checkpoint.get("start") is not None:
        snapshots.append({**state, "changed_at": checkpoint["start"]})
    rows = {}
    for snapshot in snapshots:
        if not isinstance(snapshot, dict):
            continue
        try:
            stamp = float(snapshot["changed_at"])
        except (KeyError, TypeError, ValueError):
            continue
        if math.isfinite(stamp):
            rows[stamp] = (
                HostProfileStore.network_id_for_state(snapshot, run_name)
                if snapshot.get("connected")
                else ""
            )
    return tuple(sorted(rows.items()))


def record_network_visits(
    path: Path,
    interface: str,
    state: dict[str, Any],
    run_name: str,
    saved: dict[str, Any] | None = None,
) -> tuple[tuple[float, str], ...]:
    """Retain bounded interface transitions without touching capture processing.

    Parameters:
        path: Web history database.
        interface: Monitored interface.
        state: Current snapshot and its recent history.
        run_name: Fallback identity for networks without a router MAC.
        saved: Persisted continuous-connection checkpoint.

    Returns:
        Recorded transitions for this interface, oldest first.
    """
    rows = [
        (interface, stamp, identity)
        for stamp, identity in network_visits(state, run_name, saved)
    ]
    with sqlite3.connect(path, timeout=5) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS network_visits (interface TEXT NOT NULL,"
            "changed_at REAL NOT NULL,network_id TEXT NOT NULL,"
            "PRIMARY KEY(interface,changed_at))"
        )
        connection.executemany(
            "INSERT INTO network_visits VALUES (?,?,?) ON CONFLICT(interface,changed_at) "
            "DO UPDATE SET network_id=excluded.network_id WHERE network_id<>excluded.network_id",
            rows,
        )
        connection.execute(
            "DELETE FROM network_visits WHERE rowid IN (SELECT rowid FROM network_visits "
            "ORDER BY changed_at DESC LIMIT -1 OFFSET ?)",
            (MAX_NETWORK_VISITS,),
        )
        return tuple(
            connection.execute(
                "SELECT changed_at,network_id FROM network_visits WHERE interface=? ORDER BY changed_at",
                (interface,),
            )
        )


@dataclass(frozen=True)
class NetworkScope:
    """Recorded network membership, independent of the selected time window."""

    network_id: str
    visits: tuple[tuple[float, str], ...]
    connection_start: float | None

    def matches(
        self, timestamp: float, network_id: str = "", interface: str = ""
    ) -> bool:
        """Check a bounded message's explicit identity or recorded capture period.

        Parameters:
            timestamp: Message or observation time.
            network_id: Explicit recorded identity, when available.
            interface: Optional interface provided by multi-interface callers.

        Returns:
            Whether the observation belongs to the selected network.
        """
        if not math.isfinite(timestamp):
            return False
        if network_id and not network_id.startswith("run:"):
            return network_id == self.network_id
        index = bisect_right(self.visits, (timestamp, "\uffff")) - 1
        return index >= 0 and self.visits[index][1] == self.network_id

    def _prepare(self, connection: sqlite3.Connection) -> str:
        """Expose a bounded transition index to one read-only query connection.

        Parameters:
            connection: SQLite query connection.

        Returns:
            SQL-quoted selected network identity.
        """
        connection.execute(
            "CREATE TEMP TABLE IF NOT EXISTS scope_visits (changed_at REAL PRIMARY KEY,network_id TEXT)"
        )
        connection.executemany(
            "INSERT OR IGNORE INTO scope_visits VALUES (?,?)", self.visits
        )
        return connection.execute(
            "SELECT quote(?)", (self.network_id,)
        ).fetchone()[0]

    @staticmethod
    def _recorded_period(timestamp: str, identity: str) -> str:
        """Build an indexed lookup of the network present at an event time.

        Parameters:
            timestamp: Trusted SQL timestamp expression.
            identity: SQL-quoted selected identity.

        Returns:
            Network-period SQL predicate.
        """
        return (
            "(SELECT network_id FROM scope_visits WHERE changed_at<="
            + timestamp
            + " ORDER BY changed_at DESC LIMIT 1)="
            + identity
        )

    def _predicate(
        self,
        connection: sqlite3.Connection,
        timestamp: str,
        recorded: str = "''",
        interface: str = "''",
    ) -> str:
        """Build membership SQL for trusted observation expressions.

        Parameters:
            connection: Request-local read-only query connection.
            timestamp: SQL event timestamp.
            recorded: SQL recorded network identity.
            interface: SQL recorded capture interface.

        Returns:
            SQL predicate selecting this network's observations.
        """
        identity = self._prepare(connection)
        period = self._recorded_period(timestamp, identity)
        return (
            f"CASE ({recorded}) WHEN {identity} THEN 1 WHEN '' THEN {period} "
            f"ELSE CASE WHEN ({recorded}) LIKE 'run:%' THEN {period} ELSE 0 END END"
        )

    def install_detections(
        self,
        connection: sqlite3.Connection,
        database: str = "main",
        prefix: str = "",
    ) -> None:
        """Expose network-filtered detection views without changing stored records.

        Parameters:
            connection: Read-only query connection.
            database: Main database or run database attached to web history.
            prefix: Empty for regular queries or scoped_ for attached queries.
        """
        if (database, prefix) not in {("main", ""), ("run_db", "scoped_")}:
            raise ValueError("Unsupported network view")
        tables = {
            row[0]
            for row in connection.execute(
                f"SELECT name FROM {database}.sqlite_master WHERE type='table'"
            )
        }
        if "evidence" in tables:
            recorded = "CASE WHEN json_valid(e.data) THEN COALESCE(json_extract(e.data,'$.detection_provenance.network_id'),'') ELSE '' END"
            interface = "CASE WHEN json_valid(e.data) THEN COALESCE(NULLIF(json_extract(e.data,'$.interface'),'default'),'') ELSE '' END"
            if "evidence_flows" in tables and tables & {"flows", "altflows"}:
                sources = [
                    (name, alias)
                    for name, alias in (("flows", "rf"), ("altflows", "af"))
                    if name in tables
                ]
                payloads = [f"{alias}.flow" for _, alias in sources]
                payload = (
                    payloads[0]
                    if len(payloads) == 1
                    else f"COALESCE({','.join(payloads)})"
                )
                flow_interface = f"CASE WHEN json_valid({payload}) THEN NULLIF(json_extract({payload},'$.interface'),'default') END"
                joins = " ".join(
                    f"LEFT JOIN {database}.{name} {alias} ON {alias}.uid=ef.uid"
                    for name, alias in sources
                )
                linked_interface = (
                    f"(SELECT CASE WHEN COUNT(DISTINCT {flow_interface})=1 AND COUNT(*)=COUNT({flow_interface}) THEN MIN({flow_interface}) END "
                    f"FROM {database}.evidence_flows ef {joins} "
                    "WHERE ef.evidence_id=e.evidence_id)"
                )
                interface = (
                    f"COALESCE(NULLIF(({interface}),''),{linked_interface},'')"
                )
            period = self._predicate(
                connection, "e.evidence_time", recorded, interface
            )
            connection.execute(
                f"CREATE TEMP VIEW {prefix}evidence AS SELECT e.* FROM {database}.evidence e "
                f"WHERE {period}"
            )
        if "alerts" in tables:
            period = self._predicate(connection, "CAST(a.alert_time AS REAL)")
            if {"evidence", "alert_evidence"} <= tables:
                period = (
                    f"EXISTS (SELECT 1 FROM {database}.alert_evidence ae JOIN {prefix}evidence e "
                    "ON e.evidence_id=ae.evidence_id WHERE ae.alert_id=a.alert_id) OR "
                    f"(NOT EXISTS (SELECT 1 FROM {database}.alert_evidence ae WHERE ae.alert_id=a.alert_id) AND {period})"
                )
            connection.execute(
                f"CREATE TEMP VIEW {prefix}alerts AS SELECT a.* FROM {database}.alerts a WHERE {period}"
            )
        if database == "main":
            if "history_totals" in tables:
                connection.execute(
                    "CREATE TEMP VIEW history_totals AS SELECT * FROM main.history_totals WHERE 0"
                )
            if "history_state" in tables:
                connection.execute(
                    "CREATE TEMP VIEW history_state AS SELECT * FROM main.history_state WHERE key<>'summary_complete'"
                )

    def materialize_evidence(self, connection: sqlite3.Connection) -> None:
        """Resolve network membership once for a grouped request's queries.

        Parameters:
            connection: Read-only run connection with network views installed.
        """
        connection.execute(
            "CREATE TEMP TABLE scope_evidence_ids (evidence_id TEXT PRIMARY KEY) WITHOUT ROWID"
        )
        connection.execute(
            "INSERT INTO scope_evidence_ids SELECT evidence_id FROM evidence"
        )
        connection.execute("DROP VIEW temp.evidence")
        connection.execute(
            "CREATE TEMP VIEW evidence AS SELECT e.* FROM scope_evidence_ids s "
            "CROSS JOIN main.evidence e ON e.evidence_id=s.evidence_id"
        )

    def install_flows(self, connection: sqlite3.Connection) -> None:
        """Scope traffic by recorded visits or evidence-linked network identity.

        Parameters:
            connection: History connection with scoped run detections attached.
        """
        interface = "(SELECT CASE WHEN json_valid(rf.flow) THEN COALESCE(NULLIF(json_extract(rf.flow,'$.interface'),'default'),'') ELSE '' END FROM run_db.flows rf WHERE rf.uid=f.uid)"
        period = self._predicate(
            connection, "f.event_time", interface=f"COALESCE({interface},'')"
        )
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM run_db.sqlite_master WHERE type='table'"
            )
        }
        if {"evidence", "evidence_flows"} <= tables:
            period += (
                " OR EXISTS (SELECT 1 FROM run_db.evidence_flows ef JOIN scoped_evidence e "
                "ON e.evidence_id=ef.evidence_id WHERE ef.uid=f.uid)"
            )
        connection.execute(
            f"CREATE TEMP VIEW flow_index AS SELECT f.* FROM main.flow_index f WHERE {period}"
        )


@dataclass(frozen=True)
class NetworkSelection(NetworkScope):
    """Union of selected interface sessions, each with independent history."""

    members: tuple[tuple[str, NetworkScope], ...] = ()
    allow_untagged: bool = False
    connection_only: bool = False
    all_networks: bool = False
    filter_interface: bool = False

    @property
    def network_ids(self) -> frozenset[str]:
        """Return the selected network identities."""
        return frozenset(scope.network_id for _, scope in self.members)

    def matches(
        self, timestamp: float, network_id: str = "", interface: str = ""
    ) -> bool:
        """Match a message against its own interface's session boundary.

        Parameters:
            timestamp: Observation timestamp.
            network_id: Recorded network identity, if available.
            interface: Recorded capture interface, if available.

        Returns:
            Whether any selected session contains this observation.
        """
        if self.all_networks:
            return math.isfinite(timestamp) and any(
                name == interface for name, _ in self.members
            )
        explicit = bool(network_id and not network_id.startswith("run:"))
        if explicit and not self.connection_only and not self.filter_interface:
            return math.isfinite(timestamp) and network_id in self.network_ids
        if not interface and not explicit and not self.allow_untagged:
            return False
        return any(
            (not interface or interface == name)
            and (
                not (
                    self.connection_only or scope.network_id.startswith("run:")
                )
                or (
                    scope.connection_start is not None
                    and timestamp >= scope.connection_start
                )
            )
            and scope.matches(timestamp, network_id)
            for name, scope in self.members
        )

    def _predicate(
        self,
        connection: sqlite3.Connection,
        timestamp: str,
        recorded: str = "''",
        interface: str = "''",
    ) -> str:
        """Build an indexed union of interface-specific network visits.

        Parameters:
            connection: Request-local query connection.
            timestamp: SQL event timestamp.
            recorded: SQL recorded network identity.
            interface: SQL recorded capture interface.

        Returns:
            SQL predicate retaining separate reconnection boundaries.
        """
        connection.execute(
            "CREATE TEMP TABLE IF NOT EXISTS scope_attachments "
            "(interface TEXT PRIMARY KEY,network_id TEXT,start REAL,connection_only INTEGER)"
        )
        connection.execute(
            "CREATE TEMP TABLE IF NOT EXISTS scope_interface_visits "
            "(interface TEXT,changed_at REAL,network_id TEXT,PRIMARY KEY(interface,changed_at)) WITHOUT ROWID"
        )
        connection.executemany(
            "INSERT OR IGNORE INTO scope_attachments VALUES (?,?,?,?)",
            [
                (
                    name,
                    scope.network_id,
                    scope.connection_start,
                    self.connection_only
                    or scope.network_id.startswith("run:"),
                )
                for name, scope in self.members
            ],
        )
        connection.executemany(
            "INSERT OR IGNORE INTO scope_interface_visits VALUES (?,?,?)",
            [
                (name, stamp, identity)
                for name, scope in self.members
                for stamp, identity in scope.visits
            ],
        )
        if self.all_networks:
            return f"EXISTS (SELECT 1 FROM scope_attachments a WHERE ({interface})=a.interface)"
        period = (
            "(SELECT v.network_id FROM scope_interface_visits v "
            f"WHERE v.interface=a.interface AND v.changed_at<={timestamp} "
            "ORDER BY v.changed_at DESC LIMIT 1)=a.network_id"
        )
        predicate = (
            "EXISTS (SELECT 1 FROM scope_attachments a WHERE "
            f"((NOT a.connection_only AND {int(not self.filter_interface)} AND ({recorded})=a.network_id) OR ("
            f"(({interface})=a.interface OR (({interface})='' AND "
            f"({int(self.allow_untagged)} OR (({recorded})<>'' AND ({recorded}) NOT LIKE 'run:%')))) "
            f"AND (NOT a.connection_only OR {timestamp}>=a.start) "
            f"AND CASE WHEN ({recorded})=a.network_id THEN 1 "
            f"WHEN ({recorded})='' OR ({recorded}) LIKE 'run:%' THEN {period} ELSE 0 END)))"
        )
        if self.connection_only or all(
            scope.network_id.startswith("run:") for _, scope in self.members
        ):
            starts = [
                scope.connection_start
                for _, scope in self.members
                if scope.connection_start is not None
            ]
            if not starts:
                return "0"
            # Keep the shared lower bound visible to SQLite's time indexes.
            return f"{timestamp}>={min(starts)!r} AND ({predicate})"
        return predicate
