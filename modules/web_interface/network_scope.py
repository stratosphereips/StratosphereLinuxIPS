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
            and query.get("network", [""])[0] in {"current", "connection"}
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

    def matches(self, timestamp: float, network_id: str = "") -> bool:
        """Check a bounded message's explicit identity or recorded capture period.

        Parameters:
            timestamp: Message or observation time.
            network_id: Explicit recorded identity, when available.

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
        identity = self._prepare(connection)
        tables = {
            row[0]
            for row in connection.execute(
                f"SELECT name FROM {database}.sqlite_master WHERE type='table'"
            )
        }
        if "evidence" in tables:
            recorded = "CASE WHEN json_valid(e.data) THEN COALESCE(json_extract(e.data,'$.detection_provenance.network_id'),'') ELSE '' END"
            period = self._recorded_period("e.evidence_time", identity)
            connection.execute(
                f"CREATE TEMP VIEW {prefix}evidence AS SELECT e.* FROM {database}.evidence e "
                f"WHERE ({recorded})={identity} OR ((({recorded})='' OR ({recorded}) LIKE 'run:%') AND {period})"
            )
        if "alerts" in tables:
            period = self._recorded_period(
                "CAST(a.alert_time AS REAL)", identity
            )
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

    def install_flows(self, connection: sqlite3.Connection) -> None:
        """Scope traffic by recorded visits or evidence-linked network identity.

        Parameters:
            connection: History connection with scoped run detections attached.
        """
        identity = self._prepare(connection)
        period = self._recorded_period("f.event_time", identity)
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
