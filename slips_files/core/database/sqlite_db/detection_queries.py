"""Read exact detection counters and clean hourly aggregates."""

import math
import sqlite3


def detection_total(connection: sqlite3.Connection, table: str) -> int:
    """Read a maintained count, falling back for databases predating counters.

    Parameters:
        connection: Read-only run or archive connection.
        table: Internal evidence or alerts table name.

    Returns:
        Exact number of active records in the requested table.
    """
    if table not in {"evidence", "alerts"}:
        raise ValueError("Unsupported detection table")
    if connection.execute(
        "SELECT 1 FROM sqlite_master WHERE name='history_totals'"
    ).fetchone():
        row = connection.execute(
            "SELECT count FROM history_totals WHERE entity=?", (table,)
        ).fetchone()
        if row:
            return int(row[0])
    return int(
        connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    )


def hourly_evidence_source(
    connection: sqlite3.Connection, start: float | None, end: float | None
) -> str | None:
    """Combine clean complete hours with raw records at range boundaries.

    Parameters:
        connection: Run connection inside a consistent read transaction.
        start: Inclusive earliest evidence timestamp, or no lower bound.
        end: Inclusive latest evidence timestamp, or no upper bound.

    Returns:
        Trusted weighted SQL source, or None while summaries are incomplete.
    """
    if (
        end is None
        or not math.isfinite(end)
        or (start is not None and not math.isfinite(start))
    ):
        return None
    if (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='history_state'"
        ).fetchone()
        is None
    ):
        return None
    row = connection.execute(
        "SELECT value FROM history_state WHERE key='summary_complete'"
    ).fetchone()
    if row is None or row[0] != "1":
        return None
    lower = math.ceil((start or 0) / 3600) * 3600
    upper = math.floor(end / 3600) * 3600
    if (
        upper <= lower
        or connection.execute(
            "SELECT 1 FROM history_dirty_hours WHERE hour>=? AND hour<? LIMIT 1",
            (lower, upper),
        ).fetchone()
    ):
        return None
    raw_columns = "profile_ip,evidence_type,threat_level,source_module,whitelisted,accumulated_threat_level,accumulated_ratl"
    return (
        "(SELECT profile_ip,evidence_type,threat_level,source_module,whitelisted,"
        "max_atl AS accumulated_threat_level,max_ratl AS accumulated_ratl,"
        "record_count AS weight,first_time,last_time AS evidence_time,alert_count AS summarized_alerts "
        f"FROM evidence_hourly WHERE hour>={lower} AND hour<{upper} UNION ALL "
        f"SELECT {raw_columns},1 AS weight,evidence_time AS first_time,evidence_time,"
        "(SELECT COUNT(*) FROM alert_evidence ae WHERE ae.evidence_id=e.evidence_id) AS summarized_alerts "
        "FROM main.evidence e INDEXED BY evidence_time_cover_idx "
        f"WHERE evidence_time>={start if start is not None else -1e300!r} AND evidence_time<={end!r} "
        f"AND (evidence_time<{lower} OR evidence_time>={upper})) AS evidence"
    )
