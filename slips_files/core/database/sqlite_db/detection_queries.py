"""Read exact detection counters and clean hourly evidence aggregates.

This module offers two read-only helpers for the detection history storage:

* ``count_active_detection_records``: how many evidence or alert records exist.
* ``build_hourly_evidence_source_sql``: a SQL source that mixes pre-computed
  hourly summaries (fast) with raw evidence rows at the edges of a time range
  (exact).
"""

import math
import sqlite3

from .detection_history import NULLABLE_SCORE_SUMMARIES_MIGRATION_KEY

SECONDS_PER_HOUR = 3600

# Tables whose row counts can be read. Names are inserted into SQL text, so
# they must come from this allow-list and never from user input.
COUNTABLE_DETECTION_TABLES = frozenset({"evidence", "alerts"})

# "" means "use the connection's default scope (may be a request-local view)".
# "main" means "read the real storage and bypass any scope views".
ALLOWED_SCHEMA_NAMES = frozenset({"", "main"})

# Columns copied unchanged from the raw evidence table.
RAW_EVIDENCE_COLUMNS = (
    "profile_ip,evidence_type,threat_level,source_module,whitelisted,"
    "accumulated_threat_level,accumulated_ratl"
)


def _sqlite_master_has_table(
    connection: sqlite3.Connection, table_name: str, schema_prefix: str = ""
) -> bool:
    """Check whether a table (or view) with this name exists.

    Parameters:
        connection: Open SQLite connection.
        table_name: Name to look for in ``sqlite_master``.
        schema_prefix: Either "" or a prefix such as ``"main."``.

    Returns:
        True when the name is present, False otherwise.
    """
    found_row = connection.execute(
        f"SELECT 1 FROM {schema_prefix}sqlite_master WHERE name=?",
        (table_name,),
    ).fetchone()
    return found_row is not None


def _history_state_has_key(
    connection: sqlite3.Connection, state_key: str
) -> bool:
    """Check whether ``history_state`` contains a row with this key."""
    found_row = connection.execute(
        "SELECT 1 FROM history_state WHERE key=?", (state_key,)
    ).fetchone()
    return found_row is not None


def _hourly_summaries_are_complete(connection: sqlite3.Connection) -> bool:
    """Check that hourly summaries were fully built and fully migrated.

    Summaries are only trustworthy once the history writer marked them
    complete and the nullable-score migration has been applied.

    Parameters:
        connection: Run connection inside a consistent read transaction.

    Returns:
        True when the summaries can be used in place of raw evidence rows.
    """
    if not _sqlite_master_has_table(connection, "history_state"):
        return False

    summary_complete_row = connection.execute(
        "SELECT value FROM history_state WHERE key='summary_complete'"
    ).fetchone()
    if summary_complete_row is None or summary_complete_row[0] != "1":
        return False

    return _history_state_has_key(
        connection, NULLABLE_SCORE_SUMMARIES_MIGRATION_KEY
    )


def _has_dirty_hours_in_range(
    connection: sqlite3.Connection, first_hour: int, last_hour_exclusive: int
) -> bool:
    """Check whether an hour in ``[first_hour, last_hour_exclusive)`` is stale.

    A dirty hour is one whose summary no longer matches its raw records, so
    that summary must not be used.
    """
    dirty_hour_row = connection.execute(
        "SELECT 1 FROM history_dirty_hours WHERE hour>=? AND hour<? LIMIT 1",
        (first_hour, last_hour_exclusive),
    ).fetchone()
    return dirty_hour_row is not None


def count_active_detection_records(
    connection: sqlite3.Connection, table_name: str, schema_name: str = ""
) -> int:
    """Count active records, preferring the maintained counter.

    Newer databases keep a ``history_totals`` counter table that is cheap to
    read. Databases created before that table existed fall back to a full
    ``COUNT(*)`` scan.

    Parameters:
        connection: Read-only run or archive connection.
        table_name: Internal table to count; "evidence" or "alerts".
        schema_name: "main" to read real storage and bypass request-local
            scope views; "" to use the connection's default scope.

    Returns:
        Exact number of active records in the requested table.

    Raises:
        ValueError: If the table or schema name is not on the allow-list.
    """
    if table_name not in COUNTABLE_DETECTION_TABLES:
        raise ValueError("Unsupported detection table")
    if schema_name not in ALLOWED_SCHEMA_NAMES:
        raise ValueError("Unsupported detection schema")

    schema_prefix = f"{schema_name}." if schema_name else ""

    if _sqlite_master_has_table(connection, "history_totals", schema_prefix):
        maintained_count_row = connection.execute(
            f"SELECT count FROM {schema_prefix}history_totals WHERE entity=?",
            (table_name,),
        ).fetchone()
        if maintained_count_row:
            return int(maintained_count_row[0])

    # Fallback for databases that predate the maintained counters.
    full_scan_row = connection.execute(
        f"SELECT COUNT(*) FROM {schema_prefix}{table_name}"
    ).fetchone()
    return int(full_scan_row[0])


def build_hourly_evidence_source_sql(
    connection: sqlite3.Connection,
    range_start_timestamp: float | None,
    range_end_timestamp: float | None,
) -> str | None:
    """Build a SQL source mixing hourly summaries with raw boundary records.

    Complete hours inside the range come from the ``evidence_hourly``
    summaries. The partial hours at the start and end of the range come from
    the raw ``evidence`` table, so the result stays exact.

    Parameters:
        connection: Run connection inside a consistent read transaction.
        range_start_timestamp: Inclusive earliest evidence timestamp, or None
            for no lower bound.
        range_end_timestamp: Inclusive latest evidence timestamp, or None for
            no upper bound. A missing end disables the summary path.

    Returns:
        A weighted SQL sub-select aliased as ``evidence``, or None when the
        summaries cannot be trusted (incomplete, stale, or the range is too
        short to contain a full hour). Callers must then query raw evidence.
    """
    has_valid_end = range_end_timestamp is not None and math.isfinite(
        range_end_timestamp
    )
    has_valid_start = range_start_timestamp is None or math.isfinite(
        range_start_timestamp
    )
    if not has_valid_end or not has_valid_start:
        return None

    if not _hourly_summaries_are_complete(connection):
        return None

    # Only whole hours fully inside the range can use summaries.
    first_full_hour = (
        math.ceil((range_start_timestamp or 0) / SECONDS_PER_HOUR)
        * SECONDS_PER_HOUR
    )
    last_full_hour_exclusive = (
        math.floor(range_end_timestamp / SECONDS_PER_HOUR) * SECONDS_PER_HOUR
    )
    if last_full_hour_exclusive <= first_full_hour:
        return None
    if _has_dirty_hours_in_range(
        connection, first_full_hour, last_full_hour_exclusive
    ):
        return None

    lower_bound_sql = (
        range_start_timestamp if range_start_timestamp is not None else -1e300
    )

    summarized_hours_sql = (
        "SELECT profile_ip,evidence_type,threat_level,source_module,"
        "whitelisted,max_atl AS accumulated_threat_level,max_ratl AS accumulated_ratl,"
        "record_count AS weight,first_time,last_time AS evidence_time,"
        "alert_count AS summarized_alerts "
        f"FROM evidence_hourly WHERE hour>={first_full_hour} "
        f"AND hour<{last_full_hour_exclusive}"
    )
    raw_boundary_records_sql = (
        f"SELECT {RAW_EVIDENCE_COLUMNS},1 AS weight,"
        "evidence_time AS first_time,evidence_time,"
        "(SELECT COUNT(*) FROM alert_evidence ae "
        "WHERE ae.evidence_id=e.evidence_id) AS summarized_alerts "
        "FROM main.evidence e INDEXED BY evidence_time_cover_idx "
        f"WHERE evidence_time>={lower_bound_sql!r} "
        f"AND evidence_time<={range_end_timestamp!r} "
        f"AND (evidence_time<{first_full_hour} "
        f"OR evidence_time>={last_full_hour_exclusive})"
    )
    return (
        f"({summarized_hours_sql} UNION ALL {raw_boundary_records_sql}) "
        "AS evidence"
    )
