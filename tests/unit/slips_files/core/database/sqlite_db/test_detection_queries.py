"""Check exact counters and summary fallbacks for legacy or dirty databases."""

import sqlite3

import pytest

from tests.module_factory import ModuleFactory
from slips_files.core.database.sqlite_db.detection_queries import (
    build_hourly_evidence_source_sql,
    count_active_detection_records,
)


@pytest.mark.parametrize("counted", [False, True])
def test_count_active_detection_records_supports_legacy_and_counted_databases(
    counted: bool,
) -> None:
    """Count a legacy table or read its maintained exact total.

    Parameters:
        counted: Whether a maintained counter exists.
    """
    _factory = ModuleFactory()
    with sqlite3.connect(":memory:") as connection:
        connection.execute("CREATE TABLE evidence(evidence_id TEXT)")
        connection.execute("INSERT INTO evidence VALUES ('one'),('two')")
        if counted:
            connection.execute(
                "CREATE TABLE history_totals(entity TEXT,count INTEGER)"
            )
            connection.execute(
                "INSERT INTO history_totals VALUES ('evidence',2)"
            )
        assert count_active_detection_records(connection, "evidence") == 2
        with pytest.raises(ValueError):
            count_active_detection_records(connection, "untrusted_table")


@pytest.mark.parametrize(
    "start,end",
    [(None, None), (float("inf"), 100), (0, float("nan")), (0, 100)],
)
def test_summary_falls_back_for_legacy_or_invalid_ranges(
    start: float | None, end: float | None
) -> None:
    """Keep invalid or pre-upgrade requests on the normal query path.

    Parameters:
        start: Requested lower time bound.
        end: Requested upper time bound.
    """
    _factory = ModuleFactory()
    with sqlite3.connect(":memory:") as connection:
        assert build_hourly_evidence_source_sql(connection, start, end) is None


@pytest.mark.parametrize("counted", [False, True])
def test_run_totals_bypass_scoped_views(counted: bool) -> None:
    """Read explicit run totals without evaluating expensive network views.

    Parameters:
        counted: Whether the run has maintained counters or a legacy table.
    """
    _factory = ModuleFactory()
    with sqlite3.connect(":memory:") as connection:
        connection.execute("CREATE TABLE evidence(evidence_id TEXT)")
        connection.execute("INSERT INTO evidence VALUES ('one'),('two')")
        if counted:
            connection.execute(
                "CREATE TABLE history_totals(entity TEXT,count INTEGER)"
            )
            connection.execute(
                "INSERT INTO history_totals VALUES ('evidence',2)"
            )
            connection.execute(
                "CREATE TEMP VIEW history_totals AS SELECT * FROM main.history_totals WHERE 0"
            )
        connection.execute(
            "CREATE TEMP VIEW evidence AS SELECT * FROM main.evidence WHERE 0"
        )
        assert count_active_detection_records(connection, "evidence") == 0
        assert (
            count_active_detection_records(connection, "evidence", "main") == 2
        )
        with pytest.raises(ValueError):
            count_active_detection_records(
                connection, "evidence", "untrusted.schema"
            )
