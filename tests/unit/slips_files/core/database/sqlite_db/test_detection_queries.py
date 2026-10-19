"""Check exact counters and summary fallbacks for legacy or dirty databases."""

import sqlite3

import pytest

from tests.module_factory import ModuleFactory
from slips_files.core.database.sqlite_db.detection_queries import (
    detection_total,
    hourly_evidence_source,
)


@pytest.mark.parametrize("counted", [False, True])
def test_detection_total_supports_legacy_and_counted_databases(
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
        assert detection_total(connection, "evidence") == 2
        with pytest.raises(ValueError):
            detection_total(connection, "untrusted_table")


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
        assert hourly_evidence_source(connection, start, end) is None
