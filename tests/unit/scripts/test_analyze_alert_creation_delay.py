from datetime import datetime

import pytest

from scripts.analyze_alert_creation_delay import (
    build_summary,
    delay_band_label,
    truncate_datetime,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "resolution, expected",
    [
        ("day", datetime(2026, 6, 23)),
        ("hour", datetime(2026, 6, 23, 12)),
        ("minute", datetime(2026, 6, 23, 12, 34)),
    ],
)
def test_truncate_datetime_returns_expected_resolution(
    resolution: str, expected: datetime
) -> None:
    """Verify timestamps are truncated at the requested resolution.

    Parameters:
        resolution: Resolution name to apply.
        expected: Expected truncated timestamp.

    Return value:
        None.
    """
    module_factory = ModuleFactory()
    value = datetime(2026, 6, 23, 12, 34, 56, 789)

    assert module_factory
    assert truncate_datetime(value, resolution) == expected


@pytest.mark.parametrize(
    "delay_seconds, expected",
    [
        (-0.1, "negative"),
        (0.5, "0s-1s"),
        (60.0, "1m-5m"),
        (86400.0, ">=1d"),
    ],
)
def test_delay_band_label_classifies_boundaries(
    delay_seconds: float, expected: str
) -> None:
    """Verify delay band labels include boundary values correctly.

    Parameters:
        delay_seconds: Delay value to classify.
        expected: Expected delay band label.

    Return value:
        None.
    """
    module_factory = ModuleFactory()

    assert module_factory
    assert delay_band_label(delay_seconds) == expected


def test_build_summary_computes_distribution_stats() -> None:
    """Verify alert delay summary statistics are computed from values.

    Return value:
        None.
    """
    module_factory = ModuleFactory()

    summary = build_summary([1.0, 2.0, 3.0])

    assert module_factory
    assert summary.count == 3
    assert summary.mean_seconds == 2.0
    assert summary.p50_seconds == 2.0
