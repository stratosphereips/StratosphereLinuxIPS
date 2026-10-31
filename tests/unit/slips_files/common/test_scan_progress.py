"""Shared scan confidence and bounded continuation behavior."""

import pytest
from tests.module_factory import ModuleFactory
from slips_files.common.scan_progress import ConfirmedScan, scan_confidence


@pytest.mark.parametrize("count,quality,strong,expected", [(10,1,True,.85),(20,1,True,.95),(100,1,True,1),(100,.92,True,.95),(100,.85,True,.85),(100,1,False,.85)])
def test_common_confidence_requires_independent_support(count: int, quality: float, strong: bool, expected: float) -> None:
    """Distinct volume alone cannot override the caller's context safeguards.

    Parameters:
        count: Distinct observations.
        quality: Supported share of the observations.
        strong: Whether the caller's independent checks passed.
        expected: Supported confidence.
    """
    module = ModuleFactory().create_horizontal_portscan_obj()
    assert scan_confidence(.85, count, 10, quality, strong) == expected
    assert not module.detector.groups


def test_common_progress_samples_milestones_and_duplicate_resistance() -> None:
    """A small counter spans logarithmic growth without keeping every ID."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    progress = ConfirmedScan.seed(((str(i), f"uid-{i}") for i in range(100)), 1000, 1001)
    assert not progress.due()
    for i in range(100, 1200):
        progress.observe(str(i), f"uid-{i}", 1002)
    assert progress.due()
    progress.reported()
    assert not progress.due()
    count = progress.counter.estimate()
    for _ in range(5000):
        progress.observe("100", "uid-100", 1003)
    assert count == progress.counter.estimate()
    assert len(progress.samples) == 20
    assert len(progress.counter.registers) == 1024
    assert progress.last == 1003
    assert progress.next_milestone == 10000
    assert not module.detector.groups
