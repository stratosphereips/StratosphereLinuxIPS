"""Accuracy, duplicate resistance and fixed memory of confirmed-scan counters."""

import pytest

from modules.network_discovery.distinct_targets import DistinctTargets
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("count", [0, 100, 1000, 10000, 100000])
def test_counter_accuracy_and_fixed_allocation(count: int) -> None:
    """Keep reasonable estimates across decades without growing the registers.

    Parameters:
        count: Number of distinct validated destination strings.
    """
    module = ModuleFactory().create_horizontal_portscan_obj()
    counter = DistinctTargets()
    for i in range(count):
        counter.add(f"198.{i//65536}.{(i//256)%256}.{i%256}")
    estimate = counter.estimate()
    assert abs(estimate - count) <= max(1, count * 0.1)
    assert len(counter.registers) == 1024
    assert not module.detector.groups


def test_duplicate_order_does_not_change_estimate() -> None:
    """Hashes update maxima, so retries and arrival order cannot inflate them."""
    module = ModuleFactory().create_horizontal_portscan_obj()
    first, second = DistinctTargets(), DistinctTargets()
    for i in range(10000):
        first.add(f"2001:db8::{i:x}")
        second.add(f"2001:db8::{9999-i:x}")
    for _ in range(10000):
        first.add("2001:db8::1")
    assert first.registers == second.registers
    assert first.estimate() == second.estimate()
    assert not module.detector.groups
