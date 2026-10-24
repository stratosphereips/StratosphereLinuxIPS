"""Verify shared statistics and the HTTPS detector's numerical behavior."""

from copy import deepcopy

import pytest

from modules.anomaly_detection_https.anomaly_detection_https import EWMAStats
from slips_files.common.anomaly_detection import (
    quantile,
    robust_location_scale,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "values,probability,method,expected",
    [
        ([], 0.5, "linear", 0.0),
        ([7.0], 0.1, "linear", 7.0),
        ([10.0, 0.0], 0.25, "linear", 2.5),
        ([10.0, 0.0], 0.25, "lower", 0.0),
        ([10.0, 0.0], 0.25, "higher", 10.0),
        ([0.0, 10.0, 20.0], 0.5, "higher", 10.0),
        ([1.0, 8.0], -1.0, "linear", 1.0),
        ([1.0, 8.0], 2.0, "linear", 8.0),
    ],
)
def test_quantile_methods_preserve_input(
    values: list[float], probability: float, method: str, expected: float
) -> None:
    """Check interpolation, conservative tails and boundaries.

    Parameters:
        values: Empirical sample, possibly empty or unordered.
        probability: Requested percentile fraction.
        method: Interpolation or neighboring order statistic.
        expected: Expected quantile.
    """
    _module = ModuleFactory().create_service_anomaly_obj()
    original = deepcopy(values)
    assert quantile(values, probability, method) == pytest.approx(expected)
    assert quantile(
        sorted(values), probability, method, presorted=True
    ) == pytest.approx(expected)
    assert values == original
    if method == "linear":
        assert EWMAStats._quantile(values, probability) == pytest.approx(
            expected
        )


def test_quantile_rejects_unsupported_method() -> None:
    """Reject misspelled methods instead of silently changing tail behavior."""
    _module = ModuleFactory().create_service_anomaly_obj()
    with pytest.raises(ValueError, match="quantile method"):
        quantile([1.0, 2.0], 0.5, "nearest")


@pytest.mark.parametrize(
    "values,floor,center,scale",
    [
        ([], 0.25, 0.0, 0.25),
        ([2.0], 0.25, 2.0, 0.25),
        ([2.0] * 10, 0.0, 2.0, 0.0),
        ([1.0, 2.0, 3.0, 4.0, 100000.0], 0.25, 3.0, 1.4826),
        ([1.0, 2.0, 3.0, 4.0], 0.25, 2.5, 1.4826),
        ([1.0, 2.0, 3.0, 4.0], 10.0, 2.5, 10.0),
    ],
)
def test_robust_location_and_scale(
    values: list[float], floor: float, center: float, scale: float
) -> None:
    """Preserve robust centers, even medians and independent scale floors.

    Parameters:
        values: Finite sample, including constant and contaminated windows.
        floor: Minimum scale chosen by the detector.
        center: Expected median.
        scale: Expected MAD-based scale.
    """
    _module = ModuleFactory().create_service_anomaly_obj()
    assert robust_location_scale(values, floor) == pytest.approx(
        (center, scale)
    )


def test_https_scoring_and_calibration_preserve_robust_statistics() -> None:
    """Check scoring, residual floors and calibration after helper extraction."""
    _module = ModuleFactory().create_service_anomaly_obj()
    stats = EWMAStats(
        min_std_floor=0.25,
        value_window=[float(value) for value in range(11)],
        training_values=[float(value) for value in range(10)] + [50.0],
        residuals=[1.0, 2.0, 3.0, 4.0, 5.0],
        floor_update_beta=1.0,
    )
    assert stats.robust_zscore(20.0) == pytest.approx(15.0 / (3 * 1.4826))
    stats.calibrate_empirical_threshold(3.5, quantile=0.95)
    assert stats.empirical_threshold == pytest.approx(25.0 / (3 * 1.4826))
    stats.update_min_std_floor()
    assert stats.min_std_floor == pytest.approx(1.4826)


def test_https_zero_scale_and_small_sample_fallbacks() -> None:
    """Keep existing moment-based and uncalibrated-threshold fallbacks."""
    _module = ModuleFactory().create_service_anomaly_obj()
    stats = EWMAStats(mean=2.0, var=4.0, value_window=[2.0])
    assert stats.robust_zscore(8.0) == 3.0
    stats.calibrate_empirical_threshold(3.5)
    assert stats.empirical_threshold == 3.5
    stats.training_values = [2.0] * 10
    stats.min_std_floor = 0.0
    stats.calibrate_empirical_threshold(4.0)
    assert stats.empirical_threshold == 4.0
