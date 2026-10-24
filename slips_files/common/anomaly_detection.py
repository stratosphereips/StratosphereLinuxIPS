"""Small, dependency-free statistics shared by anomaly detectors."""

import math
from collections.abc import Sequence
from statistics import median
from typing import Literal


def quantile(
    values: Sequence[float],
    probability: float,
    method: Literal["linear", "lower", "higher"] = "linear",
    *,
    presorted: bool = False,
) -> float:
    """Calculate an empirical quantile without modifying the sample.

    Parameters:
        values: Finite numeric sample.
        probability: Requested fraction, clamped to the unit interval.
        method: Interpolate, or select the lower/higher neighboring value.
        presorted: Whether values are already in ascending order.

    Returns:
        Sample quantile, or zero for an empty sample.
    """
    if method not in {"linear", "lower", "higher"}:
        raise ValueError("Unsupported quantile method")
    if not values:
        return 0.0
    ordered = values if presorted else sorted(values)
    position = min(1.0, max(0.0, float(probability))) * (len(ordered) - 1)
    low, high = math.floor(position), math.ceil(position)
    if method == "lower" or low == high:
        return ordered[low]
    if method == "higher":
        return ordered[high]
    fraction = position - low
    return ordered[low] * (1.0 - fraction) + ordered[high] * fraction


def robust_location_scale(
    values: Sequence[float], min_scale: float
) -> tuple[float, float]:
    """Estimate a robust center and scale using the median and MAD.

    Parameters:
        values: Finite numeric sample, normally a bounded detector window.
        min_scale: Nonnegative lower bound for the estimated scale.

    Returns:
        Median and max(1.4826 * MAD, min_scale); empty samples use zero center.
    """
    if not values:
        return 0.0, min_scale
    center = median(values)
    mad = median([abs(value - center) for value in values])
    return center, max(1.4826 * mad, min_scale)
