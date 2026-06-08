from enum import Enum
from typing import Tuple


class RiskWeight(Enum):
    """
    This risk weight determines the sensitivity of slips.
    the more risk -> the more sensitive slips is -> the more alerts are generated
    """

    HIGH = (0.0, 0.32)
    MEDIUM = (0.32, 1.0)
    LOW = (1.0, 1.72)

    @property
    def lower_bound(self) -> float:
        return self.value[0]

    @property
    def upper_bound(self) -> float:
        return self.value[1]


def convert_float_to_risk_weight(value: float) -> RiskWeight:
    """
    Convert a numeric value to the matching risk weight bucket.

    Parameters:
        value: Numeric value to classify.

    Return value:
        Matching risk weight bucket.
    """
    value = float(value)

    if value < 0:
        return RiskWeight.LOW

    for weight in RiskWeight:
        weight_boundaries: Tuple[float, float] = weight.value
        if weight_boundaries[0] <= value < weight_boundaries[1]:
            return weight

    return RiskWeight.LOW
