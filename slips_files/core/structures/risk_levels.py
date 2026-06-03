from enum import Enum
from math import inf
from typing import Tuple


class RiskLevel(Enum):
    """
    This risk level determines the sensitivity of slips.
    the more risk -> the more sensitive slips is -> the more alerts are generated
    """

    LOW = (0.0, 0.15)
    MEDIUM = (0.15, 0.25)
    HIGH = (0.25, inf)

    @property
    def lower_bound(self):
        return self.value[0]

    @property
    def upper_bound(self):
        return self.value[1]


def convert_float_to_risk_level(value: float) -> RiskLevel:
    value = float(value)

    if value < 0:
        return RiskLevel.LOW

    for level in RiskLevel:
        level_boundaries: Tuple[float, float] = level.value
        if level_boundaries[0] <= value < level_boundaries[1]:
            return level
