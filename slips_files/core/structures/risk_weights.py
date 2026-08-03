import math
from enum import Enum

from slips_files.core.helpers.risk_weights_config_parser import (
    read_risk_weights_config,
)


config = read_risk_weights_config()

LOW_RISK_WEIGHT = config.low_risk_weight
MEDIUM_RISK_WEIGHT = config.medium_risk_weight
HIGH_RISK_WEIGHT = config.high_risk_weight
RATL_THRESHOLD = config.ratl_threshold


class RiskWeight(Enum):
    """
    Configured risk-weight multiplier used by live alerting.
    """

    LOW = LOW_RISK_WEIGHT
    MEDIUM = MEDIUM_RISK_WEIGHT
    HIGH = HIGH_RISK_WEIGHT

    @property
    def weight(self) -> float:
        """
        Returns the multiplier used in `RATL = ATL * risk_weight`.
        """
        return float(self.value)


def convert_weight_to_risk_weight_enum_member(weight: float) -> RiskWeight:
    """
    Return the enum member matching the configured risk weight value.

    Parameters:
        weight: Stored numeric risk weight.

    Return value:
        Matching risk-weight enum member.
    """
    normalized_weight = float(weight)

    for risk_weight in RiskWeight:
        if math.isclose(risk_weight.weight, normalized_weight):
            return risk_weight

    return RiskWeight.LOW


def increase_risk_weight(risk_weight: RiskWeight) -> RiskWeight:
    """
    Increase a risk-weight level by one step.

    Parameters:
        risk_weight: Current risk-weight level.

    Return value:
        Next risk-weight level, capped at the high level.
    """
    if risk_weight == RiskWeight.LOW:
        return RiskWeight.MEDIUM

    if risk_weight == RiskWeight.MEDIUM:
        return RiskWeight.HIGH

    return RiskWeight.HIGH


def get_risk_weight_for_accumulated_threat_level(
    accumulated_threat_level: float,
) -> RiskWeight:
    """
    Return the base risk-weight level.

    Parameters:
        accumulated_threat_level: Current accumulated threat level.

    Return value:
        Base risk-weight level. ATL no longer selects the risk weight.
    """
    _ = accumulated_threat_level
    return RiskWeight.LOW
