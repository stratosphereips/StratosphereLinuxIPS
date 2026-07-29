from enum import Enum

from slips_files.core.helpers.risk_weights_config_parser import (
    read_risk_weights_config,
)


config = read_risk_weights_config()

# this is the multiplier used here
# RATL_THRESHOLD = ATL_boundary * risk_weight
LOW_RISK_WEIGHT = config.low_risk_weight
MEDIUM_RISK_WEIGHT = config.medium_risk_weight
HIGH_RISK_WEIGHT = config.high_risk_weight
RATL_THRESHOLD = config.ratl_threshold


class RiskWeight(Enum):
    """
    Risk-weight bucket used by live risk-weighted alerting.

    Each level stores `(minimum_atl, maximum_atl, risk_weight)`.
    minimum_atl, maximum_atl: min and max atl value to get slips into this
    risk weight.
    """

    LOW = (0, 4, LOW_RISK_WEIGHT)
    MEDIUM = (4, 15, MEDIUM_RISK_WEIGHT)
    HIGH = (15, float("inf"), HIGH_RISK_WEIGHT)

    @property
    def minimum_atl(self) -> float:
        return self.value[0]

    @property
    def maximum_atl(self) -> float:
        return self.value[1]

    @property
    def risk_weight(self) -> float:
        """
        Return the multiplier used in `RATL = ATL * risk_weight`.

        Return value:
            Configured risk weight for this bucket.
        """
        return self.value[2]


def convert_float_to_risk_weight(value: float) -> RiskWeight:
    """
    Convert a configured risk weight to the matching bucket.

    Parameters:
        value: Numeric risk weight to classify.

    Return value:
        Matching risk-weight bucket.
    """
    value = float(value)
    if value < 0:
        return RiskWeight.LOW

    if value <= LOW_RISK_WEIGHT:
        return RiskWeight.LOW

    if value <= MEDIUM_RISK_WEIGHT:
        return RiskWeight.MEDIUM

    return RiskWeight.HIGH


def get_risk_weight_for_accumulated_threat_level(
    accumulated_threat_level: float,
) -> RiskWeight:
    """
    Return the configured risk-weight bucket for the given ATL.

    Parameters:
        accumulated_threat_level: Current accumulated threat level.

    Return value:
        Matching risk-weight bucket for the accumulated threat level.
    """
    accumulated_threat_level = max(float(accumulated_threat_level), 0.0)

    if accumulated_threat_level < RiskWeight.MEDIUM.minimum_atl:
        return RiskWeight.HIGH

    if accumulated_threat_level < RiskWeight.HIGH.minimum_atl:
        return RiskWeight.MEDIUM

    return RiskWeight.LOW
