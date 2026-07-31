import math
from enum import Enum

from slips_files.core.helpers.risk_weights_config_parser import (
    read_risk_weights_config,
)


# we have 2 sets of values one for each of the following steps:
#
# Step1: Slips needs to determine in which risk level is it now.
# -> this depends on the ATL buckets. aka (RiskWeight Enum)
#
#
# Step2: Slips needs a multiplier for each sensitivity level, to control how
# fast/slow an alert is generated.
# -> this is determined from the values in the config LOW_RISK_WEIGHT,
# MEDIUM_RISK_WEIGHT, HIGH_RISK_WEIGHT

config = read_risk_weights_config()

LOW_RISK_WEIGHT = config.low_risk_weight
MEDIUM_RISK_WEIGHT = config.medium_risk_weight
HIGH_RISK_WEIGHT = config.high_risk_weight


class RiskWeight(Enum):
    """
    Risk-weight bucket used by live risk-weighted alerting.

    Each level stores `(minimum_atl, maximum_atl, risk_weight)`.
    minimum_atl, maximum_atl: min and max atl value to get slips into this
    risk weight.
    """

    LOW = (0, 47, LOW_RISK_WEIGHT)
    MEDIUM = (47, 60, MEDIUM_RISK_WEIGHT)
    HIGH = (60, float("inf"), HIGH_RISK_WEIGHT)

    @property
    def lower_bound(self) -> float:
        return self.value[0]

    @property
    def upper_bound(self) -> float:
        return self.value[1]

    @property
    def weight(self) -> float:
        """
        Returns the multiplier used in `RATL = ATL * risk_weight`.
        """
        return self.value[2]


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
    # ensure no negative values
    accumulated_threat_level = max(float(accumulated_threat_level), 0.0)

    for risk_weight in RiskWeight:
        if (
            risk_weight.lower_bound
            <= accumulated_threat_level
            < risk_weight.upper_bound
        ):
            return risk_weight

    return RiskWeight.LOW
