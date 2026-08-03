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

    # to alert:  ATL * RW >= RATL_threshold
    # given:  LOW_RISK_WEIGHT = 0.32, RATL_threshold = 5  (from config)
    # so the minimum needed ATL to be able to alert in the low bucket when
    # the threshold is 5 is:  ATL >= 15/0.32
    # ATL >= 15.625
    # any value of atl that is less than 15.625 will not generate an alert
    # SO. the low bucket MUST be more than 15.625 for slips to be able to
    # generate an alert in the low bucket.
    # SO. from when atl is from 0 -> 15.6 (slips will never generate an alert)
    # when atl is from 15.6 -> 20 slips will gen an alert in the low risk
    # weight.
    # from 20 -> 30 slips will gen an alert in the medium risk weight.
    # from 30 -> inf slips will gen an alert in the high risk weight.
    LOW = (0, 20, LOW_RISK_WEIGHT)
    MEDIUM = (20, 30, MEDIUM_RISK_WEIGHT)
    HIGH = (30, float("inf"), HIGH_RISK_WEIGHT)

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


def increase_risk_weight(risk_weight: RiskWeight) -> RiskWeight:
    """
    Increase a risk-weight bucket by one level.

    Parameters:
        risk_weight: Current risk-weight bucket.

    Return value:
        Next risk-weight bucket, capped at the high bucket.
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
