from enum import Enum

from slips_files.core.helpers.risk_weights_config_parser import (
    read_risk_weights_config,
)


config = read_risk_weights_config()

# this is the multiplier used here
# RATL_THRESHOLD = ATL_boundary * risk_weight
LOW_SENSITIVITY_WEIGHT = config.low_sensitivity_weight
MEDIUM_SENSITIVITY_WEIGHT = config.medium_sensitivity_weight
HIGH_SENSITIVITY_WEIGHT = config.high_sensitivity_weight
RATL_THRESHOLD = config.ratl_threshold


LOW_ATL_BOUNDARY = RATL_THRESHOLD / LOW_SENSITIVITY_WEIGHT
MEDIUM_ATL_BOUNDARY = RATL_THRESHOLD / MEDIUM_SENSITIVITY_WEIGHT
HIGH_ATL_BOUNDARY = RATL_THRESHOLD / HIGH_SENSITIVITY_WEIGHT


class Sensitivity(Enum):
    """
    Sensitivity bucket used by live risk-weighted alerting.

    Each level stores `(minimum_atl, maximum_atl, sensitivity_weight)`.
    """

    LOW = (LOW_ATL_BOUNDARY, float("inf"), LOW_SENSITIVITY_WEIGHT)
    MEDIUM = (
        MEDIUM_ATL_BOUNDARY,
        LOW_ATL_BOUNDARY,
        MEDIUM_SENSITIVITY_WEIGHT,
    )
    HIGH = (0.0, MEDIUM_ATL_BOUNDARY, HIGH_SENSITIVITY_WEIGHT)

    @property
    def minimum_atl(self) -> float:
        return self.value[0]

    @property
    def maximum_atl(self) -> float:
        return self.value[1]

    @property
    def sensitivity_weight(self) -> float:
        """
        Return the multiplier used in `RATL = ATL * sensitivity_weight`.

        Return value:
            Configured sensitivity weight for this bucket.
        """
        return self.value[2]

    @property
    def alertable_atl_boundary(self) -> float:
        """
        Return the minimum ATL that can alert in this bucket.

        Return value:
            Minimum alertable ATL for this sensitivity bucket.
        """
        return RATL_THRESHOLD / self.sensitivity_weight


def convert_sensitivity_weight_to_risk_weight(value: float) -> Sensitivity:
    """
    Convert a configured sensitivity weight to the matching bucket.

    Parameters:
        value: Numeric sensitivity weight to classify.

    Return value:
        Matching sensitivity bucket.
    """
    value = float(value)
    if value < 0:
        return Sensitivity.LOW

    if value <= LOW_SENSITIVITY_WEIGHT:
        return Sensitivity.LOW

    if value <= MEDIUM_SENSITIVITY_WEIGHT:
        return Sensitivity.MEDIUM

    return Sensitivity.HIGH


def get_sensitivity_for_accumulated_threat_level(
    accumulated_threat_level: float,
) -> Sensitivity:
    """
    in which sensitivity is slips based on the given accumulated threat
    level?

    Parameters:
        accumulated_threat_level: Current accumulated threat level.

    Return value:
        Matching sensitivity bucket for the accumulated threat level.
    """
    accumulated_threat_level = max(float(accumulated_threat_level), 0.0)

    if accumulated_threat_level >= Sensitivity.LOW.minimum_atl:
        return Sensitivity.LOW

    if accumulated_threat_level >= Sensitivity.MEDIUM.minimum_atl:
        return Sensitivity.MEDIUM

    if accumulated_threat_level < Sensitivity.HIGH.maximum_atl:
        return Sensitivity.HIGH

    return Sensitivity.LOW
