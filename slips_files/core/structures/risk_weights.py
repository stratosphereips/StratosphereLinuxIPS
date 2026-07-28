from enum import Enum
from typing import Tuple

from slips_files.common.parsers.config_parser import ConfigParser


def _read_configured_risk_weight(config_name: str) -> float:
    """
    Read a risk weight boundary from slips.yaml.

    Parameters:
        config_name: Detection configuration key to read.

    Return value:
        Configured risk weight boundary as a float.
    """
    risk_weight = ConfigParser().read_configuration(
        "detection", config_name, None
    )
    if risk_weight is None:
        raise ValueError(f"Missing detection.{config_name} in slips.yaml.")

    return float(risk_weight)


LOW_RISK_WEIGHT = _read_configured_risk_weight("low_risk_weight")
MEDIUM_RISK_WEIGHT = _read_configured_risk_weight("medium_risk_weight")
HIGH_RISK_WEIGHT = _read_configured_risk_weight("high_risk_weight")


class RiskWeight(Enum):
    """
    This risk weight determines the sensitivity of slips.
    the more risk -> the more sensitive slips is -> the more alerts are generated
    """

    LOW = (0.0, LOW_RISK_WEIGHT)
    MEDIUM = (LOW_RISK_WEIGHT, MEDIUM_RISK_WEIGHT)
    HIGH = (MEDIUM_RISK_WEIGHT, HIGH_RISK_WEIGHT)

    @property
    def lower_bound(self) -> float:
        return self.value[0]

    @property
    def upper_bound(self) -> float:
        return self.value[1]


def convert_float_to_risk_weight(value: float) -> RiskWeight:
    """
    Convert a numeric value to the matching risk weight bucket from
    RiskWeight Enum

    Parameters:
        value: Numeric value to classify.

    Return value:
        Matching risk weight bucket.
    """
    value = float(value)
    fallback = RiskWeight.LOW

    if value < 0:
        return RiskWeight.LOW

    if value > RiskWeight.HIGH.upper_bound:
        return RiskWeight.HIGH

    for weight in RiskWeight:
        weight_boundaries: Tuple[float, float] = weight.value
        if weight_boundaries[0] <= value < weight_boundaries[1]:
            return weight

    return fallback
