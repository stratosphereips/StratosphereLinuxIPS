from enum import Enum


class RiskLevel(Enum):
    """
    This risk level determines the sensitivity of slips.
    the more risk -> the more sensitive slips is -> the more alerts are
    generated
    """

    LOW = 0
    MEDIUM = 0.15
    HIGH = 0.25
