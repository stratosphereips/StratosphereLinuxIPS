from enum import Enum
from math import inf


class RiskLevel(Enum):
    """
    This risk level determines the sensitivity of slips.
    the more risk -> the more sensitive slips is -> the more alerts are generated
    """

    LOW = (0.0, 0.15)
    MEDIUM = (0.15, 0.25)
    HIGH = (0.25, inf)

    @property
    def min_score(self):
        return self.value[0]

    @property
    def max_score(self):
        return self.value[1]
