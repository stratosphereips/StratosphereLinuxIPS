from enum import Enum


class Label(Enum):
    """
    label of flows should be one of the following
    """

    MALICIOUS = "Malicious"
    BENIGN = "Benign"
    BACKGROUND = "Background"
