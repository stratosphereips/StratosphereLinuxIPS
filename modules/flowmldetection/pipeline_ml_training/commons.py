from enum import Enum


class Label(Enum):
    MALICIOUS = "Malicious"
    BENIGN = "Benign"
    BACKGROUND = "Background"


BENIGN = Label.BENIGN.value
MALICIOUS = Label.MALICIOUS.value
BACKGROUND = Label.BACKGROUND.value
