from enum import Enum, auto


class Label(Enum):
    BENIGN = auto()
    MALICIOUS = auto()
    BACKGROUND = auto()


BENIGN = Label.BENIGN
MALICIOUS = Label.MALICIOUS
BACKGROUND = Label.BACKGROUND
