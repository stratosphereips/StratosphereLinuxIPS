from dataclasses import dataclass
from enum import Enum, auto

from slips_files.core.structures.evidence import Direction


# every flow seen by slips gets its fields converted in the following
# formats to be able to categorize it in redis


class State(Enum):
    EST = auto()
    NOT_EST = auto()


class Protocol(Enum):
    TCP = auto()
    UDP = auto()
    ICMP = auto()
    ICMP6 = auto()


class Role(Enum):
    CLIENT = auto()
    SERVER = auto()


class DataType(Enum):
    PORT = auto()
    IP = auto()


class Property(Enum):
    DST_PORTS = auto()
    DST_IPS = auto()
    SRC_PORTS = auto()
    SRC_IPS = auto()


@dataclass(frozen=True, slots=True)
class FlowQuery:
    direction: Direction
    state: State
    protocol: Protocol
    role: Role
    type_data: DataType
    property: Property

    def __post_init__(self):
        if self.type_data == DataType.PORT and self.property not in {
            Property.SRC_IPS,
            Property.DST_IPS,
        }:
            raise ValueError(
                f"Invalid self.property {self.property}. must "
                f"be [Property.SRC_IPS | Property.DST_IPS] "
            )

        if self.type_data == DataType.IP and self.property not in {
            Property.SRC_PORTS,
            Property.DST_PORTS,
        }:
            raise ValueError(
                f"Invalid self.property {self.property}. must "
                f"be [Property.SRC_PORTS, Property.DST_PORTS] "
            )
