from dataclasses import dataclass
from enum import Enum, auto

from slips_files.core.structures.evidence import Direction


# These Enums are used to construct a redis query in an organized way.
#
#
# Let's say we need a bunch of
#     Flows for Profile X -> that happened in Tw Y -> where X was the client (Role)
#     -> and the proto was TCP (Protocol) -> where conns were established (State).
#     and we need them sorted by Ports (KeyType) and each port should
#     contain the IPs that connected to it (Request)
#
# So we construct a query off of the following enums to be able to retreive
# the above complexity from the db in the most optimized way possible.
#
#
# I Recommend looking at the values of the
# profile_1.1.1.1_timewindow2:* keys
# in redis after a slips run to get an idea of what you're dealing with


class State(Enum):
    """Connection state of the flow (established vs not established)."""

    EST = auto()
    NOT_EST = auto()


class Protocol(Enum):
    """Transport or network protocol used by the flow."""

    TCP = auto()
    UDP = auto()
    ICMP = auto()
    ICMP6 = auto()


class Role(Enum):
    """
    Represents the role of the profile in the flow.
    Used for describing profiles.

    CLIENT: traffic originated by the profile.
    SERVER: traffic destined to the profile.
    """

    CLIENT = auto()
    SERVER = auto()


class KeyType(Enum):
    """
    Each query returns a dict. this is what the keys will be. ports or ips?

    PORT: group flows by port.
    IP: group flows by IP address.
    """

    PORT = auto()
    IP = auto()


class Request(Enum):
    """
    this should be the answer to the following question:
    what do i want to know about this profile & tw?

    SRC_* refers to source-side attributes.
    DST_* refers to destination-side attributes.
    """

    DST_PORTS = auto()
    DST_IPS = auto()
    SRC_PORTS = auto()
    SRC_IPS = auto()


@dataclass(frozen=True, slots=True)
class FlowQuery:
    """
    Describes a flow query, splitted and categorized and ready to be processed
    by redis.

    The combination of `key_type` and `request` is constrained so that
    the request attr is always the opposite dimension of `key_type`
    (e.g. if the request is PORT → the key_type should always be *_IPS).
    """

    direction: Direction
    state: State
    protocol: Protocol
    role: Role
    key_type: KeyType
    # this should be the answer to the following question:
    # what do i want to know about this profile & tw?
    # what kind of values is expected as the return of this query? do i
    # want dst ips? dst ports? etc.
    request: Request

    def __post_init__(self):
        if self.key_type == KeyType.PORT and self.request not in {
            Request.SRC_IPS,
            Request.DST_IPS,
        }:
            raise ValueError(
                f"Invalid self.request {self.request}. must "
                f"be [Request.SRC_IPS | Request.DST_IPS]"
            )

        if self.key_type == KeyType.IP and self.request not in {
            Request.SRC_PORTS,
            Request.DST_PORTS,
        }:
            raise ValueError(
                f"Invalid self.request {self.request}. must "
                f"be [Request.SRC_PORTS | Request.DST_PORTS]"
            )
