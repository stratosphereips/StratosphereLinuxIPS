from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

from slips_files.core.structures.evidence import (
    Direction,
    ProfileID,
    TimeWindow,
)


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

    The flow can go out of the IP (we are acting as Client)
    or into the IP (we are acting as Server), check the docs of
    Analysis direction
    https://stratospherelinuxips.readthedocs.io/en/develop/usage.html#modifying-the-configuration-file
    for more info.

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
    SRC_IPS = auto()


@dataclass(frozen=True, slots=True)
class FlowQuery:
    """
    Describes a Redis flow query and is able to fully render itself
    into the Redis key format via __repr__.

    Redis key format:
        profile_{ip}_{tw}:
            {role}:{protocol}:{state}:{dir}_{key_type}[:<{ip}|{port}>]:{request}

    Examples:
    profile_1.1.1.1_timewindow2:client:tcp:not_est:dst:ports:dst_ips
    profile_1.1.1.1_timewindow2:server:udp:est:src:ips:192.168.1.2:dst_ports


    Constraints:
    - if the request is PORT → the key_type should always be *_IPS and vice versa
    - you can't use a request without specifying an IP/port attr
    """

    profileid: ProfileID
    timewindow: TimeWindow

    direction: Direction
    state: State
    protocol: Protocol
    role: Role

    key_type: KeyType
    # this should be the answer to the following question:
    # what do i want to know about this profile & tw?
    # what kind of values is expected as the return of this query? do i
    # want dst ips? dst ports? etc.
    request: Optional[Request]

    # optional query filters
    ip: Optional[str] = None
    port: Optional[int] = None

    def __post_init__(self):
        #  key_type and request consistency
        if self.key_type == KeyType.PORT:
            if self.request and self.request not in {
                Request.SRC_IPS,
                Request.DST_IPS,
            }:
                raise ValueError(
                    "When key_type=PORT, request must be SRC_IPS or DST_IPS"
                )

        if self.key_type == KeyType.IP:
            if self.request and self.request != Request.DST_PORTS:
                raise ValueError(
                    "When key_type=IP, request must be DST_PORTS or None"
                )

        # filter validation
        if self.ip is not None and self.port is not None:
            raise ValueError("Only one of ip or port may be set")

        if self.ip is not None and self.key_type != KeyType.IP:
            raise ValueError("ip filter requires key_type=IP")

        if self.port is not None and self.key_type != KeyType.PORT:
            raise ValueError("port filter requires key_type=PORT")

        if not self.request and (self.ip or self.port):
            raise ValueError(
                f"Using request {self.request} requires ip or " f"port."
            )

    def __repr__(self) -> str:
        role = self.role.name.lower()
        protocol = self.protocol.name.lower()
        state = self.state.name.lower()
        direction = self.direction.name.lower()
        key_type = self.key_type.name.lower()
        # request example:
        # if key_type=PORT: request will be IP
        # if key_type=IP: request will be PORT
        if self.request is not None:
            request = self.request.name.lower()

        base = (
            f"{self.profileid}_{self.timewindow}"
            f":{role}:{protocol}:{state}:{direction}_{key_type}"
        )

        if self.port is not None and self.request is not None:
            # e.g something like
            # profile_1.1.1.1_timewindow2:server:udp:est:src:ips:192
            # .168.12.2:dst_ports
            # aka get me all the dst ports my priv ip connected to 1.1.1.1 on
            return f"{base}:{self.port}:{request}"

        if self.ip is not None and self.request is not None:
            # e.g something like
            # profile_1.1.1.1_timewindow2:server:udp:est:src:ips:192
            # .168.12.2:dst_ports
            # aka get me all the dst ports my priv ip connected to 1.1.1.1 on
            return f"{base}:{self.ip}:{request}"

        return f"{base}"
