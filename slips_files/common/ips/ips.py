"""Shared network address constants used across Slips."""

BROADCAST_MAC: str = "ff:ff:ff:ff:ff:ff"
NULL_MAC: str = "00:00:00:00:00:00"

IPV4_ANY: str = "0.0.0.0"
IPV4_BROADCAST: str = "255.255.255.255"
IPV4_LOCALHOST: str = "127.0.0.1"
IPV6_LOCALHOST: str = "::1"

LOCALHOST_HOSTNAME: str = "localhost"

SPECIAL_MAC_ADDRESSES: tuple[str, str] = (NULL_MAC, BROADCAST_MAC)
SPECIAL_IPV4_ADDRESSES: tuple[str, str] = (IPV4_ANY, IPV4_BROADCAST)
LOCALHOST_IPS: tuple[str, str] = (IPV4_LOCALHOST, IPV6_LOCALHOST)
