"""Check Linux and macOS live network settings collection."""

import sys
from unittest.mock import patch

import netifaces
import pytest

from managers import network_state
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "values, expected",
    [
        (["10.0.0.53", "10.0.0.53", "bad"], ["10.0.0.53"]),
        (["fe80::53%en0", "2001:db8::53"], ["fe80::53", "2001:db8::53"]),
    ],
)
def test_valid_dns_addresses(values: list[str], expected: list[str]) -> None:
    """Discard malformed and repeated resolver addresses.

    Parameters:
        values: Candidate DNS addresses.
        expected: Normalized addresses.
    """
    _ = ModuleFactory()
    assert network_state.valid_dns_addresses(values) == expected


@pytest.mark.parametrize(
    "platform, command_result, expected",
    [
        (
            "linux",
            "Link 2 (wlan0): 10.0.0.53 2001:db8::53\n",
            ["10.0.0.53", "2001:db8::53"],
        ),
        (
            "darwin",
            "resolver #1\n  nameserver[0] : 10.0.0.53\n"
            "  if_index : 4 (en0)\nresolver #2\n"
            "  nameserver[0] : 192.168.1.1\n  if_index : 5 (en1)\n",
            ["10.0.0.53"],
        ),
    ],
)
def test_dns_servers_per_interface(
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    command_result: str,
    expected: list[str],
) -> None:
    """Read resolvers of the monitored link on both operating systems.

    Parameters:
        monkeypatch: Restores operating-system values after the test.
        platform: Emulated operating system.
        command_result: Resolver command response.
        expected: DNS addresses of the monitored interface.
    """
    _ = ModuleFactory()
    monkeypatch.setattr(sys, "platform", platform)
    with (
        patch.object(network_state, "command_output", return_value=command_result),
        patch.object(network_state.socket, "if_nametoindex", return_value=4),
    ):
        assert network_state.dns_servers(
            "en0" if platform == "darwin" else "wlan0", 2
        ) == expected


def test_dns_servers_use_network_manager_when_resolved_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Find Linux DNS when NetworkManager supplies it.

    Parameters:
        monkeypatch: Restores the platform after the test.
    """
    _ = ModuleFactory()
    monkeypatch.setattr(sys, "platform", "linux")
    with patch.object(
        network_state, "command_output", side_effect=["", "10.0.0.53\n"]
    ):
        assert network_state.dns_servers("wlan0", 2) == ["10.0.0.53"]


@pytest.mark.parametrize(
    "platform, output",
    [
        ("linux", "10.0.0.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"),
        ("darwin", "? (10.0.0.1) at aa:bb:cc:dd:ee:ff on en0"),
    ],
)
def test_gateway_mac_from_neighbor_cache(
    monkeypatch: pytest.MonkeyPatch, platform: str, output: str
) -> None:
    """Read the router MAC on Linux and macOS.

    Parameters:
        monkeypatch: Restores the platform after the test.
        platform: Emulated operating system.
        output: Local neighbor command response.
    """
    _ = ModuleFactory()
    monkeypatch.setattr(sys, "platform", platform)
    with patch.object(network_state, "command_output", return_value=output):
        assert network_state.gateway_mac("wlan0", "10.0.0.1") == (
            "aa:bb:cc:dd:ee:ff"
        )


def test_collect_network_state_after_address_change() -> None:
    """Use the current interface prefix rather than an old subnet."""
    _ = ModuleFactory()
    with (
        patch.object(network_state.netifaces, "ifaddresses", return_value={
            netifaces.AF_INET: [
                {"addr": "169.254.1.3", "netmask": "255.255.0.0"},
                {"addr": "10.0.0.25", "netmask": "255.255.255.0"},
            ],
        }),
        patch.object(
            network_state.utils, "get_gateway_for_iface", return_value="10.0.0.1"
        ),
        patch.object(network_state, "gateway_mac", return_value="aa:bb:cc:dd:ee:ff"),
        patch.object(network_state, "dns_servers", return_value=["10.0.0.53"]),
    ):
        state = network_state.collect_network_state("wlan0", 1)

    assert state["host_ip"] == "10.0.0.25"
    assert state["local_network"] == "10.0.0.0/24"
    assert state["gateway_ip"] == "10.0.0.1"
    assert state["dns_servers"] == ["10.0.0.53"]


def test_collect_network_state_disconnected() -> None:
    """Clear service settings when an interface disappears."""
    _ = ModuleFactory()
    with (
        patch.object(network_state.netifaces, "ifaddresses", side_effect=ValueError),
        patch.object(network_state.utils, "get_gateway_for_iface", return_value=None),
        patch.object(network_state, "gateway_mac", return_value=""),
    ):
        state = network_state.collect_network_state("wlan0", 1)

    assert state["connected"] is False
    assert state["host_ip"] == ""
    assert state["local_network"] == ""
    assert state["dns_servers"] == []


def test_collect_network_state_ipv6_netmask() -> None:
    """Convert macOS-style IPv6 masks into a usable local prefix."""
    _ = ModuleFactory()
    with (
        patch.object(network_state.netifaces, "ifaddresses", return_value={
            netifaces.AF_INET6: [{
                "addr": "fd00:1::25%en0",
                "netmask": "ffff:ffff:ffff:ffff::",
            }],
        }),
        patch.object(network_state.utils, "get_gateway_for_iface", return_value=None),
        patch.object(network_state, "gateway_mac", return_value=""),
        patch.object(network_state, "dns_servers", return_value=[]),
    ):
        state = network_state.collect_network_state("en0", 1)

    assert state["host_ip"] == "fd00:1::25"
    assert state["local_network"] == "fd00:1::/64"
