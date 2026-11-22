# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for modules/ip_info/gateway_info.py"""

from unittest.mock import Mock

import pytest

from tests.module_factory import ModuleFactory

GATEWAY_INFO = "modules.ip_info.gateway_info"


@pytest.mark.parametrize("gateway", [None, "not-an-ip"])
def test_gateway_discovery_skips_invalid_addresses(
    mocker, gateway: str | None
) -> None:
    """Ignore interfaces for which the OS reports no valid gateway.

    Parameters:
        mocker: Pytest mock fixture.
        gateway: Missing or malformed gateway returned by the OS.
    """
    gateway_info = ModuleFactory().create_ip_info_obj().gateway
    gateway_info.is_running_non_stop = True
    mocker.patch(
        f"{GATEWAY_INFO}.utils.get_all_interfaces",
        return_value=["en0"],
    )
    mocker.patch(
        f"{GATEWAY_INFO}.utils.get_gateway_for_iface",
        return_value=gateway,
    )

    assert gateway_info.get_gateway_ip_if_interface() == {}


@pytest.mark.parametrize(
    "is_running_non_stop, expected_gateways",
    [
        (True, {"en0": "192.168.1.1"}),
        (False, None),
    ],
)
def test_gateway_ip_is_only_looked_up_on_a_live_interface(
    mocker, is_running_non_stop: bool, expected_gateways: dict | None
) -> None:
    """A pcap or a zeek dir has no gateway the OS could tell us about.

    Parameters:
        mocker: Pytest mock fixture.
        is_running_non_stop: Whether Slips monitors a live interface.
        expected_gateways: Gateway IP of each interface, if looked up.
    """
    gateway_info = ModuleFactory().create_ip_info_obj().gateway
    gateway_info.is_running_non_stop = is_running_non_stop
    mocker.patch(
        f"{GATEWAY_INFO}.utils.get_all_interfaces",
        return_value=["en0"],
    )
    mocker.patch(
        f"{GATEWAY_INFO}.utils.get_gateway_for_iface",
        return_value="192.168.1.1",
    )

    assert gateway_info.get_gateway_ip_if_interface() == expected_gateways


@pytest.mark.parametrize(
    "gw_ips, mac_in_db, expected",
    [
        (
            {"eth0": "192.168.1.1"},
            "AA:BB:CC:DD:EE:FF",
            {"eth0": "AA:BB:CC:DD:EE:FF"},
        ),
        ({"wlan0": "10.0.0.1"}, None, None),  # no MAC found
    ],
)
def test_mac_found_in_db_or_not(gw_ips, mac_in_db, expected):
    """Test when MAC exists or not in the DB."""
    gateway_info = ModuleFactory().create_ip_info_obj().gateway
    gateway_info.db.get_mac_addr_from_profile.return_value = mac_in_db
    gateway_info.is_running_non_stop = True
    gateway_info._get_wifi_interface_if_ap = Mock(return_value=None)
    gateway_info._get_mac_using_ip_neigh = Mock(return_value=None)
    gateway_info._get_mac_using_arp_cache = Mock(return_value=None)
    result = gateway_info.get_gateway_mac(gw_ips)

    assert result == expected


@pytest.mark.parametrize("gateway", [None, "not-an-ip"])
def test_gateway_mac_skips_invalid_addresses(gateway: str | None) -> None:
    """Do not query gateway data or OS neighbor tools for invalid addresses.

    Parameters:
        gateway: Missing or malformed gateway value.
    """
    gateway_info = ModuleFactory().create_ip_info_obj().gateway
    gateway_info._get_mac_using_ip_neigh = Mock()
    gateway_info._get_mac_using_arp_cache = Mock()

    assert gateway_info.get_gateway_mac({"en0": gateway}) is None
    gateway_info.db.get_mac_addr_from_profile.assert_not_called()
    gateway_info._get_mac_using_ip_neigh.assert_not_called()
    gateway_info._get_mac_using_arp_cache.assert_not_called()


def test_non_stop_false_skips_mac_lookup():
    """Should skip all lookups when not running non-stop."""
    gateway_info = ModuleFactory().create_ip_info_obj().gateway
    gateway_info.is_running_non_stop = False
    gateway_info.db.get_mac_addr_from_profile = Mock(return_value=None)
    gateway_info._get_mac_using_ip_neigh = Mock()
    gateway_info._get_mac_using_arp_cache = Mock()
    result = gateway_info.get_gateway_mac({"eth0": "192.168.1.1"})

    assert result is None
    gateway_info._get_mac_using_ip_neigh.assert_not_called()
    gateway_info._get_mac_using_arp_cache.assert_not_called()


@pytest.mark.parametrize(
    "db_return_value",
    ["wlan0", None],
)
def test_get_wifi_interface_if_ap(db_return_value):
    """get_wifi_interface() already returns the interface name, not a
    dict, so this should just pass it through."""
    gateway_info = ModuleFactory().create_ip_info_obj().gateway
    gateway_info.db.get_wifi_interface = Mock(return_value=db_return_value)

    assert gateway_info._get_wifi_interface_if_ap() == db_return_value


def test_wifi_interface_uses_own_mac():
    """If interface is WiFi AP, use get_own_mac()."""
    gateway_info = ModuleFactory().create_ip_info_obj().gateway
    gateway_info._get_wifi_interface_if_ap = Mock(return_value="wlan0")
    gateway_info.get_own_mac = Mock(return_value="AA:AA:AA:AA:AA:AA")
    gateway_info.db.get_mac_addr_from_profile = Mock(return_value=None)
    result = gateway_info.get_gateway_mac({"wlan0": "10.0.0.1"})

    assert result == {"wlan0": "AA:AA:AA:AA:AA:AA"}


def test_mac_from_ip_neigh():
    """Should use ip neigh if available."""
    gateway_info = ModuleFactory().create_ip_info_obj().gateway
    gateway_info.db.get_mac_addr_from_profile = Mock(return_value=None)
    gateway_info._get_mac_using_ip_neigh = Mock(
        return_value="AA:BB:CC:11:22:33"
    )

    result = gateway_info.get_gateway_mac({"eth0": "172.16.0.1"})

    assert result == {"eth0": "AA:BB:CC:11:22:33"}
    gateway_info._get_mac_using_ip_neigh.assert_called_once_with("172.16.0.1")


def test_mac_from_arp_cache_if_ip_neigh_fails():
    """Should fallback to ARP cache if ip neigh fails."""
    gateway_info = ModuleFactory().create_ip_info_obj().gateway
    gateway_info.db.get_mac_addr_from_profile = Mock(return_value=None)
    gateway_info._get_mac_using_ip_neigh = Mock(return_value=None)
    gateway_info._get_mac_using_arp_cache = Mock(
        return_value="FF:EE:DD:CC:BB:AA"
    )

    result = gateway_info.get_gateway_mac({"eth0": "192.168.0.1"})

    assert result == {"eth0": "FF:EE:DD:CC:BB:AA"}
    gateway_info._get_mac_using_arp_cache.assert_called_once_with(
        "192.168.0.1"
    )


def test_all_methods_fail_returns_none():
    """If all lookups fail, return None."""
    gateway_info = ModuleFactory().create_ip_info_obj().gateway
    gateway_info.db.get_mac_addr_from_profile = Mock(return_value=None)
    gateway_info._get_mac_using_ip_neigh = Mock(return_value=None)
    gateway_info._get_mac_using_arp_cache = Mock(return_value=None)
    gateway_info.get_own_mac = Mock(return_value=None)
    result = gateway_info.get_gateway_mac({"eth0": "1.1.1.1"})

    assert result is None
