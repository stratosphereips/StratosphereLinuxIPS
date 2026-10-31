# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import patch, Mock

import netifaces
import pytest

from tests.module_factory import ModuleFactory
import sys


@pytest.mark.parametrize(
    "is_interface, host_ips, modified_profiles, "
    "expected_calls, expected_result",
    [
        # Shouldn't update host IP
        (
            True,
            {"eth0": "192.168.1.1"},
            {"192.168.1.1"},
            0,
            {"eth0": "192.168.1.1"},
        ),
        # Shouldn't update host IP (not interface)
        (False, {"eth0": "192.168.1.1"}, set(), 0, None),
    ],
)
def test_update_host_ip_shouldnt_update(
    is_interface,
    host_ips,
    modified_profiles,
    expected_calls,
    expected_result,
):
    host_ip_man = ModuleFactory().create_host_ip_manager_obj()
    host_ip_man.refresh_network_state = Mock(
        return_value=host_ips if is_interface else None
    )
    result = host_ip_man.update_host_ip(host_ips, modified_profiles)
    assert result == expected_result
    host_ip_man.refresh_network_state.assert_called_once_with()


@pytest.mark.parametrize(
    "is_interface, host_ips, modified_profiles, " "expected_calls",
    [
        # Shouldn't update host IP
        (True, {"eth0": "192.168.1.1"}, set(), 1)
    ],
)
def test_update_host_ip_should_update(
    is_interface,
    host_ips,
    modified_profiles,
    expected_calls,
):
    host_ip_man = ModuleFactory().create_host_ip_manager_obj()
    host_ip_man.refresh_network_state = Mock(return_value=host_ips)

    assert host_ip_man.update_host_ip(host_ips, modified_profiles) == host_ips
    host_ip_man.refresh_network_state.assert_called_once_with()


@patch("netifaces.ifaddresses")
def test_get_host_ips_without_interface(mock_ifaddresses: Mock) -> None:
    """Allow stdin and module input without a capture interface.

    Parameters:
        mock_ifaddresses: Mock interface lookup, which must not be used.
    """
    host_ip_man = ModuleFactory().create_host_ip_manager_obj()
    host_ip_man.main.args.interface = None
    host_ip_man.main.args.access_point = None
    assert host_ip_man._get_host_ips() == {}
    mock_ifaddresses.assert_not_called()


@patch("netifaces.ifaddresses")
def test_get_host_ips_single_interface(mock_ifaddresses):
    """Test _get_host_ips when using a single interface via -i."""
    host_ip_man = ModuleFactory().create_host_ip_manager_obj()
    host_ip_man.main.args.interface = "eth0"
    host_ip_man.main.args.access_point = None

    mock_ifaddresses.return_value = {
        netifaces.AF_INET: [{"addr": "192.168.1.10"}]
    }

    result = host_ip_man._get_host_ips()

    assert result == {"eth0": "192.168.1.10"}
    mock_ifaddresses.assert_called_once_with("eth0")


@patch("netifaces.ifaddresses")
def test_get_host_ips_ipv6_fallback(mock_ifaddresses):
    """Test _get_host_ips uses IPv6 when no IPv4 is found."""
    host_ip_man = ModuleFactory().create_host_ip_manager_obj()
    host_ip_man.main.args.interface = "wlan0"
    host_ip_man.main.args.access_point = None

    mock_ifaddresses.return_value = {
        netifaces.AF_INET6: [{"addr": "fe80::1234:abcd%wlan0"}]
    }

    result = host_ip_man._get_host_ips()
    assert result == {"wlan0": "fe80::1234:abcd"}


@patch("netifaces.ifaddresses")
def test_get_host_ips_skips_loopback(mock_ifaddresses):
    """Test _get_host_ips ignores loopback addresses."""
    host_ip_man = ModuleFactory().create_host_ip_manager_obj()
    host_ip_man.main.args.interface = "lo"
    host_ip_man.main.args.access_point = None

    mock_ifaddresses.return_value = {
        netifaces.AF_INET: [{"addr": "127.0.0.1"}]
    }

    result = host_ip_man._get_host_ips()
    assert result == {}


@pytest.mark.parametrize(
    "running_on_interface, host_ip," "expected_result",
    [
        # testcase1: Running on interface, valid IP
        (True, {"eth0": "192.168.1.100"}, {"eth0": "192.168.1.100"}),
        # testcase2: Not running on interface
        (False, {"eth0": "192.168.1.100"}, None),
    ],
)
def test_store_host_ip(
    running_on_interface,
    host_ip,
    expected_result,
):
    host_ip_man = ModuleFactory().create_host_ip_manager_obj()
    host_ip_man.refresh_network_state = Mock(return_value=expected_result)

    with patch.object(sys, "argv", ["-i"] if running_on_interface else []):
        with patch("time.sleep"):
            result = host_ip_man.store_host_ip()
            assert result == expected_result
            host_ip_man.refresh_network_state.assert_called_once_with()


def test_refresh_network_state_replaces_values_after_wifi_switch() -> None:
    """Replace old settings even when the former host remains active."""
    host_ip_man = ModuleFactory().create_host_ip_manager_obj()
    host_ip_man.main.args.interface = "en0"
    host_ip_man.main.args.access_point = None
    host_ip_man.main.db.is_running_non_stop.return_value = True
    previous = {
        "interface": "en0", "connected": True,
        "addresses": [{"ip": "192.168.1.20", "network": "192.168.1.0/24"}],
        "host_ip": "192.168.1.20", "local_network": "192.168.1.0/24",
        "gateway_ip": "192.168.1.1", "gateway_mac": "",
        "dns_servers": ["192.168.1.1"], "version": 3,
    }
    current = {
        **previous,
        "addresses": [{"ip": "10.0.0.25", "network": "10.0.0.0/24"}],
        "host_ip": "10.0.0.25", "local_network": "10.0.0.0/24",
        "gateway_ip": "10.0.0.1", "dns_servers": ["10.0.0.53"],
    }
    host_ip_man.main.db.get_network_state.return_value = previous

    with patch("managers.host_ip_manager.collect_network_state", return_value=current):
        result = host_ip_man.update_host_ip(
            {"en0": "192.168.1.20"}, {"192.168.1.20"}
        )

    assert result == {"en0": "10.0.0.25"}
    published = host_ip_man.main.db.replace_network_state.call_args.args[1]
    assert published["version"] == 4
    assert published["dns_servers"] == ["10.0.0.53"]
    assert published["history"] == []
    assert "192.168.1.20 -> 10.0.0.25" in host_ip_man.main.print.call_args.args[0]


def test_refresh_network_state_keeps_bounded_history() -> None:
    """Retain a short record of settings for delayed flow analysis."""
    host_ip_man = ModuleFactory().create_host_ip_manager_obj()
    host_ip_man.main.args.interface = "en0"
    host_ip_man.main.args.access_point = None
    host_ip_man.main.db.is_running_non_stop.return_value = True
    old = {
        "interface": "en0", "host_ip": "192.168.1.20",
        "local_network": "192.168.1.0/24", "dns_servers": ["192.168.1.1"],
        "changed_at": 100.0, "version": 11,
        "history": [{"changed_at": float(index)} for index in range(11)],
    }
    new = {
        "interface": "en0", "host_ip": "10.0.0.25",
        "local_network": "10.0.0.0/24", "dns_servers": ["10.0.0.53"],
        "gateway_ip": "10.0.0.1", "gateway_mac": "",
    }
    host_ip_man.main.db.get_network_state.return_value = old

    with patch("managers.host_ip_manager.collect_network_state", return_value=new):
        host_ip_man.refresh_network_state()

    published = host_ip_man.main.db.replace_network_state.call_args.args[1]
    assert len(published["history"]) == 10
    assert published["history"][-1]["local_network"] == "192.168.1.0/24"
    assert "history" not in published["history"][-1]
