# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import MagicMock, patch, Mock

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
    host_ip_man.main.db.is_running_non_stop.return_value = is_interface

    host_ip_man.get_host_ip = Mock()
    host_ip_man.get_host_ip.return_value = "192.168.1.2"
    host_ip_man.main.db.set_host_ip = MagicMock()
    host_ip_man.store_host_ip = MagicMock()
    result = host_ip_man.update_host_ip(host_ips, modified_profiles)
    assert result == expected_result
    assert host_ip_man.get_host_ip.call_count == expected_calls


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
    host_ip_man.main.db.is_running_non_stop.return_value = is_interface

    host_ip_man.get_host_ip = Mock(return_value="192.168.1.2")
    host_ip_man.store_host_ip = MagicMock()

    host_ip_man.update_host_ip(host_ips, modified_profiles)
    assert host_ip_man.store_host_ip.call_count == expected_calls


@pytest.mark.parametrize(
    "args_interface,args_access_point,iface_addrs,expected",
    [
        # Single interface with valid IPv4
        (
            "eth0",
            None,
            {netifaces.AF_INET: [{"addr": "192.168.1.10"}]},
            {"eth0": "192.168.1.10"},
        ),
        # Only loopback IP -> should be skipped
        (
            "lo",
            None,
            {netifaces.AF_INET: [{"addr": "127.0.0.1"}]},
            {},
        ),
        # Interface without AF_INET -> skipped
        (
            "eth1",
            None,
            {},
            {},
        ),
    ],
)
@patch("netifaces.ifaddresses")
def test_get_host_ips_single_interface(
    mock_ifaddresses,
    args_interface,
    args_access_point,
    iface_addrs,
    expected,
):
    """Test _get_host_ips for single-interface cases."""
    host_ip_man = ModuleFactory().create_host_ip_manager_obj()
    host_ip_man.main.args.interface = args_interface
    host_ip_man.main.args.access_point = args_access_point

    mock_ifaddresses.return_value = iface_addrs
    result = host_ip_man._get_host_ips()

    assert result == expected
    mock_ifaddresses.assert_called_once_with(args_interface)


@patch("netifaces.ifaddresses")
def test_get_host_ips_multiple_interfaces_from_access_point(mock_ifaddresses):
    """Test _get_host_ips when using multiple interfaces via --access-point."""
    host_ip_man = ModuleFactory().create_host_ip_manager_obj()
    host_ip_man.main.args.interface = None
    host_ip_man.main.args.access_point = "wlan0,eth0"

    def mock_ifaddresses_side_effect(iface):
        if iface == "wlan0":
            return {netifaces.AF_INET: [{"addr": "10.0.0.5"}]}
        elif iface == "eth0":
            return {netifaces.AF_INET: [{"addr": "192.168.0.8"}]}
        return {}

    mock_ifaddresses.side_effect = mock_ifaddresses_side_effect

    result = host_ip_man._get_host_ips()
    assert result == {"wlan0": "10.0.0.5", "eth0": "192.168.0.8"}


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
    host_ip_man.main.db.is_running_non_stop.return_value = running_on_interface
    host_ip_man._get_host_ips = MagicMock(return_value=host_ip)
    host_ip_man.main.db.set_host_ip = MagicMock()

    with patch.object(sys, "argv", ["-i"] if running_on_interface else []):
        with patch("time.sleep"):
            result = host_ip_man.store_host_ip()
            assert result == expected_result
