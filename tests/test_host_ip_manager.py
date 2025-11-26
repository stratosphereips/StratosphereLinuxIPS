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
    host_ip_man.main.db.is_running_non_stop.return_value = running_on_interface
    host_ip_man._get_host_ips = MagicMock(return_value=host_ip)
    host_ip_man.main.db.set_host_ip = MagicMock()

    with patch.object(sys, "argv", ["-i"] if running_on_interface else []):
        with patch("time.sleep"):
            result = host_ip_man.store_host_ip()
            assert result == expected_result
