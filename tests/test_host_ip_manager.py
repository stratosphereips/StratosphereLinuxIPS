# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import MagicMock, patch, Mock
import pytest
from tests.module_factory import ModuleFactory
import sys


@pytest.mark.parametrize(
    "is_interface, host_ip, modified_profiles, "
    "expected_calls, expected_result",
    [  # Testcase1: Should update host IP
        (True, "192.168.1.1", set(), 1, "192.168.1.2"),
        # Testcase2: Shouldn't update host IP
        (True, "192.168.1.1", {"192.168.1.1"}, 0, "192.168.1.1"),
        # Testcase3: Shouldn't update host IP (not interface)
        (False, "192.168.1.1", set(), 0, None),
    ],
)
def test_update_host_ip(
    is_interface,
    host_ip,
    modified_profiles,
    expected_calls,
    expected_result,
):
    host_ip_man = ModuleFactory().create_host_ip_manager_obj()
    host_ip_man.main.db.is_running_non_stop.return_value = is_interface

    host_ip_man.get_host_ip = Mock()
    host_ip_man.get_host_ip.return_value = "192.168.1.2"
    host_ip_man.main.db.set_host_ip = MagicMock()
    result = host_ip_man.update_host_ip(host_ip, modified_profiles)
    assert result == expected_result
    assert host_ip_man.get_host_ip.call_count == expected_calls


@pytest.mark.parametrize(
    "interfaces, ifaddresses, expected",
    [
        (  # 2 here is AF_INET
            ["lo", "eth0"],
            {"lo": {}, "eth0": {2: [{"addr": "192.168.1.10"}]}},
            "192.168.1.10",
        ),
        (
            ["lo", "eth0"],
            {
                "lo": {2: [{"addr": "127.0.0.1"}]},
                "eth0": {2: [{"addr": "127.0.0.2"}]},
            },
            None,
        ),
        (["lo"], {"lo": {2: [{"addr": "127.0.0.1"}]}}, None),
    ],
)
def test_get_host_ip(interfaces, ifaddresses, expected):
    host_ip_man = ModuleFactory().create_host_ip_manager_obj()
    host_ip_man.main.args.interface = None  # simulate not passed, to use all
    host_ip_man.main.args.growing = (
        True  # simulate -g used, so use all interfaces
    )

    with patch(
        "managers.host_ip_manager.netifaces.interfaces",
        return_value=interfaces,
    ), patch(
        "managers.host_ip_manager.netifaces.ifaddresses",
        side_effect=lambda iface: ifaddresses.get(iface, {}),
    ), patch(
        "managers.host_ip_manager.netifaces.AF_INET", 2
    ):
        result = host_ip_man.get_host_ip()
        assert result == expected


@pytest.mark.parametrize(
    "running_on_interface, host_ip,"
    "set_host_ip_side_effect, expected_result",
    [
        # testcase1: Running on interface, valid IP
        (True, "192.168.1.100", None, "192.168.1.100"),
        # testcase2: Not running on interface
        (False, "192.168.1.100", None, None),
    ],
)
def test_store_host_ip(
    running_on_interface,
    host_ip,
    set_host_ip_side_effect,
    expected_result,
):
    host_ip_man = ModuleFactory().create_host_ip_manager_obj()
    host_ip_man.main.db.is_running_non_stop.return_value = running_on_interface
    host_ip_man.get_host_ip = MagicMock(return_value=host_ip)
    host_ip_man.main.db.set_host_ip = MagicMock(
        side_effect=set_host_ip_side_effect
    )

    with patch.object(sys, "argv", ["-i"] if running_on_interface else []):
        with patch("time.sleep"):
            result = host_ip_man.store_host_ip()
            assert result == expected_result
