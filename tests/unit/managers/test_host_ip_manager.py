# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import socket
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


def test_get_host_ip_success():
    host_ip_man = ModuleFactory().create_host_ip_manager_obj()
    expected_ip = "192.168.1.100"

    with patch("socket.socket") as mock_socket:
        mock_instance = MagicMock()
        mock_socket.return_value = mock_instance

        mock_instance.getsockname.return_value = (expected_ip, 80)

        result = host_ip_man.get_host_ip()

        assert result == expected_ip
        mock_instance.connect.assert_any_call(("1.1.1.1", 80))
        mock_instance.getsockname.assert_called_once()


def test_get_host_ip_failure():
    host_ip_man = ModuleFactory().create_host_ip_manager_obj()

    with patch("socket.socket") as mock_socket:
        mock_instance = MagicMock()
        mock_socket.return_value = mock_instance

        mock_instance.connect.side_effect = socket.error()

        result = host_ip_man.get_host_ip()

        assert result is None
        mock_instance.connect.assert_any_call(("1.1.1.1", 80))
        mock_instance.connect.assert_any_call(("2606:4700:4700::1111", 80))
        mock_instance.getsockname.assert_not_called()


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
