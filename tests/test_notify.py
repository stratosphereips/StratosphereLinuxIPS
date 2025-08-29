# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import patch, MagicMock
import pytest
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "returncode, expected_result",
    [
        # Testcase 1: notify-send is installed
        (256, True),
        # Testcase 2: notify-send is not installed
        (32512, False),
        # Testcase 3: Other return code (potentially an error)
        (1, False),
    ],
)
def test_is_notify_send_installed(returncode, expected_result):
    with patch("os.system") as mock_system:
        mock_system.return_value = returncode
        notify = ModuleFactory().create_notify_obj()
        result = notify.is_notify_send_installed()
        assert result == expected_result


@pytest.mark.parametrize(
    "system, euid, environ, who_output, " "users, pwd_output, expected_cmd",
    [
        # Testcase 1: Non-Linux system
        ("Darwin", 0, {}, "", [], None, "notify-send -t 5000 "),
        # Testcase 2: Linux, non-root user
        ("Linux", 1000, {}, "", [], None, "notify-send -t 5000 "),
        # Testcase 3: Linux, root user, 'who' command successful
        (
            "Linux",
            0,
            {"DISPLAY": ":0"},
            "testuser tty1 2023-07-25 10:00 (:0)",
            [],
            MagicMock(pw_uid=1000),
            "sudo -u testuser DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="
            "unix:path=/run/user/1000/bus notify-send -t 5000 ",
        ),
    ],
)
def test_setup_notifications(
    system, euid, environ, who_output, users, pwd_output, expected_cmd
):
    with patch("platform.system", return_value=system), patch(
        "os.geteuid", return_value=euid
    ), patch(
        "psutil.Process", return_value=MagicMock(environ=lambda: environ)
    ), patch(
        "os.popen", return_value=MagicMock(read=lambda: who_output)
    ), patch(
        "psutil.users", return_value=users
    ), patch(
        "pwd.getpwnam", return_value=pwd_output
    ):

        notify = ModuleFactory().create_notify_obj()
        notify.setup_notifications()
        assert notify.notify_cmd == expected_cmd


@pytest.mark.parametrize(
    "system, notify_cmd, alert, expected_partial_command",
    [
        # Testcase 1: Linux system
        (
            "Linux",
            "notify-send -t 5000 ",
            "Test alert",
            '"Slips" "Test alert"',
        ),
        # Testcase 2: macOS (Darwin) system
        (
            "Darwin",
            "",
            "Test alert",
            'display notification "Test alert" ' 'with title "Slips"',
        ),
        # Testcase 3: Linux system with custom notify command
        ("Linux", "custom_notify_cmd ", "Test alert", '"Slips" "Test alert"'),
    ],
)
def test_show_popup(system, notify_cmd, alert, expected_partial_command):
    with patch("platform.system", return_value=system), patch(
        "os.system"
    ) as mock_system:

        notify = ModuleFactory().create_notify_obj()
        notify.notify_cmd = notify_cmd
        mock_system.reset_mock()

        notify.show_popup(alert)
        print(f"Calls to os.system: {mock_system.call_args_list}")
        assert any(
            expected_partial_command in str(call)
            for call in mock_system.call_args_list
        ), (
            f"Expected command containing '{expected_partial_command}' "
            f"not found in calls to os.system"
        )
