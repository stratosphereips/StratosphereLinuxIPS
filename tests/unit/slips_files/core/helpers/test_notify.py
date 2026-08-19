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
        result = notify._is_notify_send_installed()
        assert result == expected_result


def _logged_in_user(name):
    """psutil.users() entry whose .name is the given username."""
    user = MagicMock()
    user.name = name
    return user


@pytest.mark.parametrize(
    "system, euid, environ, who_output, " "users, pwd_output, expected_cmd",
    [
        # Testcase 1: Non-Linux system
        ("Darwin", 0, {}, "", [], None, "notify-send -t 5000 "),
        # Testcase 2: Linux, non-root user
        ("Linux", 1000, {}, "", [], None, "notify-send -t 5000 "),
        # Testcase 3: Linux root without a graphical session
        ("Linux", 0, {}, "", [], None, "notify-send -t 5000 "),
        # Testcase 4: Linux, root user, 'who' command successful
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
        # Testcase 5: Linux, root user, the display isn't listed by 'who',
        # so the first logged in user is used
        (
            "Linux",
            0,
            {"DISPLAY": ":1"},
            "",
            [_logged_in_user("loggedinuser")],
            MagicMock(pw_uid=1001),
            "sudo -u loggedinuser DISPLAY=:1 DBUS_SESSION_BUS_ADDRESS="
            "unix:path=/run/user/1001/bus notify-send -t 5000 ",
        ),
        # Testcase 6: Linux, root user, no display owner can be determined
        ("Linux", 0, {"DISPLAY": ":1"}, "", [], None, "notify-send -t 5000 "),
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
        notify._setup_notifications_if_root()
        assert notify.notify_cmd == expected_cmd


@pytest.mark.parametrize(
    "returncode, expected_enabled, expected_setup_calls",
    [
        # Testcase 1: notify-send is installed, notifications are usable
        (256, True, 1),
        # Testcase 2: notify-send is missing, notifications stay disabled
        (32512, False, 0),
    ],
)
def test_init_enables_notifications_only_when_notify_send_is_installed(
    returncode, expected_enabled, expected_setup_calls
):
    with patch(
        "slips_files.core.helpers.notify.IS_IN_A_DOCKER_CONTAINER", False
    ), patch("os.system", return_value=returncode), patch(
        "slips_files.core.helpers.notify.Notify."
        "_setup_notifications_if_root"
    ) as mock_setup:
        notify = ModuleFactory().create_notify_obj()

        assert notify.enabled is expected_enabled
        assert mock_setup.call_count == expected_setup_calls


def test_setup_notifications_with_an_unknown_user():
    """the user owning the display has no entry in the passwd db"""
    with patch("platform.system", return_value="Linux"), patch(
        "os.geteuid", return_value=0
    ), patch(
        "psutil.Process",
        return_value=MagicMock(environ=lambda: {"DISPLAY": ":0"}),
    ), patch(
        "os.popen",
        return_value=MagicMock(
            read=lambda: "ghostuser tty1 2023-07-25 10:00 (:0)"
        ),
    ), patch(
        "pwd.getpwnam", side_effect=KeyError("ghostuser")
    ):
        notify = ModuleFactory().create_notify_obj()
        notify._setup_notifications_if_root()

        assert notify.notify_cmd == "notify-send -t 5000 "


def test_notifications_are_disabled_in_docker():
    # the flag is read once at import time, so patch the module constant
    # instead of os.environ
    with patch(
        "slips_files.core.helpers.notify.IS_IN_A_DOCKER_CONTAINER", "True"
    ), patch("os.system") as mock_system:
        notify = ModuleFactory().create_notify_obj()

        notify.show_popup("Test alert")

        assert notify.enabled is False
        assert notify.notify_cmd == "notify-send -t 5000 "
        mock_system.assert_not_called()


@pytest.mark.parametrize(
    "system, notify_cmd, alert, expected_command",
    [
        # Testcase 1: Linux system
        (
            "Linux",
            "notify-send -t 5000 ",
            "Test alert",
            'notify-send -t 5000  "Slips" "Test alert"',
        ),
        # Testcase 2: macOS (Darwin) system
        (
            "Darwin",
            "",
            "Test alert",
            'osascript -e \'display notification "Test alert" with title "Slips"\' ',
        ),
        # Testcase 3: Linux system with custom notify command
        (
            "Linux",
            "custom_notify_cmd ",
            "Test alert",
            'custom_notify_cmd  "Slips" "Test alert"',
        ),
    ],
)
def test_show_popup(system, notify_cmd, alert, expected_command):
    # the CI image sets IS_IN_A_DOCKER_CONTAINER, which makes show_popup()
    # return early, so patch the module constant to test the actual popup
    with patch(
        "slips_files.core.helpers.notify.IS_IN_A_DOCKER_CONTAINER", False
    ), patch("platform.system", return_value=system), patch(
        "os.system"
    ) as mock_system:

        notify = ModuleFactory().create_notify_obj()
        notify.notify_cmd = notify_cmd
        mock_system.reset_mock()

        notify.show_popup(alert)
        mock_system.assert_called_once_with(expected_command)
