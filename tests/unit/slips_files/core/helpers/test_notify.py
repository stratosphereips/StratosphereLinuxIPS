# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import patch, MagicMock
import subprocess
import logging
import pytest
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "executable,expected_result", [("notify-send", True), (None, False)]
)
def test_is_notify_send_installed(
    executable: str | None, expected_result: bool
) -> None:
    factory = ModuleFactory()
    with (
        patch(
            "slips_files.core.helpers.notify.shutil.which",
            return_value=executable,
        ),
        patch("os.system") as system,
    ):
        notify = factory.create_notify_obj()
        assert notify._is_notify_send_installed() is expected_result
        system.assert_not_called()


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
    factory = ModuleFactory()
    with (
        patch("platform.system", return_value=system),
        patch("os.geteuid", return_value=euid),
        patch(
            "psutil.Process", return_value=MagicMock(environ=lambda: environ)
        ),
        patch("os.popen", return_value=MagicMock(read=lambda: who_output)),
        patch("psutil.users", return_value=users),
        patch("pwd.getpwnam", return_value=pwd_output),
    ):

        notify = factory.create_notify_obj()
        notify._setup_notifications_if_root()
        assert notify.notify_cmd == expected_cmd


@pytest.mark.parametrize(
    "executable,expected_enabled,expected_setup_calls",
    [("notify-send", True, 1), (None, False, 0)],
)
def test_init_enables_linux_notifications_when_available(
    executable: str | None, expected_enabled: bool, expected_setup_calls: int
) -> None:
    factory = ModuleFactory()
    with (
        patch(
            "slips_files.core.helpers.notify.IS_IN_A_DOCKER_CONTAINER", False
        ),
        patch("platform.system", return_value="Linux"),
        patch(
            "slips_files.core.helpers.notify.shutil.which",
            return_value=executable,
        ),
        patch(
            "slips_files.core.helpers.notify.Notify._setup_notifications_if_root"
        ) as setup,
    ):
        notify = factory.create_notify_obj()
        assert notify.enabled is expected_enabled
        assert setup.call_count == expected_setup_calls


@pytest.mark.parametrize("executable", ["osascript", None])
def test_macos_notifications_do_not_require_linux_notify_send(
    executable: str | None,
) -> None:
    """Enable macOS independently of Linux desktop dependencies.

    Parameters:
        executable: Available AppleScript executable, or a missing backend.
    """
    factory = ModuleFactory()
    with (
        patch(
            "slips_files.core.helpers.notify.IS_IN_A_DOCKER_CONTAINER", False
        ),
        patch("platform.system", return_value="Darwin"),
        patch(
            "slips_files.core.helpers.notify.shutil.which",
            return_value=executable,
        ) as which,
        patch(
            "slips_files.core.helpers.notify.Notify._is_notify_send_installed"
        ) as linux_check,
        patch(
            "slips_files.core.helpers.notify.Notify._setup_notifications_if_root"
        ) as setup,
    ):
        notify = factory.create_notify_obj()
        assert notify.enabled is (executable is not None)
        which.assert_called_once_with("osascript")
        linux_check.assert_not_called()
        setup.assert_not_called()


def test_setup_notifications_with_an_unknown_user():
    """the user owning the display has no entry in the passwd db"""
    factory = ModuleFactory()
    with (
        patch("platform.system", return_value="Linux"),
        patch("os.geteuid", return_value=0),
        patch(
            "psutil.Process",
            return_value=MagicMock(environ=lambda: {"DISPLAY": ":0"}),
        ),
        patch(
            "os.popen",
            return_value=MagicMock(
                read=lambda: "ghostuser tty1 2023-07-25 10:00 (:0)"
            ),
        ),
        patch("pwd.getpwnam", side_effect=KeyError("ghostuser")),
    ):
        notify = factory.create_notify_obj()
        notify._setup_notifications_if_root()

        assert notify.notify_cmd == "notify-send -t 5000 "


def test_notifications_are_disabled_in_docker() -> None:
    factory = ModuleFactory()
    with (
        patch(
            "slips_files.core.helpers.notify.IS_IN_A_DOCKER_CONTAINER", "True"
        ),
        patch("slips_files.core.helpers.notify.shutil.which") as which,
        patch("slips_files.core.helpers.notify.subprocess.run") as run,
    ):
        notify = factory.create_notify_obj()
        notify.show_popup("Test alert")
        assert notify.enabled is False
        which.assert_not_called()
        run.assert_not_called()


@pytest.mark.parametrize(
    "system,prefix",
    [
        ("Linux", ["notify-send", "-t", "5000"]),
        (
            "Linux",
            [
                "sudo",
                "-u",
                "user name",
                "DISPLAY=:0",
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
                "notify-send",
                "-t",
                "5000",
            ],
        ),
        ("Darwin", ["osascript"]),
    ],
)
@pytest.mark.parametrize(
    "alert",
    [
        "Test alert",
        'Host "name" isn\'t trusted\n$(echo unsafe); `id` \\ end',
        "-leading-dash",
    ],
)
def test_show_popup(system: str, prefix: list[str], alert: str) -> None:
    factory = ModuleFactory()
    import shlex

    with (
        patch(
            "slips_files.core.helpers.notify.IS_IN_A_DOCKER_CONTAINER", False
        ),
        patch("platform.system", return_value=system),
        patch(
            "slips_files.core.helpers.notify.shutil.which",
            return_value="available",
        ),
        patch(
            "slips_files.core.helpers.notify.Notify._setup_notifications_if_root"
        ),
        patch("slips_files.core.helpers.notify.subprocess.run") as run,
    ):
        notify = factory.create_notify_obj()
        notify.notify_cmd = shlex.join(prefix)
        notify.show_popup(alert)
        command = run.call_args.args[0]
        assert command[0] == prefix[0]
        assert command[-1] == alert
        if system == "Darwin":
            assert command[1] == "-e"
            assert alert not in command[2]
            assert (
                'display notification (item 1 of argv) with title "Slips"'
                in command[2]
            )
            assert command[-2] == "--"
        else:
            assert command == [*prefix, "Slips", alert]
        run.assert_called_once_with(
            command, capture_output=True, text=True, check=True, timeout=5
        )


@pytest.mark.parametrize(
    "error",
    [
        FileNotFoundError("osascript unavailable"),
        subprocess.TimeoutExpired("osascript", 5),
        subprocess.CalledProcessError(
            1, "osascript", stderr="Notification failed"
        ),
    ],
)
def test_notification_failure_is_reported_without_stopping_detection(
    error: Exception, caplog: pytest.LogCaptureFixture
) -> None:
    """Keep analysis running and expose desktop backend failures.

    Parameters:
        error: Missing, stalled or failing operating system backend.
        caplog: Captured notification diagnostic.
    """
    factory = ModuleFactory()
    caplog.set_level(logging.WARNING, logger="slips_files.core.helpers.notify")
    with (
        patch(
            "slips_files.core.helpers.notify.IS_IN_A_DOCKER_CONTAINER", False
        ),
        patch("platform.system", return_value="Darwin"),
        patch(
            "slips_files.core.helpers.notify.shutil.which",
            return_value="osascript",
        ),
        patch(
            "slips_files.core.helpers.notify.subprocess.run", side_effect=error
        ),
    ):
        notify = factory.create_notify_obj()
        notify.show_popup("Test alert")
    assert "Unable to display Slips notification" in caplog.text


def test_disabled_notifications_do_not_launch_a_process() -> None:
    """Avoid starting a backend after desktop notifications were disabled."""
    factory = ModuleFactory()
    with (
        patch(
            "slips_files.core.helpers.notify.IS_IN_A_DOCKER_CONTAINER", False
        ),
        patch("platform.system", return_value="Darwin"),
        patch(
            "slips_files.core.helpers.notify.shutil.which", return_value=None
        ),
        patch("slips_files.core.helpers.notify.subprocess.run") as run,
    ):
        notify = factory.create_notify_obj()
        notify.show_popup("Test alert")
        run.assert_not_called()
