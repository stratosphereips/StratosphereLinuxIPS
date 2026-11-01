# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os
import platform
import logging
import psutil
import pwd
import shlex
import shutil
import subprocess

IS_IN_A_DOCKER_CONTAINER = os.environ.get("IS_IN_A_DOCKER_CONTAINER", False)


class Notify:
    def __init__(self) -> None:
        self.enabled = False
        self.notify_cmd = "notify-send -t 5000 "
        if IS_IN_A_DOCKER_CONTAINER:
            return
        if platform.system() == "Darwin":
            self.enabled = shutil.which("osascript") is not None
            if not self.enabled:
                logging.getLogger(__name__).warning(
                    "Desktop notifications disabled: osascript is unavailable"
                )
        elif platform.system() == "Linux" and self._is_notify_send_installed():
            self.enabled = True
            self._setup_notifications_if_root()

    def _is_notify_send_installed(self) -> bool:
        """
        Checks if notify-send bin is installed
        """
        if shutil.which("notify-send"):
            return True
        print(
            "notify-send is not installed. install it using:\n"
            "sudo apt-get install libnotify-bin"
        )
        return False

    def _setup_notifications_if_root(self) -> None:
        """
        Configure notify-send for root processes on Linux.
        """
        self.notify_cmd = "notify-send -t 5000 "
        if platform.system() != "Linux" or os.geteuid() != 0:
            return

        # Get the display used by the graphical session. If it is unavailable,
        # there is no desktop session to which root can send a notification.
        used_display = psutil.Process().environ().get("DISPLAY", "")
        if not used_display:
            return

        user = None

        # Find the user who owns the display. Root cannot send notifications
        # to that user's graphical session directly.
        command = f'who | grep "({used_display})" '
        cmd_output = os.popen(command).read()
        if len(cmd_output) >= 5:
            user = cmd_output.splitlines()[0].split()[0]

        # If the display is not listed by who, use the first logged-in user.
        if user is None:
            logged_in_users = psutil.users()
            if logged_in_users:
                user = str(logged_in_users[0].name)
            else:
                return

        # Get the UID and run notify-send as the user who owns the session.
        try:
            uid = pwd.getpwnam(user).pw_uid
        except KeyError:
            return
        self.notify_cmd = (
            f"sudo -u {shlex.quote(user)} "
            f"DISPLAY={shlex.quote(used_display)} "
            f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus "
            "notify-send -t 5000 "
        )

    def show_popup(self, alert_to_log: str) -> None:
        """Display an alert through the current desktop notification backend.

        Parameters:
            alert_to_log: Alert description passed as literal notification text.
        """
        if not self.enabled or IS_IN_A_DOCKER_CONTAINER:
            return
        if platform.system() == "Linux":
            command = [*shlex.split(self.notify_cmd), "Slips", alert_to_log]
        elif platform.system() == "Darwin":
            script = (
                "on run argv\n"
                'display notification (item 1 of argv) with title "Slips"\n'
                "end run"
            )
            command = ["osascript", "-e", script, "--", alert_to_log]
        else:
            return
        try:
            subprocess.run(
                command, capture_output=True, text=True, check=True, timeout=5
            )
        except (OSError, subprocess.SubprocessError) as error:
            detail = getattr(error, "stderr", None) or str(error)
            logging.getLogger(__name__).warning(
                "Unable to display Slips notification: %s", detail.strip()
            )
