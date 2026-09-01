# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os
import platform
import psutil
import pwd
import shlex

IS_IN_A_DOCKER_CONTAINER = os.environ.get("IS_IN_A_DOCKER_CONTAINER", False)


class Notify:
    def __init__(self):
        self.enabled = False
        self.notify_cmd = "notify-send -t 5000 "
        if IS_IN_A_DOCKER_CONTAINER:
            return
        if self._is_notify_send_installed():
            self.enabled = True
            self._setup_notifications_if_root()

    def _is_notify_send_installed(self) -> bool:
        """
        Checks if notify-send bin is installed
        """
        cmd = "notify-send > /dev/null 2>&1"
        returncode = os.system(cmd)
        if returncode == 256:
            # it is installed
            return True
        # elif returncode == 32512:
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

    def show_popup(self, alert_to_log: str):
        """
        Function to display a popup with the alert depending on the OS
        """
        if IS_IN_A_DOCKER_CONTAINER:
            return
        if platform.system() == "Linux":
            #  is notify_cmd is set in
            #  setup_notifications function depending on the user
            os.system(f'{self.notify_cmd} "Slips" "{alert_to_log}"')
        elif platform.system() == "Darwin":
            os.system(
                f"osascript -e 'display notification"
                f' "{alert_to_log}" with title "Slips"\' '
            )
