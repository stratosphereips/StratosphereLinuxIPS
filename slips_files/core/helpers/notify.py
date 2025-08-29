# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os
import platform
import psutil
import pwd


class Notify:
    def __init__(self):
        self.bin_found = False
        if self.is_notify_send_installed():
            self.bin_found = True

    def is_notify_send_installed(self) -> bool:
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

    def setup_notifications(self):
        """
        Get the used display, the user using this display and the uid of this
         user in case of using Slips as root on linux
        """
        # in linux, if the user's not root, notifications command will need
        # extra configurations
        if platform.system() != "Linux" or os.geteuid() != 0:
            self.notify_cmd = "notify-send -t 5000 "
            return False

        # Get the used display (if the user has only 1 screen it will be
        # set to 0), if not we should know which screen is slips running on.
        # A "display" is the address for your screen. Any program that
        # wants to write to your screen has to know the address.
        used_display = psutil.Process().environ()["DISPLAY"]

        # when you login as user x in linux, no user other than x is authorized to write to your display, not even root
        # now that we're running as root, we dont't have acess to the used_display
        # get the owner of the used_display, there's no other way than running the 'who' command
        command = f'who | grep "({used_display})" '
        cmd_output = os.popen(command).read()

        # make sure we found the user of this used display
        if len(cmd_output) < 5:
            # we don't know the user of this display!!, try getting it using psutil
            # user 0 is the one that owns tty1
            user = str(psutil.users()[0].name)
        else:
            # get the first user from the 'who' command
            user = cmd_output.split("\n")[0].split()[0]

        # get the uid
        uid = pwd.getpwnam(user).pw_uid
        # run notify-send as user using the used_display
        # and give it the dbus addr
        self.notify_cmd = (
            f"sudo -u {user} DISPLAY={used_display} "
            f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus "
            f"notify-send -t 5000 "
        )

    def show_popup(self, alert_to_log: str):
        """
        Function to display a popup with the alert depending on the OS
        """
        if platform.system() == "Linux":
            #  is notify_cmd is set in
            #  setup_notifications function depending on the user
            os.system(f'{self.notify_cmd} "Slips" "{alert_to_log}"')
        elif platform.system() == "Darwin":
            os.system(
                f"osascript -e 'display notification"
                f' "{alert_to_log}" with title "Slips"\' '
            )
