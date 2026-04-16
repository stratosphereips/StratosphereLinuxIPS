# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only


"""
Handles updating of slips version
"""

from slips_files.common.parsers.config_parser import ConfigParser


class UpdateManager:
    def __init__(self, is_first_run: bool):
        self.read_configuration()
        self.is_first_run = is_first_run

    def read_configuration(self):
        conf = ConfigParser()
        self.update_slips = conf.auto_update_slips()

    def is_first_run(self) -> bool:
        """
        The very first time, slips is started by the user via CLI. then
        for each new update, it's started by this update manager.
        this func returns true if the user just started slips from cli.
        """
        return self.is_first_run

    def update_slips_version(self):
        if self.is_first_run():
            # we're not live updating, there isnt going to be an older
            # version of slips draining in this case.
            ...
        else:
            # prep for handover. old version to the new one.
            ...

    def should_update_slips(self) -> bool:
        if not self.update_slips:
            return False

        # Never live update when analyzing anything other than an interface
        # If  not running on interface: return false
        # return (new_version_available() and
        #         new_version_supports_backwards_compatibility()):
