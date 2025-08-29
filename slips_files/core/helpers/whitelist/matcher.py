# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from slips_files.core.structures.evidence import Direction


class WhitelistMatcher:
    """
    matches ioc properties to whitelist properties
    for example if in the config file we have
    "facebook, alerts, to"
    this matcher maches when given a fb ip, makes sure we're whitelisting
    an alert, not a flow
    and makes sure we're whitelisting all flows TO fb and not from fb.
    its called like this
    self.match.ignored_flow_type(given_flow_type)
    just read the code, you'll get it.
    i had to group these matching functions somewhere
    """

    def __init__(self):
        # Checking if a flow belongs to a whitelisted org is costly. and arp
        # flows are a lot, so we are not checking them.
        self.ignored_flow_types = ["arp"]

    def is_ignored_flow_type(self, flow_type) -> bool:
        """
        returns true if the given type shouldn't be checked against the
        whitelisted organizations
        """
        return flow_type in self.ignored_flow_types

    def what_to_ignore(self, checking: str, whitelist_to_ignore: str) -> bool:
        """
        returns True if we're checking a flow, and the whitelist has
        'flows' or 'both' as the type to ignore
        OR
        if we're checking an alert and the whitelist has 'alerts' or 'both' as the
        type to ignore
        :param checking: can be flows or alerts
        :param whitelist_to_ignore: can be flows or alerts
        """
        return checking == whitelist_to_ignore or whitelist_to_ignore == "both"

    def direction(
        self,
        ioc_direction: Direction,
        dir_from_whitelist: str,
    ) -> bool:
        """
        Checks if the ioc direction given (ioc_direction) matches the
        direction
        that we
        should whitelist taken from whitelist.conf (dir_from_whitelist)

        for example
        if dir_to_check is srs and the dir_from whitelist is both,
        this function returns true

        :param ioc_direction: Direction obj, this is the dir of the ioc
        that we wanna check
        :param dir_from_whitelist: the direction read from whitelist.conf.
        can be "src", "dst" or "both":
        """
        if dir_from_whitelist == "both":
            return True

        whitelist_src = (
            "src" in dir_from_whitelist and ioc_direction == Direction.SRC
        )
        whitelist_dst = (
            "dst" in dir_from_whitelist and ioc_direction == Direction.DST
        )

        return whitelist_src or whitelist_dst
