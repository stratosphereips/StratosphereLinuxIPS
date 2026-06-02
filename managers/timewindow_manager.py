# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import time
from typing import (
    Any,
    Optional,
)


class TimewindowManager:
    def __init__(self, main: Any) -> None:
        """
        :param main: Main Slips instance.
        """
        self.main = main
        self.current_timewindow: int = 1
        self.next_timewindow_update: Optional[float] = None
        self.twid_width: Optional[float] = None
        self.read_configuration()

    def read_configuration(self):
        self.twid_width = self.main.conf.get_tw_width_in_seconds()

    def _is_running_non_stop(self) -> bool:
        """
        Cache whether Slips is running non-stop to avoid repeated
        unecessary db calls
        """
        if not hasattr(self, "is_running_non_stop"):
            self.is_running_non_stop: bool = self.main.db.is_running_non_stop()
        return self.is_running_non_stop

    def _init_first_timewindow_ever(self) -> None:
        """sets info for the very first tw (tw 1)"""
        if self.next_timewindow_update is not None:
            # we're past the first tw
            return

        slips_start_time = float(self.main.db.get_slips_start_time())
        self.next_timewindow_update = slips_start_time + self.twid_width
        self.current_timewindow = 1
        self.main.db.incr_current_timewindow()

    def update_current_timewindow_if_due(self) -> None:
        """
        Update the current timewindow if it's time to
        """
        if not self._is_running_non_stop():
            # in pcaps and zeek dirs, no need to keep track of the cur
            # timewindow
            return

        self._init_first_timewindow_ever()
        if self.next_timewindow_update is None or self.twid_width is None:
            return

        now = time.time()
        if now < self.next_timewindow_update:
            # not time to update yet
            return

        self.current_timewindow += 1
        self.next_timewindow_update += self.twid_width
        self.main.db.incr_current_timewindow()
