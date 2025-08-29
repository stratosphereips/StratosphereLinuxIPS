# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from threading import Timer
import asyncio


class InfiniteTimer:
    """
    Timer to update Threat Intelligence Files when Slips starts
    """

    def __init__(self, seconds, target):
        self.timer_running = False
        self.target_running = False
        self.seconds = seconds
        self.target = target
        self.thread = None

    def _handle_target(self):
        self.target_running = True
        asyncio.run(self.target())
        self.target_running = False
        self._start_timer()

    def _start_timer(self):
        if (
            self.timer_running
        ):  # Code could have been running when cancel was called.
            self.thread = Timer(self.seconds, self._handle_target)
            self.thread.start()

    def start(self):
        if not self.timer_running and not self.target_running:
            self.timer_running = True
            self._start_timer()

    def cancel(self):
        if self.thread is not None:
            self.timer_running = (
                False  # Just in case thread is running and cancel fails.
            )
            self.thread.cancel()
