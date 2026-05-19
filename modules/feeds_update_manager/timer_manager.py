# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
import time
from threading import Timer
from typing import (
    Awaitable,
    Callable,
    List,
    Optional,
    Sequence,
)


class PeriodicUpdateTimer:
    """
    Timer to run one async target when any configured period is due.
    """

    def __init__(
        self,
        periods: Sequence[float],
        target: Callable[[], Awaitable[None]],
    ) -> None:
        """Initialize the timer with periods and a target coroutine.

        :param periods: Seconds between target runs for each schedule.
        :param target: Coroutine function to call when a schedule is due.
        :return: None.
        """
        self.timer_running = False
        self.target_running = False
        self.periods: List[float] = [
            period for period in periods if period > 0
        ]
        self.target = target
        self.thread: Optional[Timer] = None
        # list of timestamps the given target func is going to be running on
        self.next_due_at: List[float] = []

    def _set_initial_due_times(self) -> None:
        """Set the first due timestamp for each configured period.

        :return: None.
        """
        now = time.monotonic()
        self.next_due_at = [now + period for period in self.periods]

    def _advance_due_times(self) -> None:
        """Advance all reached schedules to their next due timestamp.

        :return: None.
        """
        now = time.monotonic()
        for idx, period in enumerate(self.periods):
            while self.next_due_at[idx] <= now:
                self.next_due_at[idx] += period

    def _handle_target(self) -> None:
        """Run the target and schedule the next due timer.

        :return: None.
        """
        self.target_running = True
        try:
            asyncio.run(self.target())
        finally:
            self.target_running = False
            self._advance_due_times()
            self._start_next_timer()

    def _start_next_timer(self) -> None:
        """Start a timer for the nearest due timestamp.

        :return: None.
        """
        if not self.timer_running or not self.next_due_at:
            return
        nearest_due_time = min(self.next_due_at)
        time_until_nearest_due_time = nearest_due_time - time.monotonic()
        # make sure its never negative
        delay = max(0, time_until_nearest_due_time)
        self.thread = Timer(delay, self._handle_target)
        self.thread.start()

    def start(self) -> None:
        """Start the periodic update timer.

        :return: None.
        """
        if self.periods and not self.timer_running and not self.target_running:
            self.timer_running = True
            self._set_initial_due_times()
            self._start_next_timer()

    def cancel(self) -> None:
        """Cancel any scheduled update timer.

        :return: None.
        """
        self.timer_running = False
        if self.thread is not None:
            self.thread.cancel()
