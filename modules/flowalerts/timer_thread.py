# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import threading


class TimerThread(threading.Thread):
    """Thread that executes 1 task after N seconds. Only to run the process_global_data."""

    def __init__(self, interval, function, parameters):
        threading.Thread.__init__(self)
        self._finished = threading.Event()
        self._interval = interval
        self.function = function
        self.parameters = parameters

    def shutdown(self):
        """Stop this thread"""
        self._finished.set()

    def run(self):
        try:
            if self._finished.is_set():
                return True

            # sleep for interval or until shutdown
            self._finished.wait(self._interval)

            self.task()
            return True

        except KeyboardInterrupt:
            return True

    def task(self):
        # print(f'Executing the function with {self.parameters} on
        # {datetime.datetime.now()}')
        self.function(*self.parameters)
