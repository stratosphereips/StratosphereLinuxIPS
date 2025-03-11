# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import viztracer
import time
import threading
import yappi
import io
import pstats
import os

from slips_files.common.abstracts.performance_profiler import (
    IPerformanceProfiler,
)


class CPUProfiler(IPerformanceProfiler):
    def __init__(self, db, output, mode="dev", limit=20, interval=20):
        """
        :param output: the currently used slips output directory
        """
        valid_modes = ["dev", "live"]
        if mode not in valid_modes:
            print(
                "cpu_profiler_mode = "
                + mode
                + " is invalid, must be one of "
                + str(valid_modes)
                + ", CPU Profiling will be disabled"
            )
        if mode == "dev":
            self.profiler = DevProfiler(output)
        if mode == "live":
            self.profiler = LiveProfiler(db, limit, interval)

    def _create_profiler(self):
        self.profiler._create_profiler()

    def start(self):
        print("CPU Profiler Started")
        self.profiler.start()

    def stop(self):
        self.profiler.stop()
        print("CPU Profiler Ended")

    def print(self):
        self.profiler.print()


class DevProfiler(IPerformanceProfiler):
    def __init__(self, output):
        """
        :param output: the currently used slips output directory
        """
        self.profiler = self._create_profiler()
        self.output = output

    def _create_profiler(self):
        return viztracer.VizTracer()

    def start(self):
        self.profiler.start()

    def stop(self):
        self.profiler.stop()

    def print(self):
        """
        Prints the profiling result to cpu_profiling_result in slips output
        directory
        """
        result_path = os.path.join(self.output, "cpu_profiling_result.json")
        self.profiler.save(output_file=result_path)


class LiveProfiler(IPerformanceProfiler):
    def __init__(self, db, limit=20, interval=20):
        self.profiler = self._create_profiler()
        self.limit = limit
        self.interval = interval
        self.is_running = False
        self.timer_thread = threading.Thread(target=self._sampling_loop)
        self.db = db
        self.stats = None

    def _create_profiler(self):
        return yappi

    def start(self):
        if not self.is_running:
            self.is_running = True
            self.profiler.start()
            self.timer_thread.start()

    def stop(self):
        if self.is_running:
            self.is_running = False
            self.profiler.stop()

    def print(self):
        self.stats.print_stats(self.limit)

    def _sampling_loop(self):
        stringio = io.StringIO()
        while self.is_running:
            # replace the print with a redis update
            self.profiler.clear_stats()

            time.sleep(self.interval)

            self.stats = pstats.Stats(stream=stringio)
            self.stats.add(
                self.profiler.convert2pstats(self.profiler.get_func_stats())
            )
            self.stats.sort_stats("cumulative")
            self.print()  # prints to stringio, not stdout

            self.db.publish("cpu_profile", stringio.getvalue())
