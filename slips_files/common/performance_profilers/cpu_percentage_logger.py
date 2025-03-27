# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os
import time
import psutil

from slips_files.common.slips_utils import utils


class CPUUsageTracker:
    def __init__(self, output_dir, slips_pid):
        self.slips_start_time = time.time()
        self.log_file_path = os.path.join(output_dir, "cpu_usage.csv")
        with open(self.log_file_path, "w") as logger:
            logger.write("'Time Elapsed (minutes)', 'CPU Percentage'\n")

        # to get the cpu stats for slips only
        self.slips_main_proc = psutil.Process(slips_pid)
        # this is the reference time. used to tell psutil to start tracking
        # cpu usage from now.
        self.slips_main_proc.cpu_percent(interval=0.1)
        # This is the time when the cpu profiler was started.
        # every x mins we'll be noting the cpu percentage.
        self.cpu_profiler_time = time.time()

    def get_cpu_usage_with_children(self):
        """
        Returns the cpu usage of the main slips proc and all of its children
        """
        # get the parent process cpu usage
        # this is the percentage since last call
        cpu_usage = self.slips_main_proc.cpu_percent(interval=None)

        for child in self.slips_main_proc.children(recursive=True):
            cpu_usage += child.cpu_percent(interval=None)

        return cpu_usage

    def get_cpu_percentage(self):
        percentage = self.get_cpu_usage_with_children()
        now = time.time()
        self.cpu_profiler_time = now
        # since slips started
        elapsed_time = utils.get_time_diff(
            self.slips_start_time, now, "minutes"
        )
        elapsed_time = round(elapsed_time, 2)
        with open(self.log_file_path, "a") as logger:
            logger.write(f"{elapsed_time}, {percentage}\n")

    def is_time_to_log_cpu_usage(self):
        """should return True every 5 mins"""
        return time.time() - self.cpu_profiler_time >= 5 * 60

    def run(self):
        """captures cpu usage every 5 mins and logs the result to
        cpu_usage.csv the current output dir"""
        if self.is_time_to_log_cpu_usage():
            self.get_cpu_percentage()
