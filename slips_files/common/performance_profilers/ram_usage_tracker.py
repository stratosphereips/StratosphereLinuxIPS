# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os
import time
import psutil

from slips_files.common.slips_utils import utils


class RAMUsageTracker:
    def __init__(self, output_dir, slips_pid):
        self.slips_start_time = time.time()
        self.log_file_path = os.path.join(output_dir, "ram_usage.csv")
        with open(self.log_file_path, "w") as logger:
            logger.write("Time Elapsed (minutes), RAM Usage/USS (MB)\n")

        # to get the ram stats for slips only
        self.slips_main_proc = psutil.Process(slips_pid)

        # this is the time when the ram profiler was started.
        # every x mins we'll be noting the ram usage.
        self.ts_of_last_inspection = time.time()

    def get_ram_usage_with_children(self) -> float:
        """
        returns the ram usage (USS) of the main slips proc
         and all of its children in MB
        """
        # get the parent process ram usage
        # this https://gmpy.dev/blog/2016/real-process-memory-and-environ-in-python
        # explains why we're using USS instead of RSS
        ram_usage = self.slips_main_proc.memory_full_info().uss

        slips_main_children = self.slips_main_proc.children(recursive=True)

        # print(f"@@@@@@@@@@@@@@@@ slips children :")
        # pprint.pp(slips_main_children)
        # print()

        for child in slips_main_children:
            try:
                ram_usage += child.memory_full_info().uss
            except psutil.NoSuchProcess:
                # some module may have terminated
                pass
        usage_mb = ram_usage / (1024 * 1024)
        return usage_mb

    def get_ram_usage(self):
        usage = self.get_ram_usage_with_children()
        now = time.time()
        self.ts_of_last_inspection = now
        # since slips started
        elapsed_time = utils.get_time_diff(
            self.slips_start_time, now, "minutes"
        )
        elapsed_time = round(elapsed_time, 2)
        with open(self.log_file_path, "a") as logger:
            logger.write(f"{elapsed_time}, {usage}\n")
        # print(f"{elapsed_time}, {usage}")

    def is_time_to_log_ram_usage(self):
        """should return True every 5 mins starting from the first time
        ram is inspected"""
        return time.time() - self.ts_of_last_inspection >= 5 * 60

    def run(self):
        """captures ram usage every 5 mins and logs the result to
        ram_usage.csv the current output dir"""
        if self.is_time_to_log_ram_usage():
            self.get_ram_usage()
