import os
import time
import psutil

from slips_files.common.slips_utils import utils


class RamUsageTracker:
    def __init__(self, output_dir, pid):
        # initialize start time
        self.start_time = time.time()
        self.log_file_path = os.path.join(output_dir, "ram_usage.csv")
        with open(self.log_file_path, "w") as logger:
            logger.write("'time elapsed (minutes)', 'ram usage (mb)'\n")

        # create psutil process for the given pid
        self.psutil_process = psutil.Process(pid)
        # record the initial time for tracking
        self.profiler_time = time.time()

    def get_ram_usage(self):
        # get memory usage of the parent process
        total_memory = self.psutil_process.memory_info().rss

        # iterate over all child processes and add their memory usage
        for child in self.psutil_process.children(recursive=True):
            total_memory += child.memory_info().rss

        usage_mb = total_memory / (1024 * 1024)
        now = time.time()
        elapsed_time = utils.get_time_diff(self.start_time, now, "minutes")
        elapsed_time = round(elapsed_time, 2)
        with open(self.log_file_path, "a") as logger:
            logger.write(f"{elapsed_time}, {usage_mb}\n")
        self.profiler_time = now

    def is_time_to_log_ram_usage(self):
        # should return true every 5 mins
        return time.time() - self.profiler_time >= 5 * 60

    def run(self):
        # capture ram usage every 5 mins and log the result to ram_usage.csv
        if self.is_time_to_log_ram_usage():
            self.get_ram_usage()
