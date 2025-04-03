# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os
import time

from slips_files.common.slips_utils import utils


class FlowRateLogger:
    def __init__(self, output_dir, db):
        self.db = db
        self.slips_start_time = time.time()
        self.log_file_path = os.path.join(output_dir, "flow_rate.csv")
        with open(self.log_file_path, "w") as logger:
            logger.write("Time Elapsed (minutes), Flows Per Minute\n")

        # this is the time when the logger was started.
        # every x mins we'll be looging the fpm.
        self.ts_of_last_inspection = time.time()

    def get_flow_rate(self):
        flow_per_min = self.db.get_flows_analyzed_per_minute()

        now = time.time()
        self.ts_of_last_inspection = now
        # since slips started
        elapsed_time = utils.get_time_diff(
            self.slips_start_time, now, "minutes"
        )
        elapsed_time = round(elapsed_time, 2)
        with open(self.log_file_path, "a") as logger:
            logger.write(f"{elapsed_time}, {flow_per_min}\n")

        print(f"{elapsed_time}, {flow_per_min}")

    def is_time_to_log(self):
        """should return True every 1 min starting from the first time
        the fpm was logged"""
        return time.time() - self.ts_of_last_inspection >= 60

    def run(self):
        """captures fpm every 1 min and logs the result to
        flow_rate.csv the current output dir"""
        if self.is_time_to_log():
            self.get_flow_rate()
