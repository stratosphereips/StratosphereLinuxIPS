# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os

from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.imodule import IModule
import json
import csv
from pathlib import Path


class HTTPLifeCycleLogger(IModule):
    """
    Logs the time each CPU-intensive operation takes in the life cycle of
    an HTTP flow, starting from input.py until slips forgets about the flow.
    """

    name = "HTTPLifeCycleLogger"
    description = "Template module"
    authors = ["Alya"]

    def init(self):
        self.c1 = self.db.subscribe("http_lifecycle_logger")
        self.channels = {
            "http_lifecycle_logger": self.c1,
        }

        filename = os.path.join(self.output_dir, "http_lifecycle_logger.csv")
        self.csv_file = Path(filename)
        self.headers = ["uid", "feature", "time_it_took", "comment"]

        with self.csv_file.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.headers)
            writer.writeheader()

    def pre_main(self):
        utils.drop_root_privs_permanently()

    def main(self):
        if msg := self.get_msg("http_lifecycle_logger"):
            msg = json.loads(msg["data"])
            with self.csv_file.open("a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=self.headers)
                writer.writerow(
                    {
                        "uid": msg.get("uid", ""),
                        "operation": msg.get("operation", ""),
                        "time_it_took": msg.get("time_it_took", ""),
                        "comment": msg.get("comment", ""),
                    }
                )
