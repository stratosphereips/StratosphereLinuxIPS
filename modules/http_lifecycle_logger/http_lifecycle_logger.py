# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os
import json
import csv
from pathlib import Path

from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.imodule import IModule


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
        self.channels = {"http_lifecycle_logger": self.c1}

        filename = os.path.join(self.output_dir, "http_lifecycle_logger.csv")
        self.csv_file = Path(filename)

        # Start with only "uid", will expand dynamically with operations
        self.headers = ["uid"]
        self.ensure_csv_file()

        # Buffer for incomplete lifecycles
        self.lifecycle_buffer = {}

    def ensure_csv_file(self):
        """Ensure CSV file exists with current headers"""
        with self.csv_file.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.headers)
            writer.writeheader()

    def pre_main(self):
        utils.drop_root_privs_permanently()

    def shutdown_gracefully(self):
        self.print("Incomplete life cycles:")
        import pprint

        pprint.pp(self.lifecycle_buffer)

    def main(self):
        if msg := self.get_msg("http_lifecycle_logger"):
            msg = json.loads(msg["data"])
            uid = msg.get("uid", "")
            operation = msg.get("operation", "")
            time_it_took = msg.get("time_it_took", 0)

            if not uid:
                return  # skip invalid

            if isinstance(uid, list):
                uid = uid[0]

            # Init buffer dict for this UID
            if uid not in self.lifecycle_buffer:
                self.lifecycle_buffer[uid] = {"uid": uid}

            # Save time in its column
            self.lifecycle_buffer[uid][operation] = round(
                float(time_it_took), 2
            )

            # If "done", flush row to CSV
            if operation == "done":
                row = self.lifecycle_buffer[uid]
                # Extend headers dynamically if new operations appear
                new_ops = [
                    op
                    for op in row.keys()
                    if op not in self.headers and op != "done"
                ]
                if new_ops:
                    self.headers.extend(new_ops)

                    # rewrite file with new headers
                    old_rows = []
                    if self.csv_file.exists():
                        with self.csv_file.open(
                            "r", newline="", encoding="utf-8"
                        ) as f:
                            old_rows = list(csv.DictReader(f))

                    with self.csv_file.open(
                        "w", newline="", encoding="utf-8"
                    ) as f:
                        writer = csv.DictWriter(f, fieldnames=self.headers)
                        writer.writeheader()
                        for r in old_rows:
                            writer.writerow(r)

                # Append the row
                with self.csv_file.open(
                    "a", newline="", encoding="utf-8"
                ) as f:
                    writer = csv.DictWriter(f, fieldnames=self.headers)
                    row.pop("done")
                    writer.writerow(row)

                del self.lifecycle_buffer[uid]
