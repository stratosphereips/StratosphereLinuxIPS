# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import json
import os
import sys

from slips_files.common.abstracts.iinput_handler import IInputHandler


class StdinInput(IInputHandler):
    def __init__(self, input_process):
        super().__init__(input_process)
        self.db = self.input.db

    def _stdin(self):
        """opens the stdin in read mode"""
        sys.stdin.close()
        sys.stdin = os.fdopen(0, "r")
        return sys.stdin

    def run(self) -> bool:
        self.input.print("Receiving flows from stdin.")
        for line in self._stdin():
            if line == "\n":
                continue
            if line == "done":
                break
            # slips supports reading zeek json conn.log only using stdin,
            # tabs aren't supported
            if self.input.line_type == "zeek":
                try:
                    line = json.loads(line)
                except json.decoder.JSONDecodeError:
                    self.input.print("Invalid json line")
                    continue

            line_info = {
                "type": "stdin",
                "line_type": self.input.line_type,
                "data": line,
            }
            self.input.print(f"\t> Sent Line: {line_info}", 0, 3)
            self.input.give_profiler(line_info)
            self.input.lines += 1
            self.input.print("Done reading 1 flow.\n ", 0, 3)
        return True

    def shutdown_gracefully(self):
        self.input.mark_self_as_done_processing()
        return True
