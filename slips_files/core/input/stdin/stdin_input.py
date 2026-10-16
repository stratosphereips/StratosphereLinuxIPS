# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import json
import os
import sys
from typing import TextIO

from slips_files.common.abstracts.iinput_handler import IInputHandler


class StdinInput(IInputHandler):
    def __init__(self, input_process):
        super().__init__(input_process)
        self.db = self.input.db

    def _stdin(self) -> TextIO:
        """Return the parent's transferred input stream in the child."""
        descriptor = self.input.stdin_descriptor
        if descriptor is None:
            return sys.stdin
        return os.fdopen(descriptor.detach(), "r")

    def run(self) -> bool:
        self.input.print("Receiving flows from stdin.")
        for line in self._stdin():
            if line == "\n":
                continue
            if line.strip() == "done":
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
                "interface": "default",
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
