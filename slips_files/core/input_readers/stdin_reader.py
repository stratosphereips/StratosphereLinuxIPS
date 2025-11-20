# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import os
import sys

from slips_files.common.abstracts.iinput_reader import IInputReader


class StdinReader(IInputReader):
    name = "StdinReader"
    description = "Reads flows from stdin"

    def init(self): ...

    def stdin(self):
        """opens the stdin in read mode"""
        sys.stdin.close()
        sys.stdin = os.fdopen(0, "r")
        return sys.stdin

    def read(self, line_type) -> bool:
        self.print("Receiving flows from stdin.")
        for line in self.stdin():
            if line == "\n":
                continue
            if line == "done":
                break
            # slips supports reading zeek json conn.log only using stdin,
            # tabs aren't supported
            if line_type == "zeek":
                try:
                    line = json.loads(line)
                except json.decoder.JSONDecodeError:
                    self.print("Invalid json line")
                    continue

            line_info = {
                "type": "stdin",
                "line_type": line_type,
                "data": line,
            }
            self.print(f"	> Sent Line: {line_info}", 0, 3)
            self.give_profiler(line_info)
            # self.lines += 1
            self.print("Done reading 1 flow.\n ", 0, 3)
        return True
