# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from slips_files.common.abstracts.iinput_reader import IInputReader


class SuricataReader(IInputReader):
    name = "SuricataReader"
    description = "Reads Suricata files"

    def init(self):
        self.lines = 0

    def read(self, given_path):
        """returns the number of lines read"""
        total_flows = self.get_flows_number(given_path)
        self.db.set_input_metadata({"total_flows": total_flows})

        with open(given_path) as file_stream:
            for t_line in file_stream:
                line = {
                    "type": "suricata",
                    "data": t_line,
                }
                self.print(f"	> Sent Line: {line}", 0, 3)
                if len(t_line.strip()) != 0:
                    self.give_profiler(line)
                self.lines += 1
                if self.testing:
                    break
        return self.lines
