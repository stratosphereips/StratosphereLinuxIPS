# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from slips_files.common.abstracts.iinput_reader import IInputReader


class BinetflowReader(IInputReader):
    name = "BinetflowReader"
    description = "Reads Binetflow files"

    def init(self): ...

    def read(self, given_path):
        # the number of flows returned by get_flows_number contains the header
        # , so subtract that
        total_flows = self.get_flows_number(given_path) - 1
        self.db.set_input_metadata({"total_flows": total_flows})

        lines = 0
        with open(given_path) as file_stream:
            # read first line to determine the type of line, tab or comma separated
            t_line = file_stream.readline()
            type_ = "argus-tabs" if "\t" in t_line else "argus"
            line = {"type": type_, "data": t_line}
            self.give_profiler(line)
            lines += 1

            # go through the rest of the file
            for t_line in file_stream:
                line = {"type": type_, "data": t_line}
                # argus files are either tab separated orr comma separated
                if len(t_line.strip()) != 0:
                    self.give_profiler(line)

                lines += 1
                if self.testing:
                    break
        return lines
