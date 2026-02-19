# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from slips_files.common.abstracts.iinput_handler import IInputHandler


class BinetflowInput(IInputHandler):
    def __init__(self, input_process):
        super().__init__(input_process)
        self.db = self.input.db

    def run(self):
        # -1 to not count the header line as a flow
        self.input.total_flows = (
            self.input.get_flows_number(self.input.given_path) - 1
        )
        self.db.set_input_metadata({"total_flows": self.input.total_flows})

        self.input.lines = 0
        with open(self.input.given_path) as file_stream:
            # read first line to determine the type of line, tab or comma separated
            t_line = file_stream.readline()
            type_ = "argus-tabs" if "\t" in t_line else "argus"
            line = {"type": type_, "data": t_line}
            self.input.give_profiler(line)
            self.input.lines += 1

            # go through the rest of the file
            for t_line in file_stream:
                line = {"type": type_, "data": t_line}
                # argus files are either tab separated orr comma separated
                if len(t_line.strip()) != 0:
                    self.input.give_profiler(line)

                self.input.lines += 1
                if self.input.testing:
                    break

        self.input.mark_self_as_done_processing()
        return True

    def shutdown_gracefully(self):
        self.input.mark_self_as_done_processing()
        return True
