# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from slips_files.common.abstracts.iinput_handler import IInputHandler


class SuricataInput(IInputHandler):
    def __init__(self, input_process):
        super().__init__(input_process)
        self.db = self.input.db

    def run(self):
        self.input.total_flows = self.input.get_flows_number(
            self.input.given_path
        )
        self.db.set_input_metadata({"total_flows": self.input.total_flows})
        with open(self.input.given_path) as file_stream:
            for t_line in file_stream:
                line = {
                    "type": "suricata",
                    "data": t_line,
                }
                self.input.print(f"\t> Sent Line: {line}", 0, 3)
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
