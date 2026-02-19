# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import json

from slips_files.common.abstracts.iinput_handler import IInputHandler


class CystInput(IInputHandler):
    def __init__(self, input_process):
        super().__init__(input_process)
        self.db = self.input.db

    def run(self):
        """
        Read flows sent by any external module (for example the CYST module)
        Supported flows are of type zeek conn log
        """
        # slips supports reading zeek json conn.log only using CYST
        # this type is passed here by slips.py, so in the future
        # to support more types, modify slips.py
        if self.input.line_type != "zeek":
            return

        channel = self.db.subscribe("new_module_flow")
        self.input.channels.update({"new_module_flow": channel})
        while not self.input.should_stop():
            # the CYST module will send msgs to this channel when it reads a
            # new flow from the CYST UDS
            # todo when to break? cyst should send something like stop?

            msg = self.input.get_msg("new_module_flow")
            if msg and msg["data"] == "stop_process":
                self.input.shutdown_gracefully()
                return True

            if msg := self.input.get_msg("new_module_flow"):
                msg: str = msg["data"]
                msg = json.loads(msg)
                flow = msg["flow"]
                src_module = msg["module"]
                line_info = {
                    "type": "external_module",
                    "module": src_module,
                    "line_type": self.input.line_type,
                    "data": flow,
                }
                self.input.print(f"   > Sent Line: {line_info}", 0, 3)
                self.input.give_profiler(line_info)
                self.input.lines += 1
                self.input.print("Done reading 1 CYST flow.\n ", 0, 3)

        self.input.mark_self_as_done_processing()
        return True

    def shutdown_gracefully(self):
        self.input.mark_self_as_done_processing()
        return True
