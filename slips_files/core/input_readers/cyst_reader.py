# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json

from slips_files.common.abstracts.iinput_reader import IInputReader


class CYSTReader(IInputReader):
    name = "CYSTReader"
    description = "Reads flows sent by CYST"

    def init(self, input_proc=None):
        # to be able to stop the process gracefully and manage channels.
        self.input_proc = input_proc

    def read(self, line_type):
        """
        Read flows sent by any external module (for example the cYST module)
        Supported flows are of type zeek conn log
        """
        # slips supports reading zeek json conn.log only using CYST
        # this type is passed here by slips.py, so in the future
        # to support more types, modify slips.py
        if line_type != "zeek":
            return

        lines = 0
        channel = self.db.subscribe("new_module_flow")
        self.input_proc.channels.update({"new_module_flow": channel})
        while not self.input_proc.should_stop():
            # the CYST module will send msgs to this channel when it reads
            # a new flow from the CYST UDS

            # todo when to break? cyst should send something like stop?

            msg = self.input_proc.get_msg("new_module_flow")
            if msg and msg["data"] == "stop_process":
                self.input_proc.shutdown_gracefully()
                return True

            if msg := self.get_msg("new_module_flow"):
                msg: str = msg["data"]
                msg = json.loads(msg)
                flow = msg["flow"]
                src_module = msg["module"]
                line_info = {
                    "type": "external_module",
                    "module": src_module,
                    "line_type": line_type,
                    "data": flow,
                }
                self.print(f"   > Sent Line: {line_info}", 0, 3)
                self.give_profiler(line_info)
                lines += 1
                self.print("Done reading 1 CYST flow.\n ", 0, 3)

        return lines
