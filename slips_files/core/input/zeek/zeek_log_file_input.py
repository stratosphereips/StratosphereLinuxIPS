# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import os

from slips_files.common.abstracts.iinput_handler import IInputHandler
from slips_files.core.supported_logfiles import SUPPORTED_LOGFILES
from slips_files.common.slips_utils import utils


class ZeekLogFileInput(IInputHandler):
    def __init__(self, input_process):
        super().__init__(input_process)
        self.db = self.input.db

    def run(self):
        """
        Handles conn.log files given to slips directly,
         and conn.log flows given to slips through CYST unix socket.
        """
        if (
            utils.is_ignored_zeek_log_file(self.input.given_path)
            and "cyst" not in self.input.given_path.lower()
        ):
            self.input.print(
                f"Warning: Unsupported Zeek log file '{self.input.given_path}'. "
                f"Only these log types are supported: {SUPPORTED_LOGFILES} "
                f"(with a .log extension)."
            )
            return False

        if os.path.exists(self.input.given_path):
            # in case of CYST flows, the given path is 'cyst' and there's no
            # way to get the total flows
            self.input.is_zeek_tabs = self.input.zeek_utils.is_zeek_tabs_file(
                self.input.given_path
            )
            total_flows = self.input.get_flows_number(self.input.given_path)
            self.db.set_input_metadata({"total_flows": total_flows})
            self.input.total_flows = total_flows

        self.db.add_zeek_file(self.input.given_path, "default")

        # this timeout is the only thing that
        # makes the read_zeek_files() return
        # without it, it will keep listening forever for new zeek log files
        # as we're running on an interface
        self.input.bro_timeout = 30
        self.input.lines = self.input.zeek_utils.read_zeek_files()
        self.input.mark_self_as_done_processing()
        return True

    def shutdown_gracefully(self):
        self.input.zeek_utils.close_all_handles()
        self.input.mark_self_as_done_processing()
        return True
