# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import os

from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.iinput_handler import IInputHandler
from slips_files.core.input.observer_manager import InputObserver
from slips_files.core.input.zeek.utils.zeek_file_remover import ZeekFileRemover


class ZeekDirInput(IInputHandler):
    def __init__(self, input_process):
        super().__init__(input_process)
        self.db = self.input.db
        self.observer = InputObserver(self.input)
        self.file_remover = ZeekFileRemover(self.input, self.input.zeek_utils)

    def run(self):
        """
        This function runs when
        - a finite zeek dir is given to slips with -f
        - a growing zeek dir is given to slips with -g
        This func does not run when slips is running on an interface with
        -i or -ap
        """
        # wait max 10 seconds before stopping slips if no new flows are read
        self.input.bro_timeout = 10
        growing_zeek_dir: bool = self.db.is_growing_zeek_dir()
        if growing_zeek_dir:
            # slips is given a dir that is growing i.e zeek dir running on an
            # interface
            # don't stop zeek or slips
            self.input.bro_timeout = float("inf")

        self.input.zeek_dir = self.input.given_path
        # if slips is just reading a finite zeek dir, there's no way to
        # know the interface
        interface = "default"
        if self.input.args.growing:
            interface = self.input.args.interface
        self.observer.start(self.input.zeek_dir, interface)
        if self.input.is_running_non_stop:
            self.file_remover.start()

        # if 1 file is zeek tabs the rest should be the same
        if not hasattr(self.input, "is_zeek_tabs"):
            full_path = os.path.join(
                self.input.given_path, os.listdir(self.input.given_path)[0]
            )
            self.input.is_zeek_tabs = self.input.zeek_utils.is_zeek_tabs_file(
                full_path
            )

        total_flows = 0
        for file in os.listdir(self.input.given_path):
            full_path = os.path.join(self.input.given_path, file)

            # exclude ignored files from the total flows to be processed
            if utils.is_ignored_zeek_log_file(full_path):
                continue

            if not growing_zeek_dir:
                # get the total number of flows slips is going to read
                total_flows += self.input.get_flows_number(full_path)

            # Add log file to the database
            self.db.add_zeek_file(full_path, interface)

            # in testing mode, we only need to read one zeek file to know
            # that this function is working correctly
            if self.input.testing:
                break

        if total_flows == 0 and not growing_zeek_dir:
            # we're given an empty dir/ zeek logfile
            self.input.mark_self_as_done_processing()
            return True

        self.input.total_flows = total_flows
        self.db.set_input_metadata({"total_flows": total_flows})
        self.input.lines = self.input.zeek_utils.read_zeek_files()
        self.input.print_lines_read()
        self.input.mark_self_as_done_processing()
        return True

    def shutdown_gracefully(self):
        self.observer.stop()
        self.file_remover.shutdown_gracefully()
        self.input.zeek_utils.close_all_handles()
        self.input.mark_self_as_done_processing()
        return True
