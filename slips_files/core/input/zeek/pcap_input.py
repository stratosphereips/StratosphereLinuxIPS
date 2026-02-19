# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from slips_files.common.abstracts.iinput_handler import IInputHandler
from slips_files.core.input.observer_manager import InputObserver
from slips_files.core.input.zeek.utils.zeek_file_remover import ZeekFileRemover


class PcapInput(IInputHandler):
    def __init__(self, input_process):
        super().__init__(input_process)
        self.db = self.input.db
        self.observer = InputObserver(self.input)
        self.file_remover = ZeekFileRemover(self.input, self.input.zeek_utils)

    def run(self):
        """
        runs when slips is given a pcap with -f
        """
        self.input.zeek_utils.ensure_zeek_dir()
        self.input.print(f"Storing zeek log files in {self.input.zeek_dir}")
        if self.input.is_running_non_stop:
            self.file_remover.start()

        # This is for stopping the inputprocess
        # if bro does not receive any new line while reading a pcap
        self.input.bro_timeout = 30
        self.input.zeek_utils.init_zeek(
            self.observer, self.input.zeek_dir, self.input.given_path
        )

        self.input.lines = self.input.zeek_utils.read_zeek_files()
        self.input.print_lines_read()
        self.input.mark_self_as_done_processing()
        return True

    def shutdown_gracefully(self):
        self.observer.stop()
        self.file_remover.shutdown_gracefully()
        self.input.zeek_utils.shutdown_zeek_runtime()
        self.input.zeek_utils.close_all_handles()
        self.input.mark_self_as_done_processing()
        return True
