# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import json
import os
import threading
import time

from slips_files.core.supported_logfiles import SUPPORTED_LOGFILES


class ZeekFileRemover:
    def __init__(self, input_process, zeek_utils):
        """
        Handles deleting rotated zeek files.
        :param input_process: Input.py instance that owns the channels.
        """
        self.input = input_process
        self.zeek_utils = zeek_utils
        self.thread = threading.Thread(
            target=self.remove_old_zeek_files,
            daemon=True,
            name="input_remover_thread",
        )
        self._started = False

    def start(self):
        """
        Start the remover thread once and ensure the rotation channel exists.

        :return: None
        """
        if self._started:
            return
        self._started = True
        channel = self.input.db.subscribe("remove_old_files")
        self.input.channels.update({"remove_old_files": channel})
        self.thread.start()

    def shutdown_gracefully(self):
        """
        Wait briefly for the remover thread to exit.

        :return: True
        """
        try:
            self.thread.join(3)
        except Exception:
            pass
        return True

    def process_rotation_message(self, changed_files: dict):
        """
        Close any stale handle for a rotated Zeek file and schedule cleanup.

        :param changed_files: a dict with old_file and new_file paths.
        """
        # for example the old log file should be  ./zeek_files/dns.2022-05-11-14-43-20.log
        # new log file should be dns.log without the ts
        old_log_file = changed_files["old_file"]
        new_log_file = changed_files["new_file"]
        new_logfile_without_path = new_log_file.split("/")[-1].split(".")[0]

        # ignored files have no open handle, so we should only delete them from disk
        if new_logfile_without_path not in SUPPORTED_LOGFILES:
            try:
                # just delete the old file
                os.remove(old_log_file)
            except FileNotFoundError:
                pass
            return

        self.zeek_utils.close_rotated_file_handle(new_log_file)
        # this file was just rotated.
        rotated_at = time.time()
        # zeek utils decides when to delete it.
        self.zeek_utils.schedule_rotated_file_deletion(
            old_log_file, rotated_at
        )

    def remove_old_zeek_files(self):
        """
        This thread waits for filemonitor.py to tell it that zeek changed the log files,
        it deletes old zeek-date.log files and clears slips' open handles and sleeps again
        """
        while not self.input.should_stop():
            # keep the rotated files for the period specified in slips.yaml
            if msg := self.input.get_msg("remove_old_files"):
                # this channel receives renamed zeek log files,
                # we can safely delete them and close their handle
                changed_files = json.loads(msg["data"])
                self.process_rotation_message(changed_files)
