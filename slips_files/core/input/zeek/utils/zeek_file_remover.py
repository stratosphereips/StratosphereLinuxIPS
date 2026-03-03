# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import datetime
import json
import os
import threading

from slips_files.common.slips_utils import utils
from slips_files.core.supported_logfiles import SUPPORTED_LOGFILES


class ZeekFileRemover:
    def __init__(self, input_process, zeek_utils):
        self.input = input_process
        self.zeek_utils = zeek_utils
        self.thread = threading.Thread(
            target=self.remove_old_zeek_files,
            daemon=True,
            name="input_remover_thread",
        )
        self._started = False

    def start(self):
        if self._started:
            return
        self._started = True
        channel = self.input.db.subscribe("remove_old_files")
        self.input.channels.update({"remove_old_files": channel})
        self.thread.start()

    def shutdown_gracefully(self):
        try:
            self.thread.join(3)
        except Exception:
            pass
        return True

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

                # for example the old log file should be  ./zeek_files/dns.2022-05-11-14-43-20.log
                # new log file should be dns.log without the ts
                old_log_file = changed_files["old_file"]
                new_log_file = changed_files["new_file"]
                new_logfile_without_path = new_log_file.split("/")[-1].split(
                    "."
                )[0]
                # ignored files have no open handle, so we should only delete them from disk
                if new_logfile_without_path not in SUPPORTED_LOGFILES:
                    # just delete the old file
                    os.remove(old_log_file)
                    continue

                # don't allow inputprocess to access the
                # open_file_handlers dict until this thread sleeps again
                lock = threading.Lock()
                lock.acquire()
                try:
                    # close slips' open handles
                    self.zeek_utils.open_file_handlers[new_log_file].close()
                    # delete cached filename
                    del self.zeek_utils.open_file_handlers[new_log_file]
                except KeyError:
                    # we don't have a handle for that file,
                    # we probably don't need it in slips
                    # ex: loaded_scripts.log, stats.log etc..
                    pass
                # delete the old log file (the one with the ts)
                self.zeek_utils.to_be_deleted.append(old_log_file)
                self.zeek_utils.time_rotated = float(
                    utils.convert_ts_format(
                        datetime.datetime.now(), "unixtimestamp"
                    )
                )
                lock.release()
