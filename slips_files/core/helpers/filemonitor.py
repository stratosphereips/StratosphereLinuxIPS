# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# Stratosphere Linux IPS. A machine-learning Intrusion Detection System
# Copyright (C) 2021 Sebastian Garcia

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# Contact: eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz, stratosphere@aic.fel.cvut.cz

import os
import json
import time
from watchdog.events import RegexMatchingEventHandler
from slips_files.common.slips_utils import utils


class FileEventHandler(RegexMatchingEventHandler):
    REGEX = [r".*\.log$", r".*\.conf$"]

    def __init__(self, dir_to_monitor, input_type, db):
        super().__init__(regexes=self.REGEX)
        self.dir_to_monitor = dir_to_monitor
        utils.drop_root_privs()
        self.db = db
        self.input_type = input_type

    def on_created(self, event):
        """this will be triggered everytime zeek creates a log file"""
        filename, ext = os.path.splitext(event.src_path)
        if "log" in ext:
            self.db.add_zeek_file(filename + ext)

    def on_moved(self, event):
        """
        this will be triggered everytime zeek renames all log files
        """
        # tell inputProcess to change open handles
        if event.dest_path != "True":
            to_send = {"old_file": event.dest_path, "new_file": event.src_path}
            to_send = json.dumps(to_send)
            self.db.publish("remove_old_files", to_send)

            # give inputProc.py time to close the handle or delete the file
            time.sleep(1)

    def on_modified(self, event):
        """
        this will be triggered everytime zeek modifies a log file
        """
        # we only need to know modifications to reporter.log,
        # so if zeek receives a termination signal,
        # slips would know about it
        filename, ext = os.path.splitext(event.src_path)
        if "reporter" in filename:
            # check if it's a termination signal
            # get the exact file name (a ts is appended to it)
            for file in os.listdir(self.dir_to_monitor):
                if "reporter" not in file:
                    continue
                with open(os.path.join(self.dir_to_monitor, file), "r") as f:
                    while line := f.readline():
                        if "termination" in line:
                            # tell slips to terminate
                            self.db.publish_stop()
                            break
        elif "whitelist" in filename:
            self.db.publish("reload_whitelist", "reload")
