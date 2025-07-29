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
import asyncio
from watchdog.events import RegexMatchingEventHandler


class FileEventHandler(RegexMatchingEventHandler):
    REGEX = [r".*\.log$", r".*\.conf$"]

    def __init__(self, dir_to_monitor, input_type, db):
        super().__init__(regexes=self.REGEX)
        self.dir_to_monitor = dir_to_monitor
        self.db = db
        self.input_type = input_type

    async def on_created(self, event):
        """this will be triggered everytime zeek creates a log file"""
        filename, ext = os.path.splitext(event.src_path)
        if "log" in ext:
            await self.db.add_zeek_file(filename + ext)

    async def on_moved(self, event):
        """
        this will be triggered everytime zeek renames all log files
        """
        # tell inputProcess to change open handles
        if event.dest_path != "True":
            to_send = {"old_file": event.dest_path, "new_file": event.src_path}
            to_send = json.dumps(to_send)
            await self.db.publish("remove_old_files", to_send)

            # give inputProc.py time to close the handle or delete the file
            # In an async context, avoid time.sleep() and use asyncio.sleep()
            await asyncio.sleep(1)

    async def on_modified(self, event):
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
                # For file I/O in an async context, ideally use async file operations
                # if available (e.g., aiofiles). For simplicity here, sticking with
                # synchronous open, but be aware it can block the event loop.
                with open(os.path.join(self.dir_to_monitor, file), "r") as f:
                    while line := f.readline():
                        if "termination" in line:
                            # tell slips to terminate
                            await self.db.publish_stop()
                            break
        elif "whitelist" in filename:
            await self.db.publish("reload_whitelist", "reload")
