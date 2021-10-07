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
from watchdog.events import RegexMatchingEventHandler
from slips_files.core.database import __database__

class FileEventHandler(RegexMatchingEventHandler):
    REGEX = [r".*\.log$", r".*\.conf$"]

    def __init__(self, config):
        super().__init__(self.REGEX)
        self.config = config
        # Start the DB
        __database__.start(self.config)

    def on_created(self, event):
        self.process(event)

    def process(self, event):
        filename, ext = os.path.splitext(event.src_path)
        if 'log' in ext:
            __database__.add_zeek_file(filename)

    def on_modified(self, event):
        filename, ext = os.path.splitext(event.src_path)
        if 'whitelist' in filename:
            __database__.publish("reload_whitelist","reload")
