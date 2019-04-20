# This file watches a folder for new files with the regex *.log. Used to monitor the apearence of new
# Zeek log files to read

import os
from watchdog.events import RegexMatchingEventHandler
import redis
from slips.core.database import __database__

class FileEventHandler(RegexMatchingEventHandler):
    REGEX = [r".*\.log$"]

    def __init__(self):
        super().__init__(self.REGEX)

    def on_created(self, event):
        self.process(event)

    def process(self, event):
        filename, ext = os.path.splitext(event.src_path)
        __database__.add_zeek_file(filename)

