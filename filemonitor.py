# This file watches a folder for new files with the regex *.log. Used to monitor the apearence of new
# Zeek log files to read

import os
from watchdog.events import RegexMatchingEventHandler
import redis

class FileEventHandler(RegexMatchingEventHandler):
    REGEX = [r".*\.log$"]

    def __init__(self):
        super().__init__(self.REGEX)
        # We need the connection to the database so we can communicate the processes
        self.r = redis.StrictRedis(host='localhost', port=6379, db=0, charset="utf-8", decode_responses=True)

    def on_created(self, event):
        self.process(event)

    def process(self, event):
        filename, ext = os.path.splitext(event.src_path)
        self.r.rpush('zeekfiles', filename)

