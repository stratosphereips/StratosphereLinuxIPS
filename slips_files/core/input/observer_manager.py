# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from watchdog.observers import Observer

from slips_files.core.helpers.filemonitor import FileEventHandler


class InputObserver:
    def __init__(self, input_process):
        self.input = input_process
        self.observer = None

    def start(self, zeek_dir: str, pcap_or_interface: str):
        """
        :param zeek_dir: directory to monitor
        """
        # Now start the observer of new files. We need the observer because Zeek does not create all the files
        # at once, but when the traffic appears. That means that we need
        # some process to tell us which files to read in real time when they appear
        # Get the file eventhandler
        # We have to set event_handler and event_observer before running zeek.
        event_handler = FileEventHandler(
            zeek_dir, self.input.db, pcap_or_interface
        )

        self.observer = Observer()
        # Schedule the observer with the callback on the file handler
        self.observer.schedule(event_handler, zeek_dir, recursive=True)
        # monitor changes to whitelist
        self.observer.schedule(event_handler, "config/", recursive=True)
        # Start the observer
        self.observer.start()

    def stop(self):
        # Stop the observer
        try:
            self.observer.stop()
            self.observer.join(10)
        except AttributeError:
            # In the case of nfdump, there is no observer
            pass
