"""Prevent workers from surviving the process that owns their queues."""

import os
from multiprocessing import parent_process
from threading import Event, Thread
from typing import Any, Callable

from slips_files.common.slips_utils import utils


def watch_parent(
    parent: Any, finished: Event, exit_process: Callable[[int], Any] = os._exit
) -> None:
    """Exit an orphan without touching abandoned multiprocessing locks.

    Parameters:
        parent: Multiprocessing parent identity, including its death sentinel.
        finished: Set when the worker completes its normal cleanup.
        exit_process: Immediate exit operation, injectable for verification.
    """
    while not finished.wait(1):
        if not parent.is_alive():
            exit_process(70)
            return


def start_parent_watchdog(database: Any) -> Event:
    """Watch the actual spawning parent without polling Redis or scanning PIDs.

    Parameters:
        database: Worker database used to register the bounded thread name.

    Returns:
        Event to set after normal completion; no watcher starts in the main.
    """
    finished = Event()
    parent = parent_process()
    if parent is not None:
        utils.start_thread(
            Thread(
                target=watch_parent,
                args=(parent, finished),
                name="parent_watchdog",
                daemon=True,
            ),
            database,
        )
    return finished
