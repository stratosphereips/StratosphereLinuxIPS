# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import time
from threading import Event


def timewindow_updater(db, tw_width: float, stop_event: Event):
    """
    runs in a thread, wakes up only to update the current timewindow
    number in the db and sleeps again for the whole tw width
    """
    while not stop_event.is_set():
        now = time.time()
        cur_tw = db.get_timewindow(now, "", add_to_db=False)
        db.set_current_timewindow(cur_tw)
        # to avoid busy waiting
        stop_event.wait(tw_width)
