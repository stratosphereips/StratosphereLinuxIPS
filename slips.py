#!/usr/bin/env python3
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

from __future__ import print_function

import multiprocessing
import os
import sys
import time
import warnings

# Must be set before importing anything from Slips: class-level locks and
# shared values (e.g. in Output) are created at import time, and only
# spawn-style ones can be reopened by a spawned child. Children get only
# picklable config and build their own resources, so every OS uses the same
# start method.
multiprocessing.set_start_method("spawn", force=True)

from slips.main import Main  # noqa: E402
from slips.daemon import Daemon  # noqa: E402


# Ignore warnings on CPU from tensorflow
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
# Ignore warnings in general
warnings.filterwarnings("ignore")


####################
# Main
####################
if __name__ == "__main__":
    if sys.version_info[0] < 3:
        sys.exit("Slips can only run on python3+ .. Stopping.")

    slips = Main()

    if slips.args.stopdaemon:
        # -S is provided
        daemon_status: dict = Daemon(slips).stop()
        # it takes about 5 seconds for the stop_slips msg
        # to arrive in the channel, so give slips time to stop
        time.sleep(5)
        if daemon_status["stopped"]:
            print("Daemon stopped.")
        else:
            print(daemon_status["error"])

    elif slips.args.daemon:
        print("Slips daemon starting..", flush=True)
        Daemon(slips).start()
    else:
        # interactive mode
        slips.start()
