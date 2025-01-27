# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os
from typing import (
    Dict,
    List,
)


def get_open_redis_ports_in_order() -> List[Dict[str, str]]:
    available_db = []
    file_path = "running_slips_info.txt"

    if os.path.exists(file_path):
        with open(file_path) as file:
            for line in file:
                if (
                    line.startswith("Date")
                    or line.startswith("#")
                    or len(line) < 3
                ):
                    continue
                line = line.split(",")
                available_db.append(
                    {"filename": line[1], "redis_port": line[2]}
                )

    return available_db


def is_comment(line: str) -> bool:
    """returns true if the given line is a comment"""
    return (line.startswith("#") or line.startswith("Date")) or len(line) < 3


def get_open_redis_servers() -> Dict[int, dict]:
    """
    returns the opened redis servers read from running_slips.info.txt
    returns the following dict: {port: {
        "timestamp": ...,
        "file_or_interface": ...,
        "port": ...,
        "pid": ...,
        "zeek_dir": ...,
        "output_dir": ...,
        "slips_pid": ...,
        "is_daemon": ...,
        "save_the_db": ...,
    }}
    """
    running_logfile = "running_slips_info.txt"
    open_servers: Dict[int, dict] = {}
    try:
        with open(running_logfile) as f:
            for line in f.read().splitlines():
                if is_comment(line):
                    continue

                line = line.split(",")

                try:
                    (
                        timestamp,
                        file_or_interface,
                        port,
                        pid,
                        zeek_dir,
                        output_dir,
                        slips_pid,
                        is_daemon,
                        save_the_db,
                    ) = line

                    open_servers[port] = {
                        "timestamp": timestamp,
                        "file_or_interface": file_or_interface,
                        "port": port,
                        "pid": pid,
                        "zeek_dir": zeek_dir,
                        "output_dir": output_dir,
                        "slips_pid": slips_pid,
                        "is_daemon": is_daemon,
                        "save_the_db": save_the_db,
                    }
                except ValueError:
                    # sometimes slips can't get the server pid and logs
                    # "False" in the logfile instead of the PID
                    # there's nothing we can do about it
                    pass

        return open_servers

    except FileNotFoundError:
        return {}
