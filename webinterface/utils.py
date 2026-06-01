# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import os
import socket
from typing import (
    BinaryIO,
    Dict,
    List,
)

RDB_HEADER_SIZE = 9
RDB_MAGIC = b"REDIS"


def is_port_open(port: int) -> bool:
    """
    Check whether a TCP port is accepting connections on localhost.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def has_rdb_extension(filename: str) -> bool:
    """
    Check whether a filename uses the Redis RDB extension.

    Parameters:
    filename: Uploaded filename to inspect.

    Return:
    True when the filename ends with .rdb.
    """
    return os.path.splitext(filename)[1].lower() == ".rdb"


def is_redis_rdb_file(file_obj: BinaryIO) -> bool:
    """
    Verify a file-like object has a Redis RDB header.

    Parameters:
    file_obj: Binary stream positioned anywhere in the uploaded file.

    Return:
    True when the stream starts with a Redis RDB magic header and version.
    """
    position = file_obj.tell()
    try:
        file_obj.seek(0)
        header = file_obj.read(RDB_HEADER_SIZE)
    finally:
        file_obj.seek(position)

    return (
        len(header) == RDB_HEADER_SIZE
        and header.startswith(RDB_MAGIC)
        and header[len(RDB_MAGIC) :].isdigit()
    )


def get_open_redis_ports_in_order() -> List[Dict[str, str]]:
    available_db = []
    file_path = "running_slips_info.txt"
    seen_ports = set()

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
                redis_port = line[2]
                try:
                    port = int(redis_port)
                except ValueError:
                    continue
                if port in seen_ports or not is_port_open(port):
                    continue
                available_db.append(
                    {"filename": line[1], "redis_port": redis_port}
                )
                seen_ports.add(port)

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
