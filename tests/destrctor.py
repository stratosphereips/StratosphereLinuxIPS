# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
Close all redis-servers opened by the unit tests
"""

import os
import redis


def get_pid_of_redis_server(port: int) -> str:
    """
    Gets the pid of the redis server running on this port
    Returns str(port) or false if there's no redis-server running on this port
    """
    cmd = "ps aux | grep redis-server"
    cmd_output = os.popen(cmd).read()
    for line in cmd_output.splitlines():
        if str(port) in line:
            pid = line.split()[1]
            return pid
    return False


def flush_redis_server(port: str = ""):
    """
    Flush the redis server on this pid, only 1 param should be given, pid or port
    :param pid: can be False if port is given
    Gets the pid of the port is not given
    """

    # clear the server opened on this port
    try:
        # if connected := __database__.connect_to_redis_server(port):
        # noinspection PyTypeChecker
        # todo move this to the db
        r = redis.StrictRedis(
            host="localhost",
            port=port,
            db=0,
            charset="utf-8",
            socket_keepalive=True,
            decode_responses=True,
            retry_on_timeout=True,
            health_check_interval=20,
        )
        r.flushall()
        r.flushdb()
        r.script_flush()
        return True
    except (redis.exceptions.ConnectionError, RuntimeError):
        # server already killed!
        return False


def kill_redis_server(pid):
    """
    Kill the redis server on this pid
    """
    try:
        pid = int(pid)
    except ValueError:
        # The server was killed before logging its PID
        # the pid of it is 'not found'
        return False

    # signal 0 is to check if the process is still running or not
    # it returns 1 if the process used_redis_servers.txt exited
    try:
        # check if the process is still running
        while os.kill(pid, 0) != 1:
            # sigterm is 9
            os.kill(pid, 9)
    except ProcessLookupError:
        # ProcessLookupError: process already exited, sometimes this exception is raised
        # but the process is still running, keep trying to kill it
        return True
    except PermissionError:
        # PermissionError happens when the user tries to close redis-servers
        # opened by root while he's not root,
        # or when he tries to close redis-servers
        # opened without root while he's root
        return False
    return True


if __name__ == "__main__":
    redis_server_ports = [65531, 6380, 6381, 1234]
    closed_servers = 0
    for redis_port in redis_server_ports:
        # On modern systems, the netstat utility comes pre-installed,
        # this can be done using psutil but it needs root on macos
        redis_pid = get_pid_of_redis_server(redis_port)
        if not redis_pid:
            # server isn't started yet
            continue

        # print(f'Redis port: {redis_port} is found using PID {redis_pid} ')
        try:
            flush_redis_server(str(redis_port))
            print(f"Flushed redis-server opened on port: {redis_port}")
            kill_redis_server(redis_pid)
            print(f"Killed redis-server on port {redis_port} PID: {redis_pid}")
            closed_servers += 1
        except redis.exceptions.ConnectionError:
            continue

    print(f"Closed {closed_servers} unused redis-servers")

    zeek_tmp_dir = os.path.join(os.getcwd(), "zeek_dir_for_testing")
    try:
        os.rmdir(zeek_tmp_dir)
    except (FileNotFoundError, OSError):
        pass
