# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import contextlib
import shutil
import redis
import os
import time
import socket
import subprocess
from typing import Dict, Union
from slips_files.core.output import Output
from slips_files.common.slips_utils import utils
from slips_files.core.database.database_manager import DBManager


class RedisManager:
    open_servers_pids: Dict[int, dict]

    def __init__(self, main):
        self.main = main
        # slips picks a redis port from the following range
        self.start_port = 32768
        self.end_port = 32850
        self.running_logfile = "running_slips_info.txt"

    def get_start_port(self):
        return self.start_port

    def log_redis_server_pid(self, redis_port: int, redis_pid: int):
        now = utils.get_human_readable_datetime()
        try:
            # used in case we need to remove the line using 6379 from running
            # logfile
            with open(self.running_logfile, "a") as f:
                # add the header lines if the file is newly created
                if f.tell() == 0:
                    f.write(
                        "# This file contains a list of used redis ports.\n"
                        "# Once a server is killed, it will be removed from "
                        "this file.\n\n"
                        "Date, File or interface, Used port, Server PID,"
                        " Output Zeek Dir, Logs Dir, Slips PID, Is Daemon, "
                        "Save the DB\n"
                    )

                f.write(
                    f"{now},{self.main.input_information},{redis_port},"
                    f"{redis_pid},{self.main.zeek_dir},{self.main.args.output},"
                    f"{os.getpid()},"
                    f"{bool(self.main.args.daemon)},{self.main.args.save}\n"
                )
        except PermissionError:
            # last run was by root, change the file ownership to non-root
            os.remove(self.running_logfile)
            open(self.running_logfile, "w").close()
            self.log_redis_server_pid(redis_port, redis_pid)

        if redis_port == 6379:
            # remove the old logline using this port
            self.remove_old_logline(6379)

    def load_redis_db(self, redis_port):
        # to be able to use running_slips_info later as a non-root user,
        # we shouldn't modify it as root

        self.main.input_information = os.path.basename(self.main.args.db)
        redis_pid: int = self.get_pid_of_redis_server(redis_port)
        self.zeek_folder = '""'
        self.log_redis_server_pid(redis_port, redis_pid)
        self.remove_old_logline(redis_port)

        print(
            f"{self.main.args.db} loaded successfully.\n"
            f"Run ./kalipso.sh and choose port {redis_port}"
        )

    def load_db(self):
        self.input_type = "database"
        self.main.db.init_redis_server()

        # this is where the db will be loaded
        redis_port = 32850
        # make sure the db on 32850 is flushed and ready for the new db to be
        # loaded
        if pid := self.get_pid_of_redis_server(redis_port):
            self.flush_redis_server(pid=pid)
            self.kill_redis_server(pid)

        if not self.main.db.load(self.main.args.db):
            print(f"Error loading the database {self.main.args.db}")
        else:
            self.load_redis_db(redis_port)

        self.main.terminate_slips()

    def get_end_port(self):
        return self.end_port

    def check_redis_database(
        self, redis_host="localhost", redis_port=6379
    ) -> bool:
        """
        Check if we have redis-server running (this is the cache db it should
        always be running)
        """
        tries = 0
        while True:
            try:
                # first try connecting to the cache db normally
                r = redis.StrictRedis(
                    host=redis_host,
                    port=redis_port,
                    db=1,
                    charset="utf-8",
                    decode_responses=True,
                )
                r.ping()
                return True
            except Exception as ex:
                # only try to open redis-server twice.
                if tries == 2:
                    print(
                        f"[Main] Problem starting redis cache database."
                        f" \n{ex}\nStopping"
                    )
                    self.main.terminate_slips()
                    return False

                print("[Main] Starting redis cache database..")
                os.system(
                    "redis-server config/redis.conf --daemonize yes "
                    " > /dev/null 2>&1"
                )
                # give the server time to start
                time.sleep(1)
                tries += 1

    def get_random_redis_port(self) -> int:
        """
        Keeps trying to connect to random generated ports until
        we found an available port.
        returns the port number
        """
        for port in range(self.start_port, self.end_port + 1):
            # Create a socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                # Attempt to bind to the port
                sock.bind(("localhost", port))
                # Close the socket if successful
                sock.close()
                return port
            except OSError:
                # Port is already in use, continue to the next port
                sock.close()
                continue

        # there's no usable port in this range
        print(
            f"All ports from {self.start_port} to {self.end_port} are used. "
            "Unable to start slips.\n"
        )

        return False

    def clear_redis_cache_database(
        self, redis_host="localhost", redis_port=6379
    ) -> bool:
        """
        Clear cache database
        """
        rcache = redis.StrictRedis(
            host=redis_host,
            port=redis_port,
            db=1,
            charset="utf-8",
            decode_responses=True,
        )
        rcache.flushdb()
        return True

    def close_all_ports(self):
        """
        Closes all the redis ports in running_slips_info.txt and
         in slips supported range of ports
        """
        if not hasattr(self, "open_servers_PIDs"):
            self.get_open_redis_servers()

        # close all ports in logfile
        for pid in self.open_servers_pids:
            pid: int
            self.flush_redis_server(pid=pid)
            self.kill_redis_server(pid)

        # closes all the ports in slips supported range of ports
        slips_supported_range = list(range(self.start_port, self.end_port + 1))
        slips_supported_range.append(6379)
        for port in slips_supported_range:
            if pid := self.get_pid_of_redis_server(port):
                self.flush_redis_server(pid=pid)
                self.kill_redis_server(pid)

        # print(f"Successfully closed all redis servers on ports
        # {self.start_port} to {self.end_port}")
        print("Successfully closed all open redis servers")

        with contextlib.suppress(FileNotFoundError):
            os.remove(self.running_logfile)
        self.main.terminate_slips()
        return

    def print_port_in_use(self, port: int):
        print(
            f"[Main] Port {port} is already in use by another process"
            f"\nChoose another port using -P <portnumber>"
            f"\nOr kill your open redis ports using: ./slips.py -k "
        )

    def close_slips_if_port_in_use(self, port: int):
        if utils.is_port_in_use(port):
            self.print_port_in_use(port)
            self.main.terminate_slips()

    def get_pid_of_redis_server(self, port: int) -> int:
        """
        Gets the pid of the redis server running on this port
        Returns str(port) or false if there's no redis-server running on this
        port
        """
        cmd = "ps aux | grep redis-server"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        cmd_output, _ = process.communicate()
        for line in cmd_output.splitlines():
            line: bytes
            line: str = line.decode()
            if str(port) in line:
                pid: int = int(line.split()[1])
                return pid

        return False

    @staticmethod
    def is_comment(line: str) -> bool:
        """returns true if the given line is a comment"""
        return (line.startswith("#") or line.startswith("Date")) or len(
            line
        ) < 3

    def get_open_redis_servers(self) -> Dict[int, dict]:
        """
        fills and returns self.open_servers_PIDs
        with PIDs and ports of the redis servers started by slips
        read from running_slips.info.txt
        """
        self.open_servers_pids: Dict[int, dict] = {}
        try:
            with open(self.running_logfile, "r") as f:
                for line in f.read().splitlines():
                    # skip comments
                    if self.is_comment(line):
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

                        self.open_servers_pids[pid] = {
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
                        # sometimes slips can't get the server pid and logs "False"
                        # in the logfile instead of the PID
                        # there's nothing we can do about it
                        pass

            return self.open_servers_pids

        except FileNotFoundError:
            # print(f"Error: {self.running_logfile} is not found.
            # Can't kill open servers. Stopping.")
            return {}

    def print_open_redis_servers(self):
        """
        Returns a dict {counter: (used_port,pid) }
        """
        open_servers = {}
        to_print = (
            "Choose which one to kill [0,1,2 etc..]\n"
            "[0] Close all Redis servers\n"
        )
        there_are_ports_to_print = False
        try:
            with open(self.running_logfile, "r") as f:
                line_number = 0
                for line in f.read().splitlines():
                    # skip comments
                    if (
                        line.startswith("#")
                        or line.startswith("Date")
                        or len(line) < 3
                    ):
                        continue
                    line_number += 1
                    line = line.split(",")
                    file, port, pid = line[1], line[2], line[3]
                    there_are_ports_to_print = True
                    to_print += f"[{line_number}] {file} - port {port}\n"
                    open_servers[line_number] = (int(port), int(pid))
        except FileNotFoundError:
            print(
                f"{self.running_logfile} is not found. Can't get open redis servers. Stopping."
            )
            return False

        if there_are_ports_to_print:
            print(to_print)
        else:
            print(f"No open redis servers in {self.running_logfile}")

        return open_servers

    def get_port_of_redis_server(self, pid: int) -> Union[int, bool]:
        """
        returns the port of the redis running on the given pid
        """
        cmd = "ps aux | grep redis-server"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        cmd_output, _ = process.communicate()
        for line in cmd_output.splitlines():
            line: bytes
            line: str = line.decode()
            if str(pid) in line:
                port: str = line.split(":")[-1]
                try:
                    return int(port)
                except ValueError:
                    return False

        # pid wasn't found using the above cmd
        return False

    def get_redis_port(self) -> int:
        """
        returns teh redis server port to use based on the given args -P,
        -m or the default port
        if all ports are unavailable, this function terminates slips
        """
        if self.main.args.port:
            redis_port = int(self.main.args.port)
            # if the default port is already in use, slips should override it
            if redis_port != 6379:
                # close slips if port is in use
                self.close_slips_if_port_in_use(redis_port)
        elif self.main.args.multiinstance:
            redis_port = self.get_random_redis_port()
            if not redis_port:
                # all ports are unavailable
                inp = input("Press Enter to close all ports.\n")
                if inp == "":
                    self.close_all_ports()
                self.main.terminate_slips()
        else:
            # even if this port is in use, it will be overwritten by slips
            redis_port = 6379
        return redis_port

    def flush_redis_server(self, pid: int = None, port: int = None):
        """
        Flush the redis server on this pid, only 1 param should be
        given, pid or port
        :kwarg pid: can be False if port is given
        :kwarg port: redis server port to flush
        Gets the pid of the port if not given
        """
        if not port and not pid:
            return False

        # sometimes the redis port is given, get it manually
        if pid:
            if not hasattr(self, "open_servers_PIDs"):
                self.get_open_redis_servers()

            pid_info: Dict[str, str] = self.open_servers_pids.get(pid, {})
            port: int = pid_info.get("port", False)
            if not port:
                # try to get the port using a cmd
                port: int = self.get_port_of_redis_server(pid)
                if not port:
                    return False

        # clear the server opened on this port
        try:
            db = DBManager(
                Output(),
                self.main.args.output,
                port,
                start_sqlite=False,
                start_redis_server=False,
            )
            # if the redis server opened by slips is closed manually by the
            # user, not by slips, slips won't be able to connect to it
            # that's why we check for db.rdb
            if db.rdb:
                db.rdb.r.flushall()
                db.rdb.r.flushdb()
                db.rdb.r.script_flush()
                return True
        except (redis.exceptions.ConnectionError, RuntimeError):
            # server already killed!
            return False

    def kill_redis_server(self, pid):
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

    def remove_old_logline(self, redis_port):
        """
        This function should be called after adding a new duplicate line with
         redis_port
        The only line with redis_port should be the last line, so this
        functions removes all the lines above with the given port.
        """
        redis_port = str(redis_port)
        tmpfile = "tmp_running_slips_log.txt"
        with open(self.running_logfile, "r") as logfile:
            with open(tmpfile, "w") as tmp:
                all_lines = logfile.read().splitlines()
                # we want to delete the old log line containing this port
                # but leave the new one (the last one)
                for line in all_lines[:-1]:
                    if redis_port not in line:
                        tmp.write(f"{line}\n")

                # write the last line
                tmp.write(all_lines[-1] + "\n")
        # replace file with original name
        os.replace(tmpfile, self.running_logfile)

    def remove_server_from_log(self, redis_port):
        """Deletes the server running on the given redis_port from
        running_slips_logs."""
        redis_port = str(redis_port)
        tmpfile = "tmp_running_slips_log.txt"

        try:
            with (
                open(self.running_logfile, "r") as logfile,
                open(tmpfile, "w") as tmp,
            ):
                for line in logfile:
                    if redis_port not in line:
                        tmp.write(line)

            # Atomically replace the original file with the temp file
            shutil.move(tmpfile, self.running_logfile)

        except Exception as e:
            # Handle exceptions such as file access errors
            if os.path.exists(tmpfile):
                os.remove(tmpfile)
            raise e

    def close_open_redis_servers(self):
        """
        Function to close unused open redis-servers based on what the user chooses
        """
        if not hasattr(self, "open_servers_PIDs"):
            # fill the dict
            self.get_open_redis_servers()

        with contextlib.suppress(KeyboardInterrupt):
            # open_servers {counter: (port,pid),...}}
            open_servers: dict = self.print_open_redis_servers()
            if not open_servers:
                self.main.terminate_slips()

            try:
                server_to_close: int = int(input())
            except ValueError:
                print("Invalid input.")
                self.main.terminate_slips()

            # close all ports in running_slips_logs.txt and in our supported range
            if server_to_close == 0:
                self.close_all_ports()
                self.main.terminate_slips()
                return

            # close the given server number
            try:
                pid: int = open_servers[server_to_close][1]
                port: int = open_servers[server_to_close][0]

                if self.flush_redis_server(pid=pid) and self.kill_redis_server(
                    pid
                ):
                    print(f"Killed redis server on port {port}.")
                else:
                    # if you dont have permission, dont removei from logs
                    print(
                        f"Redis server running on port {port} "
                        f"is either already killed or you don't have "
                        f"permission to kill it."
                    )

                self.remove_server_from_log(port)
            except (KeyError, ValueError):
                print(f"Invalid input {server_to_close}")

        self.main.terminate_slips()
