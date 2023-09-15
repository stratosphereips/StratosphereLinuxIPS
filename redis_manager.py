from slips_files.core.database.database_manager import DBManager
from slips_files.common.slips_utils import utils
import contextlib
from datetime import datetime
import redis
import os
import time
import socket
import subprocess

class RedisManager:
    def __init__(self, main):
        self.main = main
        # slips picks a redis port from the following range
        self.start_port = 32768
        self.end_port = 32850
        self.running_logfile = 'running_slips_info.txt'

    def get_start_port(self):
        return self.start_port

    def log_redis_server_PID(self, redis_port, redis_pid):
        now = utils.convert_format(datetime.now(), utils.alerts_format)
        try:
            # used in case we need to remove the line using 6379 from running logfile
            with open(self.running_logfile, 'a') as f:
                # add the header lines if the file is newly created
                if f.tell() == 0:
                    f.write(
                        '# This file contains a list of used redis ports.\n'
                        '# Once a server is killed, it will be removed from this file.\n'
                        'Date, File or interface, Used port, Server PID,'
                        ' Output Zeek Dir, Logs Dir, Slips PID, Is Daemon, Save the DB\n'
                    )

                f.write(
                    f'{now},{self.main.input_information},{redis_port},'
                    f'{redis_pid},{self.main.zeek_dir},{self.main.args.output},'
                    f'{os.getpid()},'
                    f'{bool(self.main.args.daemon)},{self.main.args.save}\n'
                )
        except PermissionError:
            # last run was by root, change the file ownership to non-root
            os.remove(self.running_logfile)
            open(self.running_logfile, 'w').close()
            self.log_redis_server_PID(redis_port, redis_pid)

        if redis_port == 6379:
            # remove the old logline using this port
            self.remove_old_logline(6379)

    def load_redis_db(self, redis_port):
        # to be able to use running_slips_info later as a non-root user,
        # we shouldn't modify it as root

        self.main.input_information = os.path.basename(self.main.args.db)
        redis_pid = self.get_pid_of_redis_server(redis_port)
        self.zeek_folder = '""'
        self.log_redis_server_PID(redis_port, redis_pid)
        self.remove_old_logline(redis_port)

        print(
            f'{self.main.args.db} loaded successfully.\n'
            f'Run ./kalipso.sh and choose port {redis_port}'
        )

    def load_db(self):
        self.input_type = 'database'
        # self.input_information = 'database'
        self.main.db.start(6379)

        # this is where the db will be loaded
        redis_port = 32850
        # make sure the db on 32850 is flushed and ready for the new db to be loaded
        if pid := self.get_pid_of_redis_server(redis_port):
            self.flush_redis_server(pid=pid)
            self.kill_redis_server(pid)

        if not self.main.db.load(self.main.args.db):
            print(f'Error loading the database {self.main.args.db}')
        else:
            self.load_redis_db(redis_port)
            # self.main.db.disable_redis_persistence()

        self.main.terminate_slips()


    def get_end_port(self):
        return self.end_port
    
    def check_redis_database(
        self, redis_host='localhost', redis_port=6379
    ) -> bool:
        """
        Check if we have redis-server running (this is the cache db it should always be running)
        """
        tries = 0
        while True:
            try:
                # first try connecting to the cache db normally
                r = redis.StrictRedis(
                    host=redis_host,
                    port=redis_port,
                    db=1,
                    charset='utf-8',
                    decode_responses=True,
                )
                r.ping()
                return True
            except Exception as ex:
                # only try to open redis-server twice.
                if tries == 2:
                    print(f'[Main] Problem starting redis cache database. \n{ex}\nStopping')
                    self.main.terminate_slips()
                    return False

                print('[Main] Starting redis cache database..')
                os.system('redis-server config/redis.conf --daemonize yes  > /dev/null 2>&1')
                # give the server time to start
                time.sleep(1)
                tries += 1


    def get_random_redis_port(self) -> int:
        """
        Keeps trying to connect to random generated ports until we found an available port.
        returns the port number
        """
        for port in range(self.start_port, self.end_port+1):
            # Create a socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                # Attempt to bind to the port
                sock.bind(('localhost', port))
                # Close the socket if successful
                sock.close()
                return port
            except OSError:
                # Port is already in use, continue to the next port
                sock.close()
                continue

        # there's no usable port in this range
        print(f"All ports from {self.start_port} to {self.end_port} are used. "
               "Unable to start slips.\n")

        return False
    
    def clear_redis_cache_database(
        self, redis_host='localhost', redis_port=6379
    ) -> bool:
        """
        Clear cache database
        """
        rcache = redis.StrictRedis(
            host=redis_host,
            port=redis_port,
            db=1,
            charset='utf-8',
            decode_responses=True,
        )
        rcache.flushdb()
        return True
    
    def close_all_ports(self):
        """
        Closes all the redis ports  in logfile and in slips supported range of ports
        """
        if not hasattr(self, 'open_servers_PIDs'):
            self.get_open_redis_servers()

        # close all ports in logfile
        for pid in self.open_servers_PIDs:
            self.flush_redis_server(pid=pid)
            self.kill_redis_server(pid)


        # closes all the ports in slips supported range of ports
        slips_supported_range = list(range(self.start_port, self.end_port + 1))
        slips_supported_range.append(6379)
        for port in slips_supported_range:
            if pid := self.get_pid_of_redis_server(port):
                self.flush_redis_server(pid=pid)
                self.kill_redis_server(pid)


        # print(f"Successfully closed all redis servers on ports {self.start_port} to {self.end_port}")
        print("Successfully closed all open redis servers")

        with contextlib.suppress(FileNotFoundError):
            os.remove(self.running_logfile)
        self.main.terminate_slips()
        return

    def get_pid_of_redis_server(self, port: int) -> str:
        """
        Gets the pid of the redis server running on this port
        Returns str(port) or false if there's no redis-server running on this port
        """
        cmd = 'ps aux | grep redis-server'
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        cmd_output, _ = process.communicate()
        for line in cmd_output.splitlines():
            if str(port).encode() in line:
                pid = line.split()[1]
                return pid
        return False

    def get_open_redis_servers(self) -> dict:
        """
        Returns the dict of PIDs and ports of the redis servers started by slips
        """
        self.open_servers_PIDs = {}
        try:
            with open(self.running_logfile, 'r') as f:
                for line in f.read().splitlines():
                    # skip comments
                    if (
                        line.startswith('#')
                        or line.startswith('Date')
                        or len(line) < 3
                    ):
                        continue
                    line = line.split(',')
                    pid, port = line[3], line[2]
                    self.open_servers_PIDs[pid] = port
            return self.open_servers_PIDs
        except FileNotFoundError:
            # print(f"Error: {self.running_logfile} is not found. Can't kill open servers. Stopping.")
            return {}

    def print_open_redis_servers(self):
        """
        Returns a dict {counter: (used_port,pid) }
        """
        open_servers = {}
        to_print = f"Choose which one to kill [0,1,2 etc..]\n" \
                   f"[0] Close all Redis servers\n"
        there_are_ports_to_print = False
        try:
            with open(self.running_logfile, 'r') as f:
                line_number = 0
                for line in f.read().splitlines():
                    # skip comments
                    if (
                        line.startswith('#')
                        or line.startswith('Date')
                        or len(line) < 3
                    ):
                        continue
                    line_number += 1
                    line = line.split(',')
                    file, port, pid = line[1], line[2], line[3]
                    there_are_ports_to_print = True
                    to_print += f"[{line_number}] {file} - port {port}\n"
                    open_servers[line_number] = (port, pid)
        except FileNotFoundError:
            print(f"{self.running_logfile} is not found. Can't get open redis servers. Stopping.")
            return False

        if there_are_ports_to_print:
            print(to_print)
        else:
            print(f"No open redis servers in {self.running_logfile}")

        return open_servers


    def get_port_of_redis_server(self, pid: str):
        """
        returns the port of the redis running on this pid
        """
        cmd = 'ps aux | grep redis-server'
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        cmd_output, _ = process.communicate()
        for line in cmd_output.splitlines():
            if str(pid).encode() in line:
                port = line.split(':')[-1]
                return port
        return False


    def flush_redis_server(self, pid: str='', port: str=''):
        """
        Flush the redis server on this pid, only 1 param should be given, pid or port
        :param pid: can be False if port is given
        Gets the pid of the port is not given
        """
        if not port and not pid:
            return False

        # sometimes the redis port is given, no need to get it manually
        if not port and pid:
            if not hasattr(self, 'open_servers_PIDs'):
                self.get_open_redis_servers()
            port = self.open_servers_PIDs.get(str(pid), False)
            if not port:
                # try to get the port using a cmd
                port = self.get_port_of_redis_server(pid)
        port = str(port)

        # clear the server opened on this port
        try:
            # if connected := self.main.db.connect_to_redis_server(port):
            # noinspection PyTypeChecker
            #todo move this to the db
            r = redis.StrictRedis(
                    host='localhost',
                    port=port,
                    db=0,
                    charset='utf-8',
                    socket_keepalive=True,
                    decode_responses=True,
                    retry_on_timeout=True,
                    health_check_interval=20,
                    )
            r.flushall()
            r.flushdb()
            r.script_flush()
            return True
        except redis.exceptions.ConnectionError:
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
        This function should be called after adding a new duplicate line with redis_port
        The only line with redis_port will be the last line, remove all the ones above
        """
        redis_port = str(redis_port)
        tmpfile = 'tmp_running_slips_log.txt'
        with open(self.running_logfile, 'r') as logfile:
            with open(tmpfile, 'w') as tmp:
                all_lines = logfile.read().splitlines()
                # we want to delete the old log line containing this port
                # but leave the new one (the last one)
                for line in all_lines[:-1]:
                    if redis_port not in line:
                        tmp.write(f'{line}\n')

                # write the last line
                tmp.write(all_lines[-1]+'\n')
        # replace file with original name
        os.replace(tmpfile, self.running_logfile)


    def remove_server_from_log(self, redis_port):
        """ deletes the server running on the given pid from running_slips_logs """
        redis_port = str(redis_port)
        tmpfile = 'tmp_running_slips_log.txt'
        with open(self.running_logfile, 'r') as logfile:
            with open(tmpfile, 'w') as tmp:
                all_lines = logfile.read().splitlines()
                # delete the line using that port
                for line in all_lines:
                    if redis_port not in line:
                        tmp.write(f'{line}\n')

        # replace file with original name
        os.replace(tmpfile, self.running_logfile)

    def close_open_redis_servers(self):
        """
        Function to close unused open redis-servers based on what the user chooses
        """
        if not hasattr(self, 'open_servers_PIDs'):
            # fill the dict
            self.get_open_redis_servers()

        with contextlib.suppress(KeyboardInterrupt):
            # open_servers {counter: (port,pid),...}}
            open_servers:dict = self.print_open_redis_servers()
            if not open_servers:
                self.main.terminate_slips()

            server_to_close = input()
            # close all ports in running_slips_logs.txt and in our supported range
            if server_to_close == '0':
                self.close_all_ports()

            elif len(open_servers) > 0:
                # close the given server number
                try:
                    pid = open_servers[int(server_to_close)][1]
                    port = open_servers[int(server_to_close)][0]
                    if self.flush_redis_server(pid=pid) and self.kill_redis_server(pid):
                        print(f"Killed redis server on port {port}.")
                    else:
                        print(f"Redis server running on port {port} "
                              f"is either already killed or you don't have "
                              f"enough permission to kill it.")
                    self.remove_server_from_log(port)
                except (KeyError, ValueError):
                    print(f"Invalid input {server_to_close}")

        self.main.terminate_slips()