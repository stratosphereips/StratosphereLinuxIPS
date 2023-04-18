import contextlib
from slips_files.core.database.database import __database__
from slips_files.common.slips_utils import utils
from datetime import datetime
import redis
import os
import time
import uuid

class RedisManager:
    def __init__(self, terminate_slips=None):
        # slips picks a redis port from the following range
        self.start_port = 32768
        self.end_port = 32850
        self.terminate_slips = terminate_slips
        self.running_logfile = 'running_slips_info.txt'

    def get_start_port(self):
        return self.start_port

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
                # only try to open redi-server once.
                if tries == 2:
                    print(f'[Main] Problem starting redis cache database. \n{ex}\nStopping')
                    if self.terminate_slips:
                        self.terminate_slips()
                    return False

                print('[Main] Starting redis cache database..')
                os.system('redis-server redis.conf --daemonize yes  > /dev/null 2>&1')
                # give the server time to start
                time.sleep(1)
                tries += 1


    def get_random_redis_port(self):
        """
        Keeps trying to connect to random generated ports until we're connected.
        returns the used port
        """
        # generate a random unused port
        for port in range(self.start_port, self.end_port+1):
            # check if 1. we can connect
            # 2.server is not being used by another instance of slips
            # note: using r.keys() blocks the server
            try:
                if __database__.connect_to_redis_server(port):
                    server_used = len(list(__database__.r.keys())) < 2
                    if server_used:
                        # if the db managed to connect to this random port, then this is
                        # the port we'll be using
                        return port
            except redis.exceptions.ConnectionError:
                # Connection refused to this port
                continue
        # there's no usable port in this range
        print(f"All ports from {self.start_port} to {self.end_port} are used. "
               "Unable to start slips.\n")
        return False
    
    def get_random_prefix(self) -> str:
        return str(uuid.uuid4())
    
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
    
    def close_all_instance(self):
        """
        Closes all the redis ports  in logfile and in slips supported range of ports
        """
        if not hasattr(self, 'open_servers_IDs'):
            self.get_open_redis_servers_ID()

        unique_ports = set()
        # close all ports in logfile
        for _id in self.open_servers_IDs:
            # self.flush_redis_id(_id=_id, port = self.open_servers_IDs[_id])
            unique_ports.add(self.open_servers_IDs[_id])

        # Kill default port
        
        for port in unique_ports:
            # Skip cache db which is in port 6379
            r = redis.StrictRedis(
                host='localhost',
                port=self.open_servers_IDs[_id],
                db=0,
                charset='utf-8',
                socket_keepalive=True,
                decode_responses=True,
                retry_on_timeout=True,
                health_check_interval=20,
                )
            r.flushdb()
            
            if str(port) == '6379':
                continue
            
            pid = self.get_pid_of_redis_server(port = port)
            self.kill_redis_server(pid)



        # closes all the ports in slips supported range of ports
        # slips_supported_range = list(range(self.start_port, self.end_port + 1))
        # slips_supported_range.append(6379)

        # for port in slips_supported_range:
        #     if _id := self.get_pid_of_redis_server(port):
        #         self.flush_redis_server(_id=id)
        #         self.kill_redis_server(pid)



        # print(f"Successfully closed all redis servers on ports {self.start_port} to {self.end_port}")
        print("Successfully closed all open redis servers")

        with contextlib.suppress(FileNotFoundError):
            os.remove(self.running_logfile)
        if self.terminate_slips:
            self.terminate_slips()
        return

    def get_pid_of_redis_server(self, port: int) -> str:
        """
        Gets the pid of the redis server running on this port
        Returns str(port) or false if there's no redis-server running on this port
        """
        cmd = 'ps aux | grep redis-server'
        cmd_output = os.popen(cmd).read()
        for line in cmd_output.splitlines():
            if str(port) in line:
                pid = line.split()[1]
                return pid
        return False

    def get_open_redis_servers_ID(self) -> dict:
        """
        Returns the dict of PIDs and ports of the redis servers started by slips
        """
        self.open_servers_IDs = {}
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
                    _id, port = line[3], line[2]
                    self.open_servers_IDs[_id] = port
            return self.open_servers_IDs
        except FileNotFoundError:
            # print(f"Error: {self.running_logfile} is not found. Can't kill open servers. Stopping.")
            return {}

    def print_open_redis_id(self):
        """
        Returns a dict {counter: (used_port,pid) }
        """
        open_ids = {}
        to_print = f"Choose which one to kill [0,1,2 etc..]\n" \
                   f"[0] Close all Redis ids\n"
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
                    file, port, _id = line[1], line[2], line[3]
                    there_are_ports_to_print = True
                    to_print += f"[{line_number}] {file} - port {port} - id {_id}\n"
                    open_ids[line_number] = (port, _id)
        except FileNotFoundError:
            print(f"{self.running_logfile} is not found. Can't get open redis id. Stopping.")
            return False

        if there_are_ports_to_print:
            print(to_print)
        else:
            print(f"No open redis id in {self.running_logfile}")

        return open_ids


    def get_port_of_redis_server(self, pid: str):
        """
        returns the port of the redis running on this pid
        """
        cmd = 'ps aux | grep redis-server'
        cmd_output = os.popen(cmd).read()
        for line in cmd_output.splitlines():
            if str(pid) in line:
                port = line.split(':')[-1]
                return port
        return False


    def flush_redis_id(self, _id: str='', port: str=''):
        """
        Flush the redis server on this pid, only 1 param should be given, pid or port
        :param pid: can be False if port is given
        Gets the pid of the port is not given
        """
        if not port and not _id:
            return False

        # sometimes the redis port is given, no need to get it manually
        if not port and _id:
            if not hasattr(self, 'open_servers_IDs'):
                self.get_open_redis_servers_ID()
            port = self.open_servers_IDs.get(str(_id), False)
            if not port:
                # use default port
                port = '6379'

        port = str(port)

        # clear the server opened on this port
        try:
            # if connected := __database__.connect_to_redis_server(port):
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
            
            # r.flushall()
            # r.flushdb()
            # r.script_flush()

            # Delete keys with the prefix id
            for key in r.scan_iter(_id + "*"):
                r.delete(key)
            
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


    def remove_server_from_log(self, _id):
        """ deletes the server running on the given pid from running_slips_logs """
        _id = str(_id)
        tmpfile = 'tmp_running_slips_log.txt'
        with open(self.running_logfile, 'r') as logfile:
            with open(tmpfile, 'w') as tmp:
                all_lines = logfile.read().splitlines()
                # delete the line using that port
                for line in all_lines:
                    if _id not in line:
                        tmp.write(f'{line}\n')

        # replace file with original name
        os.replace(tmpfile, self.running_logfile)

    def close_open_redis_id(self):
        """
        Function to close unused open redis-servers based on what the user chooses
        """
        if not hasattr(self, 'open_servers_IDs'):
            # fill the dict
            self.get_open_redis_servers_ID()

        with contextlib.suppress(KeyboardInterrupt):
            # open_servers {counter: (port,pid),...}}
            open_ids:dict = self.print_open_redis_id()
            if not open_ids and self.terminate_slips:
                self.terminate_slips()

            id_to_close = input()
            # close all ports in running_slips_logs.txt and in our supported range
            if id_to_close == '0':
                self.close_all_instance()

            elif len(open_ids) > 0:
                # close the given server number
                try:
                    _id = open_ids[int(id_to_close)][1]
                    port = open_ids[int(id_to_close)][0]
                    if self.flush_redis_id(_id=_id, port = port):
                        print(f"Deleted process of id {_id} on port {port}.")
                    else:
                        print(f"Redis server running on port {port} with id {_id}"
                              f"is either already deleted or you don't have "
                              f"enough permission to delete it.")
                    self.remove_server_from_log(_id)
                except (KeyError, ValueError):
                    print(f"Invalid input {server_to_close}")

        if self.terminate_slips:
            self.terminate_slips()