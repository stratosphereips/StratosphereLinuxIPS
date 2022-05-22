"""
Close all redis-servers opened by the unit tests
"""
import os
import subprocess
import re
import pty
import redis


def connect_to_redis_server(port: str):
    """Connects to the given port and Sets r and rcache"""
    try:
        # start the redis server
        os.system(
            f'redis-server --port {port} --daemonize yes > /dev/null 2>&1'
        )

        # db 0 changes everytime we run slips
        # set health_check_interval to avoid redis ConnectionReset errors:
        # if the connection is idle for more than 30 seconds,
        # a round trip PING/PONG will be attempted before next redis cmd.
        # If the PING/PONG fails, the connection will reestablished

        # retry_on_timeout=True after the command times out, it will be retried once,
        # if the retry is successful, it will return normally; if it fails, an exception will be thrown

        r = redis.StrictRedis(
            host='localhost',
            port=port,
            db=0,
            charset='utf-8',
            socket_keepalive=True,
            retry_on_timeout=True,
            decode_responses=True,
            health_check_interval=20,
        )  # password='password')
        return r
    except redis.exceptions.ConnectionError:
        # unable to connect to this port, try another one
        return False


redis_server_ports = [65531, 6380, 6381, 1234]
closed_servers = 0
for redis_port in redis_server_ports:
    # On modern systems, the netstat utility comes pre-installed,
    # this can be done using psutil but it needs root on macos
    command = f'netstat -peanut'
    result = subprocess.run(command.split(), capture_output=True)
    # Get command output
    output = result.stdout.decode('utf-8')

    # A pty is a pseudo-terminal - it's a software implementation that appears to
    # the attached program like a terminal, but instead of communicating
    # directly with a "real" terminal, it transfers the input and output to another program.
    # master, slave = pty.openpty()
    # connect the slave to the pty, and transfer from slave to master
    # subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=slave, stderr=slave, close_fds=True)
    # connect the master to slips
    # cmd_output = os.fdopen(master)
    for line in output.splitlines():
        if f':{redis_port}' in line and 'redis-server' in line:
            line = re.split(r'\s{2,}', line)
            # get the substring that has the pid
            try:
                redis_pid = line[-1]
                _ = redis_pid.index('/')
            except ValueError:
                redis_pid = line[-2]
            redis_pid = redis_pid.split('/')[0]
            print(f'redis_port: {redis_port} is found using PID {redis_pid} ')
            try:
                # clear the server before killing
                db = connect_to_redis_server(redis_port)
                if db:
                    db.flushall()
                    db.flushdb()
                    db.script_flush()

                print(f'Flushed redis-server opened on port: {redis_port}')

                # signal 0 is to check if the process is still running or not
                # it returns 1 if the process exited
                try:
                    # check if the process is still running
                    while os.kill(int(redis_pid), 0) != 1:
                        # sigterm is 9
                        os.kill(int(redis_pid), 9)
                    closed_servers += 1
                except (ProcessLookupError, PermissionError):
                    # process already exited, sometimes this exception is raised
                    # but the process is still running, keep trying to kill it
                    # PermissionError happens when the user tries to close redis-servers
                    # opened by root while he's not root,
                    # or when he tries to close redis-servers
                    # opened without root while he's root
                    continue
                print(
                    f'Killed redis-server on port {redis_port} PID: {redis_pid}'
                )
            except redis.exceptions.ConnectionError:
                continue


print(f'Closed {closed_servers} unused redis-servers')
