"""
Close all redis-servers opened by the unit tests
"""
import os
import subprocess
import re
import pty

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
        if f":{redis_port}" in line:
            line = re.split(r'\s{2,}', line)
            # get the substring that has the pid
            try:
                redis_pid = line[-1]
                _ = redis_pid.index('/')
            except ValueError:
                redis_pid = line[-2]
            redis_pid = redis_pid.split('/')[0]
            print(f"found {redis_pid} for redis_port: {redis_port}")
            break
    else:
        print(f"Redis port: {redis_port} isn't open")
        continue

    # signal 0 is to check if the process is still running or not
    # it returns 1 if the process exitted
    try:
        # check if the process is still running
        while os.kill(int(redis_pid), 0) != 1:
            # sigterm is 9
            os.kill(int(redis_pid), 9)
        closed_servers += 1
    except ProcessLookupError:
        # process already exited, sometimes this exception is raised
        # but the process is still running, keep trying to kill it
        continue
print(f"Closed {closed_servers} open servers")