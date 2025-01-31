"""
This file tests 2 different config files other than slips' default config/slips.yaml
test/test.yaml and tests/test2.yaml
"""

import shutil
from pathlib import PosixPath

import redis

from tests.common_test_utils import (
    create_output_dir,
    assert_no_errors,
)
from tests.module_factory import ModuleFactory
import pytest
import os
import subprocess
import time
import sys
from unittest.mock import Mock

alerts_file = "alerts.log"

def countdown(seconds, message):
    """
    counts down from the given number of seconds, printing a message each second.
    """
    while seconds > 0:
        sys.stdout.write(
            f"\rSending {message} in {seconds} "
        )  # overwrite the line
        sys.stdout.flush()  # ensures immediate output
        time.sleep(1)  # waits for 1 second
        seconds -= 1
    sys.stdout.write(f"\rSending {message} now!          \n")


def message_send(port, message):
    # connect to redis database 0
    redis_client = redis.StrictRedis(host="localhost", port=port, db=0)

    # publish the message to the "network2fides" channel
    channel = "network2fides"
    redis_client.publish(channel, message)

    print(f"Test message published to channel '{channel}'.")


message_alert_TL_NL = """{
    "type": "tl2nl_alert",
    "version": 1,
    "data": 
    "payload": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
}"""

message_alert_NL_S = """{
    "type": "nl2tl_alert",
    "version": 1,
    "data": 
        "sender": "<Metadata of peer who's alerting>"
        "payload": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
}"""

@pytest.mark.parametrize(
    "path, output_dir, redis_port",
    [
        (
            "dataset/test13-malicious-dhcpscan-zeek-dir",
            "fides_integration_test/",
            6644,
        )
    ],
)
def test_messaging_1(path, output_dir, redis_port):
    """
    Tests whether Iris properly distributes an alert message from Fides to the network (~other peers)
    """
    output_dir: PosixPath = create_output_dir(output_dir)
    output_file = os.path.join(output_dir, "slips_output.txt")
    command = [
        "./slips.py",
        "-t",
        "-g",
        "-e",
        "1",
        "-f",
        str(path),
        "-o",
        str(output_dir),
        "-c",
        "tests/integration_tests/fides_config.yaml",
        "-P",
        str(redis_port),
    ]

    print("running slips ...")
    print(output_dir)

    # Open the log file in write mode
    with open(output_file, "w") as log_file:
        # Start the subprocess, redirecting stdout and stderr to the same file
        process = subprocess.Popen(
            command,  # Replace with your command
            stdout=log_file,
            stderr=log_file,
        )

        print(f"Output and errors are logged in {output_file}")
        countdown(30, "sigterm")
        # send a SIGTERM to the process
        os.kill(process.pid, 15)
        print("SIGTERM sent. killing slips")
        os.kill(process.pid, 9)

    print(f"Slips with PID {process.pid} was killed.")

    print("Slip is done, checking for errors in the output dir.")
    assert_no_errors(output_dir)
    print("Checking database")
    db = ModuleFactory().create_db_manager_obj(
        redis_port, output_dir=output_dir, start_redis_server=False
    )
    # t.o.d.o. send() is not implemented
    # iris is supposed to be receiving this msg, that last thing fides does
    # is send a msg to this channel for iris to receive it
    assert db.get_msgs_received_at_runtime("Fides")["fides2network"] == "1"

    print("Deleting the output directory")
    shutil.rmtree(output_dir)
