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


def message_send(port, channel, message):
    # connect to redis database 0
    redis_client = redis.StrictRedis(host="localhost", port=port, db=0)

    # publish the message to the "network2fides" channel
    redis_client.publish(channel, message)

    print(f"Test message published to channel '{channel}'.")


message_alert_TL_NL = """{
    "type": "tl2nl_alert",
    "version": 1,
    "data": {
      "payload": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
    }
}"""


message_alert_NL_S = """{
    "type": "nl2tl_alert",
    "version": 1,
    "data": 
        "sender": "<Metadata of peer who's alerting>"
        "payload": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
}"""

@pytest.mark.parametrize(
    "path, output_dir, peer_output_dir, redis_port, peer_redis_port",
    [
        (
            "dataset/test13-malicious-dhcpscan-zeek-dir",
            "iris_integration_test/",
            "iris_integration_test_peer",
            6644,
            6655,
        )
    ],
)
def test_messaging_1(path, output_dir, peer_output_dir, redis_port, peer_redis_port):
    """
    Tests whether Iris properly distributes an alert message from Fides to the network (~other peers)
    """
    output_dir: PosixPath = create_output_dir(output_dir)
    output_file = os.path.join(output_dir, "slips_output.txt")
    iris_output_file = os.path.join(output_dir, "slips_iris-peer_output.txt")

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

    peer_command = [
        "./slips.py",
        "-t",
        "-g",
        "-e",
        "1",
        "-f",
        str(path),
        "-o",
        str(peer_output_dir),
        "-c",
        "tests/integration_tests/iris_config.yaml",
        "-P",
        str(peer_redis_port),
    ]

    print("running slips ...")
    print(output_dir)

    # Open the log file in write mode
    with open(output_file, "w") as log_file:
        with open(iris_output_file, "w") as iris_log_file:
            # Start the subprocess, redirecting stdout and stderr to the same file
            process = subprocess.Popen(
                command,  # Replace with your command
                stdout=log_file,
                stderr=log_file,
            )

            Pprocess = subprocess.Popen(peer_command, stdout=iris_log_file, stderr=iris_log_file)

            print(f"Output and errors are logged in {output_file}")
            countdown(60, "sigterm")
            message_send(redis_port, message=message_alert_TL_NL, channel="fides2network",)
            # these seconds are the time we give slips to process the msg
            countdown(30, "sigterm")
            # send a SIGTERM to the process
            os.kill(process.pid, 15)
            os.kill(Pprocess.pid, 15)
            print("SIGTERM sent. killing slips + iris")
            os.kill(process.pid, 9)
            os.kill(Pprocess.pid, 9)

    print(f"Slips with PID {process.pid} was killed.")
    print(f"Slips peer with PID {Pprocess.pid} was killed.")

    print("Slip is done, checking for errors in the output dir.")
    assert_no_errors(output_dir)
    assert_no_errors(peer_output_dir)
    print("Checking")

    print("Deleting the output directory")
    # shutil.rmtree(output_dir)
    # shutil.rmtree(peer_output_dir)
