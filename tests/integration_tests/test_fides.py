"""
This file tests 2 different config files other than slips' default config/slips.yaml
test/test.yaml and tests/test2.yaml
"""

import shutil
from pathlib import PosixPath

from modules.fidesModule.model.peer import PeerInfo
from modules.fidesModule.persistence.sqlite_db import SQLiteDB
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
from modules.fidesModule.persistence.trust_db import SlipsTrustDatabase
from unittest.mock import Mock
import modules.fidesModule.model.peer_trust_data as ptd
import unittest

alerts_file = "alerts.log"


def countdown_sigterm(seconds):
    """
    counts down from the given number of seconds, printing a message each second.
    """
    while seconds > 0:
        sys.stdout.write(
            f"\rSending sigterm in {seconds} "
        )  # overwrite the line
        sys.stdout.flush()  # ensures immediate output
        time.sleep(1)  # waits for 1 second
        seconds -= 1
    sys.stdout.write("\rSending sigterm now!          \n")

def message_send():
    import redis

    # connect to redis database 0
    redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)

    message = '''
        {
            "type": "nl2tl_intelligence_response",
            "version": 1,
            "data": [
                {
                    "sender": {
                        "id": "peer1",
                        "organisations": ["org1", "org2"],
                        "ip": "192.168.1.1"
                    },
                    "payload": {
                        "intelligence": {
                            "target": {"type": "server", "value": "192.168.1.10"},
                            "confidentiality": {"level": 0.8},
                            "score": 0.5,
                            "confidence": 0.95
                        },
                        "target": "stratosphere.org"
                    }
                },
                {
                    "sender": {
                        "id": "peer2",
                        "organisations": ["org2"],
                        "ip": "192.168.1.2"
                    },
                    "payload": {
                        "intelligence": {
                            "target": {"type": "workstation", "value": "192.168.1.20"},
                            "confidentiality": {"level": 0.7},
                            "score": -0.85,
                            "confidence": 0.92
                        },
                        "target": "stratosphere.org"
                    }
                }
            ]
        }
        '''

    # publish the message to the "network2fides" channel
    channel = "network2fides"
    redis_client.publish(channel, message)

    print(f"Test message published to channel '{channel}'.")

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
def test_conf_file2(path, output_dir, redis_port):
    """
    In this test we're using tests/test2.conf
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
        countdown_sigterm(30)
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
def test_trust_recommendation_response(path, output_dir, redis_port):
    """
    In this test we're using tests/test2.conf
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
        print(f"Manipulating database")
        mock_logger = Mock()
        mock_logger.print_line = Mock()
        mock_logger.error = Mock()

        db = SQLiteDB(mock_logger, "fides_test_db.sqlite")
        db.store_peer_trust_data(ptd.trust_data_prototype(peer=PeerInfo(
                                                                id="peer1",
                                                                organisations=["org1", "org2"],
                                                                ip="192.168.1.1"),
                                                            has_fixed_trust=False)
        )
        db.store_peer_trust_data(ptd.trust_data_prototype(peer=PeerInfo(
            id="peer2",
            organisations=["org2"],
            ip="192.168.1.2"),
            has_fixed_trust=True)
        )
        print(f"Sending test message")
        message_send()

        countdown_sigterm(30)
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
    assert db.get_msgs_received_at_runtime("Fides")["fides2network"] == "1"

    print("Checking Fides' database")
    # TODO check updated database using assert

    print("Deleting the output directory")
    shutil.rmtree(output_dir)
