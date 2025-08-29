"""
This file tests 2 different config files other than slips' default config/slips.yaml
test/test.yaml and tests/test2.yaml
"""

import shutil
from pathlib import PosixPath

import redis

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
from unittest.mock import Mock
import modules.fidesModule.model.peer_trust_data as ptd

# TODO
# from tests.common_test_utils import (
#     modify_yaml_config,
# )


alerts_file = "alerts.log"


def delete_file_if_exists(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"File '{file_path}' has been deleted.")
    else:
        print(f"File '{file_path}' does not exist.")


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


def message_send(port):
    # connect to redis database 0
    # channel = "fides2network"
    channel = "network2fides"
    message = """
    {
        "type": "nl2tl_intelligence_response",
        "version": 1,
        "data": [
            {
                "sender": {
                    "id": "peer1",
                    "organisations": ["org_123", "org_456"],
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
                    "organisations": ["org_789"],
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
    """
    redis_client = redis.StrictRedis(host="localhost", port=port, db=0)
    # publish the message to the "network2fides" channel
    redis_client.publish(channel, message)

    print(f"Test message published to channel '{channel}'.")


def message_receive(port):
    import redis
    import json

    # connect to redis database 0
    redis_client = redis.StrictRedis(host="localhost", port=port, db=0)

    # define a callback function to handle received messages
    def message_handler(message):
        if message["type"] == "message":  # ensure it's a message type
            data = message["data"].decode("utf-8")  # decode byte data
            print("Received message:")
            print(
                json.dumps(json.loads(data), indent=4)
            )  # pretty-print JSON message

    # subscribe to the "fides2slips" channel
    pubsub = redis_client.pubsub()
    pubsub.subscribe("fides2network")

    print("Listening on the 'fides2network' channel. Waiting for messages...")

    # process one message
    for message in pubsub.listen():
        message_handler(message)
        break  # exit after processing one message


@pytest.mark.parametrize(
    "path, output_dir, redis_port",
    [
        (
            "dataset/test13-malicious-dhcpscan-zeek-dir",
            "fides_test_conf_file2/",
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
        countdown(40, "sigterm")
        # send a SIGTERM to the process
        os.kill(process.pid, 15)
        print("SIGTERM sent. killing slips")
        os.kill(process.pid, 9)

    message_receive(redis_port)

    print(f"Slips with PID {process.pid} was killed.")

    print("Slip is done, checking for errors in the output dir.")
    assert_no_errors(output_dir)
    print("Checking database")
    db = ModuleFactory().create_db_manager_obj(
        redis_port, output_dir=output_dir, start_redis_server=False
    )
    # iris is supposed to be receiving this msg, that last thing fides does
    # is send a msg to this channel for iris to receive it
    assert db.get_msgs_received_at_runtime("Fides")["fides2network"] == "1"
    assert db.get_msgs_received_at_runtime("Fides")["new_alert"] == "1"
    print(db.get_msgs_received_at_runtime("Fides"))

    print("Deleting the output directory")
    shutil.rmtree(output_dir, ignore_errors=True)


@pytest.mark.parametrize(
    "path, output_dir, redis_port",
    [
        (
            "dataset/test15-malicious-zeek-dir",
            "fides_test_trust_recommendation_response/",
            6645,
        )
    ],
)
def test_trust_recommendation_response(path, output_dir, redis_port):
    """
    This test simulates a common situation in the global P2P system, where
     Fides Module wanted to evaluate trust in an unknown peer and asked for
      the opinion of other peers.
    The known peers responded and Fides Module is processing the response.
    Scenario:
        - Fides did not know a peer whose ID is 'stratosphere.org' and have
        asked for opinion of known peers: peer1 and peer2
        - The peers are responding in a message; see message in message_send()
        - The message is processed + THE TEST ITSELF

    Preparation:
        - Have a response to send to a correct channel (it would have been
         done by Iris, here it is simulated)
        - Inject peer1 and peer2 into the database - Fides Module must know
        those peers, NOTE that Fides Module only asks for opinion from known
         peers
        - Run Slips (includes Fides Module) in a thread and wait for all
         modules to start

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
    config_file_path = "modules/fidesModule/config/fides.conf.yml"
    config_temp_path = "modules/fidesModule/config/fides.conf.yml.bak"
    config_line = "database: 'fides_test_database.sqlite'\n"
    shutil.copy(config_file_path, config_temp_path)
    test_db = "fides_test_database.sqlite"

    try:
        # Append the new line to the config
        with open(config_file_path, "a") as file:
            file.write(config_line)

        print("running slips ...")
        print(output_dir)

        mock_logger = Mock()
        mock_logger.print_line = Mock()
        mock_logger.error = Mock()
        print("Manipulating database")
        fdb = SQLiteDB(mock_logger, test_db)
        fdb.store_peer_trust_data(
            ptd.trust_data_prototype(
                peer=PeerInfo(
                    id="peer1",
                    organisations=["org1", "org2"],
                    ip="192.168.1.1",
                ),
                has_fixed_trust=False,
            )
        )
        fdb.store_peer_trust_data(
            ptd.trust_data_prototype(
                peer=PeerInfo(
                    id="peer2", organisations=["org2"], ip="192.168.1.2"
                ),
                has_fixed_trust=True,
            )
        )

        # Open the log file in write mode
        with open(output_file, "w") as log_file:
            # Start the subprocess, redirecting stdout and stderr to the same file
            process = subprocess.Popen(
                command,  # Replace with your command
                stdout=log_file,
                stderr=log_file,
            )

            print(f"Output and errors are logged in {output_file}")
            # these 12s are the time we wait for slips to start all the modules
            countdown(60, "test message")
            message_send(redis_port)
            # these 18s are the time we give slips to process the msg
            countdown(30, "sigterm")
            # send a SIGTERM to the process
            os.kill(process.pid, 15)
            print("SIGTERM sent. killing slips")
            os.kill(process.pid, 15)

        print(f"Slips with PID {process.pid} was killed.")

        print("Slip is done, checking for errors in the output dir.")
        assert_no_errors(output_dir)
        print("Checking database")

        db = ModuleFactory().create_db_manager_obj(
            redis_port, output_dir=output_dir, start_redis_server=False
        )

        # assert db.get_msgs_received_at_runtime("Fides")["fides2network"] == "1"

        print("Checking Fides' data outlets")
        assert fdb.get_peer_trust_data("peer1").service_history != []
        assert fdb.get_peer_trust_data("peer2").service_history != []
        assert fdb.get_peer_trust_data("peer1").service_history_size == 1
        assert fdb.get_peer_trust_data("peer2").service_history_size == 1
        assert db.get_cached_network_opinion(
            "stratosphere.org", 200000000000, 200000000000
        ) == {
            "target": "stratosphere.org",
            "score": "0.0",
            "confidence": "0.0",
        }

        print("Deleting the output directory")
        shutil.rmtree(output_dir)
    finally:
        # Restore the original file
        os.remove(test_db)
        shutil.move(config_temp_path, config_file_path)
        print("Config file restored to original state.")
