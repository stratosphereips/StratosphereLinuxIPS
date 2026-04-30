"""
This file tests 2 different config files other than slips' default config/slips.yaml
test/test.yaml and tests/test2.yaml
"""

import json
import shutil
from pathlib import PosixPath, Path
import signal

import redis

from modules.fides.messaging.network_bridge import NetworkBridge
from modules.fides.model.peer import PeerInfo
from modules.fides.persistence.fides_sqlite_db import FidesSQLiteDB
from tests.common_test_utils import (
    create_output_dir,
    assert_no_errors,
    close_test_redis_server,
    modify_yaml_config,
)
from tests.module_factory import ModuleFactory
import pytest
import os
import subprocess
import time
import sys
from unittest.mock import Mock
import modules.fides.model.peer_trust_data as ptd

# TODO
# from tests.common_test_utils import (
#     modify_yaml_config,
# )


alerts_file = "alerts.log"
TEST_DIR = Path(__file__).resolve().parent
FIDES_CONFIG_FILENAME = "fides_runtime.conf.yml"
SLIPS_CONFIG_FILENAME = "fides_runtime_slips.yaml"


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
    # Fides expects the network protocol version, not the Slips package version.
    message = json.loads(message)
    message.update({"version": NetworkBridge.version})
    message = json.dumps(message)

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


def stop_process_group(process, process_name, timeout_seconds=15):
    """
    Stop a spawned process group and wait for it to exit.

    Parameters:
        process: subprocess.Popen instance to stop.
        process_name: Human-readable name used in log messages.
        timeout_seconds: Maximum number of seconds to wait after SIGTERM.

    Returns:
        None
    """
    if process.poll() is not None:
        return

    process_group_id = os.getpgid(process.pid)
    os.killpg(process_group_id, signal.SIGTERM)
    print(f"SIGTERM sent to {process_name} process group {process_group_id}.")

    try:
        process.wait(timeout=timeout_seconds)
        return
    except subprocess.TimeoutExpired:
        pass

    if process.poll() is not None:
        return

    os.killpg(process_group_id, signal.SIGKILL)
    process.wait()
    print(f"SIGKILL sent to {process_name} process group {process_group_id}.")


def wait_for_runtime_message_count(
    redis_port: int,
    output_dir: Path,
    module_name: str,
    channel: str,
    expected_count: str,
    timeout_seconds: int = 30,
) -> dict:
    """
    Wait for a module runtime message counter to reach an expected value.

    Parameters:
        redis_port: Redis port used by the running Slips instance.
        output_dir: Output directory associated with the running test.
        module_name: Module whose runtime counters are being checked.
        channel: Runtime counter key to wait for.
        expected_count: Expected counter value stored in Redis.
        timeout_seconds: Maximum time to wait before failing.

    Returns:
        dict: Latest runtime counters for the module.
    """
    deadline = time.time() + timeout_seconds
    latest_counters = {}

    while time.time() < deadline:
        db = ModuleFactory().create_db_manager_obj(
            redis_port, output_dir=output_dir, start_redis_server=False
        )
        latest_counters = db.get_msgs_received_at_runtime(module_name) or {}
        if latest_counters.get(channel) == expected_count:
            return latest_counters
        time.sleep(1)

    raise AssertionError(
        f"Timed out waiting for {module_name} runtime counter "
        f"{channel} to reach {expected_count}. Latest counters: "
        f"{latest_counters}"
    )


def get_main_interface():
    try:
        out = subprocess.check_output(
            ["ip", "-o", "route", "show", "default"], text=True
        )
        return out.split(" dev ")[1].split()[0]
    except Exception:
        return None


def get_runtime_config_dir(output_dir_name: str) -> Path:
    """
    Return the runtime config directory for a Fides integration test.

    Parameters:
        output_dir_name: Name of the Slips output directory for the test.

    Returns:
        Path: Directory where generated runtime configs should be stored.
    """
    return TEST_DIR / "runtime_configs" / output_dir_name


def create_runtime_fides_configs(
    output_dir: Path, db_name: str
) -> tuple[Path, Path]:
    """
    Create isolated Slips and Fides config files for an integration test.

    Parameters:
        output_dir: Test output directory used to derive the runtime config
            location.
        db_name: Database filename to be created under the permanent directory.

    Returns:
        tuple: Generated Slips config path and permanent DB path.
    """
    config_dir = get_runtime_config_dir(output_dir.name)
    config_dir.mkdir(parents=True, exist_ok=True)

    runtime_fides_config = modify_yaml_config(
        input_path="modules/fides/config/fides.conf.yml",
        output_dir=config_dir,
        output_filename=FIDES_CONFIG_FILENAME,
        changes={"database": db_name},
    )
    runtime_slips_config = modify_yaml_config(
        input_path=str(TEST_DIR / "fides_config.yaml"),
        output_dir=config_dir,
        output_filename=SLIPS_CONFIG_FILENAME,
        changes={
            "global_p2p": {
                "fides_conf": str(runtime_fides_config),
            }
        },
    )

    return runtime_slips_config, Path("permanent") / db_name


@pytest.mark.parametrize(
    "path, output_dir",
    [
        (
            "dataset/test13-malicious-dhcpscan-zeek-dir",
            "fides_test_conf_file2/",
        )
    ],
)
def test_conf_file2(path, output_dir, integration_port_factory):
    """
    In this test we're using the local fides integration config file.
    """
    redis_port = integration_port_factory("redis")
    output_dir: PosixPath = create_output_dir(output_dir)
    db_name = f"{output_dir.name}_fides_p2p_db.sqlite"
    slips_config, test_db = create_runtime_fides_configs(output_dir, db_name)
    output_file = os.path.join(output_dir, "slips_output.txt")
    command = [
        sys.executable,
        "./slips.py",
        "-t",
        "-g",
        str(path),
        # dummy interface required by -g
        "-i",
        str(get_main_interface()),
        "-e",
        "1",
        "-o",
        str(output_dir),
        "-c",
        str(slips_config),
        "-P",
        str(redis_port),
    ]
    success = False
    process = None
    try:
        print("running slips using output dir...")
        print(output_dir)

        # Open the log file in write mode
        with open(output_file, "w") as log_file:
            # Start the subprocess, redirecting stdout and stderr to the same file
            process = subprocess.Popen(
                command,  # Replace with your command
                stdout=log_file,
                stderr=log_file,
                start_new_session=True,
            )

            print(f"Output and errors are logged in {output_file}")
            countdown(40, "sigterm")
            runtime_counters = wait_for_runtime_message_count(
                redis_port,
                output_dir,
                "fides",
                "fides2network",
                "1",
            )
            stop_process_group(process, "fides slips")

        print(f"Slips with PID {process.pid} was killed.")

        print("Slips is done, checking for errors in the output dir.")
        assert_no_errors(output_dir)
        print("Checking database")
        # db = ModuleFactory().create_db_manager_obj(
        #     redis_port, output_dir=output_dir, start_redis_server=False
        # )
        # iris is supposed to be receiving this msg, that last thing fides does
        # is send a msg to this channel for iris to receive it
        assert runtime_counters["fides2network"] == "1"
        assert runtime_counters["new_alert"] == "1"
        print(runtime_counters)
        success = True
    finally:
        if process is not None and process.poll() is None:
            stop_process_group(process, "fides slips")
        close_test_redis_server(redis_port)
        if test_db.exists():
            test_db.unlink()
        shutil.rmtree(
            get_runtime_config_dir(output_dir.name), ignore_errors=True
        )
        if success:
            print("Deleting the output directory")
            shutil.rmtree(output_dir, ignore_errors=True)


@pytest.mark.parametrize(
    "path, output_dir",
    [
        (
            "dataset/test15-malicious-zeek-dir",
            "fides_test_trust_recommendation_response/",
        )
    ],
)
def test_trust_recommendation_response(
    path, output_dir, integration_port_factory
):
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
    redis_port = integration_port_factory("redis")
    output_dir: PosixPath = create_output_dir(output_dir)
    db_name = f"{output_dir.name}_fides_test_database.sqlite"
    print(f"db_name: {db_name}")

    slips_config, permanent_db = create_runtime_fides_configs(
        output_dir, db_name
    )
    print(f"slips_config: {slips_config}  permanent_db: {permanent_db}")

    output_file = os.path.join(output_dir, "slips_output.txt")
    print(f"output_file: {output_file}")
    command = [
        sys.executable,
        "./slips.py",
        "-t",
        "-g",
        str(path),
        # dummy interface required by -g
        "-i",
        str(get_main_interface()),
        "-e",
        "1",
        "-o",
        str(output_dir),
        "-c",
        str(slips_config),
        "-P",
        str(redis_port),
    ]
    # success = False
    process = None

    print(f"command: {' '.join(command)}")

    # try:
    print("running slips with output dir: ...")
    print(output_dir)

    mock_logger = Mock()
    mock_logger.print_line = Mock()
    mock_logger.error = Mock()
    print(
        "Manipulating database: Inject peer1 and peer2 into the "
        "database - Fides Module must know those peers"
    )
    fdb = FidesSQLiteDB(mock_logger, str(permanent_db))
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
            has_fixed_trust=False,
        )
    )

    with open(output_file, "w") as log_file:
        process = subprocess.Popen(
            command,
            stdout=log_file,
            stderr=log_file,
            start_new_session=True,
        )

        print(f"Output and errors are logged in {output_file}")

        # these seconds are the time we wait for slips to start all the
        # modules
        countdown(60, "test message")

        # this msg simulates a msg sent by peers to the started
        # slips instance
        message_send(redis_port)

        # these 30s are the time we give slips to process the msg
        countdown(30, "sigterm")
        stop_process_group(process, "fides slips")

    print(f"Slips with PID {process.pid} was killed.")

    print("Slips is done, checking for errors in the output dir.")
    assert_no_errors(output_dir)

    print("Checking database")
    db = ModuleFactory().create_db_manager_obj(
        redis_port, output_dir=output_dir, start_redis_server=False
    )

    # assert db.get_msgs_received_at_runtime("fides")["fides2network"] == "1"
    print("Checking Fides' data outlets")
    print(
        f"@@@@@@@@@@@@@@@@ {fdb.get_peer_trust_data("peer1").service_history}"
    )

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
    # success = True
    # except:
    #     pass

    # finally:
    #     if process is not None and process.poll() is None:
    #         stop_process_group(process, "fides slips")
    #     close_test_redis_server(redis_port)
    #     if permanent_db.exists():
    #         permanent_db.unlink()
    #     shutil.rmtree(
    #         get_runtime_config_dir(output_dir.name), ignore_errors=True
    #     )
    #     if success:
    #         print("Deleting the output directory")
    #         shutil.rmtree(output_dir)
