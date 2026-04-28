"""
This file tests 2 different config files other than slips' default config/slips.yaml
test/test.yaml and tests/test2.yaml
"""

import re
import shutil
from pathlib import PosixPath

import redis

from tests.common_test_utils import (
    create_output_dir,
    assert_no_errors,
    close_test_redis_server,
    modify_yaml_config,
)
import pytest
import os
import subprocess
import time
import sys
from pathlib import Path

alerts_file = "alerts.log"
TEST_DIR = Path(__file__).resolve().parent
PEER1_CONFIG_DIR = TEST_DIR / "peer1_config"
PEER2_CONFIG_DIR = TEST_DIR / "peer2_config"


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


def check_strings_in_file(string_list, file_path):
    # Check if the file exists
    if not os.path.exists(file_path):
        print(f"File {file_path} does not exist.")
        return False

    # Open the file and read its content
    try:
        with open(file_path, "r") as file:
            file_content = file.read()

        # Check if all strings in the list are present in the file content
        for string in string_list:
            if string not in file_content:
                return False
        return True

    except Exception as e:
        print(f"Error reading file: {e}")
        return False


def wait_for_file(file_path, timeout_seconds):
    """
    Wait until a file exists or the timeout elapses.

    Parameters:
        file_path: Path to the expected file.
        timeout_seconds: Maximum number of seconds to wait.

    Returns:
        True if the file exists before the timeout, otherwise False.
    """
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if os.path.exists(file_path):
            return True
        time.sleep(1)
    return os.path.exists(file_path)


def get_default_interface():
    """
    Get the default network interface.

    Returns:
        str: Name of the default network interface.
    """
    with open("/proc/net/route") as f:
        for line in f.readlines()[1:]:
            fields = line.strip().split()
            if fields[1] == "00000000":  # default route
                return fields[0]


def extract_connection_string(log_file_first_iris):
    """
    Extract the first peer connection string from the Iris log file.

    Parameters:
        log_file_first_iris: Path to the first peer Iris log file.

    Returns:
        str: The extracted connection string.
    """
    with open(log_file_first_iris, "r") as log:
        for line in log:
            match = re.search(r"connection string:\s+'(.+)'", line)
            if match:
                return match.group(1)

    print("No connection string found in log file.")
    exit(1)


def assert_peer1_setup(peer1_slips_config):
    """
    Assert that the first peer config was generated as expected.

    Parameters:
        peer1_slips_config: Path to the first peer Slips config.

    Returns:
        None
    """
    assert check_strings_in_file(
        ["iris_conf: tests/integration/test_iris/peer1_config/iris.yaml"],
        peer1_slips_config,
    )


def assert_peer2_setup(
    peer2_slips_config,
    peer2_iris_config,
    connection_string,
    peer_redis_port,
    peer_server_port,
):
    """
    Assert that the second peer config was generated as expected.

    Parameters:
        peer2_slips_config: Path to the second peer Slips config.
        peer2_iris_config: Path to the second peer Iris config.
        connection_string: Multiaddress used to connect to the first peer.
        peer_redis_port: Redis port used by the second peer.
        peer_server_port: Iris server port used by the second peer.

    Returns:
        None
    """
    assert check_strings_in_file(
        ["iris_conf: tests/integration/test_iris/peer2_config/iris.yaml"],
        peer2_slips_config,
    )
    assert check_strings_in_file(
        [
            f"Port: {peer_redis_port}",
            f"Port: {peer_server_port}",
            "DisableBootstrappingNodes: true",
            "KeyFile: second.priv",
            connection_string,
        ],
        peer2_iris_config,
    )


def assert_peer1_results(output_dir):
    """
    Assert the first peer completed without runtime errors.

    Parameters:
        output_dir: Output directory of the first peer.

    Returns:
        None
    """
    assert_no_errors(output_dir)


def assert_peer2_results(output_dir_peer, log_file_second_iris):
    """
    Assert the second peer completed without runtime errors and started Iris.

    Parameters:
        output_dir_peer: Output directory of the second peer.
        log_file_second_iris: Path to the second peer Iris log file.

    Returns:
        None
    """
    assert_no_errors(output_dir_peer)
    assert check_strings_in_file(
        ["connection string:"],
        log_file_second_iris,
    )


def prepare_and_start_peer1(
    zeek_dir_path,
    output_dir,
    redis_port,
    server_port,
    default_interface,
    log_file,
):
    """
    Generate config for peer1, start it, and return startup metadata.

    Parameters:
        zeek_dir_path: Zeek dataset path used by the test.
        output_dir: Output directory for peer1.
        redis_port: Redis port used by peer1.
        server_port: Iris server port used by peer1.
        default_interface: Interface required by Slips when using `-g`.
        log_file: Open file handle used to capture peer1 output.

    Returns:
        tuple: Peer1 process, Iris log path, and Slips config path.
    """
    peer1_slips_config = PEER1_CONFIG_DIR / "slips.yaml"
    peer1_iris_config = PEER1_CONFIG_DIR / "iris.yaml"
    peer1_iris_config_path = Path(
        "tests/integration/test_iris/peer1_config"
    ) / (peer1_iris_config.name)

    modify_yaml_config(
        input_path="config/iris_config.yaml",
        output_dir=PEER1_CONFIG_DIR,
        output_filename=peer1_iris_config.name,
        changes={
            "Redis": {"Port": redis_port},
            "Server": {"Port": server_port},
            "PeerDiscovery": {
                "DisableBootstrappingNodes": True,
                "ListOfMultiAddresses": [],
            },
        },
    )
    modify_yaml_config(
        input_path="config/slips.yaml",
        output_dir=PEER1_CONFIG_DIR,
        output_filename=peer1_slips_config.name,
        changes={
            "global_p2p": {
                "use_global_p2p": True,
                "iris_conf": str(peer1_iris_config_path),
            },
            "modules": {"disable": ["template", "updatemanager"]},
        },
    )

    command = [
        sys.executable,
        "./slips.py",
        "-t",
        "-g",
        str(zeek_dir_path),
        "-i",
        default_interface,
        "-e",
        "1",
        "-o",
        str(output_dir),
        "-c",
        str(peer1_slips_config),
        "-P",
        str(redis_port),
    ]

    process = subprocess.Popen(
        command,
        stdout=log_file,
        stderr=log_file,
    )
    log_file_first_iris = output_dir / "iris/iris_logs.txt"
    return process, log_file_first_iris, peer1_slips_config


def prepare_and_start_peer2(
    zeek_dir_path,
    output_dir_peer,
    peer_redis_port,
    peer_server_port,
    default_interface,
    connection_string,
    log_file,
):
    """
    Generate config for peer2, start it, and return startup metadata.

    Parameters:
        zeek_dir_path: Zeek dataset path used by the test.
        output_dir_peer: Output directory for peer2.
        peer_redis_port: Redis port used by peer2.
        peer_server_port: Iris server port used by peer2.
        default_interface: Interface required by Slips when using `-g`.
        connection_string: Multiaddress of peer1 used by peer2.
        log_file: Open file handle used to capture peer2 output.

    Returns:
        tuple: Peer2 process, Iris log path, Slips config path, and Iris config path.
    """
    peer2_iris_config = PEER2_CONFIG_DIR / "iris.yaml"
    peer2_iris_config_path = Path(
        "tests/integration/test_iris/peer2_config"
    ) / (peer2_iris_config.name)
    peer2_slips_config = PEER2_CONFIG_DIR / "slips.yaml"

    modify_yaml_config(
        input_path="config/slips.yaml",
        output_dir=PEER2_CONFIG_DIR,
        output_filename=peer2_slips_config.name,
        changes={
            "global_p2p": {
                "use_global_p2p": True,
                "iris_conf": str(peer2_iris_config_path),
            },
            "modules": {"disable": ["template", "updatemanager"]},
        },
    )
    modify_yaml_config(
        input_path="config/iris_config.yaml",
        output_dir=PEER2_CONFIG_DIR,
        output_filename=peer2_iris_config.name,
        changes={
            "Redis": {"Port": peer_redis_port},
            "Server": {"Port": peer_server_port},
            "PeerDiscovery": {
                "DisableBootstrappingNodes": True,
                "ListOfMultiAddresses": [connection_string],
            },
            "Identity": {"KeyFile": "second.priv"},
        },
    )

    peer_command = [
        sys.executable,
        "./slips.py",
        "-t",
        "-g",
        str(zeek_dir_path),
        "-i",
        default_interface,
        "-e",
        "1",
        "-o",
        str(output_dir_peer),
        "-c",
        str(peer2_slips_config),
        "-P",
        str(peer_redis_port),
    ]
    peer_process = subprocess.Popen(
        peer_command, stdout=log_file, stderr=log_file
    )
    log_file_second_iris = output_dir_peer / "iris/iris_logs.txt"
    return (
        peer_process,
        log_file_second_iris,
        peer2_slips_config,
        peer2_iris_config,
    )


@pytest.mark.parametrize(
    "zeek_dir_path, output_dir, peer_output_dir",
    [
        (
            "dataset/test13-malicious-dhcpscan-zeek-dir",
            "iris_integration_test/",
            "peer_iris_integration_test/",
        )
    ],
)
def test_messaging(
    zeek_dir_path,
    output_dir,
    peer_output_dir,
    integration_port_factory,
):
    """
    Tests whether Iris properly distributes an alert message generated by
    Slips to the network (~other peers).

    First Slips instance is a general node in the network, its connection
     string is generated and extracted from logs as a normal user would do,
    in a very standard use case.

    The second instance of Slips acts as a normal-user-peer that joins the
    network via the aforementioned Slips instance,
    which extends the standard use case of connecting to such P2P network.
    """
    default_interface = get_default_interface()
    redis_port = integration_port_factory("peer1 redis")
    peer_redis_port = integration_port_factory("peer2 redis")
    server_port = integration_port_factory("peer1 iris")
    peer_server_port = integration_port_factory("peer2 iris")

    # Two Slips instances are necessary to be run in this test.

    # Prepare output dir for peer1
    output_dir: PosixPath = create_output_dir(output_dir)
    output_file = os.path.join(output_dir, "slips_output.txt")

    # Prepare output dir for the peer2
    output_dir_peer: PosixPath = create_output_dir(peer_output_dir)
    output_file_peer = os.path.join(output_dir_peer, "slips_output.txt")
    peer2_iris_config = PEER2_CONFIG_DIR / "iris.yaml"
    success = False
    try:
        print("running slips ...")
        with open(output_file, "w") as log_file:
            with open(output_file_peer, "w") as iris_log_file:
                process, log_file_first_iris, peer1_slips_config = (
                    prepare_and_start_peer1(
                        zeek_dir_path=zeek_dir_path,
                        output_dir=output_dir,
                        redis_port=redis_port,
                        server_port=server_port,
                        default_interface=default_interface,
                        log_file=log_file,
                    )
                )
                assert_peer1_setup(peer1_slips_config)

                # First peer (its Iris) needs to be ready and available for
                # connections when the second peer tries to reach out to it.
                countdown(20, "second peer")
                # get the connection string from the first peer and give it
                # to the second one so it is reachable
                assert wait_for_file(log_file_first_iris, 30), (
                    "Expected Iris log file was not created: "
                    f"{log_file_first_iris}"
                )
                original_conn_string = extract_connection_string(
                    log_file_first_iris
                )

                (
                    peer_process,
                    log_file_second_iris,
                    peer2_slips_config,
                    peer2_iris_config,
                ) = prepare_and_start_peer2(
                    zeek_dir_path=zeek_dir_path,
                    output_dir_peer=output_dir_peer,
                    peer_redis_port=peer_redis_port,
                    peer_server_port=peer_server_port,
                    default_interface=default_interface,
                    connection_string=original_conn_string,
                    log_file=iris_log_file,
                )
                assert_peer2_setup(
                    peer2_slips_config=peer2_slips_config,
                    peer2_iris_config=peer2_iris_config,
                    connection_string=original_conn_string,
                    peer_redis_port=peer_redis_port,
                    peer_server_port=peer_server_port,
                )

                print(
                    f"Output and errors of first peer are logged in"
                    f" {output_file}"
                )

                # let Slips properly and fully star with all of its parts and modules.
                countdown(80, "Sending msg in fides2network")
                # Sending a manual message to make sure there is an alert generated, because
                # is is highly probable that both slips have covered their network captures
                # before the infrastructure of P2P network was fully up and running
                message_send(
                    redis_port,
                    message=message_alert_TL_NL,
                    channel="fides2network",
                )

                # these seconds are the time we give slips to process the msg
                countdown(30, "Sending SIGTERM to the 2 peers")
                # Kill em with kindness.
                os.kill(process.pid, 15)
                os.kill(peer_process.pid, 15)
                print("SIGTERM sent.")

                print("Sending SIGKILL to the 2 instances of Slips + iris")
                # Kill em. Without kindness.
                os.kill(process.pid, 9)
                print(f"Slips with PID {process.pid} was killed.")

                os.kill(peer_process.pid, 9)
                print(f"Slips peer with PID {peer_process.pid} was killed.")

        print("Slips is done, checking for errors in the 2 output dirs.")
        assert_peer1_results(output_dir)
        assert_peer2_results(output_dir_peer, log_file_second_iris)
        success = True
    finally:
        if success:
            close_test_redis_server(redis_port)
            close_test_redis_server(peer_redis_port)
            print("Deleting the output directories")
            shutil.rmtree(output_dir)
            shutil.rmtree(output_dir_peer)
            os.remove("modules/iris/second.priv")

        # reset the generated peer2 Iris config back to its default values
        # after the test finishes.
        modify_yaml_config(
            input_path="config/iris_config.yaml",
            output_dir=PEER2_CONFIG_DIR,
            output_filename=peer2_iris_config.name,
            changes={
                "Redis": {"Port": 6644},
                "Server": {"Port": 9010},
                "PeerDiscovery": {},
                "Identity": {"KeyFile": "private.key"},
            },
        )
