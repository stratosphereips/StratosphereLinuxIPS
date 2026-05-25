"""
This file tests 2 different config files other than slips' default config/slips.yaml
test/test.yaml and tests/test2.yaml
"""

import re
import signal
import shutil
from pathlib import PosixPath

import redis

from tests.common_test_utils import (
    create_output_dir,
    assert_no_errors,
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


def assert_peer1_setup(peer1_slips_config, peer1_iris_config_path):
    """
    Assert that the first peer config was generated as expected.

    Parameters:
        peer1_slips_config: Path to the first peer Slips config.
        peer1_iris_config_path: Relative path to the first peer Iris config.

    Returns:
        None
    """
    assert check_strings_in_file(
        [f"iris_conf: {peer1_iris_config_path}"],
        peer1_slips_config,
    )


def assert_peer2_setup(
    peer2_slips_config,
    peer2_iris_config,
    peer2_iris_config_path,
    connection_string,
    peer_redis_port,
    peer_server_port,
    peer2_key_path,
):
    """
    Assert that the second peer config was generated as expected.

    Parameters:
        peer2_slips_config: Path to the second peer Slips config.
        peer2_iris_config: Path to the second peer Iris config.
        peer2_iris_config_path: Relative path to the second peer Iris config.
        connection_string: Multiaddress used to connect to the first peer.
        peer_redis_port: Redis port used by the second peer.
        peer_server_port: Iris server port used by the second peer.
        peer2_key_path: Relative path to the generated peer2 private key.

    Returns:
        None
    """
    assert check_strings_in_file(
        [f"iris_conf: {peer2_iris_config_path}"],
        peer2_slips_config,
    )
    assert check_strings_in_file(
        [
            f"Port: {peer_redis_port}",
            f"Port: {peer_server_port}",
            "DisableBootstrappingNodes: true",
            f"KeyFile: {peer2_key_path}",
            connection_string,
        ],
        peer2_iris_config,
    )


def prepare_peer_config_paths(
    config_dir: Path, prefix: str
) -> tuple[Path, Path, Path]:
    """
    Build runtime config paths for a test peer.

    Parameters:
        config_dir: Directory where generated config files will be stored.
        prefix: Prefix used to name the generated files.

    Returns:
        tuple: Slips config path, Iris config path, and Iris config path relative to repo root.
    """
    config_dir.mkdir(parents=True, exist_ok=True)
    iris_config = config_dir / f"{prefix}_iris.yaml"
    slips_config = config_dir / f"{prefix}_slips.yaml"
    iris_config_path = Path(os.path.relpath(iris_config, Path.cwd()))
    return slips_config, iris_config, iris_config_path


def get_runtime_config_dir(output_dir_name: str, peer_name: str) -> Path:
    """
    Return the runtime config directory for an Iris integration-test peer.

    Parameters:
        output_dir_name: Name of the peer output directory.
        peer_name: Peer-specific prefix used by the test.

    Returns:
        Path: Directory where generated runtime configs should be stored.
    """
    return TEST_DIR / "runtime_configs" / output_dir_name / peer_name


def get_iris_relative_key_path(key_path: Path) -> str:
    """
    Build a key path relative to the Iris module working directory.

    Parameters:
        key_path: Path to the private key file to be generated by Iris.

    Returns:
        str: Relative path from `modules/iris` to the key file.
    """
    return os.path.relpath(key_path, Path("modules/iris"))


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
    config_dir = get_runtime_config_dir(output_dir.name, "peer1")
    (
        peer1_slips_config,
        peer1_iris_config,
        peer1_iris_config_path,
    ) = prepare_peer_config_paths(config_dir, "peer1")

    modify_yaml_config(
        input_path="config/iris_config.yaml",
        output_dir=config_dir,
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
        output_dir=config_dir,
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
        start_new_session=True,
    )
    log_file_first_iris = output_dir / "iris/iris_logs.txt"
    return (
        process,
        log_file_first_iris,
        peer1_slips_config,
        peer1_iris_config_path,
    )


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
    config_dir = get_runtime_config_dir(output_dir_peer.name, "peer2")
    (
        peer2_slips_config,
        peer2_iris_config,
        peer2_iris_config_path,
    ) = prepare_peer_config_paths(config_dir, "peer2")
    peer2_key_path = output_dir_peer / "peer2.private.key"
    peer2_key_path_for_iris = get_iris_relative_key_path(peer2_key_path)

    modify_yaml_config(
        input_path="config/slips.yaml",
        output_dir=config_dir,
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
        output_dir=config_dir,
        output_filename=peer2_iris_config.name,
        changes={
            "Redis": {"Port": peer_redis_port},
            "Server": {"Port": peer_server_port},
            "PeerDiscovery": {
                "DisableBootstrappingNodes": True,
                "ListOfMultiAddresses": [connection_string],
            },
            "Identity": {"KeyFile": peer2_key_path_for_iris},
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
        peer_command,
        stdout=log_file,
        stderr=log_file,
        start_new_session=True,
    )
    log_file_second_iris = output_dir_peer / "iris/iris_logs.txt"
    return (
        peer_process,
        log_file_second_iris,
        peer2_slips_config,
        peer2_iris_config,
        peer2_iris_config_path,
        peer2_key_path,
        peer2_key_path_for_iris,
    )


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
    peer2_key_path = None
    success = False
    try:
        print("running slips ...")
        with open(output_file, "w") as log_file:
            with open(output_file_peer, "w") as iris_log_file:
                (
                    process,
                    log_file_first_iris,
                    peer1_slips_config,
                    peer1_iris_config_path,
                ) = prepare_and_start_peer1(
                    zeek_dir_path=zeek_dir_path,
                    output_dir=output_dir,
                    redis_port=redis_port,
                    server_port=server_port,
                    default_interface=default_interface,
                    log_file=log_file,
                )
                assert_peer1_setup(peer1_slips_config, peer1_iris_config_path)

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
                    peer2_iris_config_path,
                    peer2_key_path,
                    peer2_key_path_for_iris,
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
                    peer2_iris_config_path=peer2_iris_config_path,
                    connection_string=original_conn_string,
                    peer_redis_port=peer_redis_port,
                    peer_server_port=peer_server_port,
                    peer2_key_path=peer2_key_path_for_iris,
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
                print("Stopping the 2 instances of Slips and waiting for exit")
                stop_process_group(process, "peer1 slips")
                stop_process_group(peer_process, "peer2 slips")

        print("Slips is done, checking for errors in the 2 output dirs.")
        assert_peer1_results(output_dir)
        assert_peer2_results(output_dir_peer, log_file_second_iris)
        success = True
    finally:
        if peer2_key_path is not None and peer2_key_path.exists():
            peer2_key_path.unlink()
        shutil.rmtree(
            TEST_DIR / "runtime_configs" / output_dir.name, ignore_errors=True
        )
        shutil.rmtree(
            TEST_DIR / "runtime_configs" / output_dir_peer.name,
            ignore_errors=True,
        )
        if success:
            print("Deleting the output directories")
            shutil.rmtree(output_dir)
            shutil.rmtree(output_dir_peer)
