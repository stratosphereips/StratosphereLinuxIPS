"""
This file tests 2 different config files other than slips' default config/slips.yaml
test/test.yaml and tests/test2.yaml
"""
import shutil
from pathlib import PosixPath
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

    # Get the current working directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Navigate two levels up
    #base_dir = os.path.abspath(os.path.join(current_dir, "..", ".."))

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
    print("Deleting the output directory")
    shutil.rmtree(output_dir)
    print("Checking database")
    db = ModuleFactory().create_db_manager_obj(
        redis_port, output_dir=output_dir, start_redis_server=False
    )
    assert db.get_msgs_received_at_runtime("Fides")["fides2network"] == '1'
