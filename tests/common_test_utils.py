from pathlib import Path
import os
import shutil
import binascii
import subprocess
import base64
from typing import (
    Dict,
    Optional,
)
from unittest.mock import Mock

IS_IN_A_DOCKER_CONTAINER = os.environ.get("IS_IN_A_DOCKER_CONTAINER", False)

integration_tests_dir = "output/integration_tests/"
alerts_file = "alerts.log"

# create the integration tests dir
if not os.path.exists(integration_tests_dir):
    path = Path(integration_tests_dir)
    path.mkdir(parents=True, exist_ok=True)


def get_mock_coro(return_value):
    """
    instead of doing async_func = Mock() which doesn't work
    you should use this function to mock it
    so async_func = get_mock_coro(x)
    """

    async def mock_coro(*args, **kwargs):
        return return_value

    return Mock(wraps=mock_coro)


def do_nothing(*args):
    """Used to override the print function because using the self.print causes broken pipes"""
    pass


def run_slips(cmd):
    """runs slips and waits for it to end"""
    slips = subprocess.Popen(cmd, stdin=subprocess.PIPE, shell=True)
    return_code = slips.wait()
    return return_code


def get_random_uid():
    return base64.b64encode(binascii.b2a_hex(os.urandom(9))).decode("utf-8")


def get_total_profiles(db):
    return int(db.scard("profiles"))


def is_evidence_present(log_file, expected_evidence):
    """Function to read the log file line by line and returns when it finds the expected evidence"""
    with open(log_file, "r") as f:
        while line := f.readline():
            if expected_evidence in line:
                return True
        # evidence not found in any line
        return False


def create_output_dir(dirname):
    """
    creates this output dir inside output/integration_tests/
    returns a full path to the created output dir
    """

    path = Path(os.path.join(integration_tests_dir, dirname))
    # clear output dir before running the test
    if os.path.exists(path):
        shutil.rmtree(path)

    path.mkdir(parents=True, exist_ok=True)

    return path


def msgs_published_are_eq_msgs_received_by_each_module(db) -> bool:
    """
    This functions checks that all modules received all msgs that were
    published for the channels they subscribed to
    """
    for module in db.get_enabled_modules():
        # get channels subscribed to by this module
        msg_tracker: Dict[str, int] = db.get_msgs_received_at_runtime(module)

        for channel, msgs_received in msg_tracker.items():
            msgs_received: int
            channel: str
            assert db.get_msgs_published_in_channel(channel) == msgs_received

        return True


def check_for_text(txt, output_dir):
    """function to parse slips_output file and check for a given string"""
    slips_output = os.path.join(output_dir, "slips_output.txt")
    with open(slips_output, "r") as f:
        for line in f:
            if txt in line:
                return True
    return False


def has_error_keywords(line):
    """
    these keywords indicate that an error needs to
    be fixed and should fail the integration tests when found
    """
    error_keywords = ("<class", "error", "Error", "Traceback")
    for keyword in error_keywords:
        if keyword in line or keyword.lower() in line:
            return True
    return False


def has_ignored_errors(line):
    """
    These are connection errors, empty feeds, download errors etc that don't
    indicate that something is wrong with slips code
    we shouldn't fail integration tests bc of them
    """
    ignored_error_keywords = (
        "Connection error",
        "while downloading",
        "Error while reading the TI file",
        "Error parsing feed",
    )
    for ignored_keyword in ignored_error_keywords:
        if ignored_keyword in line:
            return True


def read_file_if_small(file_path) -> Optional[str]:
    """
    returns all contents of a  given file if the file size is < 3MBs
    """
    if not os.path.isfile(file_path):
        print(f"File {file_path} does not exist.")
        return None

    # in bytes
    file_size = os.path.getsize(file_path)

    # Check if the file size is less than 3MB (3 * 1024 * 1024 bytes)
    if file_size < 3 * 1024 * 1024:
        with open(file_path, "r") as file:
            contents = file.read()
        return contents
    else:
        print(f"File {file_path} size exceeds 3MB.")
        return None


def assert_no_errors(output_dir):
    """function to parse slips_output file and check for errors"""
    error_files = ("slips_output.txt", "errors.log")
    error_files = [os.path.join(output_dir, file) for file in error_files]

    # we can't redirect stderr to a file and check it because we catch all
    # exceptions in slips
    for file in error_files:
        with open(file, "r") as f:
            for line in f:
                if has_ignored_errors(line):
                    continue
                # prints the content of errors.log if one line was found to
                # have an error. (only if the file is < 3MB) to avoid
                # reading large files
                # the goal of this is to be able to view the error from CI
                # without having to download the artifacts
                assert not has_error_keywords(line), (
                    read_file_if_small(file) or line
                )
