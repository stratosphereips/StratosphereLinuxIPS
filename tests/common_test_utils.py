
from pathlib import Path
import os
import shutil
import binascii
import base64

IS_IN_A_DOCKER_CONTAINER = os.environ.get('IS_IN_A_DOCKER_CONTAINER', False)

integration_tests_dir = 'output/integration_tests/'


#create the integration tests dir
if not os.path.exists(integration_tests_dir):
    path = Path(integration_tests_dir)
    path.mkdir(parents=True, exist_ok=True)

def do_nothing(*args):
    """Used to override the print function because using the self.print causes broken pipes"""
    pass


def get_random_uid():
    return base64.b64encode(binascii.b2a_hex(os.urandom(9))).decode('utf-8')


def get_total_profiles(db):
    return int(db.scard('profiles'))

def is_evidence_present(log_file, expected_evidence):
    """Function to read the log file line by line and returns when it finds the expected evidence"""
    with open(log_file, 'r') as f:
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

def check_for_text(txt, output_dir):
    """function to parse slips_output file and check for a given string"""
    slips_output = os.path.join(output_dir, 'slips_output.txt')
    with open(slips_output, 'r') as f:
        for line in f:
            if txt in line:
                return True
    return False


def has_errors(output_dir):
    """function to parse slips_output file and check for errors"""
    error_files = ('slips_output.txt', 'errors.log')
    error_files = [os.path.join(output_dir, file) for file in error_files]

    # we can't redirect stderr to a file and check it because we catch all exceptions in slips
    for file in error_files:
        with open(file, 'r') as f:
            for line in f:
                if '<class' in line or 'error' in line or 'Error' in line or 'Traceback' in line:
                    # connection errors shouldn't fail the integration tests
                    if (
                            'Connection error' in line
                            or 'while downloading' in line
                    ):
                        continue
                    return True

    return False
