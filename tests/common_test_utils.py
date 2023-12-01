
from pathlib import Path
import os
import shutil
import binascii
import subprocess
import base64

IS_IN_A_DOCKER_CONTAINER = os.environ.get('IS_IN_A_DOCKER_CONTAINER', False)

integration_tests_dir = 'output/integration_tests/'
alerts_file = 'alerts.log'

#create the integration tests dir
if not os.path.exists(integration_tests_dir):
    path = Path(integration_tests_dir)
    path.mkdir(parents=True, exist_ok=True)

def do_nothing(*args):
    """Used to override the print function because using the self.print causes broken pipes"""
    pass

def run_slips(cmd):
    """runs slips and waits for it to end"""
    slips = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        shell=True
    )
    return_code = slips.wait()
    return return_code

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


def check_error_keywords(line):
    """
    these keywords indicate that an error needs to
    be fixed and should fail the integration tests when found
    """
    error_keywords = ('<class', 'error', 'Error', 'Traceback')
    for keyword in error_keywords:
        if keyword in line:
            return True
    return False


def check_for_ignored_errors(line):
    """
    These are connection errors, empty feeds, download errors etc that don't
    indicate that something is wrong with slips code
    we shouldn't fail integration tests bc of them
    """
    ignored_error_keywords = ('Connection error',
                              'while downloading',
                              'Error while reading the TI file',
                              'Error parsing feed'
                              )
    for ignored_keyword in ignored_error_keywords:
       if ignored_keyword in line:
           return True



def has_errors(output_dir):
    """function to parse slips_output file and check for errors"""
    error_files = ('slips_output.txt', 'errors.log')
    error_files = [os.path.join(output_dir, file) for file in error_files]

    # we can't redirect stderr to a file and check it because we catch all exceptions in slips
    for file in error_files:
        with open(file, 'r') as f:
            for line in f:
                if check_for_ignored_errors(line):
                    continue

                if check_error_keywords(line):
                    return True

    return False



alerts_file = 'alerts.log'



def run_slips(cmd):
    """runs slips and waits for it to end"""
    slips = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        shell=True
    )
    return_code = slips.wait()
    return return_code