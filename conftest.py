# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
This file will contain the fixtures that are commonly needed by all other test files
for example: setting up the database, input_queue, output_queue, etc..
"""

import pytest
import os
import sys
import inspect
from multiprocessing import Queue
from unittest.mock import patch
from slips_files.core.database.database_manager import DBManager
from slips_files.core.output import Output
from slips_files.core.flows.zeek import Conn
import logging

# add parent dir to path for imports to work
current_dir = os.path.dirname(
    os.path.abspath(inspect.getfile(inspect.currentframe()))
)
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)


# Suppress TensorFlow logs from C++ backend
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"  # 3 = ERROR
# TensorFlow logs oneDNN messages even with TF_CPP_MIN_LOG_LEVEL=3.
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"

import tensorflow as tf


# Suppress Python-based TensorFlow logs
tf.get_logger().setLevel(logging.ERROR)
logging.getLogger("tensorflow").setLevel(logging.ERROR)


@pytest.fixture
def mock_db():
    # Create a mock version of the database object
    with patch("slips_files.core.database.database_manager.DBManager") as mock:
        yield mock.return_value


def do_nothing(*arg):
    """Used to override the print function because using the self.print causes
    broken pipes"""
    pass


@pytest.fixture
def input_queue():
    """This input_queue will be passed to all module constructors that need
    it"""
    input_queue = Queue()
    input_queue.put = do_nothing
    return input_queue


@pytest.fixture
def profiler_queue():
    """This profiler_queue will be passed to all module constructors that need
    it"""
    profiler_queue = Queue()
    profiler_queue.put = do_nothing
    return profiler_queue


@pytest.fixture
def database():
    db = DBManager(Output(), "output/", 6379)
    db.print = do_nothing
    return db


@pytest.fixture
def flow():
    """returns a dummy flow for testing"""
    return Conn(
        "1601998398.945854",
        "1234",
        "192.168.1.1",
        "8.8.8.8",
        5,
        "TCP",
        "dhcp",
        80,
        88,
        20,
        20,
        20,
        20,
        "",
        "",
        "Established",
        "",
    )


# Define a fixture to run before each test
@pytest.fixture(autouse=True)
def setup_teardown_before_each_test(request):
    # Code to run before each test
    print(f"\nSetting up for test: {request.node.name}")
    #
    # # Code to run after each test
    # yield
    #
    # print(f"Tearing down after test: {request.node.name}")
    # # This is where you can perform any teardown actions needed for each test
    # ...
