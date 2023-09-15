"""
This file will contain the fixtures that are commonly needed by all other test files
for example: setting up the database, input_queue, output_queue, etc..
"""
import pytest
import os, sys, inspect
from multiprocessing import Queue
from unittest.mock import patch
from slips_files.core.database.database_manager import DBManager


# add parent dir to path for imports to work
current_dir = os.path.dirname(
    os.path.abspath(inspect.getfile(inspect.currentframe()))
)
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)



@pytest.fixture
def mock_rdb():
    # Create a mock version of the database object
    with patch('slips_files.core.database.database_manager.DBManager') as mock:
        yield mock.return_value

def do_nothing(*arg):
    """Used to override the print function because using the self.print causes broken pipes"""
    pass

@pytest.fixture
def output_queue():
    """This output_queue will be passed to all module constructors that need it"""
    output_queue = Queue()
    output_queue.put = do_nothing
    return Queue()


@pytest.fixture
def input_queue():
    """This input_queue will be passed to all module constructors that need it"""
    input_queue = Queue()
    input_queue.put = do_nothing
    return input_queue


@pytest.fixture
def profiler_queue():
    """This profiler_queue will be passed to all module constructors that need it"""
    profiler_queue = Queue()
    profiler_queue.put = do_nothing
    return profiler_queue


@pytest.fixture
def database(output_queue):
    db = DBManager('output/', output_queue, 6379)
    db.print = do_nothing
    return db
