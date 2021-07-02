"""
This file will contain the fixtures that are commonly needed by all other test files
for example: setting up the database, inputqueue, outputqueue, etc..
"""
import pytest
import os,sys,inspect
from multiprocessing import Queue



# add parent dir to path for imports to work
current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

@pytest.fixture
def outputQueue():
    """ This outputqueue will be passed to all module constructors that need it """
    outputQueue = Queue()
    outputQueue.put = print
    return Queue()


@pytest.fixture
def profilerQueue():
    """ This profilerqueue will be passed to all module constructors that need it """
    profilerqueue = Queue()
    profilerqueue.put = print
    return profilerqueue


@pytest.fixture
def database():
    from slips.core.database import __database__
    return __database__





