"""
This file will contain the fixtures that are commonly needed by all other test files
for example: setting up the database, inputqueue, outputqueue, etc..
"""
import pytest
import os,sys,inspect
from multiprocessing import Queue
from inputProcess import InputProcess
import configparser


# add parent dir to path for imports to work
current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

@pytest.fixture
def outputQueue():
    """ This outputqueue will be passed to all module constructors that need it """
    return Queue()


@pytest.fixture
def profilerQueue():
    """ This profilerqueue will be passed to all module constructors that need it """
    return Queue()


@pytest.fixture
def database():
    from slips.core.database import __database__
    return __database__

@pytest.fixture
def inputProcess(outputQueue,profilerQueue):
    """ Create an instance of inputProcess.py
        needed by test_inputProcess.py test file  """
    input_information = 'dataset/sample_zeek_files'
    config = configparser.ConfigParser()
    input_type = 'file'
    inputProcess = InputProcess(outputQueue, profilerQueue,
                                input_type, input_information, config, None, 'zeek')
    inputProcess.bro_timeout=1
    # override the self.print function to avoid broken pipes
    inputProcess.print = print
    inputProcess.profilerqueue.put = print
    return inputProcess

