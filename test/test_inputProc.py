import os
import pytest
from inputProcess import InputProcess
import configparser

def do_nothing(*args):
    """ Used to override the print function because using the self.print causes broken pipes """
    pass

def create_inputProcess_instance(outputQueue, profilerQueue, input_information, input_type):
    """ Create an instance of inputProcess.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    inputProcess = InputProcess(outputQueue, profilerQueue,
                                input_type, input_information, config, None, 'zeek')
    inputProcess.bro_timeout=1
    # override the self.print function to avoid broken pipes
    inputProcess.print = do_nothing
    return inputProcess

def add_zeek_files_to_db(database, input_information):
    # add zeek files to the db , needed by the read_zeek_files function
     for file in os.listdir(input_information):
        file_name_without_extension = file[:file.index('.')]
        database.add_zeek_file(input_information+'/'+file_name_without_extension)

@pytest.mark.parametrize('input_information', ['dataset/sample_zeek_files'])
def test_read_zeek_files(outputQueue, profilerQueue, database, input_information):
     inputProcess = create_inputProcess_instance(outputQueue, profilerQueue, input_information, 'file')
     add_zeek_files_to_db(database, input_information)
     # make sure lines are read from sample_zeek_files successfully
     assert inputProcess.read_zeek_files() > 0
#todo test tab separated zeek files

@pytest.mark.parametrize("input_type,input_information", [('pcap','dataset/hide-and-seek-short.pcap')])
def test_handle_pcap_and_interface(outputQueue, profilerQueue, input_type, input_information):
    # no need to test interfaces because in that case read_zeek_files runs in a loop and never returns
    inputProcess = create_inputProcess_instance(outputQueue, profilerQueue, input_information, input_type)
    assert inputProcess.run() == True






