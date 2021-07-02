import os
import pytest
from inputProcess import InputProcess
import configparser

def create_inputProcess_instance(outputQueue, profilerQueue, input_information, input_type):
    """ Create an instance of inputProcess.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    inputProcess = InputProcess(outputQueue, profilerQueue,
                                input_type, input_information, config, None, 'zeek')
    inputProcess.bro_timeout=1
    # override the self.print function to avoid broken pipes
    inputProcess.print = print
    return inputProcess


def test_read_zeek_files(outputQueue, profilerQueue, database):
     input_information= 'dataset/sample_zeek_files'
     inputProcess = create_inputProcess_instance(outputQueue, profilerQueue, input_information, 'file')
     # add zeek files to the db , needed by the read_zeek_files function
     for file in os.listdir(input_information):
        # Add log file to database
        file_name_without_extension = file[:file.index('.')]
        database.add_zeek_file(input_information+'/'+file_name_without_extension)
     # make sure lines are read from sample_zeek_files successfully
     assert inputProcess.read_zeek_files() > 0


# @pytest.mark.parametrize()
def test_handle_pcap_and_interface():
    pass
