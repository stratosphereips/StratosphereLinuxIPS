import time,os

def test_read_zeek_files(inputProcess, database):
     input_information = 'dataset/sample_zeek_files'
     for file in os.listdir(input_information):
        # Add log file to database
        file_name_without_extension = file[:file.index('.')]
        database.add_zeek_file(input_information+'/'+file_name_without_extension)
     # make sure lines are read from sample_zeek_files successfully
     assert inputProcess.read_zeek_files() > 0
