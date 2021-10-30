"""
This file tests all kinds of input in our dataset/
It checks a random evidence and the total number of profiles in every file
"""
import os
import pytest
import  shutil
alerts_file = 'alerts.json'


def get_profiles(output_dir):
    """ This function parses stdout of slips and determines the total number of profiles
    this is an alternative for get_profiles(output_dir) because now slips clears the database after stopping
    :param output_dir: this is where slips_output.txt is, it changes based on the what file we're testing
    """
    with open(f'{output_dir}slips_output.txt', 'rb') as f:
        # iterate from the end of the file
        f.seek(-2, os.SEEK_END)
        bytes_read = 0
        while True:
            # we reached the beginning of the file or is there more to read?
            if f.tell() == 0:
                # no more lines to read
                return 'Number of profiles not found'
            # try to find the \n that marks the beginning of the line
            while f.read(1) != b'\n':
                f.seek(-2, os.SEEK_CUR)
            # we reached the beginning of a line, read the line to the right
            line = f.readline().decode()
            # check if this line has the number of profiles we need
            if 'Total Number' in line:
                line = line.split('.')[0] # Number of Profiles in DB so far: 2
                profiles = line[line.index(": ")+1:].strip()
                return int(profiles)
            # seek to the beginning of the line before the current
            bytes_read+=len(line)
            f.seek(-bytes_read, 2)
            continue

def is_evidence_present(log_file, expected_evidence):
    """ Function to read the log file line by line and returns when it finds the expected evidence """
    with open(log_file, 'r') as f:
        line = f.readline()
        while line:
            if expected_evidence in line:
                return True
            line = f.readline()
        # evidence not found in any line
        return False

def has_errors(output_file):
    """ function to parse slips_output file and check for errors """
    # we can't redirect stderr to a file and check it because we catch all exceptions in slips
    with open(output_file ,'r') as f:
        for line in f:
            if '<class' in line:
                return True
    return False


@pytest.mark.parametrize("pcap_path,expected_profiles, output_dir, expected_evidence",
                         [('dataset/hide-and-seek-short.pcap',15,'pcap/', 'New horizontal port scan to port 23'),
                          ('dataset/arp-only.pcap',3,'pcap2/','performing ARP scan')])
def test_pcap(pcap_path, expected_profiles, database, output_dir, expected_evidence):
    try:
        os.mkdir(output_dir)
    except FileExistsError:
        pass
    output_file = f'{output_dir}slips_output.txt'
    command = f'./slips.py -c slips.conf -l -f {pcap_path} -o {output_dir} > {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)
    profiles = get_profiles(output_dir)
    assert profiles > expected_profiles
    log_file = output_dir + alerts_file
    assert is_evidence_present(log_file, expected_evidence) == True
    assert has_errors(output_file) == False
    shutil.rmtree(output_dir)

@pytest.mark.parametrize("binetflow_path, expected_profiles, expected_evidence, output_dir", [
     ('dataset/test2.binetflow',1,'C&C channels detection','test2/'),
    ('dataset/test3.binetflow',20,'New horizontal port scan to port 3389','test3/'),
      ('dataset/test4.binetflow',2,'New horizontal port scan to port 81','test4/'),
     ('dataset/test5.binetflow',4,'C&C channels detection','test5/')])
def test_binetflow(database, binetflow_path, expected_profiles, expected_evidence,  output_dir ):
    try:
        os.mkdir(output_dir)
    except FileExistsError:
        pass
    output_file = f'{output_dir}slips_output.txt'    
    command = f'./slips.py -l -c slips.conf -o {output_dir} -f {binetflow_path}  >  {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)
    profiles = get_profiles(output_dir)
    assert profiles > expected_profiles
    log_file = output_dir + alerts_file
    assert is_evidence_present(log_file, expected_evidence) == True
    assert has_errors(output_file) == False
    shutil.rmtree(output_dir)


@pytest.mark.parametrize("zeek_dir_path,expected_profiles, expected_evidence,  output_dir",
     [('dataset/sample_zeek_files',4,'SSL certificate validation failed with (certificate is not yet valid)','sample_zeek_files/'),
      ('dataset/sample_zeek_files-2',20,'Horizontal port scan','sample_zeek_files-2/')])
def test_zeek_dir(database, zeek_dir_path, expected_profiles, expected_evidence,  output_dir):
    import time
    time.sleep(3)
    try:
        os.mkdir(output_dir)
    except FileExistsError:
        pass
    output_file = f'{output_dir}slips_output.txt'
    command = f'./slips.py -c slips.conf -l -f {zeek_dir_path}  -o {output_dir} > {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)
    profiles = get_profiles(output_dir)
    assert profiles > expected_profiles
    log_file = output_dir + alerts_file
    assert is_evidence_present(log_file, expected_evidence) == True
    assert has_errors(output_file) == False
    shutil.rmtree(output_dir)

@pytest.mark.parametrize("conn_log_path, expected_profiles, expected_evidence,  output_dir",
     [('dataset/sample_zeek_files/conn.log',4,'C&C channels detection','conn_log/'),
      ('dataset/sample_zeek_files-2/conn.log',5,'C&C channels detection','conn_log-2/')])
def test_zeek_conn_log(database, conn_log_path, expected_profiles, expected_evidence,  output_dir):
    try:
        os.mkdir(output_dir)
    except FileExistsError:
        pass
    output_file = f'{output_dir}slips_output.txt'
    command = f'./slips.py -l -c slips.conf -f {conn_log_path}  -o {output_dir} > {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)
    profiles = get_profiles(output_dir)
    assert profiles > expected_profiles
    log_file = output_dir + alerts_file
    assert is_evidence_present(log_file, expected_evidence) == True
    assert has_errors(output_file) == False
    shutil.rmtree(output_dir)

@pytest.mark.parametrize('suricata_path,  output_dir',[('dataset/suricata-flows.json','suricata/')])
def test_suricata(database, suricata_path,  output_dir):
    try:
        os.mkdir(output_dir)
    except FileExistsError:
        pass
    output_file = f'{output_dir}slips_output.txt'
    command = f'./slips.py -c slips.conf -l -f {suricata_path} -o {output_dir} > {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)
    profiles = get_profiles(output_dir)
    expected_evidence = 'New vertical port scan detected'
    assert profiles > 90
    log_file = output_dir + alerts_file
    assert is_evidence_present(log_file, expected_evidence) == True
    assert has_errors(output_file) == False
    shutil.rmtree(output_dir)

@pytest.mark.parametrize('nfdump_path,  output_dir',[('dataset/test.nfdump', 'nfdump/')])
def test_nfdump(database, nfdump_path,  output_dir):
    try:
        os.mkdir(output_dir)
    except FileExistsError:
        pass
    output_file = f'{output_dir}slips_output.txt'
    command = f'./slips.py -c slips.conf -l -f {nfdump_path}  -o {output_dir} > {output_file} 2>&1'
    # this function returns when slips is done
    os.system(command)
    profiles = get_profiles(output_dir)
    expected_evidence = 'C&C channels detection'
    # make sure slips generated profiles for this file (can't the number of profiles exactly because slips doesn't generate a const number of profiles per file)
    assert profiles > 0
    log_file = output_dir + alerts_file
    assert is_evidence_present(log_file, expected_evidence) == True
    assert has_errors(output_file) == False
    shutil.rmtree(output_dir)