"""
This file tests all kinds of input in our datasert/
It checks a random evidence and the total number of profiles in every file
"""
import os
import pytest
import  shutil
alerts_file = 'alerts.json'
# clear the database before starting
command = './slips.py -cc'
os.system(command)

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
            if 'Total' in line:
                line = line.split('.')[0] # Number of Profiles in DB so far: 2
                profiles = line[line.index(": ")+1:].strip()
                return int(profiles)
            # seek to the beginning of the line before the current
            bytes_read+=len(line)
            f.seek(-bytes_read, 2)
            continue


@pytest.mark.parametrize("pcap_path, output_dir", [('dataset/hide-and-seek-short.pcap','pcap/')])
def test_pcap(pcap_path, database, output_dir):
    try:
        os.mkdir(output_dir)
    except FileExistsError:
        pass
    command = f'./slips.py -c slips.conf -l -f {pcap_path} -o {output_dir} > {output_dir}slips_output.txt 2>&1'
    # this function returns when slips is done
    os.system(command)
    profiles = get_profiles(output_dir)
    assert profiles > 15
    expected_evidence = 'New horizontal port scan detected to port 23'
    log_file = output_dir + alerts_file
    with open(log_file, 'r') as f:
        assert expected_evidence in f.read()
    shutil.rmtree(output_dir)

@pytest.mark.parametrize("binetflow_path, expected_profiles, expected_evidence,db0, db1, output_dir", [
     ('dataset/test2.binetflow',1,'New horizontal port scan detected to port 443','2','3','test2/'),
    ('dataset/test3.binetflow',20,'New horizontal port scan detected to port 3389','4','5','test3/'),
      ('dataset/test4.binetflow',2,'New horizontal port scan detected to port 81','6','7','test4/'),
     ('dataset/test5.binetflow',4,'RNN C&C channels detection','8','9','test5/')])
def test_binetflow(database, binetflow_path, expected_profiles, expected_evidence, db0, db1, output_dir ):
    try:
        os.mkdir(output_dir)
    except FileExistsError:
        pass
    command = f'./slips.py -l -c slips.conf -o {output_dir} -f {binetflow_path} -db {db0} {db1} > {output_dir}slips_output.txt 2>&1'
    # this function returns when slips is done
    os.system(command)
    profiles = get_profiles(output_dir)
    assert profiles > expected_profiles
    log_file = output_dir + alerts_file
    with open(log_file, 'r') as f:
        assert expected_evidence in f.read()
    shutil.rmtree(output_dir)


@pytest.mark.parametrize("zeek_dir_path,expected_profiles, expected_evidence, db0, db1, output_dir",
     [('dataset/sample_zeek_files',4,'SSL certificate validation failed with (certificate is not yet valid)','8','9','sample_zeek_files/'),
      ('dataset/sample_zeek_files-2',20,'Horizontal port scan','10','11','sample_zeek_files-2/')])
def test_zeek_dir(database, zeek_dir_path, expected_profiles, expected_evidence, db0, db1, output_dir):
    import time
    time.sleep(3)
    try:
        os.mkdir(output_dir)
    except FileExistsError:
        pass
    command = f'./slips.py -c slips.conf -l -f {zeek_dir_path} -db {db0} {db1} -o {output_dir} > {output_dir}slips_output.txt 2>&1'
    # this function returns when slips is done
    os.system(command)
    profiles = get_profiles(output_dir)
    assert profiles > expected_profiles
    log_file = output_dir + alerts_file
    with open(log_file, 'r') as f:
        alerts = f.read()
        assert expected_evidence in alerts
    shutil.rmtree(output_dir)

@pytest.mark.parametrize("conn_log_path, expected_profiles, expected_evidence, db0, db1, output_dir",
     [('dataset/sample_zeek_files/conn.log',4,'RNN C&C channels detection','12','13','conn_log/'),
      ('dataset/sample_zeek_files-2/conn.log',5,'RNN C&C channels detection','14','15','conn_log-2/')])
def test_zeek_conn_log(database, conn_log_path, expected_profiles, expected_evidence, db0, db1, output_dir):
    try:
        os.mkdir(output_dir)
    except FileExistsError:
        pass
    command = f'./slips.py -l -c slips.conf -f {conn_log_path} -db {db0} {db1} -o {output_dir} > {output_dir}slips_output.txt 2>&1'
    # this function returns when slips is done
    os.system(command)
    profiles = get_profiles(output_dir)
    assert profiles > expected_profiles
    log_file = output_dir + alerts_file
    with open(log_file, 'r') as f:
        assert expected_evidence in f.read()
    shutil.rmtree(output_dir)

@pytest.mark.parametrize('suricata_path, db0, db1, output_dir',[('dataset/suricata-flows.json','0','1','suricata/')])
def test_suricata(database, suricata_path, db0, db1, output_dir):
    try:
        os.mkdir(output_dir)
    except FileExistsError:
        pass
    # clear cache first because we'll be using a db that's been used before
    command = "./slips.py -c slips.conf -cc"
    os.system(command)
    command = f'./slips.py -c slips.conf -l -f {suricata_path} -db {db0} {db1} -o {output_dir} > {output_dir}slips_output.txt 2>&1'
    # this function returns when slips is done
    os.system(command)
    profiles = get_profiles(output_dir)
    expected_evidence = 'New vertical port scan detected to IP 192.168.1.129 from 193.46.255.92'
    assert profiles > 90
    log_file = output_dir + alerts_file
    with open(log_file, 'r') as f:
        assert expected_evidence in f.read()
    shutil.rmtree(output_dir)

@pytest.mark.parametrize('nfdump_path, db0, db1, output_dir',[('dataset/test.nfdump', '2','3','nfdump/')])
def test_nfdump(database, nfdump_path, db0, db1, output_dir):
    try:
        os.mkdir(output_dir)
    except FileExistsError:
        pass
    # clear cache first because we'll be using a db that's been used before
    command = "./slips.py -c slips.conf -cc"
    os.system(command)
    command = f'./slips.py -c slips.conf -l -f {nfdump_path} -db {db0} {db1} -o {output_dir} > {output_dir}slips_output.txt 2>&1'
    # this function returns when slips is done
    os.system(command)
    profiles = get_profiles(output_dir)
    expected_evidence = 'RNN C&C channels detection'
    # make sure slips generated profiles for this file (can't the number of profiles exactly because slips doesn't generate a const number of profiles per file)
    assert profiles > 0
    log_file = output_dir + alerts_file
    with open(log_file, 'r') as f:
        evidence = f.read()
        assert expected_evidence in evidence
    shutil.rmtree(output_dir)
