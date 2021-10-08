""" Unit test for ../slips.py """
import os

from ..slips  import *
import time

def test_load_modules():
    failed_to_load_modules = load_modules(['template' , 'mldetection-1', 'ensembling'])[1]
    assert failed_to_load_modules == 0

def test_save():
    """ tests saving the database"""
    # this test needs sudo
    command = f'sudo ./slips.py -l -f dataset/sample_zeek_files-2 -s > /dev/null 2>&1'
    # this function returns when slips is done
    os.system(command)
    assert os.path.exists('redis_backups/sample_zeek_files-2.rdb')
    os.remove('redis_backups/sample_zeek_files-2.rdb')


def test_load(database):
    """ tests loading the database"""
    # make sure the db exists
    if not os.path.exists('redis_backups/sample_zeek_files-2'):
        # save it if it doesn't exist
        command = f'sudo ./slips.py -l -f dataset/sample_zeek_files-2 -s > /dev/null 2>&1'
        os.system(command)

    # this test needs sudo
    command = f'sudo ./slips.py -d redis_backups/sample_zeek_files-2.rdb  > /dev/null 2>&1'
    # this function returns when slips is done
    os.system(command)
    time.sleep(3)
    # a random value to make sure the db is loaded
    x = database.r.hgetall('profile_147.32.83.190_timewindow1_flows')
    assert 'CW4pvYSwLQaQ87q74' in str(x)

def test_recognize_host_ip():
    assert recognize_host_ip() != None

def test_create_folder_for_logs():
    assert create_folder_for_logs() != False

def test_check_redis_database():
    assert check_redis_database() == True

def test_clear_redis_cache_database():
    assert clear_redis_cache_database() == True

def test_check_zeek_or_bro():
    assert check_zeek_or_bro() != False

