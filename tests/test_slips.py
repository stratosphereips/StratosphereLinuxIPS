""" Unit test for ../slips.py """
import os

from ..slips  import *
import os

IS_IN_A_DOCKER_CONTAINER = os.environ.get('IS_IN_A_DOCKER_CONTAINER', False)


def test_load_modules():
    failed_to_load_modules = load_modules(['template' , 'mldetection-1', 'ensembling'])[1]
    assert failed_to_load_modules == 0

#
# @pytest.mark.skipif(IS_IN_A_DOCKER_CONTAINER, reason='This functionality is not supported in docker')
# def test_save():
#     """ tests saving the database"""
#     # this test needs sudo
#     command = f'sudo ./slips.py -l -f dataset/sample_zeek_files -s > /dev/null 2>&1'
#     # this function returns when slips is done
#     os.system(command)
#     assert os.path.exists('redis_backups/sample_zeek_files.rdb')
#     os.remove('redis_backups/sample_zeek_files.rdb')
#
# @pytest.mark.skipif(IS_IN_A_DOCKER_CONTAINER, reason='This functionality is not supported in docker')
# def test_load(database):
#     """ tests loading the database"""
#     # make sure the db exists
#     if not os.path.exists('redis_backups/sample_zeek_files.rdb'):
#         # save it if it doesn't exist
#         command = f'sudo ./slips.py -l -f dataset/sample_zeek_files -s > /dev/null 2>&1'
#         os.system(command)
#
#     # this test needs sudo
#     command = f'sudo ./slips.py -d redis_backups/sample_zeek_files.rdb  > /dev/null 2>&1'
#     # this function returns when slips is done
#     os.system(command)
#     # wait for the command to finish
#     time.sleep(3)
#     # check a random value to make sure the db is loaded
#     x = database.r.hgetall('profile_10.0.2.2_timewindow1_flows')
#     assert 'CDm47v3jrYL8lx0cOh' in str(x)

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

