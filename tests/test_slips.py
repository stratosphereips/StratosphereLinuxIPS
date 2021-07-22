""" Unit test for ../slips.py """
import os

from ..slips  import *

IS_IN_A_DOCKER_CONTAINER = os.environ.get('IS_IN_A_DOCKER_CONTAINER', False)

def do_nothing(*args):
    """ Used to override the print function because using the self.print causes broken pipes """
    pass


# Main Class tests

def create_Main_instance():
    """ returns an instance of Main() class in slips.py"""
    return Main()

def test_load_modules():
    main = create_Main_instance()
    failed_to_load_modules = main.load_modules(['template' , 'mldetection-1', 'ensembling'])[1]
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
    main = create_Main_instance()
    assert main.recognize_host_ip() != None

def test_create_folder_for_logs():
    main = create_Main_instance()
    assert main.create_folder_for_logs() != False

def test_check_redis_database():
    main = create_Main_instance()
    assert main.check_redis_database() == True

def test_clear_redis_cache_database():
    main = create_Main_instance()
    assert main.clear_redis_cache_database() == True

def test_check_zeek_or_bro():
    main = create_Main_instance()
    assert main.check_zeek_or_bro() != False

# Daemon tests
def create_Daemon_instance():
    """ returns an instance of Daemon() class in slips.py"""
    slips = create_Main_instance()
    return Daemon(slips)

def test_setup_std_streams():
    daemon = create_Daemon_instance()
    # __init__ calls read_configuration which calls setu_std_streams
    # we need to make sure that the files are there and empty
    assert os.path.exists(daemon.logsfile)
    assert os.path.exists(daemon.stdout)
    assert os.path.exists(daemon.stderr)
    assert os.path.exists(daemon.stdin)
    assert os.path.exists(daemon.pidfile)

def test_print():
    daemon = create_Daemon_instance()
    daemon.print("Test")
    with open(daemon.logsfile, 'r') as f:
        assert "Test" in f.read()

