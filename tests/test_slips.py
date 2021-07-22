""" Unit test for ../slips.py"""
from ..slips  import *
import os

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

