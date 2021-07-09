""" Unit test for ../slips.py """
from ..slips  import *


def test_load_modules():
    failed_to_load_modules = load_modules(['template' , 'mldetection-1', 'ensembling'])[1]
    assert failed_to_load_modules == 0

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

