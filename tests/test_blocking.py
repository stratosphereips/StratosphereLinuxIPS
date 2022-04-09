""" Unit test for modules/blocking/blocking.py
this file needs sudoroot to run
"""
from ..modules.blocking.blocking import Module
import configparser
import platform
import pytest
import os

IS_DEPENDENCY_IMAGE = os.environ.get('IS_DEPENDENCY_IMAGE', False)
# ignore all tests if not using linux
pytestmark = pytest.mark.skipif(platform.system() != 'Linux', reason='Blocking is supported only in Linux with root priveledges')
# When using docker in github actions,  we can't use --cap-add NET_ADMIN
# so all blocking module unit tests will fail because we don't have admin privs
# we use this environment variable to check if slips is
# running in github actions
pytestmark = pytest.mark.skipif(os.geteuid() != 0 or IS_DEPENDENCY_IMAGE != False ,
                                reason='Blocking is supported only with root priveledges')

def do_nothing(*args):
    """ Used to override the print function because using the print causes broken pipes """
    pass

def create_blocking_instance(outputQueue):
    """ Create an instance of blocking.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    blocking = Module(outputQueue, config)
    # override the print function to avoid broken pipes
    blocking.print = do_nothing
    return blocking


def is_slipschain_initialized(outputQueue) -> bool:
    blocking = create_blocking_instance(outputQueue)
    output = blocking.get_cmd_output(f'{blocking.sudo} iptables -S')
    rules = ['-A INPUT -j slipsBlocking' , '-A FORWARD -j slipsBlocking','-A OUTPUT -j slipsBlocking']
    for rule in rules:
        if rule not in output:
            return False
    return True

def test_initialize_chains_in_firewall(outputQueue, database):
    blocking = create_blocking_instance(outputQueue)
    # manually set the firewall
    blocking.firewall = 'iptables'
    blocking.initialize_chains_in_firewall()
    assert is_slipschain_initialized(outputQueue) == True
# todo
# def test_delete_slipsBlocking_chain(outputQueue, database):
#     blocking = create_blocking_instance(outputQueue)
#     # first make sure they are initialized
#     if not is_slipschain_initialized(outputQueue):
#         blocking.initialize_chains_in_firewall()
#     os.system('./slips.py -cb')
#     assert is_slipschain_initialized(outputQueue) == False

def test_block_ip(outputQueue, database):
    blocking = create_blocking_instance(outputQueue)
    blocking.initialize_chains_in_firewall()
    if not blocking.is_ip_blocked('2.2.0.0'):
        ip = "2.2.0.0"
        from_ = True
        to = True
        assert blocking.block_ip(ip,from_,to) == True

def test_unblock_ip(outputQueue, database):
    blocking = create_blocking_instance(outputQueue)
    ip = "2.2.0.0"
    from_ = True
    to = True
    # first make sure that it's blocked
    if not blocking.is_ip_blocked('2.2.0.0'):
        assert blocking.block_ip(ip,from_,to) == True
    assert blocking.unblock_ip(ip,from_,to) == True





