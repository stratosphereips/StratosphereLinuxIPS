""" Unit test for modules/blocking/blocking.py
this file needs sudoroot to run
"""
from ..modules.blocking.blocking import Module
import configparser
import os


def do_nothing(*args):
    """ Used to override the print function because using the self.print causes broken pipes """
    pass

def create_blocking_instance(outputQueue):
    """ Create an instance of blocking.py
        needed by every other test in this file  """
    config = configparser.ConfigParser()
    blocking = Module(outputQueue, config)
    # override the self.print function to avoid broken pipes
    blocking.print = do_nothing
    blocking.sudo = 'sudo '
    return blocking


def is_slipschain_initialized(outputQueue) -> bool:
    blocking = create_blocking_instance(outputQueue)
    output = blocking.get_cmd_output('sudo iptables -S')
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





