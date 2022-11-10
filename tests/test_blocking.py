"""Unit test for modules/blocking/blocking.py
this file needs sudoroot to run
"""
from ..modules.blocking.blocking import Module
import configparser
import platform
import pytest
from subprocess import check_output
import os



def has_netadmin_cap():
    """ Check the capabilities given to this docker container"""
    cmd = 'capsh --print | grep "Current:" | cut -d' ' -f3 | grep cap_net_admin'
    output = os.popen(cmd).read()
    return True if 'cap_net_admin' in output else False


IS_DEPENDENCY_IMAGE = os.environ.get('IS_DEPENDENCY_IMAGE', False)
IS_IN_A_DOCKER_CONTAINER = os.environ.get('IS_IN_A_DOCKER_CONTAINER', False)
# ignore all tests if not using linux
linuxOS = pytest.mark.skipif(
    platform.system() != 'Linux',
    reason='Blocking is supported only in Linux with root priveledges',
)
# When using docker in github actions,  we can't use --cap-add NET_ADMIN
# so all blocking module unit tests will fail because we don't have admin privs
# we use this environment variable to check if slips is
# running in github actions
isroot = pytest.mark.skipif(
    os.geteuid() != 0 or IS_DEPENDENCY_IMAGE != False,
    reason='Blocking is supported only with root priveledges',
)

# blocking requires net admin capabilities in docker, otherwise skips blocking tests
has_net_admin_cap = pytest.mark.skipif(
    IS_IN_A_DOCKER_CONTAINER and not has_netadmin_cap() ,
    reason='Blocking is supported only with --cap-add=NET_ADMIN',
)



def do_nothing(*args):
    """Used to override the print function because using the print causes broken pipes"""
    pass


def create_blocking_instance(outputQueue):
    """Create an instance of blocking.py
    needed by every other test in this file"""
    blocking = Module(outputQueue, 6380)
    # override the print function to avoid broken pipes
    blocking.print = do_nothing
    return blocking

@linuxOS
@isroot
@has_net_admin_cap
def is_slipschain_initialized(outputQueue) -> bool:
    blocking = create_blocking_instance(outputQueue)
    output = blocking.get_cmd_output(f'{blocking.sudo} iptables -S')
    rules = [
        '-A INPUT -j slipsBlocking',
        '-A FORWARD -j slipsBlocking',
        '-A OUTPUT -j slipsBlocking',
    ]
    for rule in rules:
        if rule not in output:
            return False
    return True

@linuxOS
@isroot
@has_net_admin_cap
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

@linuxOS
@isroot
@has_net_admin_cap
def test_block_ip(outputQueue, database):
    blocking = create_blocking_instance(outputQueue)
    blocking.initialize_chains_in_firewall()
    if not blocking.is_ip_blocked('2.2.0.0'):
        ip = '2.2.0.0'
        from_ = True
        to = True
        assert blocking.block_ip(ip, from_, to) == True

@linuxOS
@isroot
@has_net_admin_cap
def test_unblock_ip(outputQueue, database):
    blocking = create_blocking_instance(outputQueue)
    ip = '2.2.0.0'
    from_ = True
    to = True
    # first make sure that it's blocked
    if not blocking.is_ip_blocked('2.2.0.0'):
        assert blocking.block_ip(ip, from_, to) == True
    assert blocking.unblock_ip(ip, from_, to) == True
