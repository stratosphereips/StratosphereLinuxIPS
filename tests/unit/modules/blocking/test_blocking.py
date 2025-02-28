# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/blocking/blocking.py
this file needs sudoroot to run
"""

from tests.common_test_utils import IS_IN_A_DOCKER_CONTAINER
from tests.module_factory import ModuleFactory
import platform
import pytest
import os


def has_netadmin_cap():
    """Check the capabilities given to this docker container"""
    cmd = (
        'capsh --print | grep "Current:" | cut -d' " -f3 | grep cap_net_admin"
    )
    output = os.popen(cmd).read()
    return "cap_net_admin" in output


IS_DEPENDENCY_IMAGE = os.environ.get("IS_DEPENDENCY_IMAGE", False)
# ignore all tests if not using linux
linuxOS = pytest.mark.skipif(
    platform.system() != "Linux",
    reason="Blocking is supported only in Linux with root priveledges",
)
# When using docker in github actions,  we can't use --cap-add NET_ADMIN
# so all blocking module unit tests will fail because we don't have admin privs
# we use this environment variable to check if slips is
# running in github actions
isroot = pytest.mark.skipif(
    os.geteuid() != 0 or IS_DEPENDENCY_IMAGE is not False,
    reason="Blocking is supported only with root priveledges",
)

# blocking requires net admin capabilities in docker, otherwise skips blocking tests
has_net_admin_cap = pytest.mark.skipif(
    IS_IN_A_DOCKER_CONTAINER and not has_netadmin_cap(),
    reason="Blocking is supported only with --cap-add=NET_ADMIN",
)


@linuxOS
@isroot
@has_net_admin_cap
def is_slipschain_initialized() -> bool:
    blocking = ModuleFactory().create_blocking_obj()
    output = blocking.get_cmd_output(f"{blocking.sudo} iptables -S")
    rules = [
        "-A INPUT -j slipsBlocking",
        "-A FORWARD -j slipsBlocking",
        "-A OUTPUT -j slipsBlocking",
    ]
    return all(rule in output for rule in rules)


@linuxOS
@isroot
@has_net_admin_cap
def test_initialize_chains_in_firewall():
    blocking = ModuleFactory().create_blocking_obj()
    # manually set the firewall
    blocking.firewall = "iptables"
    blocking.initialize_chains_in_firewall()
    assert is_slipschain_initialized() is True


# todo
# def test_delete_slipsBlocking_chain():
#     blocking = ModuleFactory().create_blocking_obj()
#     # first make sure they are initialized
#     if not is_slipschain_initialized(output_queue):
#         blocking.initialize_chains_in_firewall()
#     os.system('./slips.py -cb')
#     assert is_slipschain_initialized(output_queue) == False


@linuxOS
@isroot
@has_net_admin_cap
def test_block_ip():
    blocking = ModuleFactory().create_blocking_obj()
    blocking.initialize_chains_in_firewall()
    if not blocking.is_ip_blocked("2.2.0.0"):
        ip = "2.2.0.0"
        from_ = True
        to = True
        assert blocking.block_ip(ip, from_, to) is True


@linuxOS
@isroot
@has_net_admin_cap
def test_unblock_ip():
    blocking = ModuleFactory().create_blocking_obj()
    ip = "2.2.0.0"
    from_ = True
    to = True
    # first make sure that it's blocked
    if not blocking.is_ip_blocked("2.2.0.0"):
        assert blocking.block_ip(ip, from_, to) is True
    assert blocking.unblock_ip(ip, from_, to) is True
