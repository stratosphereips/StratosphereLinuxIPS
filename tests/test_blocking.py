# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/blocking/blocking.py
this file needs sudoroot to run
"""
from tests.module_factory import ModuleFactory
import subprocess
from unittest.mock import patch
import pytest
import json

import platform
import os
from unittest.mock import call
from unittest import mock
from tests.common_test_utils import IS_IN_A_DOCKER_CONTAINER


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


def test_init_chains_in_firewall():
    blocking = ModuleFactory().create_blocking_obj()
    with patch("os.system") as mock_system, patch.object(
        blocking.__class__, "_get_cmd_output"
    ) as mock_get_output:

        # simulate slipsBlocking not in any chain
        mock_get_output.side_effect = ["", "", ""]  # input, output, forward

        blocking._init_chains_in_firewall()

        # ensure the chain is created
        mock_system.assert_any_call(
            f"{blocking.sudo} iptables -N slipsBlocking >/dev/null 2>&1"
        )

        # ensure the redirections are added
        expected_calls = [
            call(
                f"{blocking.sudo} iptables -I INPUT -j "
                f"slipsBlocking >/dev/null 2>&1"
            ),
            call(
                f"{blocking.sudo} iptables -I OUTPUT -j "
                f"slipsBlocking >/dev/null 2>&1"
            ),
            call(
                f"{blocking.sudo} iptables -I FORWARD -j "
                f"slipsBlocking >/dev/null 2>&1"
            ),
        ]
        mock_system.assert_has_calls(expected_calls, any_order=True)

        # ensure _get_cmd_output was called with correct chain checks
        mock_get_output.assert_has_calls(
            [
                call(f"{blocking.sudo} iptables -nvL INPUT"),
                call(f"{blocking.sudo} iptables -nvL OUTPUT"),
                call(f"{blocking.sudo} iptables -nvL FORWARD"),
            ]
        )


def test_is_ip_already_blocked():
    blocking = ModuleFactory().create_blocking_obj()
    # define the fake output that subprocess.run should return
    fake_output = "Chain slipsBlocking (1 references)\n  target     prot opt source               destination\n  REJECT     all  --  192.168.1.100        anywhere"

    # mock subprocess.run to return the fake output
    with mock.patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = fake_output.encode("utf-8")

        ip = "192.168.1.100"

        result = blocking._is_ip_already_blocked(ip)

        # assert the result is True because the IP is in the fake output
        assert result is True

        # assert subprocess.run was called with the correct command
        mock_run.assert_called_once_with(
            ["sudo", "iptables", "-L", "slipsBlocking", "-v", "-n"],
            stdout=subprocess.PIPE,
        )


@pytest.mark.parametrize(
    "ip,flags,already_blocked,expected",
    [
        ("192.168.1.10", {}, False, True),  # normal block
        ("192.168.1.10", {"from_": True}, False, True),  # only from
        ("192.168.1.10", {"to": True}, False, True),  # only to
        ("192.168.1.10", {}, True, False),  # already blocked
        (None, {}, False, False),  # invalid ip type
    ],
)
def test_block_ip(ip, flags, already_blocked, expected):
    blocking = ModuleFactory().create_blocking_obj()
    blocking.firewall = "iptables"
    blocking.sudo = "sudo"

    with patch.object(
        blocking, "_is_ip_already_blocked", return_value=already_blocked
    ), patch(
        "modules.blocking.exec_iptables_cmd.exec_iptables_command",
        return_value=True,
    ) as _, patch.object(
        blocking, "print"
    ), patch.object(
        blocking, "log"
    ), patch.object(
        blocking.db, "set_blocked_ip"
    ):

        result = blocking._block_ip(ip, flags)
        assert result is expected


@pytest.mark.parametrize(
    "block,expected_block_called",
    [
        (True, True),
        (False, False),
    ],
)
def test_main_blocking_logic(block, expected_block_called):
    blocking = ModuleFactory().create_blocking_obj()
    blocking_data = {
        "ip": "1.2.3.4",
        "tw": 5,
        "block": block,
        "from": True,
        "to": False,
        "dport": 80,
        "sport": 12345,
        "protocol": "tcp",
    }

    msg_block = {"data": json.dumps(blocking_data)}
    msg_tw_closed = None

    with patch.object(
        blocking, "get_msg", side_effect=[msg_block, msg_tw_closed]
    ):
        with patch.object(blocking, "_block_ip") as mock_block, patch.object(
            blocking.unblocker, "unblock_request"
        ) as mock_unblock_req, patch.object(
            blocking.unblocker, "update_requests"
        ) as mock_update:

            blocking.main()

            if expected_block_called:
                mock_block.assert_called_once_with(
                    "1.2.3.4",
                    {
                        "from_": True,
                        "to": False,
                        "dport": 80,
                        "sport": 12345,
                        "protocol": "tcp",
                    },
                )
            else:
                mock_block.assert_not_called()

            mock_unblock_req.assert_called_once_with(
                "1.2.3.4",
                5,
                {
                    "from_": True,
                    "to": False,
                    "dport": 80,
                    "sport": 12345,
                    "protocol": "tcp",
                },
            )
            mock_update.assert_not_called()


def test_main_tw_closed_triggers_update():
    blocking = ModuleFactory().create_blocking_obj()

    msg_block = None
    msg_tw_closed = {"data": "whatever"}

    with patch.object(
        blocking, "get_msg", side_effect=[msg_block, msg_tw_closed]
    ):
        with patch.object(
            blocking.unblocker, "update_requests"
        ) as mock_update:
            blocking.main()
            mock_update.assert_called_once()
