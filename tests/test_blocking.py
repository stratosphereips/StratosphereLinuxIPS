# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/blocking/blocking.py"""
from tests.module_factory import ModuleFactory
import subprocess
from unittest.mock import patch
import pytest
import json

from unittest.mock import call
from unittest import mock


def test_init_chains_in_firewall():
    blocking = ModuleFactory().create_blocking_obj()
    with (
        patch("os.system") as mock_system,
        patch.object(blocking.__class__, "_get_cmd_output") as mock_get_output,
    ):

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
        ip_tables_cmd = ["iptables", "-L", "slipsBlocking", "-v", "-n"]
        if blocking.sudo:
            expected_cmd = [blocking.sudo] + ip_tables_cmd
        else:
            expected_cmd = ip_tables_cmd

        # assert subprocess.run was called with the correct command
        mock_run.assert_called_once_with(
            expected_cmd,
            stdout=subprocess.PIPE,
        )


@pytest.mark.parametrize(
    "ip,flags,already_blocked, exec_iptables_command, expected",
    [
        ("192.168.1.10", {}, False, True, True),  # normal block
        ("192.168.1.10", {"from_": True}, False, True, True),  # only from
        ("192.168.1.10", {"to": True}, False, True, True),  # only to
        ("192.168.1.10", {}, True, True, False),  # already blocked
        (None, {}, False, False, False),  # invalid ip type
    ],
)
def test_block_ip(ip, flags, already_blocked, exec_iptables_command, expected):
    blocking = ModuleFactory().create_blocking_obj()
    blocking.firewall = "iptables"

    # blocking.sudo = "sudo"

    with (
        patch.object(
            blocking, "_is_ip_already_blocked", return_value=already_blocked
        ),
        patch(
            "modules.blocking.exec_iptables_cmd.exec_iptables_command",
            return_value=True,
        ) as _,
        patch.object(blocking, "print"),
        patch.object(blocking, "log"),
        patch.object(blocking.db, "set_blocked_ip"),
        patch(
            "modules.blocking.exec_iptables_cmd.exec_iptables_command",
            return_value=exec_iptables_command,
        ),
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
        "interface": "eth0",
    }

    msg_block = {"data": json.dumps(blocking_data)}
    msg_tw_closed = None

    with patch.object(
        blocking, "get_msg", side_effect=[msg_block, msg_tw_closed]
    ):
        with (
            patch.object(blocking, "_block_ip") as mock_block,
            patch.object(
                blocking.unblocker, "unblock_request"
            ) as mock_unblock_req,
            patch.object(blocking.unblocker, "update_requests") as mock_update,
        ):

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
                        "interface": "eth0",
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
                    "interface": "eth0",
                },
            )
            mock_update.assert_not_called()


@pytest.mark.parametrize(
    "last_closed_tw, msg_data, should_call",
    [
        ("tw1", "profileid_123_tw2", True),  # new tw, should call update
        ("tw2", "profileid_234_tw2", False),  # same tw, no update
    ],
)
def test_main_tw_closed_triggers_update(last_closed_tw, msg_data, should_call):
    blocking = ModuleFactory().create_blocking_obj()
    blocking.last_closed_tw = last_closed_tw

    msg_tw_closed = {"data": msg_data, "channel": "tw_closed"}

    with patch.object(blocking, "get_msg", side_effect=[False, msg_tw_closed]):
        with patch.object(
            blocking.unblocker, "update_requests"
        ) as mock_update:
            blocking.main()
            if should_call:
                mock_update.assert_called_once()
            else:
                mock_update.assert_not_called()
