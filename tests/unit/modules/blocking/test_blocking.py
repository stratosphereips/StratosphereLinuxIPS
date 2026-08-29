# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit test for modules/blocking/blocking.py"""
import pytest
import json
import subprocess
from unittest.mock import call, patch

from slips_files.core.structures.evidence import TimeWindow
from tests.module_factory import ModuleFactory


def test_init_chains_in_firewall():
    blocking = ModuleFactory().create_blocking_obj()
    with (
        patch("modules.blocking.blocking.os.system") as mock_system,
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
    with patch("subprocess.run") as mock_run:
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
    "ip,flags,already_blocked,exec_result,expected,expected_call_flags",
    [
        ("192.168.1.10", {}, False, True, True, ["-s", "-d"]),  # normal
        ("192.168.1.10", {"from_": True}, False, True, True, ["-s"]),
        ("192.168.1.10", {"to": True}, False, True, True, ["-d"]),
        ("192.168.1.10", {}, True, True, True, []),  # already blocked
        (None, {}, False, True, False, []),  # invalid ip type
    ],
)
def test_block_ip(
    ip,
    flags,
    already_blocked,
    exec_result,
    expected,
    expected_call_flags,
):
    blocking = ModuleFactory().create_blocking_obj()
    blocking.firewall = "iptables"

    options = {"protocol": "", "dport": "", "sport": ""}

    with (
        patch.object(
            blocking, "_is_ip_already_blocked", return_value=already_blocked
        ),
        patch(
            "modules.blocking.blocking.exec_iptables_command",
            return_value=exec_result,
        ) as mock_exec,
        patch.object(blocking, "print"),
        patch.object(blocking, "log"),
        patch.object(blocking.db, "set_blocked_ip"),
    ):

        result = blocking._block_ip(ip, flags)
        assert result is expected
        if expected_call_flags:
            expected_calls = [
                call(
                    blocking.sudo,
                    action="insert",
                    ip_to_block=ip,
                    flag=flag,
                    options=options,
                    comment="Slips rule",
                )
                for flag in expected_call_flags
            ]
            mock_exec.assert_has_calls(expected_calls)
            assert mock_exec.call_count == len(expected_call_flags)
        else:
            mock_exec.assert_not_called()


def test_block_ip_tracks_preexisting_firewall_rule() -> None:
    """Track an iptables rule inherited without a Redis blocked timestamp."""
    blocking = ModuleFactory().create_blocking_obj()
    blocking.firewall = "iptables"
    blocking.db.get_blocking_timestamp.return_value = None

    with patch.object(blocking, "_is_ip_already_blocked", return_value=True):
        result = blocking._block_ip("192.168.1.10", {})

    assert result is True
    blocking.db.set_blocked_ip.assert_called_once_with("192.168.1.10")


def test_block_ip_uses_direction_specific_private_interfaces() -> None:
    """Use input matching for source rules and output matching for targets."""
    blocking = ModuleFactory().create_blocking_obj()
    blocking.firewall = "iptables"
    flags = {
        "from_": True,
        "to": True,
        "interface": "eth0",
    }

    with (
        patch.object(blocking, "_is_ip_already_blocked", return_value=False),
        patch(
            "modules.blocking.blocking.exec_iptables_command",
            return_value=True,
        ) as execute,
        patch.object(blocking, "print"),
        patch.object(blocking, "log"),
    ):
        result = blocking._block_ip("192.168.1.10", flags)

    assert result is True
    execute.assert_has_calls(
        [
            call(
                blocking.sudo,
                action="insert",
                ip_to_block="192.168.1.10",
                flag="-s",
                options={
                    "protocol": "",
                    "dport": "",
                    "sport": "",
                    "interface": "-i eth0",
                },
                comment="Slips rule",
            ),
            call(
                blocking.sudo,
                action="insert",
                ip_to_block="192.168.1.10",
                flag="-d",
                options={
                    "protocol": "",
                    "dport": "",
                    "sport": "",
                    "interface": "-o eth0",
                },
                comment="Slips rule",
            ),
        ]
    )


def test_block_ip_rolls_back_partial_rule_insertion() -> None:
    """Remove an inserted source rule when destination insertion fails."""
    blocking = ModuleFactory().create_blocking_obj()
    blocking.firewall = "iptables"

    with (
        patch.object(blocking, "_is_ip_already_blocked", return_value=False),
        patch(
            "modules.blocking.blocking.exec_iptables_command",
            side_effect=[True, False, True],
        ) as execute,
        patch.object(blocking, "print"),
        patch.object(blocking, "log"),
        patch.object(blocking.db, "set_blocked_ip") as set_blocked,
    ):
        result = blocking._block_ip("192.168.1.10", {})

    assert result is False
    assert [item.kwargs["action"] for item in execute.call_args_list] == [
        "insert",
        "insert",
        "delete",
    ]
    assert [item.kwargs["flag"] for item in execute.call_args_list] == [
        "-s",
        "-d",
        "-s",
    ]
    set_blocked.assert_not_called()


def test_main_does_not_schedule_unblock_after_insertion_failure() -> None:
    """Do not persist an unblock deadline for a rule that was never added."""
    blocking = ModuleFactory().create_blocking_obj()
    blocking.parent_output_dir = "output/test-firewall-run"
    blocking_data = {
        "ip": "1.2.3.4",
        "tw": 5,
        "block": True,
        "from": True,
        "to": False,
    }
    request = {
        "tw_to_unblock": TimeWindow(
            number=6,
            end_time="2026-08-28T12:00:00+00:00",
        ),
        "block_this_ip_for": 1,
        "flags": {
            "from_": True,
            "to": False,
            "dport": None,
            "sport": None,
            "protocol": None,
            "interface": None,
        },
    }
    blocking.db.get_blocking_timestamp.return_value = None

    with (
        patch.object(
            blocking,
            "get_msg",
            return_value={"data": json.dumps(blocking_data)},
        ),
        patch.object(blocking, "_block_ip", return_value=False),
        patch.object(
            blocking.unblocker,
            "prepare_unblock_request",
            return_value=request,
        ),
        patch.object(
            blocking.unblocker, "register_unblock_request"
        ) as register,
        patch.object(blocking, "print"),
        patch("modules.blocking.blocking.time.time", return_value=100.0),
    ):
        blocking.main()

    register.assert_not_called()


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

    flags = {
        "from_": True,
        "to": False,
        "dport": 80,
        "sport": 12345,
        "protocol": "tcp",
        "interface": "eth0",
    }
    request = {
        "tw_to_unblock": TimeWindow(
            number=6,
            end_time="2026-08-28T12:00:00+00:00",
        ),
        "block_this_ip_for": 1,
        "flags": dict(flags),
    }
    blocking.parent_output_dir = "output/test-firewall-run"
    blocking.db.get_blocking_timestamp.return_value = None

    with (
        patch.object(
            blocking, "get_msg", side_effect=[msg_block, msg_tw_closed]
        ),
        patch.object(blocking, "_block_ip") as mock_block,
        patch.object(
            blocking.unblocker,
            "prepare_unblock_request",
            return_value=request,
        ) as mock_prepare,
        patch.object(
            blocking.unblocker, "register_unblock_request"
        ) as mock_register,
        patch.object(blocking.unblocker, "update_requests") as mock_update,
        patch("modules.blocking.blocking.time.time", return_value=100.0),
    ):

        blocking.main()

        if expected_block_called:
            mock_block.assert_called_once_with("1.2.3.4", request["flags"])
        else:
            mock_block.assert_not_called()

        mock_prepare.assert_called_once_with("1.2.3.4", 5, flags)
        mock_register.assert_called_once_with("1.2.3.4", request)
        mock_update.assert_not_called()

    assert request["flags"]["_blocked_at"] == 100.0
    assert request["flags"]["_origin_run"] == "test-firewall-run"
    assert request["flags"]["rule_comment"].startswith(
        "Slips run=test-firewall-run blocked=1970-01-01T00:01:40Z delete="
    )


def test_recover_firewall_rules_restores_schedule() -> None:
    """Restore block ownership and deadline from iptables metadata."""
    blocking = ModuleFactory().create_blocking_obj()
    comment = (
        "Slips run=old-run blocked=1970-01-01T00:01:40Z "
        "delete=1970-01-01T00:05:00Z"
    )
    common = {
        "ip": "1.2.3.4",
        "dport": None,
        "sport": None,
        "protocol": None,
        "interface": None,
        "comment": comment,
        "metadata_valid": True,
        "legacy": False,
        "blocked_at": 100.0,
        "unblock_at": 300.0,
        "run_id": "old-run",
    }
    rules = [
        {**common, "from_": True, "to": False},
        {**common, "from_": False, "to": True},
    ]
    blocking.conf.get_tw_width_in_seconds.return_value = 60

    with (
        patch(
            "modules.blocking.blocking.list_slips_firewall_rules",
            return_value=rules,
        ),
        patch.object(blocking, "log"),
        patch("modules.blocking.blocking.time.time", return_value=200.0),
    ):
        recovered = blocking._recover_firewall_rules()

    assert recovered == 1
    blocking.db.set_blocked_ip.assert_called_once_with("1.2.3.4", 100.0)
    state = blocking.db.set_firewall_block_state.call_args.args[1]
    assert state["recovered"] is True
    assert state["recovery_status"] == "recovered"
    assert state["origin_run"] == "old-run"
    assert state["remaining_timewindows"] == 1
    assert state["flags"]["from_"] is True
    assert state["flags"]["to"] is True


def test_recover_expired_firewall_rule_queues_removal() -> None:
    """Classify a recovered past deadline for immediate unblocker work."""
    blocking = ModuleFactory().create_blocking_obj()
    blocking.conf.get_tw_width_in_seconds.return_value = 60
    rule = {
        "ip": "1.2.3.4",
        "from_": True,
        "to": False,
        "dport": None,
        "sport": None,
        "protocol": None,
        "interface": None,
        "comment": (
            "Slips run=old-run blocked=1970-01-01T00:01:40Z "
            "delete=1970-01-01T00:02:30Z"
        ),
        "metadata_valid": True,
        "legacy": False,
        "blocked_at": 100.0,
        "unblock_at": 150.0,
        "run_id": "old-run",
    }

    state = blocking._recovery_state([rule], now=200.0)

    assert state["recovery_status"] == "expired; removal pending"
    assert state["remaining_timewindows"] == 0
    assert state["unblock_at"] == "1970-01-01T00:02:30+00:00"


@pytest.mark.parametrize(
    "comment, legacy, expected_status",
    [
        ("Slips rule", True, "legacy metadata"),
        ("Slips run=broken", False, "invalid metadata"),
    ],
)
def test_recover_firewall_rules_marks_unsafe_metadata_stale(
    comment: str,
    legacy: bool,
    expected_status: str,
) -> None:
    """Retain rules without a trustworthy deadline and identify them."""
    blocking = ModuleFactory().create_blocking_obj()
    rules = [
        {
            "ip": "5.6.7.8",
            "from_": True,
            "to": False,
            "dport": None,
            "sport": None,
            "protocol": None,
            "interface": None,
            "comment": comment,
            "metadata_valid": False,
            "legacy": legacy,
            "blocked_at": None,
            "unblock_at": None,
            "run_id": None,
        }
    ]

    with (
        patch(
            "modules.blocking.blocking.list_slips_firewall_rules",
            return_value=rules,
        ),
        patch.object(blocking, "log"),
        patch("modules.blocking.blocking.time.time", return_value=200.0),
    ):
        blocking._recover_firewall_rules()

    state = blocking.db.set_firewall_block_state.call_args.args[1]
    assert state["recovery_status"] == expected_status
    assert state["unblock_at"] is None
    assert state["recovered"] is True


@pytest.mark.parametrize(
    "last_closed_tw, msg_data, should_call",
    [
        (
            "tw1",
            json.dumps({"text": "profileid_123_tw2", "version": "1.0"}),
            True,
        ),
        (
            "tw2",
            json.dumps({"text": "profileid_234_tw2", "version": "1.0"}),
            False,
        ),
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
