"""Unit tests for recoverable Slips iptables rule metadata."""

import subprocess
from unittest.mock import Mock, call, patch

import pytest

from modules.blocking.exec_iptables_cmd import (
    delete_slips_rules_for_ip,
    exec_iptables_command,
    format_slips_rule_comment,
    list_slips_firewall_rules,
    parse_slips_rule_comment,
    sync_slips_rule_comment,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("returncode, expected", [(0, True), (2, False)])
def test_exec_iptables_command_preserves_argument_boundaries(
    returncode: int,
    expected: bool,
) -> None:
    """Pass comments and sanitized options as distinct iptables arguments.

    Parameters:
        returncode: Exit status returned by iptables.
        expected: Boolean result expected from the wrapper.
    """
    _module_factory = ModuleFactory()
    completed = Mock(returncode=returncode)

    with patch(
        "modules.blocking.exec_iptables_cmd.subprocess.run",
        return_value=completed,
    ) as run:
        result = exec_iptables_command(
            "sudo -n",
            action="insert",
            ip_to_block="192.168.1.10",
            flag="-s",
            options={
                "protocol": " -p tcp",
                "interface": " -i eth0",
            },
            comment="Slips run=test",
        )

    assert result is expected
    run.assert_called_once_with(
        [
            "sudo",
            "-n",
            "iptables",
            "--insert",
            "slipsBlocking",
            "-s",
            "192.168.1.10",
            "-m",
            "comment",
            "--comment",
            "Slips run=test",
            "-p",
            "tcp",
            "-i",
            "eth0",
            "-j",
            "DROP",
        ],
        stdout=subprocess.DEVNULL,
        check=False,
    )


def test_format_and_parse_slips_rule_comment() -> None:
    """Round-trip rule owner, installation time, and deletion deadline."""
    _module_factory = ModuleFactory()

    comment = format_slips_rule_comment(
        100.0,
        "1970-01-01T00:05:00+00:00",
        "eno1 run/unsafe",
    )
    parsed = parse_slips_rule_comment(comment)

    assert comment == (
        "Slips run=eno1_run_unsafe blocked=1970-01-01T00:01:40Z "
        "delete=1970-01-01T00:05:00Z"
    )
    assert parsed == {
        "managed": True,
        "metadata_valid": True,
        "legacy": False,
        "run_id": "eno1_run_unsafe",
        "blocked_at": 100.0,
        "unblock_at": 300.0,
    }


@pytest.mark.parametrize(
    "comment, managed, legacy",
    [
        ("Slips rule", True, True),
        ("Slips run=broken", True, False),
        ("somebody else's rule", False, False),
    ],
)
def test_parse_slips_rule_comment_rejects_missing_deadlines(
    comment: str,
    managed: bool,
    legacy: bool,
) -> None:
    """Reject incomplete scheduling metadata without losing ownership."""
    _module_factory = ModuleFactory()

    parsed = parse_slips_rule_comment(comment)

    assert parsed["managed"] is managed
    assert parsed["legacy"] is legacy
    assert parsed["metadata_valid"] is False


def test_list_slips_firewall_rules_reads_source_and_destination() -> None:
    """Parse exact IP directions and comments from iptables save syntax."""
    _module_factory = ModuleFactory()
    comment = (
        "Slips run=old blocked=1970-01-01T00:01:40Z "
        "delete=1970-01-01T00:05:00Z"
    )
    output = "\n".join(
        (
            "-N slipsBlocking",
            "-A slipsBlocking -s 1.2.3.4/32 -m comment "
            f'--comment "{comment}" -j DROP',
            "-A slipsBlocking -d 1.2.3.4/32 -p tcp --dport 443 "
            f'-m comment --comment "{comment}" -j DROP',
            "-A slipsBlocking -s 9.9.9.9/32 -j DROP",
        )
    )
    completed = Mock(returncode=0, stdout=output)

    with patch(
        "modules.blocking.exec_iptables_cmd.subprocess.run",
        return_value=completed,
    ):
        rules = list_slips_firewall_rules("sudo -n")

    assert len(rules) == 2
    assert rules[0]["rule_number"] == 1
    assert rules[0]["from_"] is True
    assert rules[0]["to"] is False
    assert rules[1]["rule_number"] == 2
    assert rules[1]["from_"] is False
    assert rules[1]["to"] is True
    assert rules[1]["protocol"] == "tcp"
    assert rules[1]["dport"] == "443"
    assert all(rule["metadata_valid"] for rule in rules)


def test_sync_slips_rule_comment_replaces_each_matching_rule() -> None:
    """Update saved deadlines without changing the underlying rule shape."""
    _module_factory = ModuleFactory()
    old_comment = "Slips rule"
    new_comment = (
        "Slips run=current blocked=1970-01-01T00:01:40Z "
        "delete=1970-01-01T00:05:00Z"
    )
    rules = [
        {
            "ip": "1.2.3.4",
            "rule_number": 3,
            "tokens": [
                "-A",
                "slipsBlocking",
                "-s",
                "1.2.3.4/32",
                "-m",
                "comment",
                "--comment",
                old_comment,
                "-j",
                "DROP",
            ],
        }
    ]
    completed = Mock(returncode=0)

    with (
        patch(
            "modules.blocking.exec_iptables_cmd.list_slips_firewall_rules",
            return_value=rules,
        ),
        patch(
            "modules.blocking.exec_iptables_cmd.subprocess.run",
            return_value=completed,
        ) as run,
    ):
        success = sync_slips_rule_comment("sudo -n", "1.2.3.4", new_comment)

    assert success is True
    command = run.call_args.args[0]
    assert command[:5] == ["sudo", "-n", "iptables", "-R", "slipsBlocking"]
    assert command[5] == "3"
    assert command[command.index("--comment") + 1] == new_comment


def test_delete_slips_rules_for_ip_uses_reverse_rule_numbers() -> None:
    """Delete both directions safely while iptables rule numbers shift."""
    _module_factory = ModuleFactory()
    rules = [
        {"ip": "1.2.3.4", "rule_number": 2, "from_": True, "to": False},
        {"ip": "1.2.3.4", "rule_number": 5, "from_": False, "to": True},
    ]
    completed = Mock(returncode=0)

    with (
        patch(
            "modules.blocking.exec_iptables_cmd.list_slips_firewall_rules",
            side_effect=[rules, []],
        ),
        patch(
            "modules.blocking.exec_iptables_cmd.subprocess.run",
            return_value=completed,
        ) as run,
    ):
        success = delete_slips_rules_for_ip(
            "sudo -n",
            "1.2.3.4",
            {"from_": True, "to": True},
        )

    assert success is True
    assert run.call_args_list == [
        call(
            ["sudo", "-n", "iptables", "-D", "slipsBlocking", "5"],
            stdout=-3,
            stderr=-3,
            check=False,
        ),
        call(
            ["sudo", "-n", "iptables", "-D", "slipsBlocking", "2"],
            stdout=-3,
            stderr=-3,
            check=False,
        ),
    ]
