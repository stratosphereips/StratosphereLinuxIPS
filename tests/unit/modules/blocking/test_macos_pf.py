"""Tests for the macOS Packet Filter backend."""

from unittest.mock import patch

import pytest

from modules.blocking.macos_pf import MacOSPF
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "flags, expected",
    [
        (
            {},
            [
                "block drop quick from 192.0.2.5 to any",
                "block drop quick from any to 192.0.2.5",
            ],
        ),
        (
            {"from_": True, "to": False, "interface": "en0"},
            [
                "block drop quick on en0 from 192.0.2.5 to any",
            ],
        ),
        (
            {"from_": False, "to": True, "protocol": "tcp", "dport": 443},
            [
                "block drop quick proto tcp from any to 192.0.2.5 port 443",
            ],
        ),
    ],
)
def test_pf_rule_lines(flags: dict, expected: list[str]) -> None:
    blocking = ModuleFactory().create_blocking_obj()
    pf = MacOSPF("", blocking.db)

    assert pf._rule_lines("192.0.2.5", flags) == expected


@pytest.mark.parametrize(
    "ip, flags",
    [
        ("bad address", {}),
        ("192.0.2.5", {"interface": "en0;bad"}),
        ("192.0.2.5", {"protocol": "tcp;bad"}),
        ("192.0.2.5", {"protocol": "tcp", "dport": 65536}),
    ],
)
def test_pf_rejects_invalid_rules(ip: str, flags: dict) -> None:
    blocking = ModuleFactory().create_blocking_obj()
    pf = MacOSPF("", blocking.db)

    with patch.object(pf, "_run") as run:
        assert not pf.block(ip, flags)
    run.assert_not_called()


def test_pf_block_and_unblock_replace_only_owned_anchor() -> None:
    blocking = ModuleFactory().create_blocking_obj()
    pf = MacOSPF("", blocking.db)

    with patch.object(pf, "_run", return_value=True) as run:
        assert pf.block("192.0.2.5", {})
        assert "192.0.2.5" in pf.rules
        assert pf.unblock("192.0.2.5")
        assert not pf.rules

    assert all(
        "com.apple/slips" in str(call)
        for call in run.call_args_list
        if "-a" in str(call)
    )
    assert any("-n" in str(call) for call in run.call_args_list)
