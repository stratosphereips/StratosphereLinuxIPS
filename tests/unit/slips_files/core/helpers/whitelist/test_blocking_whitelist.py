"""Test enforcement-only whitelist rules using real rule files."""

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from slips_files.core.structures.evidence import (
    Attacker,
    Direction,
    EvidenceType,
    IoCType,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("ip", ["192.0.2.10", "2001:db8:0:0::1"])
def test_blocking_rule_keeps_flows_and_evidence(tmp_path: Path, ip: str) -> None:
    """Match enforcement while preserving analysis for IPv4 and IPv6.

    Parameters:
        tmp_path: Isolated whitelist directory.
        ip: Address protected by the file rule.
    """
    factory = ModuleFactory()
    path = tmp_path / "whitelist.conf"
    path.write_text(f"ip,{ip},both,blocking\n")
    policy = factory.create_blocking_whitelist_obj(str(path))
    assert policy.is_exempt(ip)
    assert not policy.is_exempt("192.0.2.11")

    whitelist = factory.create_whitelist_obj()
    whitelist.parser.local_whitelist_path = str(path)
    whitelist.update()
    rules = whitelist.parser.whitelisted_ips
    whitelist.bloom_filters.ips = rules
    whitelist.db.is_whitelisted.side_effect = lambda key, _: (
        json.dumps(rules[key]) if key in rules else None
    )
    for direction in (Direction.SRC, Direction.DST):
        assert not whitelist.ip_analyzer.is_whitelisted(ip, direction, "flows")
        evidence = Mock(
            attacker=Attacker(ioc_type=IoCType.IP, value=ip, direction=direction),
            victim=None,
            evidence_type=EvidenceType.ARP_SCAN,
            src_port=None,
            dst_port=None,
        )
        assert not whitelist.is_whitelisted_evidence(evidence)


@pytest.mark.parametrize(
    "line",
    [
        "ip,192.0.2.10,src,blocking",
        "ip,192.0.2.10,dst,blocking",
        "ip,192.0.2.10:443,both,blocking",
        "ip,*:443,both,blocking",
        "ip,192.0.2.0/24,both,blocking",
        "ip,192.0.2.10,both,blocking,ARP_SCAN",
        "domain,example.org,both,blocking",
        "mac,aa:bb:cc:dd:ee:ff,both,blocking",
        "organization,google,both,blocking",
        "uri,/example,both,blocking",
        "ip,192.0.2.10,both,alerts",
        "ip,192.0.2.10,both,flows",
        "ip,192.0.2.10,both,both",
    ],
)
def test_other_rules_do_not_exempt_blocking(tmp_path: Path, line: str) -> None:
    """Reject ambiguous enforcement rules and keep old modes independent.

    Parameters:
        tmp_path: Isolated whitelist directory.
        line: Invalid blocking rule or existing suppression mode.
    """
    policy = ModuleFactory().create_blocking_whitelist_obj(
        str(tmp_path / "whitelist.conf")
    )
    Path(policy.path).write_text(line + "\n")
    assert policy.addresses() == set()


def test_file_changes_refresh_without_per_request_io(tmp_path: Path) -> None:
    """Reload added and removed rules while bounding file reads and stats.

    Parameters:
        tmp_path: Isolated whitelist directory.
    """
    policy = ModuleFactory().create_blocking_whitelist_obj(
        str(tmp_path / "whitelist.conf")
    )
    path = Path(policy.path)
    path.write_text("ip,192.0.2.10,both,blocking\n")
    clock = "slips_files.core.helpers.whitelist.blocking_whitelist.time.monotonic"
    with patch(clock, return_value=10) as now:
        assert policy.is_exempt("192.0.2.10")
        path.write_text("ip,192.0.2.11,both,blocking\n")
        with patch.object(Path, "stat", side_effect=AssertionError("cached")):
            for _ in range(100):
                assert policy.is_exempt("192.0.2.10")
        now.return_value = 13
        assert not policy.is_exempt("192.0.2.10")
        assert policy.is_exempt("192.0.2.11")
        path.write_text("")
        now.return_value = 16
        assert policy.addresses() == set()


@pytest.mark.parametrize(
    "rules,expected",
    [
        ("ip,192.0.2.10,both,blocking\n#ip,192.0.2.10,both,blocking\n", set()),
        ("ip,192.0.2.10,both,blocking\nip,192.0.2.10,both,alerts\n", set()),
        ("ip,192.0.2.10,both,alerts\nip,192.0.2.10,both,blocking\n", {"192.0.2.10"}),
        ("ip,2001:db8:0::1,both,blocking\n#ip,2001:db8:0::1,both,blocking\n", set()),
    ],
)
def test_file_comment_and_precedence(
    tmp_path: Path, rules: str, expected: set[str]
) -> None:
    """Honor disabled entries and existing last-rule-wins semantics.

    Parameters:
        tmp_path: Isolated whitelist directory.
        rules: Ordered file rules, including disabled ones.
        expected: Final enforcement exemptions.
    """
    policy = ModuleFactory().create_blocking_whitelist_obj(
        str(tmp_path / "whitelist.conf")
    )
    Path(policy.path).write_text(rules)
    assert policy.addresses() == expected


def test_disabled_local_whitelist_does_not_read_files() -> None:
    """Honor local whitelisting being disabled without file or Redis access."""
    policy = ModuleFactory().create_blocking_whitelist_obj("missing.conf")
    policy.enabled = False
    with patch.object(Path, "stat", side_effect=AssertionError("disabled")):
        assert not policy.is_exempt("192.0.2.10")
        assert not policy.is_exempt("invalid")
    assert policy.manager.db.mock_calls == []


def test_missing_whitelist_recovers_its_blocking_rules(tmp_path: Path) -> None:
    """Preserve enforcement exemptions when recovering a missing rule file.

    Parameters:
        tmp_path: Isolated whitelist directory.
    """
    policy = ModuleFactory().create_blocking_whitelist_obj(
        str(tmp_path / "whitelist.conf")
    )
    backup = tmp_path / "whitelist.conf.bak"
    backup.write_text("ip,192.0.2.10,both,blocking\n")
    assert policy.is_exempt("192.0.2.10")
    assert Path(policy.path).read_text() == backup.read_text()
    assert policy.manager.db.mock_calls == []
