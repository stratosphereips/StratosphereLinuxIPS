# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for modules/flow_alerts/utils.py"""

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "what_to_check, expected_ip",
    [
        ("srcip", "192.168.1.10"),
        ("dstip", "192.168.1.20"),
        ("invalid", ""),
    ],
)
def test_get_ip_to_check(what_to_check: str, expected_ip: str) -> None:
    """Test selecting the IP address requested by the check direction."""
    module_factory = ModuleFactory()
    flow_alert_utils = module_factory.create_flow_alert_utils_obj()
    flow = SimpleNamespace(saddr="192.168.1.10", daddr="192.168.1.20")

    assert flow_alert_utils.get_ip_to_check(flow, what_to_check) == expected_ip


@pytest.mark.parametrize(
    "dport, proto, expected_result",
    [
        ("53", "udp", True),
        (53, "UDP", True),
        ("53", "tcp", False),
        ("443", "udp", False),
    ],
)
def test_is_dns_flow(
    dport: str | int, proto: str, expected_result: bool
) -> None:
    """Test DNS flow detection by destination port and protocol."""
    module_factory = ModuleFactory()
    flow_alert_utils = module_factory.create_flow_alert_utils_obj()
    flow = SimpleNamespace(dport=dport, proto=proto)

    assert flow_alert_utils.is_dns_flow(flow) is expected_result


@pytest.mark.parametrize(
    "ip, expected_result",
    [
        ("0.0.0.0", True),
        ("255.255.255.255", True),
        ("127.0.0.1", True),
        ("224.0.0.1", True),
        ("169.254.1.1", True),
        ("192.168.1.10", False),
    ],
)
def test_is_ignored_localnet_ip(ip: str, expected_result: bool) -> None:
    """Test IPs ignored by different-localnet detection."""
    module_factory = ModuleFactory()
    flow_alert_utils = module_factory.create_flow_alert_utils_obj()

    assert flow_alert_utils.is_ignored_localnet_ip(ip) is expected_result


@pytest.mark.parametrize(
    "ip, expected_result",
    [
        ("8.8.8.8", True),
        ("127.0.0.1", True),
        ("169.254.1.1", True),
        ("192.168.1.10", False),
        ("fd00:1::10", False),
    ],
)
def test_is_ip_allowed_outside_localnet(
    ip: str, expected_result: bool
) -> None:
    """Test IPs that should not produce different-localnet evidence."""
    module_factory = ModuleFactory()
    flow_alert_utils = module_factory.create_flow_alert_utils_obj()

    assert (
        flow_alert_utils.is_ip_allowed_outside_localnet(ip) is expected_result
    )


@pytest.mark.parametrize(
    "saddr, daddr, dport, proto, skip_dns_flows, expected_result",
    [
        ("192.168.1.10", "192.168.2.20", "80", "tcp", True, True),
        ("8.8.8.8", "192.168.2.20", "80", "tcp", True, True),
        ("192.168.1.10", "8.8.8.8", "80", "tcp", True, False),
        ("192.168.1.10", "192.168.2.20", "53", "udp", True, False),
        ("192.168.1.10", "192.168.2.20", "53", "udp", False, True),
        ("fd00:1::10", "192.168.2.20", "80", "tcp", True, False),
    ],
)
def test_should_check_different_localnet(
    saddr: str,
    daddr: str,
    dport: str,
    proto: str,
    skip_dns_flows: bool,
    expected_result: bool,
) -> None:
    """Test common eligibility checks for different-localnet evidence."""
    module_factory = ModuleFactory()
    flow_alert_utils = module_factory.create_flow_alert_utils_obj()
    flow = SimpleNamespace(
        saddr=saddr,
        daddr=daddr,
        dport=dport,
        proto=proto,
    )

    assert (
        flow_alert_utils.should_check_different_localnet(
            flow,
            skip_dns_flows=skip_dns_flows,
        )
        is expected_result
    )


def test_should_check_different_localnet_ignores_dns_server() -> None:
    """Test skipping flows involving detected official DNS servers."""
    module_factory = ModuleFactory()
    flow_alert_utils = module_factory.create_flow_alert_utils_obj()
    db = Mock()
    db.is_official_dns_server.side_effect = lambda ip: ip == "192.168.2.53"
    flow = SimpleNamespace(
        saddr="192.168.1.10",
        daddr="192.168.2.53",
        dport="53",
        proto="udp",
    )

    assert (
        flow_alert_utils.should_check_different_localnet(
            flow,
            db=db,
            ignore_official_dns_servers=True,
        )
        is False
    )


@pytest.mark.parametrize(
    "ip_to_check, local_network, expected_result",
    [
        ("192.168.2.20", "192.168.1.0/24", True),
        ("192.168.1.20", "192.168.1.0/24", False),
        ("fd00:2::20", "fd00:1::/64", True),
        ("192.168.2.20", "fd00:1::/64", False),
        ("192.168.2.20", "", False),
    ],
)
def test_is_ip_outside_local_network(
    ip_to_check: str, local_network: str, expected_result: bool
) -> None:
    """Test local-network membership checks."""
    module_factory = ModuleFactory()
    flow_alert_utils = module_factory.create_flow_alert_utils_obj()
    db = Mock()
    db.get_local_network.return_value = local_network
    flow = SimpleNamespace(interface="eth0")

    assert (
        flow_alert_utils.is_ip_outside_local_network(db, flow, ip_to_check)
        is expected_result
    )


@pytest.mark.parametrize(
    "is_running_non_stop, time_diff, expected_result",
    [
        (False, 0, True),
        (True, 40, True),
        (True, 20, False),
    ],
)
def test_is_interface_timeout_reached(
    is_running_non_stop: bool, time_diff: int, expected_result: bool
) -> None:
    """Test interface startup grace-period handling."""
    module_factory = ModuleFactory()
    flow_alert_utils = module_factory.create_flow_alert_utils_obj()
    db = Mock()
    db.get_slips_start_time.return_value = "2026-06-04 12:00:00"

    with patch(
        "slips_files.common.slips_utils.utils.get_time_diff",
        return_value=time_diff,
    ):
        assert (
            flow_alert_utils.is_interface_timeout_reached(
                db,
                is_running_non_stop,
                wait_time=30,
            )
            is expected_result
        )
