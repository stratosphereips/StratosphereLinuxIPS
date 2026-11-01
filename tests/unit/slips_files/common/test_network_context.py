"""Regressions for packet-time network selection while roaming."""

from types import SimpleNamespace

import pytest

from slips_files.common.network_context import network_state_at
from tests.module_factory import ModuleFactory


@pytest.fixture
def roaming_state() -> dict:
    """Return Home and hotspot snapshots surrounding the reported flow."""
    return {
        "changed_at": 1793385863.053489,
        "local_network": "172.20.10.0/28",
        "host_ip": "172.20.10.2",
        "mac": "12:5b:07:66:c0:22",
        "gateway_ip": "172.20.10.1",
        "gateway_mac": "ce:3f:36:4b:ad:64",
        "history": [
            {
                "changed_at": 1793385000,
                "local_network": "192.168.1.0/24",
                "host_ip": "192.168.1.100",
                "mac": "50:ed:3c:39:bc:d9",
                "gateway_ip": "192.168.1.1",
                "gateway_mac": "d8:58:d7:1:ff:e1",
            }
        ],
    }


@pytest.mark.parametrize(
    "source, target, smac, dmac, offset, expected",
    [
        (
            "172.20.10.1",
            "172.20.10.2",
            "ce:3f:36:4b:ad:64",
            "12:5b:07:66:c0:22",
            0,
            "172.20.10.0/28",
        ),
        (
            "172.20.10.2",
            "172.20.10.1",
            "12:5B:07:66:C0:22",
            "",
            0,
            "172.20.10.0/28",
        ),
        (
            "172.20.10.1",
            "172.20.10.3",
            "ce:3f:36:4b:ad:64",
            "",
            0,
            "172.20.10.0/28",
        ),
        ("172.20.10.1", "172.20.10.2", "", "", 0, "192.168.1.0/24"),
        (
            "172.20.10.1",
            "172.20.10.2",
            "02:00:00:00:00:03",
            "02:00:00:00:00:04",
            0,
            "192.168.1.0/24",
        ),
        (
            "172.20.10.1",
            "172.20.10.2",
            "ce:3f:36:4b:ad:64",
            "12:5b:07:66:c0:22",
            -20,
            "192.168.1.0/24",
        ),
        (
            "192.168.1.100",
            "172.20.10.1",
            "50:ed:3c:39:bc:d9",
            "d8:58:d7:1:ff:e1",
            0,
            "192.168.1.0/24",
        ),
        (
            "172.20.10.1",
            "10.0.0.2",
            "ce:3f:36:4b:ad:64",
            "",
            0,
            "192.168.1.0/24",
        ),
    ],
)
def test_polling_gap_requires_matching_ip_and_hardware(
    roaming_state: dict,
    source: str,
    target: str,
    smac: str,
    dmac: str,
    offset: float,
    expected: str,
) -> None:
    """Choose the next subnet only for corroborated frames near its poll.

    Parameters:
        roaming_state: Recorded settings on both networks.
        source: Packet source IP.
        target: Packet destination IP.
        smac: Ethernet source address.
        dmac: Ethernet destination address.
        offset: Seconds from the reported packet time.
        expected: Correct capture subnet.
    """
    _factory = ModuleFactory()
    flow = SimpleNamespace(saddr=source, daddr=target, smac=smac, dmac=dmac)
    chosen = network_state_at(roaming_state, 1793385861.47659 + offset, flow)
    assert chosen["local_network"] == expected


@pytest.mark.parametrize("with_history", [False, True])
def test_delayed_frame_can_resolve_the_original_polling_gap(
    roaming_state: dict,
    with_history: bool,
) -> None:
    """Keep queued hotspot packets off the current Home network.

    Parameters:
        roaming_state: Original hotspot settings.
        with_history: Whether the original settings remain available.
    """
    _factory = ModuleFactory()
    hotspot = {
        key: value for key, value in roaming_state.items() if key != "history"
    }
    current = dict(roaming_state["history"][0], changed_at=1793385953.500989)
    current["history"] = (
        [roaming_state["history"][0], hotspot] if with_history else []
    )
    flow = SimpleNamespace(
        saddr="172.20.10.1",
        daddr="172.20.10.2",
        smac="ce:3f:36:4b:ad:64",
        dmac="12:5b:07:66:c0:22",
    )
    chosen = network_state_at(current, 1793385861.47659, flow)
    assert (chosen or {}).get("local_network") == (
        "172.20.10.0/28" if with_history else None
    )


@pytest.mark.parametrize(
    "timestamp", ["invalid", float("nan"), float("inf"), 50, 150]
)
def test_invalid_or_unavailable_snapshot_time_is_conservative(
    timestamp: float | str,
) -> None:
    """Ignore malformed snapshots without guessing an unrecorded network.

    Parameters:
        timestamp: Candidate packet time, including invalid values.
    """
    _factory = ModuleFactory()
    state = {
        "changed_at": 200,
        "history": [
            None,
            {"changed_at": "bad"},
            {"changed_at": float("nan")},
            {"changed_at": 100},
        ],
    }
    chosen = network_state_at(state, timestamp)
    if timestamp == "invalid":
        assert chosen is state
    elif timestamp == 150:
        assert chosen == {"changed_at": 100}
    else:
        assert chosen is None
