"""Select bounded capture-time network settings across interface changes."""

import ipaddress
import math
from typing import Any

from slips_files.common.mac import normalize_mac

NETWORK_POLL_GRACE_SECONDS = 10.0


def _snapshot_time(state: dict) -> float | None:
    """Read a finite snapshot timestamp from state; return None if invalid."""
    try:
        value = float(state.get("changed_at") or 0)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) else None


def _matches_link(state: dict, flow: Any) -> bool:
    """Return whether flow IP/MAC pairs corroborate the supplied settings."""
    if flow is None or state.get("connected") is False:
        return False
    own_mac = normalize_mac(state.get("mac"))
    gateway_mac = normalize_mac(state.get("gateway_mac"))
    own_ips = {state.get("host_ip")}
    own_ips.update(
        item.get("ip")
        for item in (state.get("addresses") or [])[:64]
        if isinstance(item, dict)
    )
    for ip_field, mac_field, arp_field, other_field in (
        ("saddr", "smac", "src_hw", "daddr"),
        ("daddr", "dmac", "dst_hw", "saddr"),
    ):
        address = getattr(flow, ip_field, "")
        mac = normalize_mac(
            getattr(flow, arp_field, "") or getattr(flow, mac_field, "")
        )
        if not address or not mac:
            continue
        if own_mac and mac == own_mac and address in own_ips:
            return True
        if (
            gateway_mac
            and mac == gateway_mac
            and address == state.get("gateway_ip")
        ):
            try:
                other = ipaddress.ip_address(getattr(flow, other_field, ""))
                subnet = ipaddress.ip_network(
                    state.get("local_network", ""), strict=False
                )
            except ValueError:
                continue
            if other in subnet:
                return True
    return False


def network_state_at(
    state: dict | None, observed_at: float, flow: Any = None
) -> dict | None:
    """Select settings at packet time, resolving corroborated polling delays.

    Parameters:
        state: Current interface settings and at most ten recent snapshots.
        observed_at: Packet's Unix timestamp.
        flow: Optional packet endpoints and Ethernet or ARP hardware addresses.

    Returns:
        Recorded settings, or None when capture-time settings are unknown.
    """
    if not isinstance(state, dict):
        return None
    try:
        timestamp = float(observed_at)
    except (TypeError, ValueError):
        return state
    if not math.isfinite(timestamp):
        return None
    history = state.get("history") or []
    if not isinstance(history, list):
        history = []
    snapshots = sorted(
        (changed_at, index, item)
        for index, item in enumerate([*history[-10:], state])
        if isinstance(item, dict)
        and (changed_at := _snapshot_time(item)) is not None
    )
    previous = [
        item for changed_at, _, item in snapshots if changed_at <= timestamp
    ]
    active = previous[-1] if previous else None
    upcoming = [
        candidate
        for changed_at, _, candidate in snapshots
        if timestamp < changed_at <= timestamp + NETWORK_POLL_GRACE_SECONDS
    ]
    if not upcoming or (active is not None and _matches_link(active, flow)):
        return active
    for candidate in upcoming:
        if _matches_link(candidate, flow):
            return candidate
    return active
