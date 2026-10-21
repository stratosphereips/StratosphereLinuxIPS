"""Identify peer networks and resolve optional legacy observation metadata."""

import ipaddress
from pathlib import Path
import sqlite3
from typing import Any


def network_id_for_state(state: dict[str, Any], run_name: str) -> str:
    """Identify a network by router MAC or isolate it to one run.

    Parameters:
        state: Current interface settings.
        run_name: Run identifier for networks without a known router.

    Returns:
        Network identity suitable for storing a user-provided name.
    """
    gateway_mac = str(state.get("gateway_mac") or "").strip().lower()
    if gateway_mac:
        return f"gateway:{gateway_mac}"
    return f"run:{run_name}" if run_name else ""


def network_for_observation(
    path: Path, ip: str, observed_at: float
) -> dict[str, str]:
    """Resolve the saved network for an address at an event timestamp.

    Parameters:
        path: Permanent host profile database path.
        ip: Host address associated with the detection.
        observed_at: Detection time as a Unix timestamp.

    Returns:
        Network identity and display name, or an explicit unknown label.
    """
    unknown = {
        "network_id": "",
        "network_name": "",
        "network_label": "Unknown network (not recorded)",
    }
    try:
        normalized_ip = str(ipaddress.ip_address(ip))
        timestamp = float(observed_at)
    except (TypeError, ValueError):
        return unknown
    if not path.exists():
        return unknown
    if ipaddress.ip_address(normalized_ip).is_global:
        return {
            "network_id": "public",
            "network_name": "",
            "network_label": "Public internet",
        }
    try:
        with sqlite3.connect(
            f"file:{path}?mode=ro", uri=True, timeout=5
        ) as connection:
            rows = connection.execute(
                "SELECT o.network_id, COALESCE(h.network_label,''), "
                "o.first_seen, o.last_seen, n.name "
                "FROM host_endpoint_observations o "
                "LEFT JOIN hosts h ON h.network_id=o.network_id AND h.ip=o.ip "
                "LEFT JOIN network_names n ON n.network_id=o.network_id "
                "WHERE o.ip=?",
                (normalized_ip,),
            ).fetchall()
    except sqlite3.Error:
        return unknown
    matching = [row for row in rows if row[2] <= timestamp <= row[3]]
    network_ids = {str(row[0]) for row in matching}
    if len(network_ids) != 1:
        if len(network_ids) > 1:
            return {
                "network_id": ",".join(sorted(network_ids)),
                "network_name": "",
                "network_label": "Multiple networks",
            }
        return unknown
    row = matching[0]
    network_name = str(row[4] or "")
    return {
        "network_id": str(row[0]),
        "network_name": network_name,
        "network_label": network_name
        or str(row[1])
        or f"Captured network · {row[0]}",
    }
