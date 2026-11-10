"""Resolve packet findings to an unambiguous stored connection."""

import json
import math
import sqlite3
from typing import Any


def find_packet_flow(
    connection: sqlite3.Connection, packet: dict[str, Any]
) -> dict[str, Any] | None:
    """Match both directions of a packet's five-tuple and connection interval.

    Parameters:
        connection: Readable run database containing flows.
        packet: Source, destination, ports, transport and packet timestamp.

    Returns:
        Stored UID, flow, profile and time window, or None for absent or ambiguous matches.
    """
    try:
        src, dst = str(packet["saddr"]), str(packet["daddr"])
        sport, dport = int(packet["sport"]), int(packet["dport"])
        proto, stamp = str(packet["proto"]).lower(), float(packet["timestamp"])
    except (KeyError, TypeError, ValueError):
        return None
    if proto not in {"tcp", "udp"} or not math.isfinite(stamp):
        return None
    if not (0 <= sport <= 65535 and 0 <= dport <= 65535):
        return None
    try:
        rows = connection.execute(
            "SELECT uid,flow,profileid,twid FROM flows "
            "WHERE profileid IN (?,?) AND event_time<=? AND json_valid(flow) "
            "AND LOWER(json_extract(flow,'$.proto'))=? "
            "AND COALESCE(json_extract(flow,'$.endtime'), "
            "event_time+COALESCE(json_extract(flow,'$.dur'),0))>=? "
            "AND ((json_extract(flow,'$.saddr')=? AND json_extract(flow,'$.daddr')=? "
            "AND CAST(json_extract(flow,'$.sport') AS INTEGER)=? "
            "AND CAST(json_extract(flow,'$.dport') AS INTEGER)=?) OR "
            "(json_extract(flow,'$.saddr')=? AND json_extract(flow,'$.daddr')=? "
            "AND CAST(json_extract(flow,'$.sport') AS INTEGER)=? "
            "AND CAST(json_extract(flow,'$.dport') AS INTEGER)=?)) LIMIT 2",
            (
                f"profile_{src}",
                f"profile_{dst}",
                stamp + 0.000001,
                proto,
                stamp - 0.000001,
                src,
                dst,
                sport,
                dport,
                dst,
                src,
                dport,
                sport,
            ),
        ).fetchall()
    except sqlite3.Error:
        return None
    if len(rows) != 1:
        return None
    row = rows[0]
    return {
        "uid": str(row[0]),
        "flow": json.loads(row[1]),
        "profileid": row[2],
        "twid": row[3],
    }
