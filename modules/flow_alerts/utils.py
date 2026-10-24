# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from typing import Any
import ipaddress
from datetime import datetime

from slips_files.common.ips import SPECIAL_IPV4_ADDRESSES
from slips_files.common.slips_utils import utils
from slips_files.core.database.database_manager import DBManager
from slips_files.core.structures.evidence import (
    Attacker,
    Direction,
    Evidence,
    EvidenceType,
    IoCType,
    ProfileID,
    ThreatLevel,
    TimeWindow,
    Victim,
)

DHCPV6_PORTS = {"546", "547"}
SPECIAL_IPV4 = SPECIAL_IPV4_ADDRESSES


def network_state_for_flow(
    db: DBManager, flow: Any, state: dict | None = None
) -> dict | None:
    """Select the network settings active when a live flow was recorded.

    Parameters:
        db: Database manager holding current and recent network settings.
        flow: Flow with an interface and optional Unix start time.
        state: Already loaded current settings, if available.

    Returns:
        Matching settings, or None when the network is unknown.
    """
    if state is None:
        state = db.get_network_state(getattr(flow, "interface", ""))
    if not isinstance(state, dict):
        return None
    try:
        timestamp = float(flow.starttime)
    except (AttributeError, TypeError, ValueError):
        return state
    matching = [
        item
        for item in [*state.get("history", []), state]
        if float(item.get("changed_at", 0)) <= timestamp
    ]
    return (
        max(matching, key=lambda item: item["changed_at"])
        if matching
        else None
    )


def get_ip_to_check(flow: Any, what_to_check: str) -> str:
    """
    Get the source or destination IP selected by the check direction.

    Parameters:
    flow: Flow-like object being analyzed.
    what_to_check: IP direction being evaluated, either srcip or dstip.

    Return:
    str: Selected IP address, or an empty string for unsupported directions.
    """
    if what_to_check == "srcip":
        return getattr(flow, "saddr", "")
    if what_to_check == "dstip":
        return getattr(flow, "daddr", "")
    return ""


def is_dns_flow(flow: Any) -> bool:
    """
    Check whether a flow is DNS traffic to destination port 53/UDP.

    Parameters:
    flow: Flow-like object being analyzed.

    Return:
    bool: True when the flow is DNS traffic.
    """
    return (
        str(getattr(flow, "dport", "")) == "53"
        and getattr(flow, "proto", "").lower() == "udp"
    )


def is_ignored_localnet_ip(
    ip: str,
    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None,
) -> bool:
    """
    Check whether an IP should be skipped for local-network evidence.

    Parameters:
    ip: IP address string.
    ip_obj: Parsed IP address object, if the caller already has one.

    Return:
    bool: True for special IPv4, loopback, multicast, or link-local IPs.
    """
    ip_obj = ip_obj or ipaddress.ip_address(ip)
    return (
        (ip_obj.version == 4 and ip in SPECIAL_IPV4)
        or ip_obj.is_loopback
        or ip_obj.is_multicast
        or ip_obj.is_link_local
    )


def is_ip_allowed_outside_localnet(ip: str) -> bool:
    """
    Check whether an IP is expected outside the configured local network.

    Parameters:
    ip: IP address string.

    Return:
    bool: True when different-localnet evidence should be skipped for this IP.
    """
    ip_obj = ipaddress.ip_address(ip)
    return is_ignored_localnet_ip(ip, ip_obj) or not ip_obj.is_private


def should_check_different_localnet(
    flow: Any,
    db: DBManager | None = None,
    skip_dns_flows: bool = False,
    ignore_official_dns_servers: bool = False,
) -> bool:
    """
    Check whether a flow is eligible for different-localnet detection.

    Parameters:
    flow: Flow-like object being analyzed.
    db: Database manager used when official DNS servers should be skipped.
    skip_dns_flows: Skip DNS flows because another analyzer handles them.
    ignore_official_dns_servers: Skip flows involving detected DNS servers.

    Return:
    bool: True when the flow has private-to-private or public-to-private
    addresses that should be compared with the configured local network.
    """
    if skip_dns_flows and is_dns_flow(flow):
        return False

    saddr = getattr(flow, "saddr", "")
    daddr = getattr(flow, "daddr", "")
    saddr_obj = ipaddress.ip_address(saddr)
    daddr_obj = ipaddress.ip_address(daddr)

    if saddr_obj.version != daddr_obj.version:
        return False

    for ip, ip_obj in ((saddr, saddr_obj), (daddr, daddr_obj)):
        if (
            ignore_official_dns_servers
            and db
            and db.is_official_dns_server(ip)
        ):
            return False

        if is_ignored_localnet_ip(ip, ip_obj):
            return False

    is_saddr_private = utils.is_private_ip(saddr_obj)
    is_daddr_private = utils.is_private_ip(daddr_obj)

    return (is_saddr_private and is_daddr_private) or (
        not is_saddr_private and is_daddr_private
    )


def local_network_for_flow(db: DBManager, flow: Any) -> str:
    """Read the local subnet that applied when a flow was captured.

    Parameters:
        db: Database holding live network history or the recording's subnet.
        flow: Flow with an interface and optional capture time.

    Returns:
        Local subnet, or an empty string when it is unknown.
    """
    state = db.get_network_state(getattr(flow, "interface", ""))
    if isinstance(state, dict):
        active = network_state_for_flow(db, flow, state)
        own_local_network = active.get("local_network", "") if active else ""
    else:
        own_local_network = db.get_local_network(
            getattr(flow, "interface", "")
        )
    return own_local_network or ""


def is_ip_outside_local_network(
    db: DBManager,
    flow: Any,
    ip_to_check: str,
) -> bool:
    """Check an address against the subnet active at capture time.

    Parameters:
        db: Database holding the interface subnet.
        flow: Flow with an interface and optional capture time.
        ip_to_check: Address to compare with that subnet.

    Returns:
        True for an address of the same IP version outside a known subnet.
    """
    if not (own_local_network := local_network_for_flow(db, flow)):
        return False

    ip_obj = ipaddress.ip_address(ip_to_check)
    own_local_network_obj = ipaddress.ip_network(
        own_local_network, strict=False
    )
    if own_local_network_obj.version != ip_obj.version:
        return False

    return ip_obj not in own_local_network_obj


def different_localnet_context(db: DBManager, flow: Any) -> tuple[str, str]:
    """Compare both ends of one flow with the same local subnet.

    Parameters:
        db: Database holding network settings and detected DNS servers.
        flow: Eligible private-address connection.

    Returns:
        Subnet and outside direction (srcip, dstip, both, or empty).
    """
    local_network = local_network_for_flow(db, flow)
    if not local_network:
        return "", ""
    network = ipaddress.ip_network(local_network, strict=False)
    outside = []
    for direction in ("srcip", "dstip"):
        ip = get_ip_to_check(flow, direction)
        ip_obj = ipaddress.ip_address(ip)
        if (
            ip_obj.version != network.version
            or is_ip_allowed_outside_localnet(ip)
            or ip_obj in network
            or is_official_dns_server(db, flow, direction)
        ):
            continue
        outside.append(direction)
    direction = "both" if len(outside) == 2 else next(iter(outside), "")
    return local_network, direction


def different_localnet_findings(
    twid: str, flow: Any, ip_outside_localnet: str, local_network: str
) -> tuple[Evidence, ...]:
    """Build high source and informational destination subnet findings.

    Parameters:
        twid: Detection time window.
        flow: Connection with its original addresses and transport fields.
        ip_outside_localnet: Outside direction: srcip, dstip, or both.
        local_network: Subnet used by the detector for this flow.

    Returns:
        One finding per endpoint, or none for a connection to the same IP.
    """
    if ipaddress.ip_address(flow.saddr) == ipaddress.ip_address(flow.daddr):
        return ()
    outside_description = {
        "srcip": "the private source address is",
        "dstip": "the private destination address is",
        "both": "both private addresses are",
    }[ip_outside_localnet]
    proto = flow.proto.lower()
    context = (
        f" using {proto.upper()}: "
        f"{outside_description} outside the local network {local_network}."
    )
    if proto in {"tcp", "udp"}:
        context += f" Destination port: {flow.dport}/{proto.upper()}."
    elif proto in {"icmp", "icmp6", "icmpv6"}:
        context += f" ICMP type: {flow.sport}; code: {flow.dport}."

    findings = []
    for host, direction, other, other_direction, level, description in (
        (
            flow.saddr,
            Direction.SRC,
            flow.daddr,
            Direction.DST,
            ThreatLevel.HIGH,
            f"{flow.saddr} initiated a connection to {flow.daddr}",
        ),
        (
            flow.daddr,
            Direction.DST,
            flow.saddr,
            Direction.SRC,
            ThreatLevel.INFO,
            f"{flow.daddr} received a connection from {flow.saddr}",
        ),
    ):
        findings.append(
            Evidence(
                evidence_type=EvidenceType.DIFFERENT_LOCALNET,
                attacker=Attacker(
                    direction=direction, ioc_type=IoCType.IP, value=host
                ),
                victim=Victim(
                    direction=other_direction, ioc_type=IoCType.IP, value=other
                ),
                threat_level=level,
                description=description + context,
                profile=ProfileID(ip=host),
                timewindow=TimeWindow(
                    number=int(twid.replace("timewindow", ""))
                ),
                uid=[flow.uid],
                timestamp=flow.starttime,
                interface=flow.interface,
                proto=flow.proto,
                confidence=1.0,
                src_port=flow.sport,
                dst_port=flow.dport,
            )
        )
    source, destination = findings
    source.rel_id = [destination.id]
    destination.rel_id = [source.id]
    return source, destination


def is_interface_timeout_reached(
    db: DBManager,
    is_running_non_stop: bool,
    wait_time: int | float,
) -> bool:
    """
    Check whether interface startup grace time has elapsed.

    Parameters:
    db: Database manager used to get the Slips start time.
    is_running_non_stop: True when Slips is running on an interface.
    wait_time: Grace period in minutes.

    Return:
    bool: True when evidence can be emitted.
    """
    if not is_running_non_stop:
        return True

    start_time = db.get_slips_start_time()
    now = datetime.now()
    diff = utils.get_time_diff(start_time, now, return_type="minutes")
    return diff >= wait_time


def is_official_dns_server(
    db: DBManager,
    flow: Any,
    what_to_check: str,
) -> bool:
    """
    returns True when the checked IP is a detected DNS server using port 53.
    """
    if what_to_check == "dstip":
        dns_server_ip = getattr(flow, "daddr", "")
        dns_server_port = getattr(flow, "dport", "")
    elif what_to_check == "srcip":
        dns_server_ip = getattr(flow, "saddr", "")
        dns_server_port = getattr(flow, "sport", "")
    else:
        return False

    if str(dns_server_port) != "53" or not dns_server_ip:
        return False

    active = network_state_for_flow(db, flow)
    if active and dns_server_ip in active.get("dns_servers", []):
        return True
    return db.is_official_dns_server(dns_server_ip)


def should_ignore_dns_or_dhcpv6_flow(
    db: DBManager,
    flow: Any,
) -> bool:
    """
    Check whether private-IP connection evidence should be skipped.

    Parameters:
    db: Database manager used to check known official DNS servers.
    flow: Flow-like object being analyzed.

    Return:
    bool: True when the flow is a DNS query to port 53, a DNS reply from a
    detected DNS server, or DHCPv6 service traffic.
    """
    if getattr(flow, "proto", "").lower() != "udp":
        return False

    daddr = getattr(flow, "daddr", "")
    saddr = getattr(flow, "saddr", "")
    dport = str(getattr(flow, "dport", ""))
    sport = str(getattr(flow, "sport", ""))

    if dport == "53" and daddr:
        return True

    if sport == "53" and saddr and db.is_official_dns_server(saddr):
        return True

    if sport in DHCPV6_PORTS or dport in DHCPV6_PORTS:
        return True

    return False
