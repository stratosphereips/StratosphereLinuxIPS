# SPDX-License-Identifier: GPL-2.0-only
"""Read live network settings on Linux and macOS."""

import ipaddress
import re
import socket
import subprocess
import sys
from typing import Any

import dns.resolver
import netifaces

from slips_files.common.slips_utils import utils


def command_output(command: list[str]) -> str:
    """Run an optional system command with a short timeout.

    Parameters:
        command: Executable and arguments.

    Returns:
        Standard output on success, otherwise an empty string.
    """
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=2, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout if result.returncode == 0 else ""


def valid_dns_addresses(values: list[str]) -> list[str]:
    """Keep unique, valid DNS IP addresses.

    Parameters:
        values: Candidate IP strings.

    Returns:
        Normalized IP addresses in original order.
    """
    result = []
    for value in values:
        try:
            address = str(ipaddress.ip_address(value.split("%", 1)[0]))
        except ValueError:
            continue
        if address not in result:
            result.append(address)
    return result


def dns_servers(interface: str, interface_count: int) -> list[str]:
    """Read resolvers assigned to an interface by the operating system.

    Parameters:
        interface: Monitored interface name.
        interface_count: Number of monitored interfaces.

    Returns:
        DNS IP addresses, or an empty list when attribution is unavailable.
    """
    if sys.platform == "darwin":
        output = command_output(["scutil", "--dns"])
        try:
            index = socket.if_nametoindex(interface)
        except OSError:
            index = -1
        addresses = []
        for block in re.split(r"(?=^resolver #\d+)", output, flags=re.M):
            match = re.search(r"^\s*if_index\s*:\s*(\d+)", block, re.M)
            if match and int(match.group(1)) == index:
                addresses.extend(
                    re.findall(
                        r"^\s*nameserver\[\d+\]\s*:\s*(\S+)", block, re.M
                    )
                )
        if addresses:
            return valid_dns_addresses(addresses)
    elif sys.platform.startswith("linux"):
        output = command_output(["resolvectl", "dns", interface])
        if ":" in output:
            addresses = valid_dns_addresses(output.split(":", 1)[1].split())
            if addresses:
                return addresses
        output = command_output(
            ["nmcli", "-g", "IP4.DNS,IP6.DNS", "device", "show", interface]
        )
        addresses = valid_dns_addresses(output.split())
        if addresses:
            return addresses

    # The system resolver is useful for a single interface, but cannot be
    # attributed correctly when Slips monitors multiple interfaces.
    if interface_count != 1:
        return []
    try:
        return valid_dns_addresses(
            list(dns.resolver.Resolver(configure=True).nameservers)
        )
    except (OSError, ValueError, dns.resolver.ResolverException):
        return []


def gateway_mac(interface: str, gateway_ip: str) -> str:
    """Look up the gateway MAC in the local neighbor cache.

    Parameters:
        interface: Monitored interface name.
        gateway_ip: Current gateway IP.

    Returns:
        MAC address if the neighbor cache knows it.
    """
    if not gateway_ip:
        return ""
    if sys.platform.startswith("linux"):
        output = command_output(
            ["ip", "neigh", "show", gateway_ip, "dev", interface]
        )
    elif sys.platform == "darwin":
        command = "ndp" if ":" in gateway_ip else "arp"
        output = command_output([command, "-n", gateway_ip])
    else:
        return ""
    match = re.search(r"\b(?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}\b", output)
    return match.group(0).lower() if match else ""


def collect_network_state(
    interface: str, interface_count: int
) -> dict[str, Any]:
    """Collect current host IPs, subnet, gateway, and DNS for an interface.

    Parameters:
        interface: Monitored interface name.
        interface_count: Number of monitored interfaces.

    Returns:
        Network settings suitable for comparing consecutive checks.
    """
    addresses = []
    try:
        iface_addrs = netifaces.ifaddresses(interface)
    except (OSError, ValueError):
        iface_addrs = {}
    for family in (netifaces.AF_INET, netifaces.AF_INET6):
        for entry in iface_addrs.get(family, []):
            value = str(entry.get("addr", "")).split("%", 1)[0]
            mask = entry.get("netmask") or entry.get("prefixlen")
            try:
                address = ipaddress.ip_address(value)
                if address.is_loopback or address.is_unspecified:
                    continue
                if (
                    family == netifaces.AF_INET6
                    and isinstance(mask, str)
                    and ":" in mask
                ):
                    mask = ipaddress.IPv6Address(mask).packed
                    mask = sum(byte.bit_count() for byte in mask)
                network = (
                    str(ipaddress.ip_network(f"{value}/{mask}", strict=False))
                    if mask
                    else ""
                )
            except ValueError:
                continue
            addresses.append({"ip": str(address), "network": network})
    preferred = next(
        (
            item
            for item in addresses
            if ":" not in item["ip"]
            and not ipaddress.ip_address(item["ip"]).is_link_local
        ),
        next(
            (
                item
                for item in addresses
                if not ipaddress.ip_address(item["ip"]).is_link_local
            ),
            {},
        ),
    )
    gateway_ip = utils.get_gateway_for_iface(interface) or ""
    return {
        "interface": interface,
        "connected": bool(preferred),
        "addresses": addresses,
        "host_ip": preferred.get("ip", ""),
        "local_network": preferred.get("network", ""),
        "gateway_ip": gateway_ip,
        "gateway_mac": gateway_mac(interface, gateway_ip),
        "dns_servers": (
            dns_servers(interface, interface_count) if preferred else []
        ),
    }
