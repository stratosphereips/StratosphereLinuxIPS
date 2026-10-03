# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import netifaces
import time
from typing import (
    Any,
    Set,
    List,
    Dict,
)

from managers.network_state import collect_network_state


class HostIPManager:
    def __init__(self, main: Any) -> None:
        """Keep current network settings for a live Slips run.

        Parameters:
            main: Main Slips process.
        """
        self.main = main

    def _monitored_interfaces(self) -> List[str]:
        """Return operating-system interfaces captured by this run.

        Returns:
            Interface names, or an empty list for file-based input.
        """
        if self.main.args.interface:
            return [self.main.args.interface]
        if self.main.args.access_point:
            return [
                name.strip()
                for name in self.main.args.access_point.split(",")
                if name.strip()
            ]
        return []

    def refresh_network_state(self) -> Dict[str, str] | None:
        """Replace changed live network settings and log each change.

        Returns:
            Current interface-to-host-IP mapping for live capture.
        """
        interfaces = self._monitored_interfaces()
        if not interfaces or not self.main.db.is_running_non_stop():
            return None
        host_ips = {}
        for interface in interfaces:
            current = collect_network_state(interface, len(interfaces))
            previous = self.main.db.get_network_state(interface) or {}
            if current["host_ip"]:
                host_ips[interface] = current["host_ip"]
            if all(
                previous.get(key) == value for key, value in current.items()
            ):
                continue
            current["changed_at"] = time.time()
            current["version"] = int(previous.get("version", 0)) + 1
            history = previous.get("history", [])
            if previous.get("changed_at"):
                old_state = {
                    key: value
                    for key, value in previous.items()
                    if key != "history"
                }
                history = [*history, old_state]
            current["history"] = history[-10:]
            self.main.db.replace_network_state(interface, current)
            self.main.print(
                f"Network settings changed on {interface}: "
                f"IP {previous.get('host_ip') or '-'} -> {current['host_ip'] or '-'}, "
                f"subnet {previous.get('local_network') or '-'} -> "
                f"{current['local_network'] or '-'}, "
                f"gateway {previous.get('gateway_ip') or '-'} -> "
                f"{current['gateway_ip'] or '-'}, "
                f"gateway MAC {previous.get('gateway_mac') or '-'} -> "
                f"{current['gateway_mac'] or '-'}, "
                f"DNS {', '.join(previous.get('dns_servers', [])) or '-'} -> "
                f"{', '.join(current['dns_servers']) or '-'}"
            )
        return host_ips

    def _get_host_ips(self) -> Dict[str, str]:
        """
        tries to determine the machine's IP.
        uses the intrfaces provided by the user with -i or -ap
        returns a dict with {interface_name: host_ip, ..}
        """
        interfaces: List[str] = (
            [self.main.args.interface]
            if self.main.args.interface
            else (
                self.main.args.access_point.split(",")
                if self.main.args.access_point
                else []
            )
        )
        found_ips = {}
        for iface in interfaces:
            addrs = netifaces.ifaddresses(iface)
            # we just need 1 host ip, v4 or v6, preferably v4 though
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr.get("addr")
                    if ip and not ip.startswith("127."):
                        found_ips[iface] = ip
                        break
            elif netifaces.AF_INET6 in addrs:
                for addr in addrs[netifaces.AF_INET6]:
                    ip = addr.get("addr")
                    if ip:
                        try:
                            ip = ip.split("%")[0]
                        except KeyError:
                            pass
                        found_ips[iface] = ip
                        break
        return found_ips

    def store_host_ip(self) -> Dict[str, str] | None:
        """Record initial network settings for live interface capture.

        Returns:
            Current interface-to-host-IP mapping, if monitoring live traffic.
        """
        return self.refresh_network_state()

    def update_host_ip(
        self, host_ips: Dict[str, str], modified_profiles: Set[str]
    ) -> Dict[str, str] | None:
        """
        Refresh live network settings every 5 seconds regardless of traffic.

        Parameters:
            host_ips: Previously known IPs, kept for caller compatibility.
            modified_profiles: Recently active profiles, unused here.

        Returns:
            Current interface-to-host-IP mapping.
        """
        return self.refresh_network_state()
