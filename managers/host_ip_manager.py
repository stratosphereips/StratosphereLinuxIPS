# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import time
import netifaces
from typing import (
    Set,
    List,
    Dict,
)

from slips_files.common.style import green


class HostIPManager:
    def __init__(self, main):
        self.main = main
        self.info_printed = False

    def _get_host_ips(self) -> Dict[str, str]:
        """
        tries to determine the machine's IP.
        uses the intrfaces provided by the user with -i or -ap
        returns a dict with {interface_name: host_ip, ..}
        """
        # we use all interfaces when -g is used, otherwise we use the given
        # interface
        interfaces: List[str] = (
            [self.main.args.interface]
            if self.main.args.interface
            else self.main.args.access_point.split(",")
        )
        found_ips = {}
        for iface in interfaces:
            addrs = netifaces.ifaddresses(iface)
            # check for IPv4 address
            if netifaces.AF_INET not in addrs:
                continue
            for addr in addrs[netifaces.AF_INET]:
                ip = addr.get("addr")
                if ip and not ip.startswith("127."):
                    found_ips[iface] = ip
        return found_ips

    def store_host_ip(self) -> Dict[str, str] | None:
        """
        stores the host ip in the db
        recursively retries to get the host IP online every 10s if not
        connected
        """
        if not self.main.db.is_running_non_stop():
            return

        if host_ips := self._get_host_ips():
            for iface, ip in host_ips.items():
                self.main.db.set_host_ip(ip, iface)
                if not self.info_printed:
                    self.main.print(
                        f"Detected host IP: {green(ip)} for {green(iface)}"
                    )
            self.info_printed = True

            return host_ips

        self.main.print("Not Connected to the internet. Reconnecting in 10s.")
        time.sleep(10)
        self.store_host_ip()

    def update_host_ip(
        self, host_ips: Dict[str, str], modified_profiles: Set[str]
    ) -> Dict[str, str]:
        """
        Is called every 5s for slips to update the host ip
        when running on an interface we keep track of the host IP.
        If there was no modified TWs in the host IP, we check if the
        network was changed.
        :param modified_profiles: modified profiles since slips start time
        """
        if not self.main.db.is_running_non_stop():
            return

        res = {}
        for iface, ip in host_ips.items():
            if ip in modified_profiles:
                res[iface] = ip
        if res:
            return res

        return self.store_host_ip()
