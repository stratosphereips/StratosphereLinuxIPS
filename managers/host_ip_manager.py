# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
import netifaces
from typing import (
    Set,
    Optional,
    List,
)

from slips_files.common.style import green


class HostIPManager:
    def __init__(self, main):
        self.main = main

    def get_host_ip(self) -> Optional[str]:
        """
        tries to determine the machine's IP.
        uses the intrfaces provided by the user if -i is given, or all
        interfaces if not.
        """
        if not (self.main.args.interface or self.main.args.growing):
            # slips is running on a file, we cant determine the host IP
            return

        # we use all interfaces when -g is used, otherwise we use the given
        # interface
        interfaces: List[str] = (
            [self.main.args.interface]
            if self.main.args.interface
            else netifaces.interfaces()
        )

        for iface in interfaces:
            addrs = netifaces.ifaddresses(iface)
            # check for IPv4 address
            if netifaces.AF_INET not in addrs:
                continue
            for addr in addrs[netifaces.AF_INET]:
                ip = addr.get("addr")
                if ip and not ip.startswith("127."):
                    return ip

    async def store_host_ip(self) -> Optional[str]:
        """
        stores the host ip in the db
        recursively retries to get the host IP online every 10s if not
        connected
        """
        if not await self.main.db.is_running_non_stop():
            return

        if host_ip := self.get_host_ip():
            await self.main.db.set_host_ip(host_ip)
            self.main.print(f"Detected host IP: {green(host_ip)}")
            return host_ip

        self.main.print("Not Connected to the internet. Reconnecting in 10s.")
        await asyncio.sleep(10)
        await self.store_host_ip()

    async def update_host_ip(
        self, host_ip: str, modified_profiles: Set[str]
    ) -> Optional[str]:
        """
        Is called every 5s for slips to update the host ip
        when running on an interface we keep track of the host IP.
        If there was no modified TWs in the host IP, we check if the
        network was changed.
        :param modified_profiles: modified profiles since slips start time
        """
        if not await self.main.db.is_running_non_stop():
            return

        if host_ip in modified_profiles:
            return host_ip

        if latest_host_ip := self.get_host_ip():
            await self.main.db.set_host_ip(latest_host_ip)
            return latest_host_ip

        return latest_host_ip
