# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import socket
import time
from typing import (
    Set,
    Optional,
)

from slips_files.common.style import green


class HostIPManager:
    def __init__(self, main):
        self.main = main

    def get_host_ip(self) -> Optional[str]:
        """
        tries to determine the machine's IP address by creating a UDP
        connection to cloudflare
        returns ipv4 or ipv6 of the current computer
        """
        for address_family in (socket.AF_INET, socket.AF_INET6):
            try:
                s = socket.socket(address_family, socket.SOCK_DGRAM)

                test_address = (
                    ("1.1.1.1", 80)
                    if address_family == socket.AF_INET
                    else ("2606:4700:4700::1111", 80)
                )

                s.connect(test_address)
                ipaddr_check = s.getsockname()[0]
                s.close()
                return ipaddr_check
            except socket.error:
                continue

        # neither ipv4 nor ipv6 worked
        return None

    def store_host_ip(self) -> Optional[str]:
        """
        stores the host ip in the db
        recursively retries to get the host IP online every 10s if not
        connected
        """
        if not self.main.db.is_running_non_stop():
            return

        if host_ip := self.get_host_ip():
            self.main.db.set_host_ip(host_ip)
            self.main.print(f"Detected host IP: {green(host_ip)}")
            return host_ip

        self.main.print("Not Connected to the internet. Reconnecting in 10s.")
        time.sleep(10)
        self.store_host_ip()

    def update_host_ip(
        self, host_ip: str, modified_profiles: Set[str]
    ) -> Optional[str]:
        """
        Is called every 5s for slips to update the host ip
        when running on an interface we keep track of the host IP.
        If there was no modified TWs in the host IP, we check if the
        network was changed.
        :param modified_profiles: modified profiles since slips start time
        """
        if not self.main.db.is_running_non_stop():
            return

        if host_ip in modified_profiles:
            return host_ip

        if latest_host_ip := self.get_host_ip():
            self.main.db.set_host_ip(latest_host_ip)
            return latest_host_ip

        return latest_host_ip
