import socket
import time
from typing import (
    Set,
    Optional,
)


class HostIPManager:
    def __init__(self, main):
        self.main = main

    def get_host_ip(self) -> Optional[str]:
        """
        tries to determine the machine's IP address by creating a UDP
        connection to a remote server
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("1.1.1.1", 80))
            ipaddr_check = s.getsockname()[0]
            s.close()
        except socket.error:
            # not connected to the internet
            return None
        return ipaddr_check

    def store_host_ip(self) -> Optional[str]:
        """
        stores the host ip in the db
        Retries to get the host IP online every 10s if not connected
        """
        if not self.main.db.is_running_non_stop():
            return

        if host_ip := self.get_host_ip():
            self.main.db.set_host_ip(host_ip)
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
