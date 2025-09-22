import re
import os
import subprocess
from typing import Dict


class APManager:
    """
    Gets AP info when slips is running as an AP in the RPI
    https://stratospherelinuxips.readthedocs.io/en/develop/immune/installing_slips_in_the_rpi.html#protect-your-local-network-with-slips-on-the-rpi

    """

    def __init__(self, main):
        self.main = main
        self.bridge_name = None
        self.eth_interface = None

    def is_running_as_ap(self) -> bool:
        eth_interface = self.is_slips_running_on_interface()
        if not eth_interface:
            return False

        bridge = self.find_which_bridge_the_given_interface_belongs_to(
            eth_interface
        )
        return True if bridge else False

    def find_which_bridge_the_given_interface_belongs_to(
        self, interface
    ) -> str | None:
        """
        find which bridge (if any) the interface belongs to
        sets self.bridge_name to the used bridge name
        """
        bridge_link = subprocess.run(
            ["bridge", "link"], capture_output=True, text=True, check=True
        )
        bridge_name = None
        for line in bridge_link.stdout.splitlines():
            if interface in line:
                # line looks like: "3: eth0@if2: <BROADCAST,MULTICAST> ..."
                m = re.search(r"master (\S+)", line)
                if m:
                    bridge_name = m.group(1)
                    self.bridge_name = bridge_name
                    return bridge_name

        if not bridge_name:
            # eth not in a bridge
            return None

    def is_slips_running_on_interface(self) -> str | None:
        """sets self.eth_interface"""
        eth_interface: str = getattr(self.args, "interface", None)
        self.eth_interface = eth_interface
        return eth_interface

    def set_ap_bridge_interfaces(self) -> Dict[str, str] | None:
        """
        if slips is running as an access point in bridge mode, this function
        expects the user to have run slips with -i eth interface.

        given an Ethernet interface (e.g., 'eth0') with -i, returns a dict
        with the 2 interfaces of the bridge, e.g.
        {
            "wifi_interface": <wifi>,
            "ethernet_interface": <eth0>}
        Otherwise, return None.

        side effects:
            sets AP interface info in the db if found.

        requires self.bridge_name and self.eth_interface  to be set.
        """
        try:
            if not self.bridge_name or not self.eth_interface:
                return None

            # get all interfaces in that bridge
            bridge_ifaces = []
            bridge_interfaces_cmd = subprocess.run(
                ["bridge", "link"], capture_output=True, text=True, check=True
            )
            for line in bridge_interfaces_cmd.stdout.splitlines():
                if f"master {self.bridge_name}" in line:
                    iface = line.split()[1].split("@")[0][:-1]
                    bridge_ifaces.append(iface)

            # pick the wifi interface (not the given eth)
            wifi_iface = None
            for iface in bridge_ifaces:
                if iface != self.eth_interface and os.path.exists(
                    f"/sys/class/net/{iface}/wireless"
                ):
                    wifi_iface = iface
                    break

            if not wifi_iface:
                return None

            # confirm wifi_iface is in AP mode
            iw = subprocess.run(
                ["iw", "dev"], capture_output=True, text=True, check=True
            )
            blocks = iw.stdout.split("Interface ")
            for block in blocks:
                if block.startswith(wifi_iface) and re.search(
                    r"type\s+AP", block
                ):
                    interfaces = {
                        "wifi_interface": wifi_iface,
                        "ethernet_interface": self.eth_interface,
                    }
                    self.db.set_ap_info(interfaces)
                    return

            return None
        except Exception:
            return None
