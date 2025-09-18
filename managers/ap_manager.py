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

    def is_slips_running_on_interface(self) -> str | None:
        eth_interface: str = getattr(self.args, "interface", None)
        return eth_interface

    def set_ap_bridge_interfaces(self) -> Dict[str, str] | None:
        """
        Given an Ethernet interface (e.g., 'eth0'),
        returns a dict with {"wifi_interface": <wifi>,
        "ethernet_interface": eth}
        if the wifi interface is running as AP in a bridge with the eth.
        Otherwise, return None.
        sets AP interface info in the db if found.
        PS: this function assumes that the interface given to slips with -i is
        the eth interface
        """
        try:
            eth_interface = self.is_slips_running_on_interface()
            if not eth_interface:
                return None

            # find which bridge (if any) the eth_interface belongs to
            brctl = subprocess.run(
                ["bridge", "link"], capture_output=True, text=True, check=True
            )
            bridge_name = None
            for line in brctl.stdout.splitlines():
                if eth_interface in line:
                    # line looks like: "3: eth0@if2: <BROADCAST,MULTICAST> ..."
                    m = re.search(r"master (\S+)", line)
                    if m:
                        bridge_name = m.group(1)
                        break

            if not bridge_name:
                # eth not in a bridge
                return None

            # get all interfaces in that bridge
            bridge_ifaces = []
            bridge_interfaces_cmd = subprocess.run(
                ["bridge", "link"], capture_output=True, text=True, check=True
            )
            for line in bridge_interfaces_cmd.stdout.splitlines():
                if f"master {bridge_name}" in line:
                    iface = line.split()[1].split("@")[0][:-1]
                    bridge_ifaces.append(iface)

            # pick the wifi interface (not the given eth)
            wifi_iface = None
            for iface in bridge_ifaces:
                if iface != eth_interface and os.path.exists(
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
                        "ethernet_interface": eth_interface,
                    }
                    self.db.set_ap_mode(interfaces)
                    return

            return None
        except Exception:
            return None
