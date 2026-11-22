# SPDX-License-Identifier: GPL-2.0-only
"""Gateway discovery for the interfaces Slips monitors."""

import ipaddress
import subprocess
from typing import Any, Dict, List, Optional, Union
from uuid import getnode

import netifaces

from slips_files.common.slips_utils import utils
from slips_files.core.database.database_manager import DBManager


class GatewayInfo:
    """Find the gateway IP and MAC of each monitored interface."""

    def __init__(
        self, db: DBManager, args: Any, is_running_non_stop: bool
    ) -> None:
        """Remember how Slips was started.

        Parameters:
            db: Database manager of the ip_info module.
            args: Command line arguments of Slips.
            is_running_non_stop: Whether Slips monitors a live interface.
        """
        self.db = db
        self.args = args
        self.is_running_non_stop = is_running_non_stop

    @staticmethod
    def get_default_gateway(self) -> str:
        gws = netifaces.gateways()
        default = gws.get("default", {})
        return default.get(netifaces.AF_INET, (None,))[0]

    def get_gateway_ip_if_interface(self) -> Dict[str, str] | None:
        """
        returns the gateway ip of the given interface if running on an
        interface.
        and returns own ip if running as an AP (aka the given interface
        is NATing/bridging traffic to another interface).
        """
        if not self.is_running_non_stop:
            # only works if running on an interface
            return

        interfaces: List[str] = utils.get_all_interfaces(self.args)
        gw_ips = {}
        for interface in interfaces:
            try:
                gw_ip = utils.get_gateway_for_iface(interface)
                ipaddress.ip_address(gw_ip)
                gw_ips[interface] = gw_ip
            except (KeyError, TypeError, ValueError):
                pass
        return gw_ips

    @staticmethod
    def get_own_mac() -> str:
        # get the MAC address as a hex string
        mac_num = getnode()
        # format it as usual MAC address format xx:xx:xx:xx:xx:xx
        mac = ":".join(
            f"{(mac_num >> ele) & 0xff:02x}" for ele in range(40, -1, -8)
        )
        return mac

    def _get_wifi_interface_if_ap(self) -> str | None:
        # get_wifi_interface() already returns the wifi interface name
        # (or the user-supplied interface if not running as an AP), not a
        # dict.
        return self.db.get_wifi_interface()

    def _get_mac_using_ip_neigh(self, gw_ip: str | None) -> str | None:
        try:
            ipaddress.ip_address(gw_ip)

            ip_output = subprocess.run(
                ["ip", "neigh", "show", gw_ip],
                capture_output=True,
                check=True,
                text=True,
            ).stdout
            mac = ip_output.split()[-2]
            return mac
        except (
            subprocess.CalledProcessError,
            IndexError,
            FileNotFoundError,
            TypeError,
            ValueError,
        ):
            return

    def _get_mac_using_arp_cache(self, gw_ip: str) -> str | None:
        try:
            gw_mac = utils.get_mac_for_ip_using_cache(gw_ip)
            return gw_mac
        except (subprocess.CalledProcessError, IndexError):
            # Could not find the MAC address of gw_ip
            return

    def get_gateway_mac(self, gw_ips: Dict[str, str]) -> Optional[str]:
        """
        Given the gw_ips, this function tries to get the MAC
         from arp.log, using ip neigh or from arp tables
        """
        wifi_interface: str | None = self._get_wifi_interface_if_ap()

        gw_macs = {}
        for interface, gw_ip in gw_ips.items():
            try:
                ipaddress.ip_address(gw_ip)
            except (TypeError, ValueError):
                continue

            # we keep a cache of the macs and their IPs
            # In case of a zeek dir or a pcap,
            # check if we have the mac of this ip already saved in the db.
            if gw_mac := self.db.get_mac_addr_from_profile(f"profile_{gw_ip}"):
                gw_mac: Union[str, None]
                gw_macs[interface] = gw_mac
                continue

            if not self.is_running_non_stop:
                # ok now we are running on pcap or a given zeek file/dir
                # and we have no MAC in arp.log (in the db) and can't use arp
                # tables, so it's up to the db.is_gw_mac() function to
                # determine the gw mac if it's seen associated with a
                # public IP
                continue

            if interface == wifi_interface:
                # this interface is the wifi interface of the AP
                if own_mac := self.get_own_mac():
                    gw_macs[interface] = own_mac
                    continue

            if gw_mac := self._get_mac_using_ip_neigh(gw_ip):
                gw_macs[interface] = gw_mac
                continue

            if gw_mac := self._get_mac_using_arp_cache(gw_ip):
                gw_macs[interface] = gw_mac
                continue

        if gw_macs:
            return gw_macs
