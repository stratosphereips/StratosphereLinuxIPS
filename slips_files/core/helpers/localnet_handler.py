import ipaddress
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Dict, List, Union
import validators

import netifaces

from slips_files.common.slips_utils import utils


class LocalnetHandler:
    def __init__(self, profiler) -> None:
        self.profiler = profiler
        self._private_client_ips = self.get_private_client_ips(
            self.profiler.client_ips
        )
        self._configured_default_localnet = (
            self._get_configured_default_localnet()
        )
        self.is_running_non_stop = self.profiler.db.is_running_non_stop()

    def get_private_client_ips(
        self, client_ips=None
    ) -> List[Union[IPv4Network, IPv6Network, IPv4Address, IPv6Address]]:
        """
        returns the private ips found in the client_ips param
        in the config file
        """
        if client_ips is None:
            client_ips = self.profiler.client_ips

        try:
            ips = list(client_ips)
        except TypeError:
            return []

        private_clients = []
        for ip in ips:
            if utils.is_private_ip(ip):
                private_clients.append(ip)
        return private_clients

    def _get_configured_default_localnet(self) -> Dict[str, str]:
        """if private client_ips are set in the config, derive the used
        local net from it"""
        for range_ in self._private_client_ips:
            if isinstance(range_, (IPv4Network, IPv6Network)):
                return {"default": str(range_)}
        return {}

    def get_localnet_of_given_interface(self) -> Dict[str, str]:
        """
        returns the local network of the given interface only if slips is
        running with -i
        """
        local_nets = {}
        for interface in utils.get_all_interfaces(self.profiler.args):
            addrs = netifaces.ifaddresses(interface).get(netifaces.AF_INET)
            if not addrs:
                return local_nets

            for addr in addrs:
                ip = addr.get("addr")
                netmask = addr.get("netmask")
                if ip and netmask:
                    network = ipaddress.IPv4Network(
                        f"{ip}/{netmask}", strict=False
                    )
                    local_nets[interface] = str(network)
        return local_nets

    def get_local_net_of_flow(self, flow) -> Dict[str, str]:
        """
        gets the local network from client_ip
        param in the config file,
        or by using the localnetwork of the first private
        srcip seen in the traffic
        """
        if self._configured_default_localnet:
            return self._configured_default_localnet.copy()

        ip: str = flow.saddr
        if cidr := utils.get_cidr_of_private_ip(ip):
            return {"default": cidr}

        return {}

    def handle_setting_local_net(self, flow):
        """
        stores the local network if possible
        sets the self.localnet_cache dict
        """
        with self.profiler.handle_setting_local_net_lock:
            if not self.should_set_localnet(flow):
                return

            self.profiler.localnet_cache.clear()
            if self.is_running_non_stop:
                self.profiler.localnet_cache.update(
                    self.get_localnet_of_given_interface()
                )
            else:
                self.profiler.localnet_cache.update(
                    self.get_local_net_of_flow(flow)
                )

            for interface, local_net in self.profiler.localnet_cache.items():
                self.profiler.db.set_local_network(local_net, interface)

    def should_set_localnet(self, flow) -> bool:
        """
        returns true only if the saddr of the current flow is ipv4, private
        and we don't have the local_net set already
        """
        if self.is_running_non_stop:
            if flow.interface in self.profiler.localnet_cache:
                return False
        elif "default" in self.profiler.localnet_cache:
            return False

        if flow.saddr == "0.0.0.0":
            return False

        if self._private_client_ips:
            return True

        if not validators.ipv4(flow.saddr):
            return False

        if self.profiler.is_ignored_ip(flow.saddr):
            return False

        saddr_obj = ipaddress.ip_address(flow.saddr)
        if not utils.is_private_ip(saddr_obj):
            return False

        return True
