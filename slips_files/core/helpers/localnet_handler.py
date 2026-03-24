import ipaddress
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Dict, List, Union

import netifaces
import validators

from slips_files.common.slips_utils import utils


class LocalnetHandler:
    def __init__(self, profiler) -> None:
        self.profiler = profiler
        self._private_client_ips = self.get_private_client_ips(
            self.profiler.client_ips
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
        local_net = {}
        for range_ in self._private_client_ips:
            if isinstance(range_, (IPv4Network, IPv6Network)):
                local_net["default"] = str(range_)
                return local_net

        ip: str = flow.saddr
        if cidr := utils.get_cidr_of_private_ip(ip):
            local_net["default"] = cidr
            return local_net

        return local_net

    def handle_setting_local_net(self, flow):
        """
        stores the local network if possible
        sets the self.localnet_cache dict
        """
        with self.profiler.handle_setting_local_net_lock:
            if not self.should_set_localnet(flow):
                return

            if self.is_running_non_stop:
                self.set_cache(self.get_localnet_of_given_interface())
            else:
                self.set_cache(self.get_local_net_of_flow(flow))

            for interface, local_net in self.iter_cache_items():
                self.profiler.db.set_local_network(local_net, interface)

    def should_set_localnet(self, flow) -> bool:
        """
        returns true only if the saddr of the current flow is ipv4, private
        and we don't have the local_net set already
        """
        if self.is_running_non_stop:
            if self.cache_contains(flow.interface):
                return False
        elif self.cache_contains("default"):
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

    def cache_contains(self, interface: str) -> bool:
        cache = self.profiler.localnet_cache
        if hasattr(cache, "contains"):
            return cache.contains(interface)
        try:
            return interface in cache
        except (AttributeError, TypeError):
            self.profiler.localnet_cache = {}
            return False

    def iter_cache_items(self):
        cache = self.profiler.localnet_cache
        try:
            return list(cache.items())
        except TypeError:
            pass
        if isinstance(cache, dict):
            return list(cache.items())
        self.profiler.localnet_cache = {}
        return []

    def set_cache(self, new_cache: Dict[str, str]) -> None:
        cache = self.profiler.localnet_cache
        if cache.set(new_cache):
            return
        if isinstance(cache, dict):
            cache.clear()
            cache.update(new_cache)
            return
        self.profiler.localnet_cache = new_cache
