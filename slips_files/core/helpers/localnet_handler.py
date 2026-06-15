import ipaddress
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Dict, List, Union

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
        self.done_recognizing_all_localnets = False
        self.localnet_cache = {}
        self.number_of_expected_localnets: int = (
            self._get_expected_localnets_number()
        )

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

    def _get_localnet_of_given_interfaces_using_netifaces(
        self,
    ) -> Dict[str, str]:
        """
        returns the ipv4 and ipv6 local networks of the given interface/s
        when slips is running with (-i or -ap)
        """
        local_nets = {}
        for interface in utils.get_all_interfaces(self.profiler.args):
            iface_addrs = netifaces.ifaddresses(interface)

            for family in (netifaces.AF_INET, netifaces.AF_INET6):
                addrs = iface_addrs.get(family, [])
                for addr in addrs:
                    ip = (addr.get("addr") or "").split("%", 1)[0]
                    netmask = addr.get("netmask") or addr.get("prefixlen")
                    if isinstance(netmask, str) and "/" in netmask:
                        netmask = netmask.rsplit("/", 1)[-1]
                    if ip and netmask:
                        network = ipaddress.ip_network(
                            f"{ip}/{netmask}", strict=False
                        )
                        local_nets[interface] = str(network)
                        break
                if interface in local_nets:
                    break
        return local_nets

    def _get_local_net_of_flow(self, flow) -> Dict[str, str]:
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

    def _get_expected_localnets_number(self):
        """
        if using -ap, we expect 2localnets,one for eeach interface,
        if using -i, we expect 1
        """
        return 2 if self.profiler.args.access_point else 1

    def handle_setting_local_net(self, flow):
        """
        stores the local network if possible
        sets the self.localnet_cache dict
        """
        if not self._should_set_localnet(flow):
            return

        if self.is_running_non_stop:
            local_nets: Dict[str, str] = (
                self._get_localnet_of_given_interfaces_using_netifaces()
            )
        else:
            # slips is analyzing a file
            local_nets: Dict[str, str] = self._get_local_net_of_flow(flow)

        self.localnet_cache = local_nets

        for interface, local_net in self.localnet_cache.items():
            self.profiler.db.set_local_network(local_net, interface)

    def _should_set_localnet(self, flow) -> bool:
        """
        returns true only if the saddr of the current flow is private
        and we don't have the local_net set already
        """
        if self.done_recognizing_all_localnets:
            return False

        if (
            self.profiler.db.get_total_recognized_localnets()
            == self.number_of_expected_localnets
        ):
            self.done_recognizing_all_localnets = True
            return False

        if self.is_running_non_stop:
            if flow.interface in self.localnet_cache:
                # localnet of this interface is already recognized
                return False

        elif "default" in self.localnet_cache:
            # slips is analyzing a pcap/zeek dir, and we already guessed the
            # localnet of it
            return False

        if flow.saddr == "0.0.0.0":
            return False

        if self._private_client_ips:
            return True

        try:
            saddr_obj = ipaddress.ip_address(flow.saddr)
        except ValueError:
            return False

        if (
            saddr_obj.is_multicast
            or saddr_obj.is_link_local
            or saddr_obj.is_loopback
            or saddr_obj.is_reserved
            or not saddr_obj.is_private
        ):
            return False
        return True
