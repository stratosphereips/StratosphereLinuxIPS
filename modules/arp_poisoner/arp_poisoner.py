# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import time
from scapy.all import ARP, send
from scapy.layers.l2 import Ether
from scapy.sendrecv import srp

from slips_files.common.abstracts.module import IModule
import json


class Template(IModule):
    name = "ARP Poisoner"
    description = "ARP Poisons attackers to isolate them from the network"
    authors = ["Alya Gomaa"]

    def init(self):
        self.c1 = self.db.subscribe("new_blocking")
        self.c2 = self.db.subscribe("tw_closed")
        self.channels = {
            "new_blocking": self.c1,
            "tw_closed": self.c2,
        }
        self.time_since_last_repoison = time.time()

    def _is_time_to_repoison(self) -> bool:
        """returns true if 10s passed since the last poison time"""
        return time.time() - self.time_since_last_repoison >= 10

    def keep_attackers_poisoned(self):
        """
        is called in a loop, executes once every 10s
        repoisons all ips in self.unblocker.requests
        """
        if not self._is_time_to_repoison():
            return

        # the unblocker will remove ips that should be unblocked from this dict
        for ip in self.unblocker.requests:
            self._arp_poison(ip)

    @staticmethod
    def _get_mac(target_ip):
        arp_req = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_req

        # send the packet and wait for a response
        answered, _ = srp(packet, timeout=2, verbose=0)
        if answered:
            return answered[0][1].hwsrc
        return None

    def _arp_poison(self, target_ip: str, interval: int = 10):
        fake_mac = "aa:aa:aa:aa:aa:aa"
        gateway_ip: str = self.db.get_gateway_ip()

        target_mac: str = self._get_mac(target_ip)
        if not target_mac:
            print(f"could not resolve MAC for {target_ip}")
            return

        print(
            f"starting ARP poison loop for ip {target_ip} at MAC {target_mac}"
        )
        # poison the target: tell it the gateway is at fake_mac
        pkt1 = ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=gateway_ip,
            hwsrc=fake_mac,
        )
        send(pkt1, verbose=0)

        # poison the network: tell everyone that the target is at fake_mac
        pkt2 = ARP(
            op=2,
            pdst="255.255.255.255",
            hwdst="ff:ff:ff:ff:ff:ff",
            psrc=target_ip,
            hwsrc=fake_mac,
        )
        send(pkt2, verbose=0)

    def main(self):
        self.keep_attackers_poisoned()
        if msg := self.get_msg("new_blocking"):
            data = json.loads(msg["data"])
            ip = data.get("ip")
            # tw: int = data.get("tw")
            # whether this ip is blocked now, or was already blocked, make an
            # unblocking request to either extend its
            # blocking period, or block it until the next timewindow is over.
            self._arp_poison(ip)
            self.unblocker.add_req(ip)

        if msg := self.get_msg("tw_closed"):
            self.unblocker.update_requests()
