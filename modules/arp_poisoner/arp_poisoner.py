# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import ipaddress
import os
import time
from threading import Lock

from scapy.all import ARP, send
from scapy.layers.l2 import Ether
from scapy.sendrecv import srp

from slips_files.common.abstracts.module import IModule
from modules.arp_poisoner.unblocker import ARPUnblocker
import json

from slips_files.common.slips_utils import utils


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
        self._time_since_last_repoison = time.time()
        self.log_file_path = os.path.join(self.output_dir, "arp_poisoning.log")
        self.blocking_logfile_lock = Lock()
        # clear it
        try:
            open(self.log_file_path, "w").close()
        except FileNotFoundError:
            pass
        self.unblocker = ARPUnblocker(
            self.db, self.should_stop, self.logger, self.log
        )

    def log(self, text):
        """Logs the given text to the blocking log file"""
        with self.blocking_logfile_lock:
            with open(self.log_file_path, "a") as f:
                human_readable_datetime = utils.convert_ts_format(
                    time.time(), utils.alerts_format
                )
                f.write(f"{human_readable_datetime} - {text}\n")

    def _is_time_to_repoison(self) -> bool:
        """returns true if 10s passed since the last poison time"""
        if time.time() - self._time_since_last_repoison >= 10:
            self._time_since_last_repoison = time.time()
            return True

        return False

    def keep_attackers_poisoned(self):
        """
        is called in a loop, executes once every 10s
        repoisons all ips in self.unblocker.requests
        """
        if not self._is_time_to_repoison() or not self.unblocker.requests:
            return

        print("@@@@@@@@@@@@@@@@ time to repoison")

        # the unblocker will remove ips that should be unblocked from this dict
        for ip in self.unblocker.requests:
            print(f"@@@@@@@@@@@@@@@@ calling _arp_poison({ip})")
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

    def _arp_poison(self, target_ip: str):
        print(f"@@@@@@@@@@@@@@@@  _arp_poison is called ({target_ip})")
        fake_mac = "aa:aa:aa:aa:aa:aa"
        gateway_ip: str = self.db.get_gateway_ip()

        target_mac: str = self._get_mac(target_ip)
        if not target_mac:
            print(f"@@@@@@@@@@@@ could not resolve MAC for {target_ip}")
            return

        print(
            f"@@@@@@@@@@@@@@@@@@ poison the target: tell it the gateway is at "
            f"fake_mac {target_ip} at MAC {target_mac}"
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

        print(
            f"@@@@@@@@@@@@@@@@@@ poison the network: tell everyone that the"
            f" target is at fake_mac "
            f" {target_ip} at MAC {target_mac}"
        )

        # poison the network: tell everyone that the target is at fake_mac
        pkt2 = ARP(
            op=2,
            pdst="255.255.255.255",
            hwdst="ff:ff:ff:ff:ff:ff",
            psrc=target_ip,
            hwsrc=fake_mac,
        )
        send(pkt2, verbose=0)

    def is_broadcast(self, ip_str, net_str) -> bool:
        try:
            net = ipaddress.ip_network(net_str, strict=False)
            ip = ipaddress.ip_address(ip_str)
            return ip == net.broadcast_address
        except ValueError:
            return False

    def is_valid_ip(self, ip) -> bool:
        """
        Checks if the ip is in out localnet, isnt the router
        """
        if utils.is_public_ip(ip):
            return False

        localnet = self.db.get_local_network()
        if ipaddress.ip_address(ip) not in ipaddress.ip_network(localnet):
            return False

        if self.is_broadcast(ip, localnet):
            return False

        if ip == self.db.get_gateway_ip():
            return False
        # no need to check if the ip is in our ips because all our ips are
        # excluded from the new_blocking channel
        return True

    def main(self):
        self.keep_attackers_poisoned()

        if msg := self.get_msg("new_blocking"):
            data = json.loads(msg["data"])
            ip = data.get("ip")
            tw: int = data.get("tw")
            print(
                f"@@@@@@@@@@@@@@@@ arp poison new blocking requets for "
                f"{ip} {tw}"
            )

            if not self.is_valid_ip(ip):
                print(f"@@@@@@@@@@@@@@@@ invalid ip {ip}")
                return

            self._arp_poison(ip)

            # whether this ip is blocked now, or was already blocked, make an
            # unblocking request to either extend its
            # blocking period, or block it until the next timewindow is over.
            self.unblocker.unblock_request(ip, tw)

        if self.get_msg("tw_closed"):
            self.unblocker.update_requests()
