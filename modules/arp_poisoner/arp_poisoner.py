# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import logging
import os
import subprocess
import time
from threading import Lock
import json
import ipaddress
from typing import Set, Tuple
from scapy.all import ARP, Ether
from scapy.sendrecv import sendp, srp

from slips_files.common.abstracts.module import IModule
from modules.arp_poisoner.unblocker import ARPUnblocker
from slips_files.common.slips_utils import utils

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class ARPPoisoner(IModule):
    name = "ARP Poisoner"
    description = "ARP poisons attackers to isolate them from the network."
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

        # the unblocker will remove ips that should be unblocked from this dict
        for ip in self.unblocker.requests:
            self._arp_poison(ip)

    def _arp_scan(self, interface) -> Set[Tuple[str, str]]:
        """gets the available ip/mac pairs in the local
        network using arp-scan tool"""
        cmd = ["arp-scan", f"--interface={interface}", "--localnet"]
        output = subprocess.check_output(cmd, text=True)

        pairs = set()
        for line in output.splitlines():
            parts = line.strip().split()
            if (
                len(parts) >= 2
                and parts[0].count(".") == 3
                and ":" in parts[1]
            ):
                ip, mac = parts[0], parts[1].lower()
                pairs.add((ip, mac))

        return pairs

    def _get_mac_using_arp(self, ip) -> str | None:
        """sends an arp asking for the mac of the given ip"""
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        # send the packet and receive response
        result = srp(packet, timeout=4, verbose=0)[0]

        if result:
            return result[0][1].hwsrc
        return None

    def _isolate_target_from_localnet(self, target_ip: str, fake_mac: str):
        """
        Tells all the available hosts in the localnet that the target_ip is
        at fake_mac using unsolicited arp replies.
        """
        # send gratuitous arp request to update caches
        gratuitous_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1,
            pdst=target_ip,
            hwdst="00:00:00:00:00:00",
            psrc=target_ip,
            hwsrc=fake_mac,
        )
        sendp(gratuitous_pkt, verbose=0)

        # PS: this function doesnt poison own cache. when an attacker is
        # found, FW blocking module handles blocking it through the fw,
        # plus we need our cache unpoisoned to be able to get the mac of
        # attackers to poison/reposion them.
        all_hosts: Set[Tuple[str, str]] = self._arp_scan(self.args.interface)
        for ip, mac in all_hosts:
            if ip == target_ip:
                continue

            pkt = Ether(dst=mac) / ARP(
                op=2,
                pdst=ip,  # which dst ip are we sending this pkt to?
                hwdst=mac,  # which dst mac are we sending this pkt to?
                # the ip/mac combo that we're announcing
                psrc=target_ip,
                hwsrc=fake_mac,
            )
            sendp(pkt, verbose=0)

    def _cut_targets_internet(
        self, target_ip: str, target_mac: str, fake_mac: str
    ):
        """
        Cuts the target's internet by telling the target_ip that the gateway
        is at fake_mac using unsolicited arp reply AND telling the gw that
        the target is at a fake mac.
        """
        # in ap mode, this gw ip is the same as our own ip
        gateway_ip: str = self.db.get_gateway_ip()

        # We use Ether() before ARP() to explicitly construct a complete Ethernet frame
        # poison the target: tell it the gateway is at fake_mac
        # gw -> attacker: im at a fake mac.
        pkt = Ether(dst=target_mac) / ARP(
            op=2,
            psrc=gateway_ip,
            hwsrc=fake_mac,
            pdst=target_ip,
            hwdst=target_mac,
        )
        sendp(pkt, iface=self.args.interface, verbose=0)

        # poison the gw, tell it the victim is at a fake mac so traffic
        # from it wont reach the victim
        # attacker -> gw: im at a fake mac.
        gateway_mac = self.db.get_gateway_mac()
        pkt = Ether(dst=gateway_mac) / ARP(
            op=2,
            psrc=target_ip,
            hwsrc=fake_mac,
            pdst=gateway_ip,
            hwdst=gateway_mac,
        )
        sendp(pkt, iface=self.args.interface, verbose=0)

    def _arp_poison(self, target_ip: str, first_time=False):
        """
        Prevents the target from accessing the internet and isolates it
        from the rest of the network.
        :kwarg first_time: is true if we're poisoning for the first time
        based on a new_blocking msg, and should be false when we're
        repoisoning every x seconds.
        """
        fake_mac = "aa:aa:aa:aa:aa:aa"
        # it makes sense here to get the mac using cache, because if we
        # reached this function, means there's an alert, means slips seen
        # traffic from that target_ip and has itsmac in the arp cache.
        # no need to use an arp packet to get the mac.
        target_mac: str = utils.get_mac_for_ip_using_cache(target_ip)

        if not target_mac:
            target_mac: str = self._get_mac_using_arp(target_ip)
            if not target_mac:
                return

        self._cut_targets_internet(target_ip, target_mac, fake_mac)
        self._isolate_target_from_localnet(target_ip, fake_mac)

        # we repoison every 10s, we dont wanna log every 10s.
        if first_time:
            self.log(f"Poisoned {target_ip} at {target_mac}.")

    def is_broadcast(self, ip_str, net_str) -> bool:
        try:
            net = ipaddress.ip_network(net_str, strict=False)
            ip = ipaddress.ip_address(ip_str)
            return ip == net.broadcast_address
        except ValueError:
            return False

    def can_poison_ip(self, ip) -> bool:
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

        # no need to check if the ip is in our ips because all our ips are
        # excluded from the new_blocking channel
        return True

    def main(self):
        self.keep_attackers_poisoned()

        if msg := self.get_msg("new_blocking"):
            data = json.loads(msg["data"])
            ip = data.get("ip")
            tw: int = data.get("tw")

            if not self.can_poison_ip(ip):
                return

            self._arp_poison(ip, first_time=True)

            # whether this ip is blocked now, or was already blocked, make an
            # unblocking request to either extend its
            # blocking period, or block it until the next timewindow is over.
            self.unblocker.unblock_request(ip, tw)

        if self.get_msg("tw_closed"):
            self.unblocker.update_requests()
