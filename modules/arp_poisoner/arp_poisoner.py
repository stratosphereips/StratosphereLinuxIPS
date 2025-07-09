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

from slips_files.common.abstracts.imodule import IModule
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
        self._time_since_last_repoison = {}
        self._time_since_last_internet_cut = {}
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
        self.last_closed_tw = ""
        self._scan_delay = 30
        self._last_scan_time = 0
        self.last_arp_scan_output = ""

    def log(self, text):
        """Logs the given text to the blocking log file"""
        with self.blocking_logfile_lock:
            with open(self.log_file_path, "a") as f:
                human_readable_datetime = utils.convert_ts_format(
                    time.time(), utils.alerts_format
                )
                f.write(f"{human_readable_datetime} - {text}\n")

    def _is_time_to_repoison(self, target: str) -> bool:
        """
        times to repoison are tracked per target ip.
        returns true if 30s passed since the last poison time
        :param target: the target ip that we want to repoison.
        Why 30? ARP caches usually expire after 30–60 seconds on most
        OSes, so we send the poison packets every 30 seconds to ensure
        that the target's cache stays poisoned and to avoid overwhelming the
        network.
        """
        if (
            target not in self._time_since_last_repoison
            or time.time() - self._time_since_last_repoison[target] >= 30
        ):
            self._time_since_last_repoison.update({target: time.time()})
            return True

        return False

    def keep_attackers_poisoned(self):
        """
        is called in a loop, executes once every 10s
        repoisons all ips in self.unblocker.requests
        """
        if not self.unblocker.requests:
            return

        ips_to_stop_poisoning = []
        # the unblocker will remove ips that should be unblocked from this dict
        for ip in self.unblocker.requests:
            # to keep all attackers poisoned, we re-poison every 30s,
            # check if the target last poisoned time is more than 30s ago
            if not self._is_time_to_repoison(ip):
                # we won't stop poisoning this ip forever, we'll just wait
                # 30s to repoison it.
                continue

            if self.unblocker.check_if_time_to_unblock(ip):
                ips_to_stop_poisoning.append(ip)
            else:
                self._attack(ip)

        for ip in ips_to_stop_poisoning:
            self.unblocker.del_request(ip)

    def _is_time_to_rescan(self) -> bool:
        """
        Returns True if it's time to rescan the network using arp-scan.
        The scan is done every self._scan_delay seconds.
        """
        now = time.time()
        if now - self._last_scan_time >= self._scan_delay:
            self._last_scan_time = now
            return True

        return False

    def _adapt_scan_delay(self, changes: bool):
        """
        adapts the arp scan delay based on whether there were changes in
        the output of arp-scan since the last scan or not.
        :param changes: True if there were changes in the arp-scan command
        since last time.
        If there were no changes, it increases the delay by 10s, up to a
        maximum of 120s (2 minutes).
        If there were changes, it resets the delay to 30s.
        The goal of this is to reduce the frequency of scans when the network
        is stable.
        """
        if changes:
            self._scan_delay = 30
        else:
            self._scan_delay = min(self._scan_delay + 10, 120)  # Up to 2 mins

    def _adjust_scan_delay_based_on_arp_scan_output(self, output: Set):
        if output == self.last_arp_scan_output:
            # if the output is the same as the last output, it means
            # there were no changes in the network, so we can increase
            # the scan delay.
            self._adapt_scan_delay(changes=False)
        else:
            self._adapt_scan_delay(changes=True)
            # store the last output for comparison
            self.last_arp_scan_output = output

    def _arp_scan(self, interface) -> Set[Tuple[str, str]]:
        """gets the available ip/mac pairs in the local
        network using arp-scan tool"""
        # why are using the arp-scan tool instead of checking the arp
        # cache? because the cache has only the ips that slips
        # saw/interacted with, and we want to get all the ips in the
        # network even if slips never saw them.

        if not self._is_time_to_rescan():
            return set()

        # --retry=0 to avoid redundant retries.
        cmd = [
            "arp-scan",
            f"--interface={interface}",
            "--localnet",
            "--retry=0",
        ]
        try:
            output = subprocess.check_output(cmd, text=True)
        except subprocess.CalledProcessError as e:
            self.print(f"arp-scan failed: {e.stderr or str(e)}", 0, 1)
            return set()

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

        self._adjust_scan_delay_based_on_arp_scan_output(pairs)
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

    def _attack(self, target_ip: str, first_time=False):
        """
        Prevents the target from accessing the internet and isolates it
        from the rest of the network.
        :kwarg first_time: is true if we're poisoning for the first time
        based on a new_blocking msg, and should be false when we're
        repoisoning every x seconds.
        """
        fake_mac = "aa:aa:aa:aa:aa:aa"

        # it makes sense here to get the mac using cache, because if we
        # reached this function, means there's an alert, means slips saw
        # traffic from that target_ip and has its mac in the arp cache.
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

            if not self.can_poison_ip(ip):
                return

            self._attack(ip, first_time=True)

            # whether this ip is blocked now, or was already blocked, make an
            # unblocking request to either extend its
            # blocking period, or block it until the next timewindow is over.
            self.unblocker.unblock_request(ip, tw)

        if msg := self.get_msg("tw_closed"):
            # this channel receives requests for closed tws for every ip
            # slips sees.
            # if slips saw 3 ips, this channel will receive 3 msgs with tw1
            # as closed. we're not interested in the ips, we just wanna
            # know when slips advances to the next tw.
            profileid_tw = msg["data"].split("_")
            twid = profileid_tw[-1]
            if self.last_closed_tw != twid:
                self.last_closed_tw = twid
                self.unblocker.update_requests()
