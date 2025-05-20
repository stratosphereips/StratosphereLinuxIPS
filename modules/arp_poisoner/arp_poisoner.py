# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import logging
import os
import subprocess
import time
from threading import Lock
import json
import ipaddress
from scapy.all import ARP, send, Ether

from slips_files.common.abstracts.module import IModule
from modules.arp_poisoner.unblocker import ARPUnblocker
from slips_files.common.slips_utils import utils

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


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

    def _get_all_ip_mac_pairs(self, interface) -> list[tuple[str, str]]:
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

    def _arp_poison_everyone_about_target(
        self, target_ip: str, target_mac: str, fake_mac: str
    ):
        """
        Tells all the available hosts in the localnet that the target_ip is
        at fake_mac using unsolicited arp replies.
        """
        print(
            f"@@@@@@@@@@@@@@@@  arp_poison_everyone_about_target is"
            f" called ({target_ip})"
        )
        interface = self.args.interface
        all_hosts: list[tuple[str, str]] = self._get_all_ip_mac_pairs(
            interface
        )
        poisoned = 0
        print(
            f"@@@@@@@@@@@@@@@@@@ poison the network: tell everyone that the"
            f" target is at fake_mac "
            f" {target_ip} at MAC {target_mac}"
        )
        print(f"@@@@@@@@@@@@@@@@ hosts t o poison: {all_hosts}")

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
            send(pkt, verbose=0)
            pkt.show()
            print(
                f"@@@@@@@@@@@@ sent to {ip} ({mac}) => told them "
                f"{target_ip} is at {fake_mac}"
            )
            poisoned += 1

        print(f"@@@@@@@@@@@@ done poisoning {poisoned} hosts")

    def _arp_poison_target_about_gateway(
        self, target_ip: str, target_mac: str, fake_mac: str
    ):
        """
        Tells the target_ip that the gateway is at fake_mac using unsolicited
        arp reply
        """
        # in ap mode, this gw ip is the same as our own ip
        gateway_ip: str = self.db.get_gateway_ip()

        print(
            f"@@@@@@@@@@@@@@@@@@ poison the target ({target_ip}, {target_mac}): "
            f"tell it "
            f"the "
            f"gateway "
            f"is at "
            f"fake_mac {gateway_ip} at MAC {target_mac}"
        )
        # poison the target: tell it the gateway is at fake_mac
        pkt = ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=gateway_ip,
            hwsrc=fake_mac,
        )
        send(pkt, verbose=0)
        print("@@@@@@@@@@@@@@@@ SENT this packet")
        pkt.show()

    def _arp_poison(self, target_ip: str, first_time=False):
        """
        :kwarg first_time: is true if we're poisoning for the first time
        based on a new_blocking msg, and should be false when we're
        repoisoning every x seconds.
        """
        print(f"@@@@@@@@@@@@@@@@  _arp_poison is called ({target_ip})")
        fake_mac = "aa:aa:aa:aa:aa:aa"
        # it makes sense here to get the mac using cache, because if we
        # reached this function, means there's an alert, means slips seen
        # traffic from that target_ip and has itsmac in the arp cache.
        # no need to use an arp packet to get the mac.
        target_mac: str = utils.get_mac_for_ip_using_cache(target_ip)
        if not target_mac:
            print(f"@@@@@@@@@@@@ could not get MAC for {target_ip}")
            return

        self._arp_poison_target_about_gateway(target_ip, target_mac, fake_mac)
        self._arp_poison_everyone_about_target(target_ip, target_mac, fake_mac)

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
                f"@@@@@@@@@@@@@@@@ arp poison new blocking request for "
                f"{ip} {tw}"
            )

            if not self.is_valid_ip(ip):
                print(f"@@@@@@@@@@@@@@@@ invalid ip {ip}")
                return

            self._arp_poison(ip, first_time=True)

            # whether this ip is blocked now, or was already blocked, make an
            # unblocking request to either extend its
            # blocking period, or block it until the next timewindow is over.
            self.unblocker.unblock_request(ip, tw)

        if self.get_msg("tw_closed"):
            self.unblocker.update_requests()
