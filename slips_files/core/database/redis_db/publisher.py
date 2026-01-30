# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import ipaddress
import json
from dataclasses import asdict


class Publisher:
    def publish_new_dhcp(self, profileid, flow):
        """
        Publish the GW addr in the new_dhcp channel
        :param starttime: epoch starttime
        """
        # this channel is used for setting the default gw ip,
        # only 1 flow is enough for that
        # on home networks, the router serves as a simple DHCP server
        to_send = {
            "profileid": profileid,
            "twid": self.get_timewindow(flow.starttime, profileid),
            "flow": asdict(flow),
        }
        self.publish("new_dhcp", json.dumps(to_send))

    def publish_new_mac(self, mac: str, ip: str):
        """
        check if mac and ip aren't multicast or link-local
        and publish to new_MAC channel to get more info about the mac
        :param mac: src/dst mac
        :param ip: src/dst ip
        src macs should be passed with srcips, dstmac with dstips
        """
        if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_multicast:
                return
        except ValueError:
            return

        # send the  MAC to IP_Info module to get vendor info about it
        to_send = {"MAC": mac, "profileid": f"profile_{ip}"}
        self.publish("new_MAC", json.dumps(to_send))

    def publish_new_software(self, profileid, flow):
        """
        Send the whole flow to new_software channel
        """
        to_send = {
            "flow": asdict(flow),
            "twid": self.get_timewindow(flow.starttime, profileid),
        }
        self.publish("new_software", json.dumps(to_send))
