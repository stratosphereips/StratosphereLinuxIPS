# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import ipaddress
import json
from dataclasses import asdict
from typing import Tuple

from slips_files.core.flows.suricata import SuricataFile
from slips_files.common.slips_utils import utils


class Publisher:
    # TODO should probably be moved to the dbmanager or redis db?
    def __init__(self, db):
        self.db = db

    def new_dhcp(self, profileid, flow):
        """
        Publish the GW addr in the new_dhcp channel
        :param starttime: epoch starttime
        """
        # this channel is used for setting the default gw ip,
        # only 1 flow is enough for that
        # on home networks, the router serves as a simple DHCP server
        to_send = {
            "profileid": profileid,
            "twid": self.db.get_timewindow(flow.starttime, profileid),
            "flow": asdict(flow),
        }
        self.db.publish("new_dhcp", json.dumps(to_send))

    def new_MAC(self, mac: str, ip: str):
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
        self.db.publish("new_MAC", json.dumps(to_send))

    def new_software(self, profileid, flow):
        """
        Send the whole flow to new_software channel
        """
        to_send = {
            "flow": asdict(flow),
            "twid": self.db.get_timewindow(flow.starttime, profileid),
        }
        self.db.publish("new_software", json.dumps(to_send))


class FlowHandler:
    """
    Each flow seen by slips will be a different instance of this class
    """

    def __init__(self, db, symbol_handler, flow):
        self.db = db
        self.publisher = Publisher(self.db)
        self.flow = flow
        self.symbol = symbol_handler
        self.running_non_stop: bool = self.db.is_running_non_stop()

    def is_supported_flow_type(self):
        supported_types = (
            "ssh",
            "ssl",
            "http",
            "dns",
            "conn",
            "flow",
            "argus",
            "nfdump",
            "notice",
            "dhcp",
            "files",
            "arp",
            "ftp",
            "smtp",
            "software",
            "weird",
            "tunnel",
        )
        return bool(
            self.flow.starttime is not None
            and self.flow.type_ in supported_types
        )

    def handle_conn(self):
        role = "Client"
        daddr_as_obj = ipaddress.ip_address(self.flow.daddr)
        # this identified the tuple, it's a combination
        # of daddr, dport and proto
        # this is legacy code and refactoring it will
        # break many things, so i wont:D
        tupleid = f"{daddr_as_obj}-{self.flow.dport}-{self.flow.proto}"

        # Compute the symbol for this flow, for this TW, for this profile.
        # The symbol is based on the 'letters' of the original
        # Startosphere IPS tool
        symbol: Tuple = self.symbol.compute(self.flow, self.twid, "OutTuples")

        # Change symbol for its internal data. Symbol is a tuple and is
        # confusing if we ever change the API
        # Add the out tuple
        self.db.add_tuple(
            self.profileid, self.twid, tupleid, symbol, role, self.flow
        )

        # Add the dstip
        self.db.add_ips(self.profileid, self.twid, self.flow, role)
        # Add the dstport
        port_type = "Dst"
        self.db.add_port(self.profileid, self.twid, self.flow, role, port_type)

        # Add the srcport
        port_type = "Src"
        self.db.add_port(self.profileid, self.twid, self.flow, role, port_type)
        # store the original flow as benign in sqlite
        self.db.add_flow(self.flow, self.profileid, self.twid, "benign")

        self.db.add_mac_addr_to_profile(self.profileid, self.flow.smac)

        if self.running_non_stop:
            # to avoid publishing duplicate MACs, when running on
            # an interface, we should have an arp.log, so we'll publish
            # MACs from there only
            return

        self.publisher.new_MAC(self.flow.smac, self.flow.saddr)
        self.publisher.new_MAC(self.flow.dmac, self.flow.daddr)

    def handle_dns(self):
        self.db.add_out_dns(self.profileid, self.twid, self.flow)
        self.db.add_altflow(self.flow, self.profileid, self.twid, "benign")

    def handle_http(self):
        self.db.add_out_http(
            self.profileid,
            self.twid,
            self.flow,
        )

        self.db.add_altflow(self.flow, self.profileid, self.twid, "benign")

    def handle_ssl(self):
        self.db.add_out_ssl(self.profileid, self.twid, self.flow)
        self.db.add_altflow(self.flow, self.profileid, self.twid, "benign")

    def handle_ssh(self):
        self.db.add_out_ssh(self.profileid, self.twid, self.flow)
        self.db.add_altflow(self.flow, self.profileid, self.twid, "benign")

    def handle_notice(self):
        self.db.add_out_notice(self.profileid, self.twid, self.flow)

        if "Gateway_addr_identified" in self.flow.note:
            # foirst check if the gw ip and mac are set by
            # profiler.get_gateway_info() or ip_info module
            gw_ip = False
            if not self.db.get_gateway_ip():
                # get the gw addr from the msg
                gw_ip = self.flow.msg.split(": ")[-1].strip()
                self.db.set_default_gateway("IP", gw_ip)

            if not self.db.get_gateway_mac() and gw_ip:
                gw_mac = self.db.get_mac_addr_from_profile(f"profile_{gw_ip}")
                if gw_mac:
                    self.db.set_default_gateway("MAC", gw_mac)

        self.db.add_altflow(self.flow, self.profileid, self.twid, "benign")

    def handle_ftp(self):
        if used_port := self.flow.used_port:
            self.db.set_ftp_port(used_port)

        self.db.add_altflow(self.flow, self.profileid, self.twid, "benign")

    def handle_smtp(self):
        to_send = {
            "flow": asdict(self.flow),
            "profileid": self.profileid,
            "twid": self.twid,
        }
        to_send = json.dumps(to_send)
        self.db.publish("new_smtp", to_send)

        self.db.add_altflow(self.flow, self.profileid, self.twid, "benign")

    def handle_software(self):
        self.db.add_software_to_profile(self.profileid, self.flow)
        epoch_time = utils.convert_format(self.flow.starttime, "unixtimestamp")
        self.flow.starttime = epoch_time
        self.publisher.new_software(self.profileid, self.flow)

        self.db.add_altflow(self.flow, self.profileid, self.twid, "benign")

    def handle_dhcp(self):
        # send this to ip_info module to get vendor info about this MAC
        self.publisher.new_MAC(
            self.flow.smac or False,
            self.flow.saddr,
        )

        self.db.add_mac_addr_to_profile(self.profileid, self.flow.smac)

        if self.flow.server_addr:
            self.db.store_dhcp_server(self.flow.server_addr)
            self.db.mark_profile_as_dhcp(self.profileid)

        epoch_time = utils.convert_format(self.flow.starttime, "unixtimestamp")
        self.flow.starttime = epoch_time

        self.publisher.new_dhcp(self.profileid, self.flow)
        for uid in self.flow.uids:
            # we're modifying the copy of self.flow
            # the goal is to store a copy of this flow for each uid in self.flow.uids
            flow = self.flow
            flow.uid = uid
            self.db.add_altflow(self.flow, self.profileid, self.twid, "benign")

    def handle_files(self):
        """
        Send files.log data to new_downloaded_file channel in the TI module to
         see if it's malicious
        """

        # files slips sees can be of 2 types: suricata or zeek
        to_send = {
            "flow": asdict(self.flow),
            "type": (
                "suricata" if isinstance(self.flow, SuricataFile) else "zeek"
            ),
            "profileid": self.profileid,
            "twid": self.twid,
        }

        to_send = json.dumps(to_send)
        self.db.publish("new_downloaded_file", to_send)
        self.db.add_altflow(self.flow, self.profileid, self.twid, "benign")

    def handle_arp(self):
        to_send = {
            "flow": asdict(self.flow),
            "profileid": self.profileid,
            "twid": self.twid,
        }
        # send to arp module
        to_send = json.dumps(to_send)
        self.db.publish("new_arp", to_send)
        self.db.add_mac_addr_to_profile(self.profileid, self.flow.smac)
        self.publisher.new_MAC(self.flow.dmac, self.flow.daddr)
        self.publisher.new_MAC(self.flow.smac, self.flow.saddr)
        self.db.add_altflow(self.flow, self.profileid, self.twid, "benign")

    def handle_weird(self):
        """
        handles weird.log zeek flows
        """
        to_send = {
            "profileid": self.profileid,
            "twid": self.twid,
            "flow": asdict(self.flow),
        }
        to_send = json.dumps(to_send)
        self.db.publish("new_weird", to_send)
        self.db.add_altflow(self.flow, self.profileid, self.twid, "benign")

    def handle_tunnel(self):
        to_send = {
            "profileid": self.profileid,
            "twid": self.twid,
            "flow": asdict(self.flow),
        }
        to_send = json.dumps(to_send)
        self.db.publish("new_tunnel", to_send)

        self.db.add_altflow(self.flow, self.profileid, self.twid, "benign")
