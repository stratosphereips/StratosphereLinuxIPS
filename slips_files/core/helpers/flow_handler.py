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

    async def new_dhcp(self, profileid, flow):
        """
        Publish the GW addr in the new_dhcp channel
        :param starttime: epoch starttime
        """
        # this channel is used for setting the default gw ip,
        # only 1 flow is enough for that
        # on home networks, the router serves as a simple DHCP server
        to_send = {
            "profileid": profileid,
            "twid": await self.db.get_timewindow(flow.starttime, profileid),
            "flow": asdict(flow),
        }
        await self.db.publish("new_dhcp", json.dumps(to_send))

    async def new_mac(self, mac: str, ip: str):
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
        await self.db.publish("new_MAC", json.dumps(to_send))

    async def new_software(self, profileid, flow):
        """
        Send the whole flow to new_software channel
        """
        to_send = {
            "flow": asdict(flow),
            "twid": await self.db.get_timewindow(flow.starttime, profileid),
        }
        await self.db.publish("new_software", json.dumps(to_send))


class FlowHandler:
    """
    Each flow seen by slips will use a different instance of this class
    depending on the type of the flow (conn, dns, etc.)
    """

    def __init__(self, db, symbol_handler, flow):
        self.db = db
        self.publisher = Publisher(self.db)
        self.flow = flow
        self.symbol = symbol_handler

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

    async def handle_conn(self):
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
        await self.db.add_tuple(
            self.profileid, self.twid, tupleid, symbol, role, self.flow
        )

        # Add the dstip
        await self.db.add_ips(self.profileid, self.twid, self.flow, role)
        # Add the dstport
        port_type = "Dst"
        await self.db.add_port(
            self.profileid, self.twid, self.flow, role, port_type
        )

        # Add the srcport
        port_type = "Src"
        await self.db.add_port(
            self.profileid, self.twid, self.flow, role, port_type
        )
        # store the original flow as benign in sqlite
        await self.db.add_flow(self.flow, self.profileid, self.twid, "benign")

        await self.db.add_mac_addr_to_profile(self.profileid, self.flow.smac)

        if await self.db.is_running_non_stop():
            # to avoid publishing duplicate MACs, when running on
            # an interface, we should have an arp.log, so we'll publish
            # MACs from there only
            return

        await self.publisher.new_mac(self.flow.smac, self.flow.saddr)
        await self.publisher.new_mac(self.flow.dmac, self.flow.daddr)

    async def handle_dns(self):
        await self.db.add_out_dns(self.profileid, self.twid, self.flow)
        await self.db.add_altflow(
            self.flow, self.profileid, self.twid, "benign"
        )

    async def handle_http(self):
        await self.db.add_out_http(
            self.profileid,
            self.twid,
            self.flow,
        )

        await self.db.add_altflow(
            self.flow, self.profileid, self.twid, "benign"
        )

    async def handle_ssl(self):
        await self.db.add_out_ssl(self.profileid, self.twid, self.flow)
        await self.db.add_altflow(
            self.flow, self.profileid, self.twid, "benign"
        )

    async def handle_ssh(self):
        await self.db.add_out_ssh(self.profileid, self.twid, self.flow)
        await self.db.add_altflow(
            self.flow, self.profileid, self.twid, "benign"
        )

    async def handle_notice(self):
        await self.db.add_out_notice(self.profileid, self.twid, self.flow)

        if "Gateway_addr_identified" in self.flow.note:
            # foirst check if the gw ip and mac are set by
            # profiler.get_gateway_info() or ip_info module
            gw_ip = False
            if not await self.db.get_gateway_ip():
                # get the gw addr from the msg
                gw_ip = self.flow.msg.split(": ")[-1].strip()
                await self.db.set_default_gateway("IP", gw_ip)

            if not await self.db.get_gateway_mac() and gw_ip:
                gw_mac = await self.db.get_mac_addr_from_profile(
                    f"profile_{gw_ip}"
                )
                if gw_mac:
                    await self.db.set_default_gateway("MAC", gw_mac)

        await self.db.add_altflow(
            self.flow, self.profileid, self.twid, "benign"
        )

    async def handle_ftp(self):
        if used_port := self.flow.used_port:
            await self.db.set_ftp_port(used_port)

        await self.db.add_altflow(
            self.flow, self.profileid, self.twid, "benign"
        )

    async def handle_smtp(self):
        to_send = {
            "flow": asdict(self.flow),
            "profileid": self.profileid,
            "twid": self.twid,
        }
        to_send = json.dumps(to_send)
        await self.db.publish("new_smtp", to_send)

        await self.db.add_altflow(
            self.flow, self.profileid, self.twid, "benign"
        )

    async def handle_software(self):
        await self.db.add_software_to_profile(self.profileid, self.flow)
        epoch_time = utils.convert_ts_format(
            self.flow.starttime, "unixtimestamp"
        )
        self.flow.starttime = epoch_time
        await self.publisher.new_software(self.profileid, self.flow)

        await self.db.add_altflow(
            self.flow, self.profileid, self.twid, "benign"
        )

    async def handle_dhcp(self):
        # send this to ip_info module to get vendor info about this MAC
        await self.publisher.new_mac(
            self.flow.smac or False,
            self.flow.saddr,
        )

        await self.db.add_mac_addr_to_profile(self.profileid, self.flow.smac)

        if self.flow.server_addr:
            await self.db.store_dhcp_server(self.flow.server_addr)
            await self.db.mark_profile_as_dhcp(self.profileid)

        epoch_time = utils.convert_ts_format(
            self.flow.starttime, "unixtimestamp"
        )
        self.flow.starttime = epoch_time

        await self.publisher.new_dhcp(self.profileid, self.flow)
        for uid in self.flow.uids:
            # we're modifying the copy of self.flow
            # the goal is to store a copy of this flow for each uid in self.flow.uids
            flow = self.flow
            flow.uid = uid
            await self.db.add_altflow(
                self.flow, self.profileid, self.twid, "benign"
            )

    async def handle_files(self):
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
        await self.db.publish("new_downloaded_file", to_send)
        await self.db.add_altflow(
            self.flow, self.profileid, self.twid, "benign"
        )

    async def handle_arp(self):
        to_send = {
            "flow": asdict(self.flow),
            "profileid": self.profileid,
            "twid": self.twid,
        }
        # send to arp module
        to_send = json.dumps(to_send)
        await self.db.publish("new_arp", to_send)
        await self.db.add_mac_addr_to_profile(self.profileid, self.flow.smac)
        await self.publisher.new_mac(self.flow.dmac, self.flow.daddr)
        await self.publisher.new_mac(self.flow.smac, self.flow.saddr)
        await self.db.add_altflow(
            self.flow, self.profileid, self.twid, "benign"
        )

    async def handle_weird(self):
        """
        handles weird.log zeek flows
        """
        to_send = {
            "profileid": self.profileid,
            "twid": self.twid,
            "flow": asdict(self.flow),
        }
        to_send = json.dumps(to_send)
        await self.db.publish("new_weird", to_send)
        await self.db.add_altflow(
            self.flow, self.profileid, self.twid, "benign"
        )

    async def handle_tunnel(self):
        to_send = {
            "profileid": self.profileid,
            "twid": self.twid,
            "flow": asdict(self.flow),
        }
        to_send = json.dumps(to_send)
        await self.db.publish("new_tunnel", to_send)

        await self.db.add_altflow(
            self.flow, self.profileid, self.twid, "benign"
        )
