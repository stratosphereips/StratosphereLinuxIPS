# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from dataclasses import asdict
from typing import Tuple

from slips_files.core.flows.suricata import SuricataFile
from slips_files.common.slips_utils import utils
from slips_files.core.structures.flow_attributes import Role


class FlowHandler:
    """
    Each flow seen by slips will be a different instance of this class
    """

    def __init__(
        self, db, symbol_handler, flow, profileid, twid, is_running_non_stop
    ):
        self.db = db
        self.flow = flow
        self.profileid = profileid
        self.twid = twid
        self.symbol = symbol_handler
        self.running_non_stop: bool = is_running_non_stop

    def handle_conn(self):
        role = Role.CLIENT

        # Compute the symbol for this flow, for this TW, for this profile.
        # The symbol is based on the 'letters' of the original
        # Startosphere IPS tool
        symbol: Tuple = self.symbol.compute(self.flow, self.twid, "OutTuples")

        # Change symbol for its internal data. Symbol is a tuple and is
        # confusing if we ever change the API
        # Add the out tuple
        self.db.add_tuple(self.profileid, self.twid, symbol, role, self.flow)
        self.db.add_ips(self.profileid, self.twid, self.flow, role)
        self.db.add_mac_addr_to_profile(
            self.profileid, self.flow.smac, self.flow.interface
        )

        if self.running_non_stop:
            # to avoid publishing duplicate MACs, when running on
            # an interface, we should have an arp.log, so we'll publish
            # MACs from there only
            return

        self.db.publish_new_mac(self.flow.smac, self.flow.saddr)
        self.db.publish_new_mac(self.flow.dmac, self.flow.daddr)

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
            if not self.db.get_gateway_ip(self.flow.interface):
                # get the gw addr from the msg
                gw_ip = self.flow.msg.split(": ")[-1].strip()
                self.db.set_default_gateway("IP", gw_ip, self.flow.interface)

            if not self.db.get_gateway_mac(self.flow.interface) and gw_ip:
                gw_mac = self.db.get_mac_addr_from_profile(f"profile_{gw_ip}")
                if gw_mac:
                    self.db.set_default_gateway(
                        "MAC", gw_mac, self.flow.interface
                    )

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
        epoch_time = utils.convert_ts_format(
            self.flow.starttime, "unixtimestamp"
        )
        self.flow.starttime = epoch_time
        self.db.publish_new_software(self.profileid, self.flow)

        self.db.add_altflow(self.flow, self.profileid, self.twid, "benign")

    def handle_dhcp(self):
        # send this to ip_info module to get vendor info about this MAC
        self.db.publish_new_mac(
            self.flow.smac or False,
            self.flow.saddr,
        )

        self.db.add_mac_addr_to_profile(
            self.profileid, self.flow.smac, self.flow.interface
        )

        if self.flow.server_addr:
            self.db.store_dhcp_server(self.flow.server_addr)
            self.db.mark_profile_as_dhcp(self.profileid)

        epoch_time = utils.convert_ts_format(
            self.flow.starttime, "unixtimestamp"
        )
        self.flow.starttime = epoch_time

        self.db.publish_new_dhcp(self.profileid, self.flow)
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
        self.db.add_mac_addr_to_profile(
            self.profileid, self.flow.smac, self.flow.interface
        )
        self.db.publish_new_mac(self.flow.dmac, self.flow.daddr)
        self.db.publish_new_mac(self.flow.smac, self.flow.saddr)
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
