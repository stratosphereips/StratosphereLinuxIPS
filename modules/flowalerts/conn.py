# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
import contextlib
import ipaddress
import json
from datetime import datetime
from typing import Tuple, List, Dict
import validators

from modules.flowalerts.dns import DNS
from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.common.flow_classifier import FlowClassifier


NOT_ESTAB = "Not Established"
ESTAB = "Established"
SPECIAL_IPV6 = ("0.0.0.0", "255.255.255.255")


class Conn(IFlowalertsAnalyzer):
    def init(self):
        # get the default gateway
        self.gateway = self.db.get_gateway_ip()
        self.p2p_daddrs = {}
        # If 1 flow uploaded this amount of MBs or more,
        # slips will alert data upload
        self.flow_upload_threshold = 100
        self.read_configuration()
        self.whitelist = self.flowalerts.whitelist
        # how much time to wait when running on interface before reporting
        # connections without DNS? Usually the computer resolved DNS
        # already, so we need to wait a little to report
        # In mins
        self.conn_without_dns_interface_wait_time = 30
        self.dns_analyzer = DNS(self.db, flowalerts=self)
        self.is_running_non_stop: bool = self.db.is_running_non_stop()
        self.classifier = FlowClassifier()
        self.our_ips = utils.get_own_ips()
        self.input_type: str = self.db.get_input_type()
        self.multiple_reconnection_attempts_threshold = 5
        # we use this to try to detect if there's dns server that has a
        # private ip outside of localnet

    def read_configuration(self):
        conf = ConfigParser()
        self.long_connection_threshold = conf.long_connection_threshold()
        self.data_exfiltration_threshold = conf.data_exfiltration_threshold()
        self.data_exfiltration_threshold = conf.data_exfiltration_threshold()
        self.client_ips: List[str] = conf.client_ips()

    def name(self) -> str:
        return "conn_analyzer"

    def check_long_connection(self, twid, flow):
        """
        Check if a duration of the connection is
        above the threshold (more than 25 minutes by default).
        """
        try:
            flow.dur = float(flow.dur)
        except TypeError:
            return

        if (
            ipaddress.ip_address(flow.daddr).is_multicast
            or ipaddress.ip_address(flow.saddr).is_multicast
        ):
            # Do not check the duration of the flow
            return

        # If duration is above threshold, we should set an evidence
        if flow.dur > self.long_connection_threshold:
            self.set_evidence.long_connection(twid, flow)
            return True
        return False

    def is_p2p(self, flow):
        """
        P2P is defined as following : proto is udp, port numbers are higher
        than 30000 at least 5 connections to different daddrs
        OR trying to connct to 1 ip on more than 5 unkown 30000+/udp ports
        """
        if flow.proto.lower() == "udp" and int(flow.dport) > 30000:
            try:
                # trying to connct to 1 ip on more than 5 unknown ports
                if self.p2p_daddrs[flow.daddr] >= 6:
                    return True
                self.p2p_daddrs[flow.daddr] = self.p2p_daddrs[flow.daddr] + 1
                # now check if we have more than 4 different dst ips
            except KeyError:
                # first time seeing this daddr
                self.p2p_daddrs[flow.daddr] = 1

            if len(self.p2p_daddrs) >= 5:
                # this is another connection on port 3000+/udp and
                # we already have 5 of them, so probably p2p
                return True
        return False

    def port_belongs_to_an_org(self, daddr, portproto, profileid):
        """
        Checks whether the given port and daddr are known to be used by a
        specific organization or not, and returns true if the daddr belongs
        to the same org as the port
        This function says that the port belongs to an org if:
        1. we have its info in ports_used_by_specific_orgs.csv
        and considers the IP belongs to an org if:
        1. both saddr and daddr have the Mac vendor fo this org e.g. apple
        2. both saddr and daddr belong to the range specified in the
        ports_used_by_specific_orgs.csv
        3. if the SNI, hostname, rDNS, ASN of this ip belong to this org
        4. match the IPs to orgs that slips has info about (apple, fb,
        google,etc.)
        """
        organization_info = self.db.get_organization_of_port(portproto)
        if not organization_info:
            # consider this port as unknown, it doesn't belong to any org
            return False

        # there's an organization that's known to use this port,
        # check if the daddr belongs to the range of this org
        organization_info = json.loads(organization_info)

        # get the organization ip or range
        org_ips: list = organization_info["ip"]

        # org_name = organization_info['org_name']

        if daddr in org_ips:
            # it's an ip and it belongs to this org, consider the port as known
            return True

        for ip in org_ips:
            # is any of them a range?
            with contextlib.suppress(ValueError):
                # we have the org range in our database, check if the daddr
                # belongs to this range
                if ipaddress.ip_address(daddr) in ipaddress.ip_network(ip):
                    # it does, consider the port as known
                    return True

        # not a range either since nothing is specified, e.g. ip is set to ""
        # check the source and dst mac address vendors
        src_mac_vendor = str(self.db.get_mac_vendor_from_profile(profileid))
        dst_mac_vendor = str(
            self.db.get_mac_vendor_from_profile(f"profile_{daddr}")
        )

        # get the list of all orgs known to use this port and proto
        for org_name in organization_info["org_name"]:
            org_name = org_name.lower()
            if (
                org_name in src_mac_vendor.lower()
                or org_name in dst_mac_vendor.lower()
            ):
                return True

            # check if the SNI, hostname, rDNS of this ip belong to org_name
            ip_identification: Dict[str, str] = self.db.get_ip_identification(
                daddr, get_ti_data=False
            )
            ip_identification = utils.get_ip_identification_as_str(
                ip_identification
            )
            if org_name in ip_identification.lower():
                return True

            # if it's an org that slips has info about (apple, fb, google,etc.),
            # check if the daddr belongs to it
            if bool(self.whitelist.org_analyzer.is_ip_in_org(daddr, org_name)):
                return True

        return False

    def check_unknown_port(self, profileid, twid, flow):
        """
        Checks dports that are not in our
        slips_files/ports_info/services.csv
        """
        if not flow.dport:
            return

        portproto = f"{flow.dport}/{flow.proto}"
        if self.db.get_port_info(portproto):
            # it's a known port
            return False

        # we don't have port info in our database
        # is it a port that is known to be used by
        # a specific organization?
        if self.port_belongs_to_an_org(flow.daddr, portproto, profileid):
            return False

        if (
            "icmp" not in flow.proto
            and not self.is_p2p(flow)
            and not self.db.is_ftp_port(flow.dport)
        ):
            # we don't have info about this port
            self.set_evidence.unknown_port(twid, flow)
            return True

    def is_telnet(self, flow) -> bool:
        try:
            dport = int(flow.dport)
        except ValueError:
            # binetflow icmp ports are hex strings
            return False

        telnet_ports = (23, 2323)
        return dport in telnet_ports and flow.proto.lower() == "tcp"

    def check_multiple_telnet_reconnection_attempts(
        self, profileid, twid, flow
    ):
        if flow.interpreted_state != NOT_ESTAB:
            return

        if not self.is_telnet(flow):
            return

        key = f"{flow.saddr}-{flow.daddr}-telnet"
        # add this conn to the stored number of reconnections
        current_reconnections = self.db.get_reconnections_for_tw(
            profileid, twid
        )
        try:
            reconnections, uids = current_reconnections[key]
            reconnections += 1
            uids.append(flow.uid)
            current_reconnections[key] = (reconnections, uids)
        except KeyError:
            current_reconnections[key] = (1, [flow.uid])
            reconnections = 1

        if reconnections < 4:
            # update the reconnections ctr in the db
            self.db.set_reconnections(profileid, twid, current_reconnections)
            return

        self.set_evidence.multiple_telnet_reconnection_attempts(
            twid, flow, reconnections, current_reconnections[key][1]
        )

        # reset the reconnection attempts of this src->dst since an evidence
        # is set
        current_reconnections[key] = (0, [])

        self.db.set_reconnections(profileid, twid, current_reconnections)

    def check_multiple_reconnection_attempts(self, profileid, twid, flow):
        """
        Alerts when 5+ reconnection attempts from the same source IP to
        the same destination IP occurs
        """
        if flow.state != "REJ":
            return

        key = f"{flow.saddr}-{flow.daddr}-{flow.dport}"

        # add this conn to the stored number of reconnections
        current_reconnections = self.db.get_reconnections_for_tw(
            profileid, twid
        )

        try:
            reconnections, uids = current_reconnections[key]
            reconnections += 1
            uids.append(flow.uid)
        except KeyError:
            uids = [flow.uid]
            reconnections = 1

        current_reconnections[key] = (reconnections, uids)
        if reconnections < self.multiple_reconnection_attempts_threshold:
            self.db.set_reconnections(profileid, twid, current_reconnections)
            return

        self.set_evidence.multiple_reconnection_attempts(
            twid, flow, reconnections, uids
        )
        # reset the reconnection counter of this src->dst
        current_reconnections[key] = (0, [])

        self.db.set_reconnections(profileid, twid, current_reconnections)

    def is_ignored_ip_data_upload(self, ip):
        """
        Ignore the IPs that we shouldn't alert about
        """

        ip_obj = ipaddress.ip_address(ip)
        if (
            ip == self.gateway
            or ip_obj.is_multicast
            or ip_obj.is_link_local
            or ip_obj.is_reserved
        ):
            return True

        return False

    def get_sent_bytes(
        self, all_flows: Dict[str, dict]
    ) -> Dict[str, Tuple[int, List[str], str]]:
        """
        Returns a dict of sent bytes to all ips in the all_flows dict
         {
            contacted_ip: (
                sum_of_mbs_sent,
                [uids],
                last_ts_of_flow_containging_this_contacted_ip
            )
        }
        """
        bytes_sent = {}
        for uid, flow in all_flows.items():
            daddr = flow["daddr"]
            sbytes: int = int(flow.get("sbytes", 0))
            ts: str = flow.get("starttime", "")

            if self.is_ignored_ip_data_upload(daddr) or not sbytes:
                continue

            if daddr in bytes_sent:
                mbs_sent, uids, _ = bytes_sent[daddr]
                mbs_sent += int(sbytes)
                uids.append(uid)
                bytes_sent[daddr] = (mbs_sent, uids, ts)
            else:
                bytes_sent[daddr] = (sbytes, [uid], ts)

        return bytes_sent

    def detect_data_upload_in_twid(self, profileid, twid):
        """
        For each contacted ip in this twid,
        check if the total bytes sent to this ip is >= data_exfiltration_threshold
        """
        all_flows: Dict[str, dict] = self.db.get_all_flows_in_profileid(
            profileid
        )
        if not all_flows:
            return

        bytes_sent: Dict[str, Tuple[int, List[str], str]]
        bytes_sent = self.get_sent_bytes(all_flows)

        for ip, ip_info in bytes_sent.items():
            ip_info: Tuple[int, List[str], str]
            bytes_uploaded, uids, ts = ip_info
            mbs_uploaded = utils.convert_to_mb(bytes_uploaded)
            if mbs_uploaded < self.data_exfiltration_threshold:
                continue

            self.set_evidence.data_exfiltration(
                ip, mbs_uploaded, profileid, twid, uids, ts
            )

    @staticmethod
    def _is_it_ok_for_ip_to_change(ip) -> bool:
        """Devices send flow as/to these ips all the time, the're not
        suspicious not need to detect them."""
        # its ok to change ips from a link local ip to another private ip
        return ip in SPECIAL_IPV6 or ipaddress.ip_address(ip).is_link_local

    def check_device_changing_ips(self, twid, flow):
        """
        Every time we have a flow for a new ip
            (an ip that we're seeing for the first time)
        we check if the MAC of this srcip was associated with another ip
        this check is only done once for each private source ip slips sees
        """
        if "conn" not in flow.type_:
            return

        if not flow.smac:
            return

        saddr_obj = ipaddress.ip_address(flow.saddr)
        if not (
            validators.ipv4(flow.saddr) and utils.is_private_ip(saddr_obj)
        ):
            return

        if self._is_it_ok_for_ip_to_change(flow.saddr):
            return

        if self.db.was_ip_seen_in_connlog_before(flow.saddr):
            # we should only check once for the first
            # time we're seeing this flow
            return

        self.db.mark_srcip_as_seen_in_connlog(flow.saddr)

        if old_ip_list := self.db.get_ip_of_mac(flow.smac):
            # old_ip is a list that may contain the ipv6 of this MAC
            # this ipv6 may be of the same device that
            # has the given saddr and MAC
            # so this would be fp. so, make sure we're checking the ipv4 only
            for ip in json.loads(old_ip_list):
                if validators.ipv4(ip) and not self._is_it_ok_for_ip_to_change(
                    ip
                ):
                    # found an ipv4 associated previously with the flow's smac
                    # is it the same as the flow's srcip?
                    old_ip = ip
                    break
            else:
                # all the IPs associated with the given macs are ipv6,
                # 1 computer might have several ipv6,
                # AND/OR a combination of ipv6 and 4
                # so this detection will only work if both the
                # old ip and the given saddr are ipv4 private ips
                return

            if old_ip != flow.saddr:
                # we found this smac associated with an
                # ip other than this saddr
                self.set_evidence.device_changing_ips(twid, flow, old_ip)

    def check_data_upload(self, profileid, twid, flow):
        """
        Set evidence when 1 flow is sending >= the flow_upload_threshold bytes
        """
        if (
            not flow.daddr
            or self.is_ignored_ip_data_upload(flow.daddr)
            or not flow.sbytes
        ):
            return False

        src_mbs = utils.convert_to_mb(int(flow.sbytes))
        if src_mbs >= self.flow_upload_threshold:
            self.set_evidence.data_exfiltration(
                flow.daddr,
                src_mbs,
                profileid,
                twid,
                [flow.uid],
                flow.starttime,
            )
            return True
        return False

    def should_ignore_conn_without_dns(self, flow) -> bool:
        """
        checks for the cases that we should ignore the connection without dns
        """
        return (
            flow.type_ != "conn"
            or flow.appproto in ("dns", "icmp")
            or utils.is_ignored_ip(flow.daddr)
            or self.db.is_dhcp_server(flow.daddr)
            # if the daddr is a client ip, it means that this is a conn
            # from the internet to our ip, the dns res was probably
            # made on their side before connecting to us,
            # so we shouldn't be doing this detection on this ip
            or utils.is_ip_in_client_ips(flow.daddr, self.client_ips)
            # because there's no dns.log to know if the dns was made
            or self.input_type == "zeek_log_file"
            or self.db.is_doh_server(flow.daddr)
            # connection without dns in case of an interface,
            # should only be detected from the srcip of this device,
            # not all ips, to avoid so many alerts of this type when port scanning
            or (self.is_running_non_stop and flow.saddr not in self.our_ips)
        )

    def check_if_resolution_was_made_by_different_version(
        self, profileid, daddr
    ):
        """
        Sometimes the same computer makes dns requests using its ipv4 and
        ipv6 address, check if this is the case
        """
        # get the other ip version of this computer
        other_ip = self.db.get_the_other_ip_version(profileid)
        if other_ip:
            other_ip = json.loads(other_ip)
        # get the domain of this ip
        dns_resolution = self.db.get_dns_resolution(daddr)

        try:
            if other_ip and other_ip in dns_resolution.get("resolved-by", []):
                return True
        except AttributeError:
            # It can be that the dns_resolution sometimes gives back a
            # list and gets this error
            pass
        return False

    def is_interface_timeout_reached(self) -> bool:
        """
        To avoid false positives in case of an interface
        don't alert ConnectionWithoutDNS until 30 minutes has passed after
        starting slips because the dns may have happened before starting slips
        """
        if not self.is_running_non_stop:
            # no timeout
            return True

        start_time = self.db.get_slips_start_time()
        now = datetime.now()
        diff = utils.get_time_diff(start_time, now, return_type="minutes")
        # 30 minutes have passed?
        return diff >= self.conn_without_dns_interface_wait_time

    async def check_connection_without_dns_resolution(
        self, profileid, twid, flow
    ) -> bool:
        """
        Checks if there's a connection to a dstip that has no cached DNS
        answer
        """
        if self.should_ignore_conn_without_dns(flow):
            return False

        if not self.is_interface_timeout_reached():
            return False

        # search 24hs back for a dns resolution
        if self.db.is_ip_resolved(flow.daddr, 24):
            return False

        # There is no DNS resolution, but it can be that Slips is
        # still reading it from the files.
        # To give time to Slips to read all the files and get all the flows
        # don't alert a Connection Without DNS until 15 seconds has passed
        # in real time from the time of this checking.
        await asyncio.sleep(15)
        if self.db.is_ip_resolved(flow.daddr, 24):
            return False

        # Reaching here means we already waited 15 seconds for the dns
        # to arrive after the connection was checked, but still no dns
        # resolution for it.

        # Sometimes the same computer makes requests using
        # its ipv4 and ipv6 address, check if this is the case
        if self.check_if_resolution_was_made_by_different_version(
            profileid, flow.daddr
        ):
            return False

        if self.is_well_known_org(flow.daddr):
            # if the SNI or rDNS of the IP matches a
            # well-known org, then this is a FP
            return False

        self.set_evidence.conn_without_dns(twid, flow)
        return True

    def check_conn_to_port_0(self, profileid, twid, flow):
        """
        Alerts on connections to or from port 0 using protocols other than
        igmp, icmp
        """
        if flow.proto.lower() in ("igmp", "icmp", "ipv6-icmp", "arp"):
            return
        try:
            flow.sport = int(flow.sport)
            flow.dport = int(flow.dport)
        except ValueError:
            return

        if flow.sport != 0 and flow.dport != 0:
            return

        attacker = flow.saddr if flow.sport == 0 else flow.daddr
        victim = flow.saddr if attacker == flow.daddr else flow.daddr
        self.set_evidence.port_0_connection(
            profileid, twid, flow, victim, attacker
        )

    def detect_connection_to_multiple_ports(self, profileid, twid, flow):
        if flow.proto != "tcp" or flow.interpreted_state != ESTAB:
            return

        dport_name = flow.appproto
        if not dport_name:
            dport_name = self.db.get_port_info(f"{flow.dport}/{flow.proto}")

        if dport_name:
            # dport is known, we are considering only unknown services
            return

        # Connection to multiple ports to the destination IP
        if profileid.split("_")[1] == flow.saddr:
            direction = "Dst"
            state = ESTAB
            protocol = "TCP"
            role = "Client"
            type_data = "IPs"

            # get all the dst ips with established tcp connections
            daddrs = self.db.get_data_from_profile_tw(
                profileid,
                twid,
                direction,
                state,
                protocol,
                role,
                type_data,
            )

            # make sure we find established connections to this daddr
            if flow.daddr not in daddrs:
                return

            dstports = list(daddrs[flow.daddr]["dstports"])
            if len(dstports) <= 1:
                return

            victim: str = flow.daddr
            attacker: str = profileid.split("_")[-1]
            self.set_evidence.connection_to_multiple_ports(
                profileid,
                twid,
                flow,
                victim,
                attacker,
                dstports,
                daddrs[flow.daddr]["uid"],
            )

        # Connection to multiple port to the Source IP.
        # Happens in the mode 'all'
        elif profileid.split("_")[-1] == flow.daddr:
            direction = "Src"
            state = ESTAB
            protocol = "TCP"
            role = "Server"
            type_data = "IPs"

            # get all the src ips with established tcp connections
            saddrs = self.db.get_data_from_profile_tw(
                profileid,
                twid,
                direction,
                state,
                protocol,
                role,
                type_data,
            )
            dstports = list(saddrs[flow.saddr]["dstports"])
            if len(dstports) <= 1:
                return

            uids = saddrs[flow.saddr]["uid"]
            attacker: str = flow.daddr
            victim: str = profileid.split("_")[-1]

            self.set_evidence.connection_to_multiple_ports(
                profileid,
                twid,
                flow,
                victim,
                attacker,
                dstports,
                uids,
            )

    def is_well_known_org(self, ip):
        """get the SNI, ASN, and  rDNS of the IP to check if it belongs
        to a well-known org"""

        ip_data = self.db.get_ip_info(ip)
        try:
            sni = ip_data["SNI"]
            if isinstance(sni, list):
                # SNI is a list of dicts, each dict contains the
                # 'server_name' and 'port'
                sni = sni[0]
                if sni in (None, ""):
                    sni = False
                elif isinstance(sni, dict):
                    sni = sni.get("server_name", False)
        except (KeyError, TypeError):
            # No SNI data for this ip
            sni = False

        try:
            rdns = ip_data["reverse_dns"]
        except (KeyError, TypeError):
            # No SNI data for this ip
            rdns = False

        flow_domains = [rdns, sni]
        for org in utils.supported_orgs:
            for domain in flow_domains:
                if self.whitelist.org_analyzer.is_ip_asn_in_org_asn(ip, org):
                    return True

                # we have the rdns or sni of this flow , now check
                if domain and self.whitelist.org_analyzer.is_domain_in_org(
                    domain, org
                ):
                    return True

                # check if the ip belongs to the range of a well known org
                # (fb, twitter, microsoft, etc.)
                if self.whitelist.org_analyzer.is_ip_in_org(ip, org):
                    return True
            return False

    def _is_ok_to_connect_to_ip(self, ip: str) -> bool:
        """
        returns true if it's ok to connect to the given IP even if it's
        "outside the given local network"
        """
        return ip in SPECIAL_IPV6 or utils.is_localhost(ip)

    def _is_dns(self, flow) -> bool:
        return str(flow.dport) == "53" and flow.proto.lower() == "udp"

    def check_different_localnet_usage(
        self,
        twid,
        flow,
        what_to_check="",
    ):
        """
        alerts when a connection to a private ip that
        doesn't belong to our local network is found
        for example:
        If we are on 192.168.1.0/24 then detect anything
        coming from/to 10.0.0.0/8
        :param what_to_check: can be 'srcip' or 'dstip'
        """
        if self._is_dns(flow):
            # dns flows are checked fot this same detection in dns.py
            return

        if self._is_ok_to_connect_to_ip(
            flow.saddr
        ) or self._is_ok_to_connect_to_ip(flow.daddr):
            return

        ip_to_check = flow.saddr if what_to_check == "srcip" else flow.daddr

        ip_obj = ipaddress.ip_address(ip_to_check)
        if not (validators.ipv4(ip_to_check) and utils.is_private_ip(ip_obj)):
            return

        own_local_network = self.db.get_local_network()
        if not own_local_network:
            # the current local network wasn't set in the db yet
            # it's impossible to get here becaus ethe localnet is set before
            # any msg is published in the new_flow channel
            return

        # if it's a private ipv4 addr, it should belong to our local network
        if ip_obj in ipaddress.IPv4Network(own_local_network):
            return

        self.set_evidence.different_localnet_usage(
            twid,
            flow,
            ip_outside_localnet=what_to_check,
        )

    def check_connection_to_local_ip(self, twid, flow):
        """
        Alerts when there's a connection from a private IP to
        another private IP except for DNS connections to the gateway
        """

        def is_dns_conn(flow):
            return (
                flow.dport == 53
                and flow.proto.lower() == "udp"
                and flow.daddr == self.db.get_gateway_ip()
            )

        def is_dhcp_conn(flow):
            # Bootstrap protocol server. Used by DHCP servers to communicate
            # addressing information to remote DHCP clients
            return (
                (flow.dport == 67 or flow.dport == 68)
                and flow.proto.lower() == "udp"
                and flow.daddr == self.db.get_gateway_ip()
            )

        with contextlib.suppress(ValueError):
            flow.dport = int(flow.dport)

        if is_dns_conn(flow) or is_dhcp_conn(flow):
            # skip DNS conns to the gw to avoid having tons of this evidence
            return

        # make sure the 2 ips are private
        if not (
            utils.is_private_ip(ipaddress.ip_address(flow.saddr))
            and utils.is_private_ip(ipaddress.ip_address(flow.daddr))
        ):
            return

        self.set_evidence.conn_to_private_ip(twid, flow)

    async def analyze(self, msg):
        if utils.is_msg_intended_for(msg, "new_flow"):
            msg = json.loads(msg["data"])
            profileid = msg["profileid"]
            twid = msg["twid"]
            flow = self.classifier.convert_to_flow_obj(msg["flow"])
            flow.interpreted_state = self.db.get_final_state_from_flags(
                flow.state, flow.pkts
            )
            self.check_long_connection(twid, flow)
            self.check_unknown_port(profileid, twid, flow)
            self.check_multiple_reconnection_attempts(profileid, twid, flow)
            self.check_multiple_telnet_reconnection_attempts(
                profileid, twid, flow
            )
            self.check_conn_to_port_0(profileid, twid, flow)
            self.check_different_localnet_usage(
                twid, flow, what_to_check="dstip"
            )
            self.check_different_localnet_usage(
                twid, flow, what_to_check="srcip"
            )
            self.flowalerts.create_task(
                self.check_connection_without_dns_resolution,
                profileid,
                twid,
                flow,
            )
            self.detect_connection_to_multiple_ports(profileid, twid, flow)
            self.check_data_upload(profileid, twid, flow)

            self.check_connection_to_local_ip(twid, flow)
            self.check_device_changing_ips(twid, flow)

        elif utils.is_msg_intended_for(msg, "tw_closed"):
            profileid_tw = msg["data"].split("_")
            profileid = f"{profileid_tw[0]}_{profileid_tw[1]}"
            twid = profileid_tw[-1]
            self.detect_data_upload_in_twid(profileid, twid)
