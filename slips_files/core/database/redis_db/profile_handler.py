# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import ipaddress
import json
import sys
import time
import traceback
from dataclasses import asdict
from math import floor
from typing import (
    Tuple,
    Union,
    Optional,
    List,
    Set,
)
import redis
import validators

from slips_files.common.slips_utils import utils


class ProfileHandler:
    """
    Helper class for the Redis class in database.py
    Contains all the logic related to flows, profiles, and timewindows
    """

    name = "DB"

    async def is_doh_server(self, ip: str) -> bool:
        """Returns whether the given IP is a DoH server"""
        info: dict = await self.get_ip_info(ip)
        return info.get("is_doh_server", False) if info else False

    async def get_outtuples_from_profile_tw(self, profileid, twid):
        """Get the out tuples"""
        return await self.r.hget(
            profileid + self.separator + twid, "OutTuples"
        )

    async def set_new_incoming_flows(self, will_slips_have_more_flows: bool):
        """A flag indicating if Slips is still receiving new flows from input and profiler or not"""
        await self.r.set(
            self.constants.WILL_SLIPS_HAVE_MORE_FLOWS,
            "yes" if will_slips_have_more_flows else "no",
        )

    async def will_slips_have_new_incoming_flows(self):
        """A flag indicating if Slips is still receiving new flows from input and profiler or not"""
        return (
            await self.r.get(self.constants.WILL_SLIPS_HAVE_MORE_FLOWS)
            == "yes"
        )

    async def get_intuples_from_profile_tw(self, profileid, twid):
        """Get the in tuples"""
        return await self.r.hget(profileid + self.separator + twid, "InTuples")

    async def get_dhcp_flows(self, profileid, twid) -> list:
        """
        Returns a dict of DHCP flows that happened in this profileid and twid
        """
        if flows := await self.r.hget(
            self.constants.DHCP_FLOWS, f"{profileid}_{twid}"
        ):
            return json.loads(flows)
        return []

    async def set_dhcp_flow(self, profileid, twid, requested_addr, uid):
        """
        Stores all DHCP flows sorted by profileid_twid
        """
        flow = {requested_addr: uid}
        if cached_flows := await self.get_dhcp_flows(profileid, twid):
            # We already have flows in this twid, update them
            cached_flows.update(flow)
            await self.r.hset(
                self.constants.DHCP_FLOWS,
                f"{profileid}_{twid}",
                json.dumps(cached_flows),
            )
        else:
            await self.r.hset(
                self.constants.DHCP_FLOWS,
                f"{profileid}_{twid}",
                json.dumps(flow),
            )

    async def get_tw_start_time(self, profileid, twid):
        """Return the time when this TW in this profile was created"""
        # We need to encode it to 'search' because the data in the sorted set is encoded
        return await self.r.zscore(f"tws{profileid}", twid.encode("utf-8"))

    async def get_first_flow_time(self) -> float | None:
        """
        Get the starttime of the first timewindow
        aka ts of the first flow
        first tw is always timewindow1
        """
        starttime_of_first_tw: str = await self.r.hget(
            self.constants.ANALYSIS, "file_start"
        )
        if starttime_of_first_tw:
            return float(starttime_of_first_tw)
        return None

    async def get_timewindow(self, flowtime, profileid):
        """
        This function returns the TW in the database where the flow belongs.
        Returns the time window id
        DISCLAIMER:

            if the given flowtime is == the starttime of a tw, it will
            belong to that tw
            if it is == the end of a tw, it will belong to the next one
            for example,
            a flow with ts = 2 belongs to tw2
            a flow with ts = 4 belongs to tw3

               tw1   tw2   tw3   tw4
           0 ──────┬─────┬──────┬──────
                   │     │      │
                   2     4      6

        """
        # If the option for only-one-tw was selected, we should
        # create the TW at least 100 years before the flowtime,
        # to cover for 'flows in the past'. Which means we should
        # cover for any flow that is coming later with time before the
        # first flow
        flowtime = float(flowtime)
        if self.width == 9999999999:
            # Seconds in 1 year = 31536000
            tw_start = float(flowtime - (31536000 * 100))
            tw_number: int = 1
        else:
            starttime_of_first_tw: float = await self.get_first_flow_time()
            if starttime_of_first_tw is not None:  # because 0 is a valid value
                tw_number: int = (
                    floor((flowtime - starttime_of_first_tw) / self.width) + 1
                )
                tw_start: float = starttime_of_first_tw + (
                    self.width * (tw_number - 1)
                )
            else:
                # This is the first timewindow
                tw_number: int = 1
                tw_start: float = flowtime

        tw_id: str = f"timewindow{tw_number}"

        await self.add_new_tw(profileid, tw_id, tw_start)
        return tw_id

    async def add_out_http(
        self,
        profileid,
        twid,
        flow,
    ):
        """
        Store in the DB an HTTP request
        All the types of flows that are not netflows are stored in a separate
        hash ordered by uid.
        The idea is that from the uid of a netflow, you can access which other
        type of info is related to that uid
        """
        http_flow = {
            "profileid": profileid,
            "twid": twid,
            "flow": asdict(flow),
        }
        to_send = json.dumps(http_flow)
        await self.publish("new_http", to_send)
        await self.publish("new_url", to_send)

        self.print(f"Adding HTTP flow to DB: {flow}", 3, 0)
        # Check if the host domain AND the URL is detected by the threat intelligence.
        # Not all flows have a host value, so don't send empty hosts to TI module.
        if len(flow.host) > 2:
            await self.give_threat_intelligence(
                profileid,
                twid,
                "dst",
                flow.starttime,
                flow.uid,
                flow.daddr,
                lookup=flow.host,
            )
            await self.give_threat_intelligence(
                profileid,
                twid,
                "dst",
                flow.starttime,
                flow.uid,
                flow.daddr,
                lookup=f"http://{flow.host}{flow.uri}",
            )
        else:
            # Use the daddr since there's no host
            await self.give_threat_intelligence(
                profileid,
                twid,
                "dstip",
                flow.starttime,
                flow.uid,
                flow.daddr,
                lookup=f"http://{flow.daddr}{flow.uri}",
            )

    async def add_out_dns(self, profileid, twid, flow):
        """
        Store in the DB a DNS request
        All the types of flows that are not netflows are stored in a separate
        hash ordered by flow.uid.
        The idea is that from the flow.uid of a netflow, you can access which
        other type of info is related to that flow.uid
        """
        to_send = {
            "profileid": profileid,
            "twid": twid,
            "flow": asdict(flow),
        }

        to_send = json.dumps(to_send)
        await self.publish("new_dns", to_send)
        await self.give_threat_intelligence(
            profileid,
            twid,
            "dstip",
            flow.starttime,
            flow.uid,
            flow.daddr,
            lookup=flow.query,
        )

        # Add DNS resolution to the db if there are answers for the query
        if flow.answers and flow.answers != ["-"]:
            srcip = profileid.split("_")[1]
            await self.set_dns_resolution(
                flow.query,
                flow.answers,
                flow.starttime,
                flow.uid,
                flow.qtype_name,
                srcip,
                twid,
            )
            # Send each DNS answer to TI module
            for answer in flow.answers:
                if "TXT" in answer:
                    continue

                extra_info = {
                    "is_dns_response": True,
                    "dns_query": flow.query,
                }
                await self.give_threat_intelligence(
                    profileid,
                    twid,
                    "dstip",
                    flow.starttime,
                    flow.uid,
                    flow.daddr,
                    lookup=answer,
                    extra_info=extra_info,
                )

    def _was_flow_flipped(self, flow) -> bool:
        """
        The majority of the FP with horizontal port scan detection
        happen because a benign computer changes WiFi, and many not
        established connections are redone, which look like a port scan to
        10 webpages. To avoid this, we IGNORE all the flows that have
        in the history of flags (field history in Zeek), the ^,
        that means that the flow was swapped/flipped.
        The below key_name is only used by the portscan module to check
        for horizontal portscan, which means we can safely ignore it
        here and it won't affect the rest of Slips
        """
        state_hist = flow.state_hist if hasattr(flow, "state_hist") else ""
        return "^" in state_hist

    @staticmethod
    def _is_multicast_or_broadcast(daddr: str) -> bool:
        """
        To avoid reporting port scans on the
        broadcast or multicast addresses or invalid values
        """
        if daddr == "255.255.255.255":
            return True

        daddr_obj = ipaddress.ip_address(daddr)
        return daddr_obj.is_multicast

    async def add_port(
        self, profileid: str, twid: str, flow: dict, role: str, port_type: str
    ):
        """
        Store info learned from ports for this flow
        The flow can go out of the IP (we are acting as Client) or into the IP
        (we are acting as Server)
        role: 'Client' or 'Server'. Client also defines that the flow is going
        out, Server that is going in
        port_type: 'Dst' or 'Src'.
        Depending if this port was a destination port or a source port
        """
        # Extract variables from columns
        dport = flow.dport
        sport = flow.sport
        totbytes = int(flow.bytes)
        pkts = int(flow.pkts)
        state = flow.state
        proto = flow.proto.upper()
        starttime = str(flow.starttime)
        uid = flow.uid
        ip = str(flow.daddr)
        spkts = flow.spkts

        if self._was_flow_flipped(flow):
            return False

        # Choose which port to use based if we were asked Dst or Src
        port = str(sport) if port_type == "Src" else str(dport)

        # If we are the Client, we want to store the dstips only
        # If we are the Server, we want to store the srcips only
        ip_key = "srcips" if role == "Server" else "dstips"

        # Get the state. Established, NotEstablished
        summary_state = utils.get_final_state_from_flags(state, pkts)

        old_profileid_twid_data = await self.get_data_from_profile_tw(
            profileid, twid, port_type, summary_state, proto, role, "Ports"
        )

        try:
            # We already have info about this dport, update it
            port_data = old_profileid_twid_data[port]
            port_data["totalflows"] += 1
            port_data["totalpkt"] += pkts
            port_data["totalbytes"] += totbytes

            # If there's a connection from this IP on this port, update the packets
            if ip in port_data[ip_key]:
                port_data[ip_key][ip]["pkts"] += pkts
                port_data[ip_key][ip]["spkts"] += spkts
                port_data[ip_key][ip]["uid"].append(uid)
            else:
                port_data[ip_key][ip] = {
                    "pkts": pkts,
                    "spkts": spkts,
                    "stime": starttime,
                    "uid": [uid],
                }

        except KeyError:
            # First time for this dport
            port_data = {
                "totalflows": 1,
                "totalpkt": pkts,
                "totalbytes": totbytes,
                ip_key: {
                    ip: {
                        "pkts": pkts,
                        "spkts": spkts,
                        "stime": starttime,
                        "uid": [uid],
                    }
                },
            }
        old_profileid_twid_data[port] = port_data
        data = json.dumps(old_profileid_twid_data)
        hash_key = f"{profileid}{self.separator}{twid}"
        key_name = f"{port_type}Ports{role}{proto}{summary_state}"
        await self.mark_profile_tw_as_modified(profileid, twid, starttime)

        if key_name == "DstPortsClientTCPNot Established":
            # This key is used in horizontal portscan module only
            # To avoid unnecessary storing and filtering of data, we store
            # only unresolved non-multicast non-broadcast IPs.
            # If this key is ever needed for another module, we'll need to
            # workaround this
            ip_resolved = await self.get_dns_resolution(ip)
            if ip_resolved or self._is_multicast_or_broadcast(ip):
                return

        await self.r.hset(hash_key, key_name, str(data))

    async def get_data_from_profile_tw(
        self,
        profileid: str,
        twid: str,
        direction: str,
        state: str,
        protocol: str,
        role: str,
        type_data: str,
    ) -> dict:
        """
        Get the info about a certain role (Client or Server),
        for a particular protocol (TCP, UDP, ICMP, etc.) for a
        particular State (Established, etc.)

        :param direction: 'Dst' or 'Src'. This is used to know if you
        want the data of the src IP or ports, or the data from
        the dst IPs or ports
        :param state: can be 'Established' or 'NotEstablished'
        :param protocol: can be 'TCP', 'UDP', 'ICMP' or 'IPV6ICMP'
        :param role: can be 'Client' or 'Server'
        Depending if the traffic is going out or not, we are Client or Server
        Client role means: the traffic is done by the given profile
        Server role means: the traffic is going to the given profile
        :param type_data: can be 'Ports' or 'IPs'
        """
        try:
            # key_name = [Src,Dst] + [Port,IP] + [Client,Server] +
            # [TCP,UDP, ICMP, ICMP6] + [Established, Not Established]
            # Example: key_name = 'SrcPortClientTCPEstablished'
            key = direction + type_data + role + protocol.upper() + state
            data = await self.r.hget(f"{profileid}{self.separator}{twid}", key)

            if data:
                return json.loads(data)

            self.print(
                f"There is no data for Key: {key}. Profile {profileid} TW {twid}",
                3,
                0,
            )
            return {}
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f"Error in getDataFromProfileTW in database.py line {exception_line}",
                0,
                1,
            )
            self.print(traceback.format_exc(), 0, 1)

    async def update_ip_info(
        self,
        old_profileid_twid_data: dict,
        pkts,
        dport,
        spkts,
        totbytes,
        ip,
        starttime,
        uid,
    ) -> dict:
        """
        Updates how many times each individual DstPort was contacted,
        the total flows sent by this IP and their UIDs,
        the total packets sent by this IP,
        and total bytes sent by this IP
        """
        dport = str(dport)
        spkts = int(spkts)
        pkts = int(pkts)
        totbytes = int(totbytes)
        if ip in old_profileid_twid_data:
            # Update info about an existing IP
            ip_data = old_profileid_twid_data[ip]
            ip_data["totalflows"] += 1
            ip_data["totalpkt"] += pkts
            ip_data["totalbytes"] += totbytes
            ip_data["uid"].append(uid)

            ip_data["dstports"]: dict

            if dport in ip_data["dstports"]:
                ip_data["dstports"][dport] += spkts
            else:
                ip_data["dstports"].update({dport: spkts})
        else:
            # First time seeing this IP
            ip_data = {
                "totalflows": 1,
                "totalpkt": pkts,
                "totalbytes": totbytes,
                "stime": starttime,
                "uid": [uid],
                "dstports": {dport: spkts},
            }
        old_profileid_twid_data.update({ip: ip_data})

        return old_profileid_twid_data

    async def update_times_contacted(self, ip, direction, profileid, twid):
        """
        :param ip: the IP that we want to update the times we contacted
        """
        # Get the hash of the timewindow
        profileid_twid = f"{profileid}{self.separator}{twid}"

        # Get the DstIPs data for this TW in this profile
        # The format is {'1.1.1.1' :  3}
        ips_contacted = await self.r.hget(profileid_twid, f"{direction}IPs")
        if not ips_contacted:
            ips_contacted = {}

        try:
            ips_contacted = json.loads(ips_contacted)
            # Add 1 because we found this IP again
            ips_contacted[ip] += 1
        except (TypeError, KeyError):
            # There was no previous data stored in the DB
            ips_contacted[ip] = 1

        ips_contacted = json.dumps(ips_contacted)
        await self.r.hset(
            profileid_twid, f"{direction}IPs", str(ips_contacted)
        )

    async def add_ips(self, profileid, twid, flow, role):
        """
        Function to add information about an IP address
        The flow can go out of the IP (we are acting as Client) or into the IP
        (we are acting as Server)
        ip_as_obj: IP to add. It can be a dstIP or srcIP depending on the role
        role: 'Client' or 'Server'
        This function does three things:
            1- Add the IP to this TW in this profile, counting how many times
            it was contacted, and storing it in the key 'DstIPs' or 'SrcIPs'
            in the hash of the profile
            2- Use the IP as a key to count how many times that IP was
            contacted on each port. We store it like this because it's the
            perfect structure to detect vertical port scans later on
            3- Check if this IP has any detection in the threat intelligence
            module. The information is added by the module directly in the DB.
        """
        uid = flow.uid
        starttime = str(flow.starttime)
        ip = flow.daddr if role == "Client" else flow.saddr

        """
        Depending if the traffic is going out or not, we are Client or Server
        Client role means:
            The profile corresponds to the src IP that received this flow
            The dstIP is here the one receiving data from your profile
            So check the dst IP
        Server role means:
            The profile corresponds to the dst IP that received this flow
            The srcIP is here the one sending data to your profile
            So check the src IP
        """
        direction = "Dst" if role == "Client" else "Src"

        # Store the Dst as IP address and notify in the channel
        # We send the obj but when accessed as str, it is automatically
        # converted to str
        await self.set_new_ip(ip)

        # OTH means that we didn't see the true src IP and dst IP
        # from Zeek docs; OTH: No SYN seen, just midstream traffic
        # (one example of this is a “partial connection” that was not
        # later closed).
        if flow.state != "OTH":
            await self.ask_for_ip_info(
                flow.saddr,
                profileid,
                twid,
                flow,
                "srcip",
                daddr=flow.daddr,
            )
            await self.ask_for_ip_info(
                flow.daddr,
                profileid,
                twid,
                flow,
                "dstip",
            )

        await self.update_times_contacted(ip, direction, profileid, twid)

        # Get the state. Established, NotEstablished
        summary_state = utils.get_final_state_from_flags(flow.state, flow.pkts)
        key_name = f"{direction}IPs{role}{flow.proto.upper()}{summary_state}"
        # Get the previous data about this key
        old_profileid_twid_data = await self.get_data_from_profile_tw(
            profileid,
            twid,
            direction,
            summary_state,
            flow.proto,
            role,
            "IPs",
        )
        profileid_twid_data: dict = await self.update_ip_info(
            old_profileid_twid_data,
            flow.pkts,
            flow.dport,
            flow.spkts,
            flow.bytes,
            ip,
            starttime,
            uid,
        )

        # Store this data in the profile hash
        await self.r.hset(
            f"{profileid}{self.separator}{twid}",
            key_name,
            json.dumps(profileid_twid_data),
        )
        return True

    async def get_all_contacted_ips_in_profileid_twid(
        self, profileid, twid
    ) -> dict:
        """
        Get all the contacted IPs in a given profile and TW
        """
        all_flows: dict = await self.get_all_flows_in_profileid_twid(
            profileid, twid
        )
        if not all_flows:
            return {}
        contacted_ips = {}
        for uid, flow in all_flows.items():
            # Get the daddr of this flow
            daddr = flow["daddr"]
            contacted_ips[daddr] = uid
        return contacted_ips

    async def mark_profile_and_timewindow_as_blocked(self, profileid, twid):
        """Add this profile and TW to the list of blocked
        A profile is only blocked if it was blocked using the user's
        firewall, not if it just generated an alert
        """
        tws = await self.get_blocked_timewindows_of_profile(profileid)
        tws.append(twid)
        await self.r.hset(
            self.constants.BLOCKED_PROFILES_AND_TWS, profileid, json.dumps(tws)
        )

    async def get_blocked_timewindows_of_profile(self, profileid):
        """Return all the list of blocked TWs"""
        if tws := await self.r.hget(
            self.constants.BLOCKED_PROFILES_AND_TWS, profileid
        ):
            return json.loads(tws)
        return []

    async def get_blocked_profiles_and_timewindows(self):
        return await self.r.hgetall(self.constants.BLOCKED_PROFILES_AND_TWS)

    async def is_blocked_profile_and_tw(self, profileid, twid):
        """
        Check if profile and timewindow is blocked
        """
        profile_tws = await self.get_blocked_timewindows_of_profile(profileid)
        return twid in profile_tws

    async def was_profile_and_tw_modified(self, profileid, twid):
        """Retrieve from the DB if this TW of this profile was modified"""
        data = await self.r.zrank(
            self.constants.MODIFIED_TIMEWINDOWS,
            profileid + self.separator + twid,
        )
        return bool(data)

    async def add_flow(
        self,
        flow,
        profileid="",
        twid="",
        label="",
    ):
        """
        Function to add a flow by interpreting the data. The flow is added to
        the correct TW for this profile.
        The profileid is the main profile that this flow is related to.
        """
        if label:
            await self.r.zincrby(self.constants.LABELS, 1, label)

        to_send = {
            "profileid": profileid,
            "twid": twid,
            "flow": asdict(flow),
            "stime": flow.starttime,
            "interpreted_state": utils.get_final_state_from_flags(
                flow.state, flow.pkts
            ),
            "label": label,
            "module_labels": {},
        }
        to_send = json.dumps(to_send)

        # Don't send ARP flows in this channel, they have their own
        # new_arp channel
        if flow.type_ != "arp":
            await self.publish("new_flow", to_send)
        return True

    async def add_software_to_profile(self, profileid, flow):
        """
        Used to associate this profile with its used software and version
        """
        sw_dict = {
            flow.software: {
                "version-major": flow.version_major,
                "version-minor": flow.version_minor,
                "uid": flow.uid,
            }
        }
        # cached_sw is {software: {'version-major':x,
        # 'version-minor':y, 'uid':...}}
        if cached_sw := await self.get_software_from_profile(profileid):
            if flow.software in cached_sw:
                # We already have this same software for this profileid.
                # Don't store this one
                return
            # Add this new software to the list of software this profile is using
            cached_sw.update(sw_dict)
            await self.r.hset(
                profileid, "used_software", json.dumps(cached_sw)
            )
        else:
            # First time for this profile to use a software
            await self.r.hset(profileid, "used_software", json.dumps(sw_dict))

    async def get_total_flows(self):
        """
        Gets total flows to process from the DB
        """
        return await self.r.hget(self.constants.ANALYSIS, "total_flows")

    async def get_analysis_info(self):
        return await self.r.hgetall(self.constants.ANALYSIS)

    async def add_out_ssh(
        self,
        profileid,
        twid,
        flow,
    ):
        """
        Store in the DB an SSH request
        All the types of flows that are not netflows are stored in a
        separate hash ordered by uid.
        The idea is that from the uid of a netflow, you can access which
        other type of info is related to that uid
        """
        to_send = {
            "profileid": profileid,
            "twid": twid,
            "flow": asdict(flow),
        }
        to_send = json.dumps(to_send)
        await self.publish("new_ssh", to_send)
        self.print(f"Adding SSH flow to DB: {flow}", 3, 0)
        await self.give_threat_intelligence(
            profileid,
            twid,
            "dstip",
            flow.starttime,
            flow.uid,
            flow.daddr,
            lookup=flow.daddr,
        )

    async def add_out_notice(
        self,
        profileid,
        twid,
        flow,
    ):
        """Send notice.log data to new_notice channel to look for
        self-signed certificates"""
        to_send = {
            "profileid": profileid,
            "twid": twid,
            "flow": asdict(flow),
        }
        to_send = json.dumps(to_send)
        await self.publish("new_notice", to_send)
        self.print(f"Adding notice flow to DB: {flow}", 3, 0)
        await self.give_threat_intelligence(
            profileid,
            twid,
            "dstip",
            flow.starttime,
            flow.uid,
            flow.daddr,
            lookup=flow.daddr,
        )

    async def add_out_ssl(self, profileid, twid, flow):
        """
        Store in the DB an SSL request
        All the types of flows that are not netflows are stored in a separate
        hash ordered by uid.
        The idea is that from the uid of a netflow, you can access which other
        type of info is related to that uid
        """
        to_send = {"profileid": profileid, "twid": twid, "flow": asdict(flow)}
        to_send = json.dumps(to_send)
        await self.publish("new_ssl", to_send)
        self.print(f"Adding SSL flow to DB: {flow}", 3, 0)
        # Check if the server_name (SNI) is detected by the threat intelligence.
        # Empty field in the end, cause we have extra field for the IP.
        # If server_name is not empty, set in the IPsInfo and send to TI
        if not flow.server_name:
            return False

        # We are giving only new server_name to the threat_intelligence module.
        await self.give_threat_intelligence(
            profileid,
            twid,
            "dstip",
            flow.starttime,
            flow.uid,
            flow.daddr,
            lookup=flow.server_name,
        )

        # Save new server name in the IPInfo. There might be several
        # server_name per IP.
        if ipdata := await self.get_ip_info(flow.daddr):
            sni_ipdata = ipdata.get("SNI", [])
        else:
            sni_ipdata = []

        sni_port = {"server_name": flow.server_name, "dport": flow.dport}
        # We do not want any duplicates.
        if sni_port not in sni_ipdata:
            # Verify that the SNI is equal to any of the domains in the DNS
            # resolution
            # Only add this SNI to our DB if it has a DNS resolution
            if dns_resolutions := await self.r.hgetall("DNSresolution"):
                # dns_resolutions is a dict with {ip:{'ts'..,'domains':...,
                # 'uid':..}}
                for ip, resolution in dns_resolutions.items():
                    resolution = json.loads(resolution)
                    if sni_port["server_name"] in resolution["domains"]:
                        # Add SNI to our DB as it has a DNS resolution
                        sni_ipdata.append(sni_port)
                        await self.set_ip_info(flow.daddr, {"SNI": sni_ipdata})
                        break

    async def get_profileid_from_ip(self, ip: str) -> Optional[str]:
        """
        Returns the profile of the given IP only if it was registered in
        Slips before
        """
        try:
            profileid = f"profile_{ip}"
            if await self.r.sismember(self.constants.PROFILES, profileid):
                return profileid
            return None
        except redis.exceptions.ResponseError as inst:
            self.print("Error in get_profileid_from_ip in database.py", 0, 1)
            self.print(type(inst), 0, 1)
            self.print(inst, 0, 1)

    async def get_profiles(self):
        """Get a list of all the profiles"""
        profiles = await self.r.smembers(self.constants.PROFILES)
        return profiles if profiles != set() else {}

    async def get_tws_from_profile(self, profileid):
        """
        Receives a profile ID and returns the list of all the TWs in that profile
        Returns a list of tuples (twid, ts) or an empty list
        """
        return (
            await self.r.zrange(f"tws{profileid}", 0, -1, withscores=True)
            if profileid
            else []
        )

    async def get_number_of_tws_in_profile(self, profileid) -> int:
        """
        Receives a profile ID and returns the number of all the
        TWs in that profile
        """
        return (
            len(await self.get_tws_from_profile(profileid)) if profileid else 0
        )

    async def get_srcips_from_profile_tw(self, profileid, twid):
        """
        Get the src IP for a specific TW for a specific profileid
        """
        return await self.r.hget(profileid + self.separator + twid, "SrcIPs")

    async def get_dstips_from_profile_tw(self, profileid, twid):
        """
        Get the dst IP for a specific TW for a specific profileid
        """
        return await self.r.hget(profileid + self.separator + twid, "DstIPs")

    async def get_t2_for_profile_tw(
        self, profileid, twid, tupleid, tuple_key: str
    ):
        """
        Get T1 and the previous_time for this previous_time, twid, and tupleid
        """
        try:
            hash_id = profileid + self.separator + twid
            data = await self.r.hget(hash_id, tuple_key)
            if not data:
                return False, False
            data = json.loads(data)
            try:
                (_, previous_two_timestamps) = data[tupleid]
                return previous_two_timestamps
            except KeyError:
                return False, False
        except Exception as e:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f"Error in getT2ForProfileTW in database.py line {exception_line}",
                0,
                1,
            )
            self.print(type(e), 0, 1)
            self.print(e, 0, 1)

    async def has_profile(self, profileid):
        """Check if we have the given profile"""
        return (
            await self.r.sismember(self.constants.PROFILES, profileid)
            if profileid
            else False
        )

    async def get_profiles_len(self) -> int:
        """Return the amount of profiles. Redis should be faster than Python
        to do this count"""
        profiles_n = await self.r.scard(self.constants.PROFILES)
        return 0 if not profiles_n else int(profiles_n)

    async def get_last_twid_of_profile(
        self, profileid: str
    ) -> Tuple[str, float]:
        """
        Returns the last TW ID (aka TW with the greatest ts seen so far) and
        the starttime of the given profile ID
        """
        if profileid:
            res = await self.r.zrange(
                f"tws{profileid}", -1, -1, withscores=True
            )
            if res:
                twid, starttime = res[0]
                return twid, starttime
        return "", 0.0

    async def get_first_twid_for_profile(
        self, profileid: str
    ) -> Optional[Tuple[str, float]]:
        """
        Return the first TW ID and the time for the given profile ID
        The returned TW ID may be a negative TW, for example tw-1, depending on
        what TW was last registered
        """
        if profileid:
            res: List[Tuple[str, float]]
            res = await self.r.zrange(f"tws{profileid}", 0, 0, withscores=True)
            if res:
                tw: str
                starttime_of_tw: float
                tw, starttime_of_tw = res[0]
                return tw, starttime_of_tw
        return None

    async def get_tw_of_ts(
        self, profileid, time
    ) -> Optional[Tuple[str, float]]:
        """
        Return the TW ID and the time for the TW that includes the given time.
        The score in the DB is the start of the timewindow, so we should search
        a TW that includes the given time by making sure the start of the TW
        is < time, and the end of the TW is > time.
        """
        try:
            data = (
                await self.r.zrangebyscore(
                    f"tws{profileid}",
                    float("-inf"),
                    float(time),
                    withscores=True,
                    start=0,
                    num=-1,
                )
            )[-1]
        except IndexError:
            # We don't have any last TW?
            data = await self.r.zrangebyscore(
                f"tws{profileid}",
                0,
                float(time),
                withscores=True,
                start=0,
                num=-1,
            )
            if not data:
                return None
            data = data[-1]
        return data

    async def add_new_tw(self, profileid, timewindow: str, startoftw: float):
        """
        Creates or adds a new timewindow to the list of TWs for the
        given profile
        Add the TW ID to the ordered set of a given profile
        :param timewindow: str ID of the TW ID, e.g., timewindow7, timewindow-9
        Returns the ID of the timewindow just created
        """
        try:
            # Add the new TW to the index of TW
            await self.r.zadd(
                f"tws{profileid}", {timewindow: float(startoftw)}
            )
            self.print(
                f"Created and added to DB for "
                f"{profileid}: a new TW: {timewindow}. "
                f" with starttime: {startoftw} ",
                0,
                4,
            )
            # The creation of a TW now does not imply that it was modified.
            # You need to put data to mark it as modified.
        except redis.exceptions.ResponseError:
            self.print("Error in addNewTW", 0, 1)
            self.print(traceback.format_exc(), 0, 1)

    async def get_number_of_tws(self, profileid):
        """Return the number of TWs for this profile ID"""
        return await self.r.zcard(f"tws{profileid}") if profileid else False

    async def get_modified_tw_since_time(
        self, time: float
    ) -> List[Tuple[str, float]]:
        """
        Return the list of modified timewindows since a certain time
        """
        # This ModifiedTW set has all timewindows of all profiles
        # The score of each TW is the ts it was last updated
        # This ts is not network time, it is local time
        data = await self.r.zrangebyscore(
            self.constants.MODIFIED_TIMEWINDOWS,
            time,
            float("+inf"),
            withscores=True,
        )
        return data or []

    async def get_modified_profiles_since(
        self, time: float
    ) -> Tuple[Set[str], float]:
        """Returns a set of modified profiles since a certain time and
        the time of the last modified profile"""
        modified_tws: List[Tuple[str, float]] = (
            await self.get_modified_tw_since_time(time)
        )
        if not modified_tws:
            # No modified TWs, and no time_of_last_modified_tw
            return set(), 0

        # Get the time of last modified TW
        time_of_last_modified_tw: float = modified_tws[-1][-1]

        # This list will store modified profiles without TWs
        # This is a list of IPs, not profile IDs
        profiles = []
        profiles.extend(
            modified_tw[0].split("_")[1] for modified_tw in modified_tws
        )
        # Return a set of unique profiles
        return set(profiles), time_of_last_modified_tw

    async def add_to_the_list_of_ipv6(
        self, ipv6_to_add: str, cached_ipv6: str
    ) -> list:
        """
        Adds the given IPv6 to the list of given cached_ipv6
        """
        if not cached_ipv6:
            cached_ipv6 = [ipv6_to_add]
        else:
            # Found a list of IPv6 in the DB
            cached_ipv6: set = set(json.loads(cached_ipv6))
            cached_ipv6.add(ipv6_to_add)
            cached_ipv6 = list(cached_ipv6)
        return cached_ipv6

    async def set_mac_vendor_to_profile(
        self, profileid: str, mac_addr: str, mac_vendor: str
    ) -> bool:
        """
        Sets the given MAC address and vendor to the given profile key
        Is only called when we don't already have a vendor for the given
        profile
        """
        if await self.get_mac_vendor_from_profile(profileid):
            # It already exists
            return False

        # We only want to update the vendor of an IP if we have a MAC for it
        # because, for example, we don't want to set a MAC to the profile
        # 0.0.0.0
        # set_mac_addr_to_profile handles the setting of addresses, and this
        # function only handles the setting of vendors

        # So first, make sure the given MAC address belongs to the given profile
        # before setting the MAC vendor
        if cached_mac_addr := await self.get_mac_addr_from_profile(profileid):
            cached_mac_addr: str
            if cached_mac_addr == mac_addr:
                # Now we're sure that the vendor of the given MAC address
                # is the vendor of this profileid
                await self.r.hset(profileid, "MAC_vendor", mac_vendor)
                return True

        return False

    async def update_mac_of_profile(self, profileid: str, mac: str):
        """Add the MAC address to the given profileid key"""
        await self.r.hset(profileid, self.constants.MAC, mac)

    def _should_associate_this_mac_with_this_ip(self, ip, mac) -> bool:
        return not (
            ip == "0.0.0.0"
            or not mac
            # Sometimes we create profiles with the MAC address.
            # Don't save that in MAC hash
            or validators.mac_address(ip)
            or self._is_gw_mac(mac)
            # We're trying to assign the GW MAC to
            # an IP that isn't the gateway's
            # This happens because any public IP probably has the GW MAC
            # in the Zeek logs, so skip
            or ip == self.get_gateway_ip()
        )

    async def add_mac_addr_to_profile(self, profileid: str, mac_addr: str):
        """
        Used to associate the given profile with the given MAC address.
        Stores this info in the 'MAC' key in the DB
        and in the profileid key of the given profile
        Format of the MAC key is
            MAC: [ipv4, ipv6, etc.]
        This function is called for all MACs found in
        dhcp.log, conn.log, arp.log, etc.
        PS: It doesn't deal with the MAC vendor
        """
        incoming_ip: str = profileid.split("_")[1]

        if not self._should_associate_this_mac_with_this_ip(
            incoming_ip, mac_addr
        ):
            return False

        # See if this is the GW MAC
        self._determine_gw_mac(incoming_ip, mac_addr)

        # Get the IPs that belong to this MAC
        cached_ips: Optional[List] = (
            await self.r.hmget(self.constants.MAC, mac_addr)
        )[0]
        if not cached_ips:
            # No MAC info stored for profileid
            ip = json.dumps([incoming_ip])
            await self.r.hset(self.constants.MAC, mac_addr, ip)

            # Now that it's decided that this MAC belongs to this profileid
            # Store the MAC in the profileid's key in the DB
            await self.update_mac_of_profile(profileid, mac_addr)
        else:
            # We found another profile that has the same MAC as this one
            # Get all the IPs, v4 and v6, that are stored with this MAC
            cached_ips: List[str] = json.loads(cached_ips)
            # Get the last one of them
            found_ip = cached_ips[-1]
            cached_ips: Set[str] = set(cached_ips)

            if incoming_ip in cached_ips:
                # This is the case where we have the given IP already
                # seen with the given MAC. Nothing to do here.
                return False

            # Make sure one profile is IPv4 and the other is IPv6
            # (so we don't mess with MITM ARP detections)
            if validators.ipv6(incoming_ip) and validators.ipv4(found_ip):
                # Associate the IPv4 we found with the incoming IPv6
                # and vice versa
                await self.set_ipv4_of_profile(profileid, found_ip)
                await self.set_ipv6_of_profile(
                    f"profile_{found_ip}", [incoming_ip]
                )

            elif validators.ipv6(found_ip) and validators.ipv4(incoming_ip):
                # Associate the IPv6 we found with the incoming IPv4
                # and vice versa
                await self.set_ipv6_of_profile(profileid, [found_ip])
                await self.set_ipv4_of_profile(
                    f"profile_{found_ip}", incoming_ip
                )
            elif validators.ipv6(found_ip) and validators.ipv6(incoming_ip):
                # If two IPv6 are claiming to have the same MAC, it's fine
                # A computer is allowed to have many IPv6
                # Add this found IPv6 to the list of IPv6 of the incoming
                # IP (profileid)

                # Get the list of cached IPv6
                ipv6: str = await self.get_ipv6_from_profile(profileid)
                # Get the list of cached IPv6 + the new one
                ipv6: list = await self.add_to_the_list_of_ipv6(found_ip, ipv6)
                await self.set_ipv6_of_profile(profileid, ipv6)

                # Add this incoming IPv6 (profileid) to the list of
                # IPv6 of the found IP
                # Get the list of cached IPv6
                ipv6: str = await self.get_ipv6_from_profile(
                    f"profile_{found_ip}"
                )
                # Get the list of cached IPv6 + the new one
                ipv6: list = await self.add_to_the_list_of_ipv6(
                    incoming_ip, ipv6
                )
                await self.set_ipv6_of_profile(f"profile_{found_ip}", ipv6)

            else:
                # Both are IPv4 and are claiming to have the same MAC address
                # OR one of them is 0.0.0.0 and didn't take an IP yet
                # Will be detected later by the ARP module
                return False

            # Add the incoming IP to the list of IPs that belong to this MAC
            cached_ips.add(incoming_ip)
            cached_ips = json.dumps(list(cached_ips))
            await self.r.hset(self.constants.MAC, mac_addr, cached_ips)

            await self.update_mac_of_profile(profileid, mac_addr)
            await self.update_mac_of_profile(f"profile_{found_ip}", mac_addr)

        return True

    async def get_mac_addr_from_profile(
        self, profileid: dict
    ) -> Union[str, None]:
        """
        Returns MAC address of the given profile as a str, or None
        Returns the info from the profileid key.
        """
        return await self.r.hget(profileid, self.constants.MAC)

    async def add_user_agent_to_profile(self, profileid, user_agent: dict):
        """
        Used to associate this profile with its used user_agent
        :param user_agent: dict containing user_agent, os_type,
        os_name, and agent_name
        """
        await self.r.hset(profileid, "first user-agent", user_agent)

    async def get_user_agents_count(self, profileid) -> int:
        """
        Returns the number of unique UAs seen for the given profileid
        """
        count = await self.r.hget(profileid, "user_agents_count")
        return int(count) if count else 0

    async def add_all_user_agent_to_profile(self, profileid, user_agent: str):
        """
        Used to keep history of past user agents of profile
        :param user_agent: str of user_agent
        """
        if not await self.r.hexists(profileid, "past_user_agents"):
            # Add the first user agent seen to the DB
            await self.r.hset(
                profileid, "past_user_agents", json.dumps([user_agent])
            )
            await self.r.hset(profileid, "user_agents_count", 1)
        else:
            # We have previous UAs
            user_agents = json.loads(
                await self.r.hget(profileid, "past_user_agents")
            )
            if user_agent not in user_agents:
                # The given UA is not cached. Cache it as a str
                user_agents.append(user_agent)
                await self.r.hset(
                    profileid, "past_user_agents", json.dumps(user_agents)
                )

                # Increment the number of user agents seen for this profile
                user_agents_count: int = await self.get_user_agents_count(
                    profileid
                )
                await self.r.hset(
                    profileid, "user_agents_count", user_agents_count + 1
                )

    async def get_software_from_profile(self, profileid):
        """
        Returns a dict with software, major_version, minor_version
        """
        if not profileid:
            return False

        if used_software := (await self.r.hmget(profileid, "used_software"))[
            0
        ]:
            used_software = json.loads(used_software)
            return used_software
        return None

    async def get_first_user_agent(self, profileid) -> str:
        """Returns the first user agent used by the given profile"""
        return (await self.r.hmget(profileid, "first user-agent"))[0]

    async def get_user_agent_from_profile(self, profileid):
        """
        Returns a dict of {'os_name', 'os_type', 'browser': , 'user_agent': }
        used by a certain profile or None
        """
        user_agent = await self.get_first_user_agent(profileid)
        if user_agent is None:
            return None

        if isinstance(user_agent, str):
            try:
                parsed = json.loads(user_agent)
                return parsed
            except (ValueError, TypeError):
                pass
        return user_agent

    async def mark_profile_as_dhcp(self, profileid):
        """
        Used to mark this profile as DHCP server
        """
        # Returns a list of DHCP if the profile is in the DB
        profile_in_db = await self.r.hmget(profileid, "dhcp")
        if not profile_in_db:
            return False
        is_dhcp_set = profile_in_db[0]
        # Check if it's already marked as DHCP
        if not is_dhcp_set:
            await self.r.hset(profileid, "dhcp", "true")

    async def add_profile(self, profileid, starttime, confidence=0.05):
        """
        Add a new profile to the DB. Both the list of profiles and the
        hashmap of profile data
        Profiles are stored in two structures. A list of profiles (index)
        and individual hashmaps for each profile (like a table)
        """
        try:
            if await self.r.sismember(self.constants.PROFILES, profileid):
                # We already have this profile
                return False

            # Add the profile to the index. The index is called 'profiles'
            await self.r.sadd(self.constants.PROFILES, str(profileid))
            # Create the hashmap with the profileid.
            # The hashmap of each profile is named with the profileid
            # Add the start time of profile
            await self.r.hset(profileid, "starttime", starttime)
            # For now duration of the TW is fixed
            await self.r.hset(profileid, "duration", self.width)
            # When a new profile is created assign threat level = 0
            # and confidence = 0.05
            await self.r.hset(profileid, "confidence", confidence)
            # The IP of the profile should also be added as a new IP
            # we know about.
            ip = profileid.split(self.separator)[1]
            # If the IP is new, add it to the list of IPs
            await self.set_new_ip(ip)
            # Publish that we have a new profile
            await self.publish("new_profile", ip)
            return True
        except redis.exceptions.ResponseError as inst:
            self.print("Error in add_profile in database.py", 0, 1)
            self.print(type(inst), 0, 1)
            self.print(inst, 0, 1)

    async def set_module_label_for_profile(self, profileid, module, label):
        """
        Set a module label for a profile.
        A module label is a label set by a module, and not
        a groundtruth label
        """
        data = await self.get_modules_labels_of_a_profile(profileid)
        data[module] = label
        data = json.dumps(data)
        await self.r.hset(profileid, "modules_labels", data)

    async def check_tw_to_close(self, close_all=False):
        """
        Check if we should close a TW
        Search in the modified TW list and compare when they
        were modified with the Slips internal time
        :param close_all: close all TWs no matter when they were last modified
        """
        sit = await self.get_slips_internal_time()

        # sit is the ts of the last TW modification detected by Slips
        # So this line means if 1h (width) passed since the last
        # modification detected, then it's time to close the TW
        modification_time = float(sit) - self.width
        if close_all:
            # Close all TWs no matter when they were last modified
            modification_time = float("inf")

        # These are the TWs that haven't been modified in the last 1h
        profiles_tws_to_close = await self.r.zrangebyscore(
            self.constants.MODIFIED_TIMEWINDOWS,
            0,
            modification_time,
            withscores=True,
        )

        for profile_tw_to_close in profiles_tws_to_close:
            profile_tw_to_close_id = profile_tw_to_close[0]
            profile_tw_to_close_time = profile_tw_to_close[1]
            self.print(
                f"The profile ID {profile_tw_to_close_id} has to be closed"
                f" because it was"
                f" last modified on {profile_tw_to_close_time} and we are "
                f"closing everything older than {modification_time}."
                f" Current time {sit}. "
                f"Difference: {modification_time - profile_tw_to_close_time}",
                3,
                0,
            )
            await self.mark_profile_tw_as_closed(profile_tw_to_close_id)

    async def mark_profile_tw_as_closed(self, profileid_tw):
        """
        Mark the TW as closed so tools can work on its data
        """
        await self.r.sadd("ClosedTW", profileid_tw)
        await self.r.zrem(self.constants.MODIFIED_TIMEWINDOWS, profileid_tw)
        await self.publish("tw_closed", profileid_tw)

    async def mark_profile_tw_as_modified(self, profileid, twid, timestamp):
        """
        Mark a TW in a profile as modified
        This means:
        1- To add it to the list of ModifiedTW
        2- Add the timestamp received to the time_of_last_modification
           in the TW itself
        3- To update the internal time of Slips
        4- To check if we should 'close' some TW
        """
        timestamp = time.time()
        data = {f"{profileid}{self.separator}{twid}": float(timestamp)}
        await self.r.zadd(self.constants.MODIFIED_TIMEWINDOWS, data)
        await self.publish("tw_modified", f"{profileid}:{twid}")
        # Check if we should close some TW
        await self.check_tw_to_close()

    async def publish_new_letter(
        self, new_symbol: str, profileid: str, twid: str, tupleid: str, flow
    ):
        """
        Analyze behavioral model with LSTM model if
        the length is divided by 3 -
        so we send when there are 3 more characters added
        """
        if len(new_symbol) % 3 != 0:
            return

        to_send = {
            "new_symbol": new_symbol,
            "profileid": profileid,
            "twid": twid,
            "tupleid": str(tupleid),
            "uid": flow.uid,
            "flow": asdict(flow),
        }
        to_send = json.dumps(to_send)
        await self.publish("new_letters", to_send)

    #
    # def get_previous_symbols(self, profileid: str, twid: str, direction:
    # str, tupleid: str):
    #     """
    #     returns all the InTuples or OutTuples for this profileid in this TW
    #     """
    #     profileid_twid = f'{profileid}{self.separator}{twid}'
    #
    #     tuples = self.r.hget(profileid_twid, direction) or '{}'
    #     tuples = json.loads(tuples)
    #
    #     # Get the last symbols of letters in the DB
    #     prev_symbols = tuples[tupleid][0]
    #     return prev_symbols
    #

    async def add_tuple(
        self,
        profileid: str,
        twid: str,
        tupleid: str,
        symbol: Tuple,
        role: str,
        flow,
    ):
        """
        Add the tuple going in or out for this profile
        and if there was previous symbols for this profile, append the new
        symbol to it
        before adding the tuple to the DB

        :param tupleid: a dash-separated str with the following format
        daddr-dport-proto
        :param symbol: (symbol, (symbol_to_add, previous_two_timestamps))
        T1: is the time diff between the past flow and the past-past flow.
        last_ts: the timestamp of the last flow
        :param role: 'Client' or 'Server'
        """
        # If the traffic is going out, it is part of our outtuples,
        # if not, part of our intuples
        if role == "Client":
            direction = "OutTuples"
        elif role == "Server":
            direction = "InTuples"

        try:
            profileid_twid = f"{profileid}{self.separator}{twid}"

            # prev_symbols is a dict with {tupleid: ['symbols_so_far',
            # [timestamps]]}
            prev_symbols: str = (
                await self.r.hget(profileid_twid, direction) or "{}"
            )
            prev_symbols: dict = json.loads(prev_symbols)

            try:
                # Get the last symbols of letters in the DB
                prev_symbol: str = prev_symbols[tupleid][0]

                # Separate the symbol to add and the previous data
                (symbol_to_add, previous_two_timestamps) = symbol
                self.print(
                    f"Not the first time for tuple {tupleid} as an "
                    f"{direction} for "
                    f"{profileid} in TW {twid}. Add the symbol: {symbol_to_add}. "
                    f"Store previous_times: {previous_two_timestamps}. "
                    f"Prev Data: {prev_symbols}",
                    3,
                    0,
                )

                # Add it to form the string of letters
                new_symbol = f"{prev_symbol}{symbol_to_add}"

                await self.publish_new_letter(
                    new_symbol, profileid, twid, tupleid, flow
                )

                prev_symbols[tupleid] = (new_symbol, previous_two_timestamps)
                self.print(
                    f"\tLetters so far for tuple {tupleid}: {new_symbol}",
                    3,
                    0,
                )
            except (TypeError, KeyError):
                # TODO check that this condition is triggered correctly
                #  only for the first case and not the rest after...
                # There was no previous data stored in the DB to append
                # the given symbol to.
                self.print(
                    f"First time for tuple {tupleid} as an {direction} for {profileid} in TW {twid}",
                    3,
                    0,
                )
                prev_symbols[tupleid] = symbol

            prev_symbols = json.dumps(prev_symbols)
            await self.r.hset(profileid_twid, direction, prev_symbols)
            await self.mark_profile_tw_as_modified(
                profileid, twid, flow.starttime
            )

        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f"Error in add_tuple in database.py line {exception_line}",
                0,
                1,
            )
            self.print(traceback.format_exc(), 0, 1)

    async def get_modules_labels_of_a_profile(self, profileid):
        """
        Get labels set by modules in the profile.
        """
        data = await self.r.hget(profileid, "modules_labels")
        data = json.loads(data) if data else {}
        return data

    async def add_timeline_line(self, profileid, twid, data, timestamp):
        """Add a line to the timeline of this profileid and twid"""
        self.print(f"Adding timeline for {profileid}, {twid}: {data}", 3, 0)
        key = str(
            profileid + self.separator + twid + self.separator + "timeline"
        )
        data = json.dumps(data)
        mapping = {data: timestamp}
        await self.r.zadd(key, mapping)
        # Mark the TW as modified since the timeline line is new data in the TW
        await self.mark_profile_tw_as_modified(profileid, twid, timestamp="")

    async def get_timeline_last_lines(
        self, profileid, twid, first_index: int
    ) -> Tuple[str, int]:
        """Get only the new items in the timeline."""
        key = str(
            profileid + self.separator + twid + self.separator + "timeline"
        )
        # The amount of lines in this list
        last_index = await self.r.zcard(key)
        # Get the data in the list from the index asked (first_index) until the last
        data = await self.r.zrange(key, first_index, last_index - 1)
        return data, last_index

    async def get_profiled_tw_timeline(self, profileid, timewindow):
        return await self.r.zrange(f"{profileid}_{timewindow}_timeline", 0, -1)

    async def mark_profile_as_gateway(self, profileid):
        """
        Used to mark this profile as DHCP server
        """
        await self.r.hset(profileid, "gateway", "true")

    async def set_ipv6_of_profile(self, profileid, ip: list):
        await self.r.hset(profileid, "IPv6", json.dumps(ip))

    async def set_ipv4_of_profile(self, profileid, ip):
        await self.r.hset(profileid, "IPv4", json.dumps([ip]))

    async def get_mac_vendor_from_profile(
        self, profileid: str
    ) -> Union[str, None]:
        """
        Returns a str MAC vendor of the given profile or None
        """
        return await self.r.hget(profileid, "MAC_vendor")

    async def get_hostname_from_profile(self, profileid: str) -> Optional[str]:
        """
        Returns hostname about a certain profile or None
        """
        return await self.r.hget(profileid, "host_name")

    async def add_host_name_to_profile(self, hostname, profileid):
        """
        Adds the given hostname to the given profile
        """
        if not await self.get_hostname_from_profile(profileid):
            await self.r.hset(profileid, "host_name", hostname)

    async def get_ipv4_from_profile(self, profileid) -> str:
        """
        Returns IPv4 about a certain profile or None
        """
        return (
            (await self.r.hmget(profileid, "IPv4"))[0] if profileid else False
        )

    async def get_ipv6_from_profile(self, profileid) -> str:
        """
        Returns IPv6 about a certain profile or None
        """
        return (
            (await self.r.hmget(profileid, "IPv6"))[0] if profileid else False
        )

    async def get_the_other_ip_version(self, profileid):
        """
        Given an IPv4, returns the IPv6 of the same computer
        Given an IPv6, returns the IPv4 of the same computer
        """
        srcip = profileid.split("_")[-1]
        ip = False
        if validators.ipv4(srcip):
            ip = await self.get_ipv6_from_profile(profileid)
        elif validators.ipv6(srcip):
            ip = await self.get_ipv4_from_profile(profileid)

        return ip
