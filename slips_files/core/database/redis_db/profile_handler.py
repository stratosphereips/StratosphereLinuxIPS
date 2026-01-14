# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
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
from redis.client import Pipeline

from slips_files.core.structures.flow_attributes import Role


class ProfileHandler:
    """
    Helper class for the Redis class in database.py
    Contains all the logic related to flows, profiles and timewindows
    """

    name = "DB"

    def is_doh_server(self, ip: str) -> bool:
        """returns whether the given ip is a DoH server"""
        info: dict = self.get_ip_info(ip)
        return info.get("is_doh_server", False) if info else False

    def get_outtuples_from_profile_tw(self, profileid, twid):
        """Get the out tuples"""
        return self.r.hgetall(f"{profileid}_{twid}:OutTuples")

    def set_new_incoming_flows(self, will_slips_have_more_flows: bool):
        """A flag indicating if slips is still receiving new flows from
        input an profiler or not"""
        self.r.set(
            self.constants.WILL_SLIPS_HAVE_MORE_FLOWS,
            "yes" if will_slips_have_more_flows else "no",
        )

    def will_slips_have_new_incoming_flows(self):
        """A flag indicating if slips is still receiving new flows from
        input an profiler or not"""
        return self.r.get(self.constants.WILL_SLIPS_HAVE_MORE_FLOWS) == "yes"

    def get_intuples_from_profile_tw(self, profileid, twid):
        """Get the in tuples"""
        return self.r.hget(f"{profileid}{self.separator}{twid}:InTuples")

    def get_dhcp_flows(self, profileid, twid) -> list:
        """
        returns a dict of dhcp flows that happened in this profileid and twid
        """
        if flows := self.r.hget(
            self.constants.DHCP_FLOWS, f"{profileid}_{twid}"
        ):
            return json.loads(flows)

    def set_dhcp_flow(self, profileid, twid, requested_addr, uid):
        """
        Stores all dhcp flows sorted by profileid_twid
        """
        flow = {requested_addr: uid}
        if cached_flows := self.get_dhcp_flows(profileid, twid):
            # we already have flows in this twid, update them
            cached_flows.update(flow)
            self.r.hset(
                self.constants.DHCP_FLOWS,
                f"{profileid}_{twid}",
                json.dumps(cached_flows),
            )
        else:
            self.r.hset(
                self.constants.DHCP_FLOWS,
                f"{profileid}_{twid}",
                json.dumps(flow),
            )

    def get_tw_start_time(self, profileid, twid):
        """Return the time when this TW in this profile was created"""
        # We need to encode it to 'search' because the data in the
        # sorted set is encoded
        return self.r.zscore(f"tws{profileid}", twid.encode("utf-8"))

    def get_first_flow_time(self) -> float | None:
        """
        Get the starttime of the first timewindow
        aka ts of the first flow
        first tw is always timewindow1
        """
        if self.starttime_of_first_tw:
            return self.starttime_of_first_tw

        starttime_of_first_tw: str = self.r.hget(
            self.constants.ANALYSIS, "file_start"
        )
        if starttime_of_first_tw:
            return float(starttime_of_first_tw)

    def get_timewindow(self, flowtime, profileid, add_to_db=True):
        """
        This function returns the TW in the database where the flow belongs.
        Returns the time window id
        :kwarg add_new: Adds the newly recognized tw to the db.

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

        Note:
            - sets self.starttime_of_first_tw

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
            if not self.starttime_of_first_tw:
                self.starttime_of_first_tw: float = self.get_first_flow_time()

            if self.starttime_of_first_tw is not None:  #  because 0 is a
                # valid
                # value
                tw_number: int = (
                    floor((flowtime - self.starttime_of_first_tw) / self.width)
                    + 1
                )

                tw_start: float = self.starttime_of_first_tw + (
                    self.width * (tw_number - 1)
                )
            else:
                # this is the first timewindow
                tw_number: int = 1
                tw_start: float = flowtime

        tw_id: str = f"timewindow{tw_number}"

        if add_to_db:
            self.add_new_tw(profileid, tw_id, tw_start)

        return tw_id

    def add_out_http(
        self,
        profileid,
        twid,
        flow,
    ):
        """
        Store in the DB a http request
        All the type of flows that are not netflows are stored in a separate
        hash ordered by uid.
        The idea is that from the uid of a netflow, you can access which other
         type of info is related to that uid
        """
        # Convert to json string
        http_flow = {
            "profileid": profileid,
            "twid": twid,
            "flow": asdict(flow),
        }
        to_send = json.dumps(http_flow)
        self.publish("new_http", to_send)
        self.publish("new_url", to_send)

        self.print(f"Adding HTTP flow to DB: {flow}", 3, 0)
        # Check if the host domain AND the url is detected by the threat
        # intelligence.
        # not all flows have a host value so don't send empty hosts to ti
        # module.
        if len(flow.host) > 2:
            self.give_threat_intelligence(
                profileid,
                twid,
                "dst",
                flow.starttime,
                flow.uid,
                flow.daddr,
                lookup=flow.host,
            )
            self.give_threat_intelligence(
                profileid,
                twid,
                "dst",
                flow.starttime,
                flow.uid,
                flow.daddr,
                lookup=f"http://{flow.host}{flow.uri}",
            )
        else:
            # use the daddr since there's no host
            self.give_threat_intelligence(
                profileid,
                twid,
                "dstip",
                flow.starttime,
                flow.uid,
                flow.daddr,
                lookup=f"http://{flow.daddr}{flow.uri}",
            )

    def add_out_dns(self, profileid, twid, flow):
        """
        Store in the DB a DNS request
        All the type of flows that are not netflows are stored in a separate
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
        self.publish("new_dns", to_send)
        self.give_threat_intelligence(
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
            self.set_dns_resolution(
                flow.query,
                flow.answers,
                flow.starttime,
                flow.uid,
                flow.qtype_name,
                srcip,
                twid,
            )
            # send each dns answer to TI module
            for answer in flow.answers:
                if "TXT" in answer or answer == "":
                    continue

                extra_info = {
                    "is_dns_response": True,
                    "dns_query": flow.query,
                }
                self.give_threat_intelligence(
                    profileid,
                    twid,
                    "dstip",
                    flow.starttime,
                    flow.uid,
                    flow.daddr,
                    lookup=answer,
                    extra_info=extra_info,
                )

    def get_all_contacted_ips_in_profileid_twid(self, profileid, twid) -> dict:
        """
        Get all the contacted IPs in a given profile and TW
        """
        all_flows: dict = self.get_all_flows_in_profileid_twid(profileid, twid)
        if not all_flows:
            return {}
        contacted_ips = {}
        for uid, flow in all_flows.items():
            # get the daddr of this flow
            daddr = flow["daddr"]
            contacted_ips[daddr] = uid
        return contacted_ips

    def mark_profile_and_timewindow_as_blocked(self, profileid, twid):
        """Add this profile and tw to the list of blocked
        a profile is only blocked if it was blocked using the user's
        firewall, not if it just generated an alert
        """
        tws = self.get_blocked_timewindows_of_profile(profileid)
        tws.append(twid)
        self.r.hset(
            self.constants.BLOCKED_PROFILES_AND_TWS, profileid, json.dumps(tws)
        )

    def get_blocked_timewindows_of_profile(self, profileid):
        """Return all the list of blocked tws"""
        if tws := self.r.hget(
            self.constants.BLOCKED_PROFILES_AND_TWS, profileid
        ):
            return json.loads(tws)
        return []

    def get_blocked_profiles_and_timewindows(self):
        return self.r.hgetall(self.constants.BLOCKED_PROFILES_AND_TWS)

    def is_blocked_profile_and_tw(self, profileid, twid):
        """
        Check if profile and timewindow is blocked
        """
        profile_tws = self.get_blocked_timewindows_of_profile(profileid)
        return twid in profile_tws

    def was_profile_and_tw_modified(self, profileid, twid):
        """Retrieve from the db if this TW of this profile was modified"""
        data = self.r.zrank(
            self.constants.MODIFIED_TIMEWINDOWS,
            profileid + self.separator + twid,
        )
        return bool(data)

    def add_flow(
        self,
        flow,
        profileid="",
        twid="",
        label="",
    ):
        """
        Function to add a flow by interpreting the data. The flow is added to
        the correct TW for this profile.
        The profileid is the main profile that this flow is related too.
        """
        if label:
            self.r.zincrby(self.constants.LABELS, 1, label)

        to_send = {
            "profileid": profileid,
            "twid": twid,
            "flow": asdict(flow),
            "stime": flow.starttime,
            "interpreted_state": self.get_final_state_from_flags(
                flow.state, flow.pkts
            ),
            "label": label,
            "module_labels": {},
        }
        to_send = json.dumps(to_send)

        # dont send arp flows in this channel, they have their own
        # new_arp channel
        if flow.type_ != "arp":
            self.publish("new_flow", to_send)
        return True

    def add_software_to_profile(self, profileid, flow):
        """
        Used to associate this profile with it's used software and version
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
        if cached_sw := self.get_software_from_profile(profileid):
            if flow.software in cached_sw:
                # we already have this same software for this proileid.
                # dont store this one
                return
            # add this new sw to the list of softwares this profile is using
            cached_sw.update(sw_dict)
            self.r.hset(profileid, "used_software", json.dumps(cached_sw))
        else:
            # first time for this profile to use a software
            self.r.hset(profileid, "used_software", json.dumps(sw_dict))

    def get_total_flows(self):
        """
        gets total flows to process from the db
        """
        total_flows = self.r.hget(self.constants.ANALYSIS, "total_flows")
        if total_flows:
            return int(total_flows)
        return 0

    def get_analysis_info(self):
        return self.r.hgetall(self.constants.ANALYSIS)

    def add_out_ssh(
        self,
        profileid,
        twid,
        flow,
    ):
        """
        Store in the DB a SSH request
        All the type of flows that are not netflows are stored in a
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
        self.publish("new_ssh", to_send)
        self.print(f"Adding SSH flow to DB: {flow}", 3, 0)
        self.give_threat_intelligence(
            profileid,
            twid,
            "dstip",
            flow.starttime,
            flow.uid,
            flow.daddr,
            lookup=flow.daddr,
        )

    def add_out_notice(
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
        self.publish("new_notice", to_send)
        self.print(f"Adding notice flow to DB: {flow}", 3, 0)
        self.give_threat_intelligence(
            profileid,
            twid,
            "dstip",
            flow.starttime,
            flow.uid,
            flow.daddr,
            lookup=flow.daddr,
        )

    def add_out_ssl(self, profileid, twid, flow):
        """
        Store in the DB an ssl request
        All the type of flows that are not netflows are stored in a separate
         hash ordered by uid.
        The idea is that from the uid of a netflow, you can access which other
         type of info is related to that uid
        """
        to_send = {"profileid": profileid, "twid": twid, "flow": asdict(flow)}
        to_send = json.dumps(to_send)
        self.publish("new_ssl", to_send)
        self.print(f"Adding SSL flow to DB: {flow}", 3, 0)
        # Check if the server_name (SNI) is detected by the threat intelligence.
        # Empty field in the end, cause we have extra field for the IP.
        # If server_name is not empty, set in the IPsInfo and send to TI
        if not flow.server_name:
            return False

        # We are giving only new server_name to the threat_intelligence module.
        self.give_threat_intelligence(
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
        if ipdata := self.get_ip_info(flow.daddr):
            sni_ipdata = ipdata.get("SNI", [])
        else:
            sni_ipdata = []

        sni_port = {"server_name": flow.server_name, "dport": flow.dport}
        # We do not want any duplicates.
        if sni_port not in sni_ipdata:
            # Verify that the SNI is equal to any of the domains in the DNS
            # resolution
            # only add this SNI to our db if it has a DNS resolution
            if dns_resolutions := self.r.hgetall("DNSresolution"):
                # dns_resolutions is a dict with {ip:{'ts'..,'domains':...,
                # 'uid':..}}
                for ip, resolution in dns_resolutions.items():
                    resolution = json.loads(resolution)
                    if sni_port["server_name"] in resolution["domains"]:
                        # add SNI to our db as it has a DNS resolution
                        sni_ipdata.append(sni_port)
                        self.set_ip_info(flow.daddr, {"SNI": sni_ipdata})
                        break

    def get_profileid_from_ip(self, ip: str) -> Optional[str]:
        """
        returns the profile of the given IP only if it was registered in
        slips before
        """
        try:
            profileid = f"profile_{ip}"
            if self.r.sismember(self.constants.PROFILES, profileid):
                return profileid
            return False
        except redis.exceptions.ResponseError as inst:
            self.print("error in get_profileid_from_ip in database.py", 0, 1)
            self.print(type(inst), 0, 1)
            self.print(inst, 0, 1)

    def get_profiles(self):
        """Get a list of all the profiles"""
        profiles = self.r.smembers(self.constants.PROFILES)
        return profiles if profiles != set() else {}

    def get_tws_from_profile(self, profileid):
        """
        Receives a profile id and returns the list of all the TW in that profile
        Returns a list of tuples (twid, ts) or an empty list
        """
        return (
            self.r.zrange(f"tws{profileid}", 0, -1, withscores=True)
            if profileid
            else False
        )

    def get_number_of_tws_in_profile(self, profileid) -> int:
        """
        Receives a profile id and returns the number of all the
        TWs in that profile
        """
        return len(self.get_tws_from_profile(profileid)) if profileid else 0

    def get_t2_for_profile_tw(
        self, profileid, twid, tupleid, direction: str
    ) -> Tuple[Optional[float], Optional[float]]:
        """
        Get T1 and the previous_time for this previous_time, twid and tupleid

        :param tupleid: = f"{daddr}-{flow.dport}-{flow.proto}"
        :param direction: can be 'InTuples' or 'OutTuples'

        returns a tuple with 2 timestamps, a ts can be None if not found
        """
        try:
            base = f"{profileid}_{twid}:{direction}"

            delats_key = f"{base}:deltas"
            delta = self.r.zscore(delats_key, tupleid)

            last_flow_ts_key = f"{base}:last_flow_ts"
            last_flow_ts = self.r.zscore(last_flow_ts_key, tupleid)

            return delta, last_flow_ts

        except Exception as e:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f"Error in get_t2_for_profile_tw in profile_handler.py "
                f"line {exception_line}",
                0,
                1,
            )
            self.print(type(e), 0, 1)
            self.print(e, 0, 1)

    def has_profile(self, profileid):
        """Check if we have the given profile"""
        return (
            self.r.sismember(self.constants.PROFILES, profileid)
            if profileid
            else False
        )

    def get_profiles_len(self) -> int:
        """Return the amount of profiles. Redis should be faster than python
        to do this count"""
        profiles_n = self.r.scard(self.constants.PROFILES)
        return 0 if not profiles_n else int(profiles_n)

    def get_last_twid_of_profile(self, profileid: str) -> Tuple[str, float]:
        """
        Returns the last TW id (aka tw with the greatest ts seen so far) and
        the starttime of the given profile id
        """
        if profileid:
            res = self.r.zrange(f"tws{profileid}", -1, -1, withscores=True)
            if res:
                twid, starttime = res[0]
                return twid, starttime

    def get_first_twid_for_profile(
        self, profileid: str
    ) -> Optional[Tuple[str, float]]:
        """
        Return the first TW id and the time for the given profile id
        the returned twid may be a negative tw for example tw-1, depends on
        what tw was last registered
        """
        if profileid:
            res: List[Tuple[str, float]]
            res = self.r.zrange(f"tws{profileid}", 0, 0, withscores=True)
            if res:
                tw: str
                starttime_of_tw: float
                tw, starttime_of_tw = res[0]
                return tw, starttime_of_tw

    def get_tw_of_ts(self, profileid, time) -> Optional[Tuple[str, float]]:
        """
        Return the TW id and the time for the TW that includes the given time.
        The score in the DB is the start of the timewindow, so we should search
        a TW that includes the given time by making sure the start of the TW
        is < time, and the end of the TW is > time.
        """
        # [-1] so we bring the last TW that matched this time.
        try:
            data = self.r.zrangebyscore(
                f"tws{profileid}",
                float("-inf"),
                float(time),
                withscores=True,
                start=0,
                num=-1,
            )[-1]

        except IndexError:
            # We dont have any last tw?
            data = self.r.zrangebyscore(
                f"tws{profileid}",
                0,
                float(time),
                withscores=True,
                start=0,
                num=-1,
            )

        return data

    def add_new_tw(self, profileid, timewindow: str, startoftw: float):
        """
        Creates or adds a new timewindow to the list of tw for the
        given profile
        Add the twid to the ordered set of a given profile
        :param timewindow: str id of the twid, e.g timewindow7, timewindow-9
        Returns the id of the timewindow just created
        """
        try:
            if not self.r.zscore(f"tws{profileid}", timewindow):
                # Add the new TW to the index of TW
                self.r.zadd(f"tws{profileid}", {timewindow: float(startoftw)})
                self.print(
                    f"Created and added to DB for "
                    f"{profileid}: a new tw: {timewindow}. "
                    f" with starttime : {startoftw} ",
                    0,
                    4,
                )
            # The creation of a TW now does not imply that it was modified.
            # You need to put data to mark is at modified.
        except redis.exceptions.ResponseError:
            self.print("Error in addNewTW", 0, 1)
            self.print(traceback.format_exc(), 0, 1)

    def get_number_of_tws(self, profileid):
        """Return the number of tws for this profile id"""
        return self.r.zcard(f"tws{profileid}") if profileid else False

    def _get_modified_tw_since_time(
        self, time: float
    ) -> List[Tuple[str, float]]:
        """
        Return the list of modified timewindows since a certain time
        """
        # this ModifiedTW set has all timewindows of all profiles
        #  the score of each tw is the ts it was last updated
        # this ts is not network time, it is local time
        data = self.r.zrangebyscore(
            self.constants.MODIFIED_TIMEWINDOWS,
            time,
            float("+inf"),
            withscores=True,
        )
        return data or []

    def get_modified_profiles_since(
        self, time: float
    ) -> Tuple[Set[str], float]:
        """Returns a set of modified profiles since a certain time and
        the time of the last modified profile"""
        modified_tws: List[Tuple[str, float]] = (
            self._get_modified_tw_since_time(time)
        )
        if not modified_tws:
            # no modified tws, and no time_of_last_modified_tw
            return [], 0

        # get the time of last modified tw
        time_of_last_modified_tw: float = modified_tws[-1][-1]

        # this list will store modified profiles without tws
        # this is a list of ips. not profileids
        profiles = []
        profiles.extend(
            modified_tw[0].split("_")[1] for modified_tw in modified_tws
        )
        # return a set of unique profiles
        return set(profiles), time_of_last_modified_tw

    def add_to_the_list_of_ipv6(
        self, ipv6_to_add: str, cached_ipv6: str
    ) -> list:
        """
        adds the given IPv6 to the list of given cached_ipv6
        """
        if not cached_ipv6:
            cached_ipv6 = [ipv6_to_add]
        else:
            # found a list of ipv6 in the db
            cached_ipv6: set = set(json.loads(cached_ipv6))
            cached_ipv6.add(ipv6_to_add)
            cached_ipv6 = list(cached_ipv6)
        return cached_ipv6

    def set_mac_vendor_to_profile(
        self, profileid: str, mac_addr: str, mac_vendor: str
    ) -> bool:
        """
        sets the given mac add and vendor to the given profile key
        is only called when we don't already have a vendor for the given
        profile
        """
        if self.get_mac_vendor_from_profile(profileid):
            # it already exists
            return False

        # we only wanna update the vendor of an ip if we have a mac for it
        # because for example, we don't wanna set a mac to the profile
        # 0.0.0.0
        # set_mac_addr_to_profile handles the setting of addrs, and this
        # func only handles the setting of vendors

        # so first, make sure the given mac addr belongs to the given profile
        # before setting the mac vendor
        if cached_mac_addr := self.get_mac_addr_from_profile(profileid):
            cached_mac_addr: str
            if cached_mac_addr == mac_addr:
                # now we're sure that the vendor of the given mac addr,
                # is the vendor of this profileid
                self.r.hset(profileid, "MAC_vendor", mac_vendor)
                return True

        return False

    def update_mac_of_profile(self, profileid: str, mac: str):
        """Add the MAC addr to the given profileid key"""
        self.r.hset(profileid, self.constants.MAC, mac)

    def _should_associate_this_mac_with_this_ip(
        self, ip, mac, interface
    ) -> bool:
        return not (
            ip == "0.0.0.0"
            or not mac
            # sometimes we create profiles with the mac address.
            # don't save that in MAC hash
            or validators.mac_address(ip)
            or self._is_gw_mac(mac, interface)
            # we're trying to assign the gw mac to
            # an ip that isn't the gateway's
            # this happens bc any public IP probably has the gw MAC
            # in the zeek logs, so skip
            or ip == self.get_gateway_ip(interface)
        )

    def add_mac_addr_to_profile(
        self, profileid: str, mac_addr: str, interface: str
    ):
        """
        Used to associate the given profile with the given MAC addr.
        stores this info in the 'MAC' key in the db
        and in the profileid key of the given profile
        format of the MAC key is
            MAC: [ipv4, ipv6, etc.]
        this functions is called for all macs found in
        dhcp.log, conn.log, arp.log etc.
        PS: it doesn't deal with the MAC vendor
        """
        incoming_ip: str = profileid.split("_")[1]

        if not self._should_associate_this_mac_with_this_ip(
            incoming_ip, mac_addr, interface
        ):
            return False

        # see if this is the gw mac
        self._determine_gw_mac(incoming_ip, mac_addr, interface)

        # get the ips that belong to this mac
        cached_ips: Optional[List] = self.r.hmget(
            self.constants.MAC, mac_addr
        )[0]
        if not cached_ips:
            # no mac info stored for profileid
            ip = json.dumps([incoming_ip])
            self.r.hset(self.constants.MAC, mac_addr, ip)

            # now that it's decided that this mac belongs to this profileid
            # stoe the mac in the profileid's key in the db
            self.update_mac_of_profile(profileid, mac_addr)
        else:
            # we found another profile that has the same mac as this one
            # get all the ips, v4 and 6, that are stored with this mac
            cached_ips: List[str] = json.loads(cached_ips)
            # get the last one of them
            found_ip = cached_ips[-1]
            cached_ips: Set[str] = set(cached_ips)

            if incoming_ip in cached_ips:
                # this is the case where we have the given ip already
                # seen with the given mac. nothing to do here.
                return False

            # make sure 1 profile is ipv4 and the other is ipv6
            # (so we don't mess with MITM ARP detections)
            if validators.ipv6(incoming_ip) and validators.ipv4(found_ip):
                # associate the ipv4 we found with the incoming ipv6
                # and vice versa
                self.set_ipv4_of_profile(profileid, found_ip)
                self.set_ipv6_of_profile(f"profile_{found_ip}", [incoming_ip])

            elif validators.ipv6(found_ip) and validators.ipv4(incoming_ip):
                # associate the ipv6 we found with the incoming ipv4
                # and vice versa
                self.set_ipv6_of_profile(profileid, [found_ip])
                self.set_ipv4_of_profile(f"profile_{found_ip}", incoming_ip)
            elif validators.ipv6(found_ip) and validators.ipv6(incoming_ip):
                # If 2 IPv6 are claiming to have the same MAC it's fine
                # a computer is allowed to have many ipv6
                # add this found ipv6 to the list of ipv6 of the incoming
                # ip(profileid)

                # get the list of cached ipv6
                ipv6: str = self.get_ipv6_from_profile(profileid)
                # get the list of cached ipv6+the new one
                ipv6: list = self.add_to_the_list_of_ipv6(found_ip, ipv6)
                self.set_ipv6_of_profile(profileid, ipv6)

                # add this incoming ipv6(profileid) to the list of
                # ipv6 of the found ip
                # get the list of cached ipv6
                ipv6: str = self.get_ipv6_from_profile(f"profile_{found_ip}")
                # get the list of cached ipv6+the new one
                ipv6: list = self.add_to_the_list_of_ipv6(incoming_ip, ipv6)
                self.set_ipv6_of_profile(f"profile_{found_ip}", ipv6)

            else:
                # both are ipv4 and are claiming to have the same mac address
                # OR one of them is 0.0.0.0 and didn't take an ip yet
                # will be detected later by the ARP module
                return False

            # add the incoming ip to the list of ips that belong to this mac
            cached_ips.add(incoming_ip)
            cached_ips = json.dumps(list(cached_ips))
            self.r.hset(self.constants.MAC, mac_addr, cached_ips)

            self.update_mac_of_profile(profileid, mac_addr)
            self.update_mac_of_profile(f"profile_{found_ip}", mac_addr)

        return True

    def get_mac_addr_from_profile(self, profileid: dict) -> Union[str, None]:
        """
        Returns MAC address  of the given profile as a str, or None
        returns the info from the profileid key.
        """

        return self.r.hget(profileid, self.constants.MAC)

    def add_user_agent_to_profile(self, profileid, user_agent: dict):
        """
        Used to associate this profile with it's used user_agent
        :param user_agent: dict containing user_agent, os_type ,
        os_name and agent_name
        """
        self.r.hset(profileid, "first user-agent", user_agent)

    def get_user_agents_count(self, profileid) -> int:
        """
        returns the number of unique UAs seen for the given profileid
        """
        return int(self.r.hget(profileid, "user_agents_count"))

    def add_all_user_agent_to_profile(self, profileid, user_agent: str):
        """
        Used to keep history of past user agents of profile
        :param user_agent: str of user_agent
        """
        if not self.r.hexists(profileid, "past_user_agents"):
            # add the first user agent seen to the db
            self.r.hset(
                profileid, "past_user_agents", json.dumps([user_agent])
            )
            self.r.hset(profileid, "user_agents_count", 1)
        else:
            # we have previous UAs
            user_agents = json.loads(
                self.r.hget(profileid, "past_user_agents")
            )
            if user_agent not in user_agents:
                # the given ua is not cached. cache it as a str
                user_agents.append(user_agent)
                self.r.hset(
                    profileid, "past_user_agents", json.dumps(user_agents)
                )

                # incr the number of user agents seen for this profile
                user_agents_count: int = self.get_user_agents_count(profileid)
                self.r.hset(
                    profileid, "user_agents_count", user_agents_count + 1
                )

    def get_software_from_profile(self, profileid):
        """
        returns a dict with software, major_version, minor_version
        """
        if not profileid:
            return False

        if used_software := self.r.hmget(profileid, "used_software")[0]:
            used_software = json.loads(used_software)
            return used_software

    def get_first_user_agent(self, profileid) -> str:
        """returns the first user agent used by the given profile"""
        return self.r.hmget(profileid, "first user-agent")[0]

    def get_user_agent_from_profile(self, profileid) -> str:
        """
        Returns a dict of {'os_name',  'os_type', 'browser': , 'user_agent': }
        used by a certain profile or None
        """

        if user_agent := self.get_first_user_agent(profileid):
            # user agents may be OpenSSH_8.6 , no need to deserialize them
            if "{" in user_agent:
                user_agent = json.loads(user_agent)
            return user_agent

    def mark_profile_as_dhcp(self, profileid):
        """
        Used to mark this profile as dhcp server
        """

        # returns a list of dhcp if the profile is in the db
        profile_in_db = self.r.hmget(profileid, "dhcp")
        if not profile_in_db:
            return False
        is_dhcp_set = profile_in_db[0]
        # check if it's already marked as dhcp
        if not is_dhcp_set:
            self.r.hset(profileid, "dhcp", "true")

    def add_profile(self, profileid, starttime, confidence=0.05):
        """
        Add a new profile to the DB. Both the list of profiles and the
         hashmap of profile data
        Profiles are stored in two structures. A list of profiles (index)
         and individual hashmaps for each profile (like a table)
        """
        try:
            if self.r.sismember(self.constants.PROFILES, profileid):
                # we already have this profile
                return False

            # Add the profile to the index. The index is called 'profiles'
            self.r.sadd(self.constants.PROFILES, str(profileid))
            # Create the hashmap with the profileid.
            # The hasmap of each profile is named with the profileid
            # Add the start time of profile
            self.r.hset(profileid, "starttime", starttime)
            # For now duration of the TW is fixed
            self.r.hset(profileid, "duration", self.width)
            # When a new profiled is created assign threat level = 0
            # and confidence = 0.05

            self.r.hset(profileid, "confidence", confidence)
            # The IP of the profile should also be added as a new IP
            # we know about.
            ip = profileid.split(self.separator)[1]
            # If the ip is new add it to the list of ips
            self.set_new_ip(ip)
            # Publish that we have a new profile
            self.publish("new_profile", ip)
            return True
        except redis.exceptions.ResponseError as inst:
            self.print("Error in add_profile in database.py", 0, 1)
            self.print(type(inst), 0, 1)
            self.print(inst, 0, 1)

    def set_module_label_for_profile(self, profileid, module, label):
        """
        Set a module label for a profile.
        A module label is a label set by a module, and not
        a groundtruth label
        """
        data = self.get_modules_labels_of_a_profile(profileid)
        data[module] = label
        data = json.dumps(data)
        self.r.hset(profileid, "modules_labels", data)

    def check_tw_to_close(self, close_all=False):
        """
        Check if we should close a TW
        Closes the tws that were last modified more than an hour
        ago (self.width)
        :param close_all: close all tws no matter when they were last
        modified, happens when slips is stopping
        """

        sit = float(self.get_slips_internal_time())

        # early exit to avoid re-checking when nothing changed. Remember
        # this func is called per flow, so it needs to be as fast as possible
        if (
            not close_all
            and hasattr(self, "_last_sit")
            and sit == self._last_sit
        ):
            return  # nothing changed since last run

        self._last_sit = sit

        # sit is the ts of the last tw modification detected by slips
        # so this line means if 1h(width) passed since the last
        # modification detected, then it's time to close the tw
        modification_time = sit - self.width
        if close_all:
            # close all tws no matter when they were last modified
            modification_time = float("inf")

        # these are the tws that havent been modified in the last 1h
        profiles_tws_to_close: List[str] = self.r.zrangebyscore(
            self.constants.MODIFIED_TIMEWINDOWS,
            0,
            modification_time,
        )
        if not profiles_tws_to_close:
            return

        # Mark the TWs as closed so modules can work on its data
        pipe = self.r.pipeline()
        for profile_tw_to_close in profiles_tws_to_close:
            pipe.zrem(self.constants.MODIFIED_TIMEWINDOWS, profile_tw_to_close)
            pipe = self.publish(
                "tw_closed", profile_tw_to_close, pipeline=pipe
            )
            if not close_all:
                # if slips isn't stopping, then do regular
                # cleanup of the past
                pipe = self._delete_past_timewindows(profile_tw_to_close, pipe)
        pipe.execute()

    def get_current_timewindow(self) -> Optional[str]:
        """returns the current timewindow if slips is running real-time (
        not pcap/log files)"""
        if not self.args.interface:
            return

        return self.r.get(self.constants.CURRENT_TIMEWINDOW)

    def _delete_past_timewindows(self, closed_profile_tw: str, pipe):
        """
        Deletes the past timewindows data from redis, starting from the
        given tw-1, so that redis only has info about the current
        timewindow and the one before it

        why do we keep 2 tws instead of the current one in redis? see PR
        #1765 in slips repo

        :param closed_profile_tw: a str like profile_8.8.8.8_timewindow7
        """
        try:
            profile, ip, tw = closed_profile_tw.split("_")
            closed_tw = int(tw.replace("timewindow", ""))
        except ValueError:
            self.print(
                f"Unable to delete old timewindows info from"
                f" {closed_profile_tw}"
            )
            return pipe

        if closed_tw < 2:
            # slips needs to always remember 2 tws, now tws to delete now
            return pipe

        current_timewindow: Optional[str] = self.get_current_timewindow()
        if current_timewindow:
            # Zeek flows don't arrive in chronological order. this is to
            # make sure that we never close incorrect tws when a zeek flow
            # too far in the past or too far in the future is found.
            tws_to_close = current_timewindow - 2
        else:
            tws_to_close = closed_tw - 2

        profileid = f"{profile}_{ip}"
        # to avoid deleting so many keys at once which causes mem spikes
        BATCH = 500
        for tw_to_close in range(tws_to_close, -1, -1):
            for i, key in enumerate(
                self.r.scan_iter(
                    match=f"{profileid}_timewindow{tw_to_close}", count=1000
                )
            ):
                pipe.unlink(key)

                if i % BATCH == 0:
                    pipe.execute()
                    pipe = self.r.pipeline()

        return pipe

    def mark_profile_tw_as_modified(
        self, profileid, twid, timestamp, pipe: Pipeline = None
    ):
        """
        Mark a TW in a profile as modified
        This means:
        1- To add it to the list of ModifiedTW
        2- Add the timestamp received to the time_of_last_modification
           in the TW itself

        Modules wait for a TW modification to do some detections.
        check the "tw_modified" channel usages to know why this func is
        useful
        """
        timestamp = timestamp or time.time()
        data = {f"{profileid}{self.separator}{twid}": float(timestamp)}
        client = pipe if pipe else self.r
        client.zadd(self.constants.MODIFIED_TIMEWINDOWS, data)
        self.publish(
            "tw_modified",
            json.dumps(
                {
                    "profileid": profileid,
                    "twid": twid,
                }
            ),
        )
        return pipe

    def publish_new_letter(
        self, new_symbol: str, profileid: str, twid: str, tupleid: str, flow
    ):
        """
        analyze behavioral model with lstm model if
        the length is divided by 3 -
        so we send when there is 3 more characters added
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
        self.publish("new_letters", to_send)

    def add_tuple(
        self,
        profileid: str,
        twid: str,
        new_symbol: Tuple[str, Tuple[float, float]],
        role: Role,
        flow,
    ):
        """
        Add the tuple going in or out for this profile
        and if there was previous symbols for this profile, append the new
        symbol to it
        daddr-dport-proto
        :param new_symbol: (symbol, (symbol_to_add, previous_two_timestamps))
            where (T1, last_flow_ts) =
            previous_two_timestamps
            T1: is the time diff between the past flow and the past-past
            flow.
            last_flow_ts: the timestamp of the last flow

        """
        # If the traffic is going out it is part of our outtuples,
        # if not, part of our intuples
        if role == Role.CLIENT:
            direction = "OutTuples"
            ip = flow.daddr
        elif role == Role.SERVER:
            direction = "InTuples"
            ip = flow.saddr
        else:
            return

        base = f"{profileid}_{twid}:{direction}"
        symbols_key = f"{base}:symbols"
        delats_key = f"{base}:deltas"
        last_flow_ts_key = f"{base}:last_flow_ts"

        tupleid = f"{ip}-{flow.dport}-{flow.proto}"
        symbol_to_add, timestamps = new_symbol
        last_2_flows_diff, last_ts = timestamps

        try:
            prev_symbol = self.r.hget(symbols_key, tupleid)
            if not prev_symbol:
                new_symbol = f"{prev_symbol}{symbol_to_add}"
                self.publish_new_letter(
                    new_symbol, profileid, twid, tupleid, flow
                )

                self.print(
                    f"First time for tuple {tupleid} as an"
                    f" {direction} for {profileid} in {twid}",
                    3,
                    0,
                )
            else:
                new_symbol = symbol_to_add

            self.r.hset(symbols_key, tupleid, new_symbol)
            if last_2_flows_diff:
                self.r.zadd(delats_key, {tupleid: last_2_flows_diff})
            if last_ts:
                self.r.zadd(last_flow_ts_key, {tupleid: last_ts})

        except Exception as e:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f"Error in add_tuple in database.py line {exception_line} "
                f"{e}",
                0,
                1,
            )
            self.print(traceback.format_exc(), 0, 1)

    def store_lines_processors(self, file_type: str, indices: dict):
        self.r.hset(
            self.constants.LINE_PROCESSORS, file_type, json.dumps(indices)
        )

    def get_line_processors(self) -> dict:
        # the keys are very limite d we can safely use hgetall here
        return self.r.hgetall(self.constants.LINE_PROCESSORS)

    def get_modules_labels_of_a_profile(self, profileid):
        """
        Get labels set by modules in the profile.
        """
        data = self.r.hget(profileid, "modules_labels")
        data = json.loads(data) if data else {}
        return data

    def add_timeline_line(self, profileid, twid, data, timestamp):
        """Add a line to the timeline of this profileid and twid"""
        self.print(f"Adding timeline for {profileid}, {twid}: {data}", 3, 0)
        key = str(
            profileid + self.separator + twid + self.separator + "timeline"
        )
        data = json.dumps(data)
        mapping = {data: timestamp}
        self.r.zadd(key, mapping)
        # Mark the tw as modified since the timeline line is new data in the TW
        self.mark_profile_tw_as_modified(profileid, twid, timestamp="")

    def get_timeline_last_lines(
        self, profileid, twid, first_index: int
    ) -> Tuple[str, int]:
        """Get only the new items in the timeline."""
        key = str(
            profileid + self.separator + twid + self.separator + "timeline"
        )
        # The amount of lines in this list
        last_index = self.r.zcard(key)
        # Get the data in the list from the index asked (first_index) until the last
        data = self.r.zrange(key, first_index, last_index - 1)
        return data, last_index

    def get_profiled_tw_timeline(self, profileid, timewindow):
        return self.r.zrange(f"{profileid}_{timewindow}_timeline", 0, -1)

    def mark_profile_as_gateway(self, profileid):
        """
        Used to mark this profile as dhcp server
        """

        self.r.hset(profileid, "gateway", "true")

    def set_ipv6_of_profile(self, profileid, ip: list):
        self.r.hset(profileid, "IPv6", json.dumps(ip))

    def set_ipv4_of_profile(self, profileid, ip):
        self.r.hset(profileid, "IPv4", json.dumps([ip]))

    def get_mac_vendor_from_profile(self, profileid: str) -> Union[str, None]:
        """
        Returns a str MAC vendor of  the given profile or None
        """

        return self.r.hget(profileid, "MAC_vendor")

    def get_hostname_from_profile(self, profileid: str) -> Optional[str]:
        """
        Returns hostname about a certain profile or None
        """
        return self.r.hget(profileid, "host_name")

    def add_host_name_to_profile(self, hostname, profileid):
        """
        Adds the given hostname to the given profile
        """
        if not self.get_hostname_from_profile(profileid):
            self.r.hset(profileid, "host_name", hostname)

    def get_ipv4_from_profile(self, profileid) -> str:
        """
        Returns ipv4 about a certain profile or None
        """
        return self.r.hmget(profileid, "IPv4")[0] if profileid else False

    def get_ipv6_from_profile(self, profileid) -> str:
        """
        Returns ipv6 about a certain profile or None
        """
        return self.r.hmget(profileid, "IPv6")[0] if profileid else False

    def get_the_other_ip_version(self, profileid):
        """
        Given an ipv4, returns the ipv6 of the same computer
        Given an ipv6, returns the ipv4 of the same computer
        """
        srcip = profileid.split("_")[-1]
        ip = False
        if validators.ipv4(srcip):
            ip = self.get_ipv6_from_profile(profileid)
        elif validators.ipv6(srcip):
            ip = self.get_ipv4_from_profile(profileid)

        return ip
