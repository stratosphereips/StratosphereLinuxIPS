# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import sys
import traceback
from typing import Iterator, Tuple

from cachetools import TTLCache
from redis.client import Pipeline
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
    ProfileID,
    TimeWindow,
)
from slips_files.core.structures.flow_attributes import (
    State,
    Role,
    Protocol,
)

PROTO_MAP = {
    "tcp": Protocol.TCP,
    "udp": Protocol.UDP,
    "icmp": Protocol.ICMP,
    "icmp6": Protocol.ICMP6,
}


class ScanDetectionsHandler:
    """
    Helper class for the Redis class in database.py
    Slips splits each flow into different categories for scan detections (
    vertical and horizontal)

    This class Contains all the logic related to preping the needed info
    for the scan detection modules

    Entries managed by this class:

    .. vertical portscans detections ..
    zset: profile_tw:[tcp|udp]:not_estab:ips:first_seen <ip> first_seen
    zset: profile_tw:[tcp|udp]:not_estab:ips:last_seen <ip> last_seen
    hash profile_tw:[tcp|udp]:not_estab:<ip>:dstports <port> <tot_pkts>
    int profile_tw:[tcp|udp]:not_estab:<ip>:tot_pkts_sum
    <tot_pkts_sent_to_all_ports>


    ..horizontal portscans detections ..
    hash: profile_tw:[tcp|udp]:not_estab:dstports:total_packets <port>
    <tot_pkts>
    zset profile_tw:[tcp|udp]:not_estab:dport:[port]:dstips:timestamps  [ip, ip, .. ]

    .. conn to multiple ports ..
    zset profile_tw:tcp:estab:ips <ip> <first_seen>
    hash profile_tw:tcp:estab:<ip>:dstports <port> <uid>

    """

    name = "DB"

    def setup(self, *args, **kwargs):
        self.use_local_p2p: bool = self.conf.use_local_p2p()
        self.ask_ip_cache = TTLCache(
            maxsize=10_000,
            ttl=self.twid_width,
        )

    def _should_ask_modules_about_ip(self, ip: str) -> bool:
        """
        determines whether to ask threat intel module about the ip or not
        based on whether we've asked about it once in the past hour.
        """
        if ip in self.ask_ip_cache:
            return False

        self.ask_ip_cache[ip] = True
        return True

    def _hscan(
        self, key: str, redis_client=None, count: int = 100
    ) -> Iterator:
        if not redis_client:
            redis_client = self.r

        cursor = 0
        while True:
            cursor, data = redis_client.hscan(key, cursor, count=count)
            for k, v in data.items():
                yield k, v
            if cursor == 0:
                break

    def _zscan(self, key: str, count: int = 100) -> Iterator:
        """scans a ZSET"""
        cursor = 0
        while True:
            cursor, items = self.r.zscan(key, cursor=cursor, count=count)
            for member, score in items:
                yield member, score
            if cursor == 0:
                break

    def _update_portscan_index_hash(
        self,
        profileid: ProfileID,
        twid: TimeWindow,
        proto: Protocol,
        ip: str,
        flow,
        pipe,
    ) -> Pipeline:
        """
        updates the hash that keeps track of IPs that have contacted a
        certain profile_tw
        PS: these ips can be source or dst ips depending on the
        analysis_direction in slips.yaml (depending on the role of the
        profile)

        ZSET:
        profile_tw:[tcp|udp]:not_estab:ips:first_seen <ip> first_seen
        profile_tw:[tcp|udp]:not_estab:ips:last_seen <ip> last_seen


        :param last_seen_timestamp: last seen flow of this ip in this
        profile_tw
        """
        proto = proto.name.lower()
        base = f"{profileid}_{twid}:{proto}:not_estab:ips"

        # if no first seen ts is set, then this flow is the first seen
        key = f"{base}:first_seen"
        pipe.zadd(key, {ip: flow.starttime}, nx=True)

        key = f"{base}:last_seen"
        # last seen is now. this flow.
        pipe.zadd(key, {ip: flow.starttime})

        return pipe

    def get_dstips_with_not_established_flows(
        self,
        profileid: ProfileID,
        twid: TimeWindow,
        proto: Protocol,
    ) -> Iterator[Tuple[str, str]]:
        """
        used by vertical portscan modules
        returns (ip, first_seen ts)
        """
        # :first_seen or last_seen here will give us the same ips
        proto = proto.name.lower()
        key = f"{profileid}_{twid}:{proto}:not_estab:ips:first_seen"
        yield from self._zscan(key)

    def get_ip_last_seen_ts(
        self, profileid: ProfileID, twid: TimeWindow, proto: Protocol, ip: str
    ):
        proto = proto.name.lower()
        key = f"{profileid}_{twid}:{proto}:not_estab:ips:last_seen"
        return self.r.zscore(key, ip)

    def convert_str_to_proto(self, str_proto: str) -> Protocol:
        """converts str proto to Protocol enum"""
        str_proto = str_proto.lower()

        enum_proto = PROTO_MAP.get(str_proto)
        if enum_proto is not None:
            return enum_proto

        # substring match
        for k, enum_proto in PROTO_MAP.keys():
            if k in str_proto:
                return enum_proto

        raise ValueError(f"Unknown protocol: {str_proto}")

    def _ask_modules_about_all_ips_in_flow(
        self, profileid: ProfileID, twid: TimeWindow, flow
    ):
        """
        Ask the IP info module about saddr and daddr of this flow
        doesn't ask for flows with "OTH" state
        """

        if flow.state == "OTH":
            # OTH means that we didnt see the true src ip and dst ip.
            # from zeek docs; OTH: No SYN seen, just midstream traffic
            # (one example of this is a “partial connection” that was not
            # later closed).
            return

        cases = {
            "srcip": flow.saddr,
            "dstip": flow.daddr,
        }

        for ip_state, ip in cases.items():
            # to avoid asking about the same ip so many times
            if not self._should_ask_modules_about_ip(ip):
                continue

            if ip in self.our_ips:
                # dont ask p2p or other modules about your own ip
                continue

            data_to_send = self.give_threat_intelligence(
                str(profileid),
                str(twid),
                ip_state,
                flow.starttime,
                flow.uid,
                flow.daddr,
                proto=flow.proto.upper(),
                lookup=ip,
            )

            if self.use_local_p2p:
                # ask other peers their opinion about this IP
                # the p2p module is expecting these 2 keys
                data_to_send.update({"cache_age": 1000, "ip": str(ip)})
                self.publish("p2p_data_request", json.dumps(data_to_send))

    def add_ips(
        self, profileid: ProfileID, twid: TimeWindow, flow, role: Role
    ):
        """
        Function to add metadata about the flow's ips and ports
        """
        # depends on my role, i will gather info about the other ip of the
        # flow, so if i'm the server i will gather info about the client and
        # vice versa
        target_ip = flow.daddr if role == Role.CLIENT else flow.saddr
        self._ask_modules_about_all_ips_in_flow(profileid, twid, flow)

        with self.r.pipeline() as pipe:
            pipe = self._store_flow_info_if_needed_by_detection_modules(
                profileid, twid, flow, role, target_ip, pipe
            )
            pipe = self.mark_profile_tw_as_modified(
                str(profileid), str(twid), flow.starttime, pipe=pipe
            )
            pipe.execute()

    def get_info_about_not_established_flows(
        self,
        profileid: ProfileID,
        twid: TimeWindow,
        proto: Protocol,
        dstip: str,
    ) -> Tuple[int, int]:
        """
        When a conn like this happens
        profile -> given dstip:dstport
        this function returns the number of pkts_sent to all dports of the
        given dstip
        and the amount_of_dports seen in flows from the given profile
        -> the given dstip
        Used for detecting vertical portscans
        returns (amount_of_dports, total_pkts_sent_to_all_dports)
        """
        str_proto = proto.name.lower()
        key = f"{profileid}_{twid}:{str_proto}:not_estab:" f"{dstip}:dstports"
        amount_of_dports = self.r.hlen(key) or 0

        key = (
            f"{profileid}_{twid}:{str_proto}:not_estab:"
            f"{dstip}:dstports:tot_pkts_sum"
        )
        total_pkts_sent_to_all_dports = self.r.get(key) or 0

        return amount_of_dports, total_pkts_sent_to_all_dports

    def get_dstports_of_not_established_flows(
        self,
        profileid: ProfileID,
        twid: TimeWindow,
        proto: Protocol,
    ) -> Iterator[Tuple[str, int]]:
        str_proto = proto.name.lower()
        key = (
            f"{profileid}_{twid}:"
            f"{str_proto}:not_estab:dstports:total_packets"
        )
        yield from self._hscan(key)

    def get_total_dstips_for_not_estab_flows_on_port(
        self,
        profileid: ProfileID,
        twid: TimeWindow,
        proto: Protocol,
        dport: str,
    ) -> int:
        """
        counts the unique dst ips where the profile has not established
        flows to on the given dst port.

        returns the length of the set for horizontal portscan detection
         profile_tw:[tcp|udp]:not_estab:dport:[port]:dstips:timestamps  [ip,
         ip, ip...]

        """
        str_proto = proto.name.lower()
        key = (
            f"{profileid}_{twid}:"
            f"{str_proto}:not_estab:dstport:{dport}:dstips:timestamps"
        )
        try:
            amount_of_dstips = int(self.r.zcard(key))
        except TypeError:
            amount_of_dstips = 0
        return amount_of_dstips

    def get_attack_starttime(
        self,
        profileid: ProfileID,
        twid: TimeWindow,
        proto: Protocol,
        dport: str,
    ) -> str:
        """
        returns the first  timestamp of the attack for
        horizontal portscan detection
         profile_tw:[tcp|udp]:not_estab:dport:[port]:dstips:timestamps  [ip,
         ip, ip...]

        """
        str_proto = proto.name.lower()
        key = (
            f"{profileid}_{twid}:"
            f"{str_proto}:not_estab:dstport:{dport}:dstips:timestamps"
        )
        try:
            min_item = self.r.zrange(key, 0, 0, withscores=True)
            if not min_item:
                return ""

            first_timestamp = str(int(min_item[0][1]))
            return first_timestamp
        except TypeError:
            return ""

    def convert_str_to_state(self, state_as_str: str) -> State:
        if state_as_str == "Established":
            return State.EST
        elif state_as_str == "Not Established":
            return State.NOT_EST
        return State.NOT_EST

    def is_there_estab_tcp_flows(
        self,
        saddr: str,
        daddr: str,
        twid: str,
    ) -> bool:
        """
        checks whethere there were estab tcp flows from the given saddr,
        to the given daddr in the given tw
        """
        key = f"profile_{saddr}_{twid}:tcp:est:dstips"
        return True if self.r.zscore(key, daddr) else False

    def get_dstports_of_flows(
        self, profileid: str, daddr: str, twid: str
    ) -> Iterator[Tuple[str, str]]:
        """
         Yields (dstport, uid) pairs for flows going from the given profile
        to daddr in the given time window.
        """
        key = f"{profileid}_{twid}:tcp:est:{daddr}:dstports"
        yield from self._hscan(key)

    def _is_info_needed_by_the_conn_to_multiple_ports_detector(
        self,
        flow,
        proto: Protocol,
        state: State,
    ) -> bool:
        """
        that detection in done in detect_connection_to_multiple_ports()
        """
        dport_name = flow.appproto
        if not dport_name:
            dport_name = self.get_port_info(f"{flow.dport}/{flow.proto}")

        if dport_name:
            # dport is known, we are considering only unknown services
            return False

        return state == State.EST and proto == Protocol.TCP

    def _store_vertical_portscan_info(
        self, pipe, profileid, twid, proto, target_ip, flow
    ) -> Pipeline:
        str_proto = proto.name.lower()
        # this hash is needed for vertical portscans detections
        # hash:
        # profile_tw:[tcp|udp]:Not_estab:<ip>:dstports <port> <tot_pkts>
        key = (
            f"{profileid}_{twid}"
            f":{str_proto}:not_estab:{target_ip}:dstports"
        )
        pipe.hincrby(key, flow.dport, int(flow.pkts))
        # increment the total pkts sent to this target ip on this
        # proto so slips can retreieve it in O(1) when setting and
        # evidence
        key = (
            f"{profileid}_{twid}"
            f":{str_proto}:not_estab:"
            f"{target_ip}:dstports:tot_pkts_sum"
        )
        pipe.incrby(key, int(flow.spkts))

        # we keep an index hash of target_ips to be able to access the
        # diff variants of the key above using them
        pipe = self._update_portscan_index_hash(
            profileid, twid, proto, target_ip, flow, pipe
        )
        return pipe

    def _store_horizontal_portscan_info(
        self, pipe, profileid, twid, proto, flow
    ) -> Pipeline:
        str_proto = proto.name.lower()
        if not self._was_flow_flipped(flow):
            # these hashes are needed for horizontal portscans detections
            # HASH:
            # profile_tw:[tcp|udp]:not_estab:dstports:total_packets
            # <dport> <tot_pkts>
            key = (
                f"{profileid}_{twid}:"
                f"{str_proto}:not_estab:dstports:total_packets"
            )
            pipe.hincrby(key, flow.dport, int(flow.pkts))

            # ZSET
            # profile_tw:[tcp|udp]:not_estab:dport:
            # [port]:dstips:timestamps  [ip,
            # ip, ip...]
            # each ip has the flow starttime as score
            key = (
                f"{profileid}_{twid}:"
                f"{str_proto}:not_estab:dstport:"
                f"{flow.dport}:dstips:timestamps"
            )
            # To make sure the stored ts is the first seen ts of this
            # daddr, we use nx=True, so if a daddr is present we dont zadd
            pipe.zadd(key, {flow.daddr: flow.starttime}, nx=True)

        return pipe

    def _store_conn_to_multiple_ports_info(
        self, pipe, profileid, twid, role, flow
    ):
        # updates the following:
        # zset profile_tw:tcp:estab:ips <ip> <first_seen>
        # hash profile_tw:tcp:estab:<ip>:dstports <port> <uid>
        if role == role.CLIENT:
            key = f"{profileid}_{twid}:tcp:est:dstips"
            pipe.zadd(key, {flow.daddr: flow.starttime}, nx=True)

            key = f"{profileid}_{twid}:tcp:est:{flow.daddr}:dstports"
            pipe.hset(key, flow.dport, flow.uid)

        elif role == role.SERVER:
            client_profileid = ProfileID(ip=flow.saddr)
            key = f"{client_profileid}_{twid}:tcp:est:dstips"
            pipe.zadd(key, {flow.saddr: flow.starttime}, nx=True)

            key = f"{client_profileid}_{twid}:tcp:est:{flow.saddr}:dstports"
            pipe.hset(key, flow.dport, flow.uid)
        return pipe

    def _store_flow_info_if_needed_by_detection_modules(
        self,
        profileid: ProfileID,
        twid: TimeWindow,
        flow,
        role: Role,
        target_ip: str,
        pipe: Pipeline,
    ) -> Pipeline:
        """
        :param target_ip: the ip we are gathering info about, depends on the
            role of the profile in the flow, if the profile ip is the
            saddr, the role is client, and the target ip is the daddr,
            and viceversa
        """
        if not utils.are_detection_modules_interested_in_this_ip(target_ip):
            return pipe

        if not hasattr(self, "tw_width"):
            self.tw_width = int(self.conf.get_tw_width_in_seconds())

        # Get the state. Established, NotEstablished
        summary_state: str = self.get_final_state_from_flags(
            flow.state, flow.pkts
        )
        state: State = self.convert_str_to_state(summary_state)
        proto: Protocol = self.convert_str_to_proto(flow.proto)

        if self._is_info_needed_by_the_portscan_detector_modules(
            role, proto, state
        ):
            pipe = self._store_vertical_portscan_info(
                pipe, profileid, twid, proto, target_ip, flow
            )

            pipe = self._store_horizontal_portscan_info(
                pipe, profileid, twid, proto, flow
            )

        if self._is_info_needed_by_the_conn_to_multiple_ports_detector(
            flow, proto, state
        ):
            pipe = self._store_conn_to_multiple_ports_info(
                pipe, profileid, twid, role, flow
            )

        return pipe

    def _was_flow_flipped(self, flow) -> bool:
        """
        The majority of the FP with horizontal port scan detection
        happen because a benign computer changes wifi, and many not
        established conns are redone, which look like a port scan to
        10 webpages. To avoid this, we IGNORE all the flows that have
        in the history of flags (field history in zeek), the ^,
        that means that the flow was swapped/flipped.
        that means that the flow was swapped/flipped.
        since this func stores info that is only needed by the horizontal
        portscan module, we can safely ignore flipped flows.
        """
        state_hist = flow.state_hist if hasattr(flow, "state_hist") else ""
        return "^" in state_hist

    def _is_info_needed_by_the_portscan_detector_modules(
        self,
        role: Role,
        proto: Protocol,
        state: State,
    ) -> bool:
        """
        Check if the given flow info is needed by any of the network
        discovery modules (horizontal or vertical portscan)
        """
        return (
            role == Role.CLIENT
            and proto in (Protocol.TCP, Protocol.UDP)
            and state == State.NOT_EST
        )

    def get_final_state_from_flags(self, state, pkts):
        """
        Analyze the flags given and return a summary of the state. Should work
         with Argus and Bro flags
        We receive the pakets to distinguish some Reset connections
        """
        # todo this shouldnt be in the DB
        try:
            pre = state.split("_")[0]
            try:
                # Try suricata states
                """
                There are different states in which a flow can be.
                Suricata distinguishes three flow-states for TCP and two
                for UDP. For TCP, these are: New, Established and Closed,
                for UDP only new and established.
                For each of these states Suricata can employ different
                 timeouts.
                """
                if "new" in state or "established" in state:
                    return "Established"
                elif "closed" in state:
                    return "Not Established"

                # We have varius type of states depending on the type of flow.
                # For Zeek
                if state in ("S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"):
                    return "Not Established"
                elif state in ("S1", "SF", "S2", "S3", "RSTO", "RSTP", "OTH"):
                    return "Established"

                # For Argus
                suf = state.split("_")[1]
                if "S" in pre and "A" in pre and "S" in suf and "A" in suf:
                    """
                    Examples:
                    SA_SA
                    SR_SA
                    FSRA_SA
                    SPA_SPA
                    SRA_SPA
                    FSA_FSA
                    FSA_FSPA
                    SAEC_SPA
                    SRPA_SPA
                    FSPA_SPA
                    FSRPA_SPA
                    FSPA_FSPA
                    FSRA_FSPA
                    SRAEC_SPA
                    FSPA_FSRPA
                    FSAEC_FSPA
                    FSRPA_FSPA
                    SRPAEC_SPA
                    FSPAEC_FSPA
                    SRPAEC_FSRPA
                    """
                    return "Established"
                elif "PA" in pre and "PA" in suf:
                    # Tipical flow that was reported in the middle
                    """
                    Examples:
                    PA_PA
                    FPA_FPA
                    """
                    return "Established"
                elif "ECO" in pre:
                    return "ICMP Echo"
                elif "ECR" in pre:
                    return "ICMP Reply"
                elif "URH" in pre:
                    return "ICMP Host Unreachable"
                elif "URP" in pre:
                    return "ICMP Port Unreachable"
                else:
                    """
                    Examples:
                    S_RA
                    S_R
                    A_R
                    S_SA
                    SR_SA
                    FA_FA
                    SR_RA
                    SEC_RA
                    """
                    return "Not Established"
            except IndexError:
                # suf does not exist, which means that this is some ICMP or
                # no response was sent for UDP or TCP
                if "ECO" in pre:
                    # ICMP
                    return "Established"
                elif "UNK" in pre:
                    # ICMP6 unknown upper layer
                    return "Established"
                elif "CON" in pre:
                    # UDP
                    return "Established"
                elif "INT" in pre:
                    # UDP trying to connect, NOT preciselly not established
                    # but also NOT 'Established'. So we considered not
                    # established because there
                    # is no confirmation of what happened.
                    return "Not Established"
                elif "EST" in pre:
                    # TCP
                    return "Established"
                elif "RST" in pre:
                    # TCP. When -z B is not used in argus, states are single
                    # words. Most connections are reseted when finished and
                    # therefore are established
                    # It can happen that is reseted being not established,
                    # but we can't tell without -z b.
                    # So we use as heuristic the amount of packets. If <=3,
                    # then is not established because the OS retries 3 times.
                    return (
                        "Not Established" if int(pkts) <= 3 else "Established"
                    )
                elif "FIN" in pre:
                    # TCP. When -z B is not used in argus, states are single
                    # words. Most connections are finished with FIN when
                    # finished and therefore are established
                    # It can happen that is finished being not established,
                    # but we can't tell without -z b.
                    # So we use as heuristic the amount of packets. If <=3,
                    # then is not established because the OS retries 3 times.
                    return (
                        "Not Established" if int(pkts) <= 3 else "Established"
                    )
                else:
                    """
                    Examples:
                    S_
                    FA_
                    PA_
                    FSA_
                    SEC_
                    SRPA_
                    """
                    return "Not Established"
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f"Error in getFinalStateFromFlags()" f" line {exception_line}",
                0,
                1,
            )
            self.print(traceback.format_exc(), 0, 1)
