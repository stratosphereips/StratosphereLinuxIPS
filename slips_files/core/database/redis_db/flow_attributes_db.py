# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import ipaddress
import json
import sys
import traceback
from typing import Generator
from redis.client import Pipeline

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


class FlowAttrHandler:
    """
    Helper class for the Redis class in database.py
    Slips splits each flow into different attributes for categorizing them,
    and for easier pattern recognition.
    This class Contains all the logic related to flows attributes and
    categorizing
    """

    name = "DB"

    def _update_portscan_index_hash(
        self,
        profileid: ProfileID,
        twid: TimeWindow,
        proto: Protocol,
        ip: str,
        last_seen_timestamp: float,
    ):
        """
        updates the hash that keeps track of IPs that have contacted a
        certain profile_tw
        PS: these ips can be source or dst ips depending on the
        analysis_direction in slips.yaml (depending on the role of the
        profile)

        hash:
        profile_tw:[tcp|udp]:not_estab:ips <ip> {
        first_seen:..., last_seen:...}


        :param last_seen_timestamp: last seen flow of this ip in this
        profile_tw
        """
        proto = proto.name.lower()
        key = f"{profileid}_{twid}:{proto}:not_estab:ips"
        old_info: str = self.r.hget(key, ip)
        try:
            new_info = json.loads(old_info)
        except json.JSONDecodeError:
            new_info = {"first_seen": last_seen_timestamp}
        new_info["last_seen"] = last_seen_timestamp
        self.r.hset(key, ip, json.dumps(new_info))

    def get_data_from_profile_tw(
        self,
    ) -> Generator:

        try:
            key: str = ""
            cursor = 0
            while True:
                cursor, data = self.r.hscan(key, cursor, count=100)
                for ip_or_port, detailed_info in data.items():
                    detailed_info = json.loads(detailed_info)
                    yield ip_or_port, detailed_info

                if cursor == 0:
                    break

        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f"Error in getDataFromProfileTW database.py line "
                f"{exception_line}",
                0,
                1,
            )
            self.print(traceback.format_exc(), 0, 1)

    def convert_str_to_state(self, state_as_str: str) -> State:
        if state_as_str == "Established":
            return State.EST
        elif state_as_str == "Not Established":
            return State.NOT_EST
        return State.NOT_EST

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
            # ask other peers their opinion about this IP
            # the p2p module is expecting these 2 keys
            data_to_send.update({"cache_age": 1000, "ip": str(ip)})
            self.publish("p2p_data_request", json.dumps(data_to_send))

    def _are_scan_detection_modules_interested_in_this_ip(self, ip) -> bool:
        """
        Check if any of the scan detection modules (horizontal portscan,
        vertical portscan, icmp scan) are interested in this ip
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
        except (ipaddress.AddressValueError, ValueError):
            return False

        return not (
            ip_obj.is_multicast
            or ip_obj.is_link_local
            or ip_obj.is_loopback
            or ip_obj.is_reserved
        )

    def add_ips(
        self, profileid: ProfileID, twid: TimeWindow, flow, role: Role
    ):
        """
        Function to add metadata about the flow's ips and ports
        """
        # depends on my role, i will gather info about the other ip of the
        # flow, so if i'm the server i will gather info about the client and
        # vice versa
        target_ip = flow.daddr if role == Role.CLIENT else flow.client
        self._ask_modules_about_all_ips_in_flow(profileid, twid, flow)

        with self.r.pipeline() as pipe:
            pipe = self._add_scan_detection_info(
                profileid, twid, flow, role, target_ip, pipe
            )
            pipe = self.mark_profile_tw_as_modified(
                str(profileid), str(twid), flow.starttime, pipe=pipe
            )
            pipe.execute()

    def _add_scan_detection_info(
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
        if not self._are_scan_detection_modules_interested_in_this_ip(
            target_ip
        ):
            return pipe

        # Get the state. Established, NotEstablished
        summary_state: str = self.get_final_state_from_flags(
            flow.state, flow.pkts
        )
        state: State = self.convert_str_to_state(summary_state)
        proto: Protocol = self.convert_str_to_proto(flow.proto)

        if self._is_info_needed_by_the_portscan_detector_modules(
            role, proto, state
        ):
            str_proto = proto.name.lower()
            # this hash is needed for vertical portscans detections
            # hash:
            # profile_tw:[tcp|udp]:Not_estab:<ip>:dstports <port> <tot_pkts>
            key = (
                f"{profileid}_{twid}"
                f":{str_proto}:not_estab:{target_ip}:dstports"
            )
            pipe.hincrby(key, flow.dport, int(flow.pkts))
            # we keep an index hash of target_ips to be able to access the
            # key above using them
            self._update_portscan_index_hash(
                profileid, twid, proto, target_ip, flow.timestamp
            )

            if not self._was_flow_flipped(flow):
                # this hash is needed for horizontal portscans detections
                # hash e.g. profile_tw:[tcp|udp]:Not_estab:<ip>:dstports
                # <port>
                # <tot_pkts>
                key = (
                    f"{profileid}_{twid}:"
                    f"{str_proto}:not_estab:{flow.daddr}:dstports"
                )
                pipe.hincrby(key, flow.dport, int(flow.pkts))

        if self._is_info_needed_by_the_icmp_scan_detector_module(
            role, proto, state, flow.sport
        ):
            # needed info for icmp scans
            # hash:
            # profile_tw:icmp:estab:sport:<port>:dstips <dstip> <flows_num>
            key = f"{profileid}_{twid}:icmp:est:sport:{flow.sport}:dstips"
            pipe.hincrby(key, flow.daddr, 1)

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

    def _is_info_needed_by_the_icmp_scan_detector_module(
        self,
        role: Role,
        proto: Protocol,
        state: State,
        source_port: int | str,
    ) -> bool:
        try:
            source_port = int(source_port)
        except ValueError:
            return False

        return (
            role == Role.CLIENT
            and proto in (Protocol.ICMP, Protocol.ICMP6)
            and state == State.EST
            # these are the ports used for common icmp scans that slips
            # currently detects
            and source_port in (8, 19, 20, 23, 24)
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
