# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import sys
import traceback
from typing import Generator

from slips_files.core.structures.evidence import (
    ProfileID,
    TimeWindow,
    Direction,
)
from slips_files.core.structures.flow_attributes import (
    FlowQuery,
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

    def get_data_from_profile_tw(
        self,
        query: FlowQuery,
    ) -> Generator:
        """
        Retrieves metadata about a given profile and time window
        based on the given query (role, protocol, state, direction).

        :param flow: FlowQuery object containing:
            - role: CLIENT or SERVER (is the traffic from or to the profile)
            - protocol: TCP, UDP, ICMP, etc.
            - state: EST or NOT_EST
            - direction: SRC or DST (source/destination of traffic)
            - data_type: PORT or IP (what we use as key in Redis)
            - related_type: the opposite dimension of data_type
              e.g., if data_type=PORT, related_type=IP
              meaning "get all IPs that used this port"
        :yield: Tuple[key, details]
            key = port or IP (depending on data_type)
            details = JSON-decoded dictionary with flow info

        I Recommend looking at the values of the
        profile_1.1.1.1_timewindow2:* keys
        in redis after a slips run to get an idea of what this func is
        querying
        """
        try:
            key: str = str(query)
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

    def add_ips(
        self, profileid: ProfileID, twid: TimeWindow, flow, role: Role
    ):
        """
        Function to add information about an IP address

        :param role:
            The flow can go out of the IP (we are acting as Client)
            or into the IP (we are acting as Server)

        This function does two things:
            1- Add the ip to this tw in this profile, counting how many times
            it was contacted and stores it in the db
            2- Use the ip as a key to count how many times that IP was
            contacted on each port. We store it like this because its the
               pefect structure to detect vertical port scans later on
            3- Check if this IP has any detection in the threat intelligence
            module. The information is added by the module directly in the DB.
        """

        # what are we adding? a dst or a src profile?
        # why are we always using DST_PORTS?
        # because no one cares about the sport (slips doesnt use them)
        # dports are used in all our detections
        # so whether we're the client or the server, we would want to know
        # what dst port we connected to and what dstport was used when an
        # ip connects to us on.

        # since we're dealing with ip's characteristics
        port = flow.dport

        if role == Role.CLIENT:
            direction = Direction.DST
            ip = flow.daddr
        else:
            direction = Direction.SRC
            ip = flow.saddr

        #############
        # Store the Dst as IP address and notify in the channel
        # We send the obj but when accessed as str, it is automatically
        # converted to str
        self.set_new_ip(ip)

        #############

        # OTH means that we didnt see the true src ip and dst ip
        # from zeek docs; OTH: No SYN seen, just midstream traffic
        # (one example of this is a “partial connection” that was not
        # later closed).
        if flow.state != "OTH":
            self.ask_for_ip_info(
                flow.saddr,
                profileid,
                twid,
                flow,
                "srcip",
                daddr=flow.daddr,
            )
            self.ask_for_ip_info(
                flow.daddr,
                profileid,
                twid,
                flow,
                "dstip",
            )

        self.update_times_contacted(ip, direction, profileid, twid)

        # Get the state. Established, NotEstablished
        summary_state: str = self.get_final_state_from_flags(
            flow.state, flow.pkts
        )
        state: State = self.convert_str_to_state(summary_state)
        proto: Protocol = self.convert_str_to_proto(flow.proto)

        # needed info for vertical portscans
        if self.is_info_needed_by_the_portscan_detector_modules(
            role, proto, state
        ):
            # hash e.g. profile_tw:TCP:Not_estab:<ip>:dstports <port>
            # <tot_pkts>
            key = (
                f"{profileid}_{twid}"
                f":{proto.name.lower()}:not_estab:"
                f"{ip}:dstports"
            )
            self.r.hincrby(key, port, int(flow.pkts))

    def is_negligible_flow(
        self, ip, role: Role, proto: Protocol, state: State
    ) -> bool:
        """
        Aka is this flow negligible for the horizontal portscan module?
        """
        if not self.is_info_needed_by_the_portscan_detector_modules(
            role, proto, state
        ):
            return False

        # this key is used in horizontal ps module only
        # to avoid unnecessary storing and filtering of data, we store
        # only unresolved non multicast non broadcast ips.
        # if this key is ever needed for another module, we'll need to
        # workaround this
        ip_resolved = self.get_dns_resolution(ip)
        if ip_resolved or self._is_multicast_or_broadcast(ip):
            return True

        return False

    def _was_flow_flipped(self, flow) -> bool:
        """
        The majority of the FP with horizontal port scan detection
        happen because a benign computer changes wifi, and many not
        established conns are redone, which look like a port scan to
        10 webpages. To avoid this, we IGNORE all the flows that have
        in the history of flags (field history in zeek), the ^,
        that means that the flow was swapped/flipped.
        since this func stores info that is only needed by the horizontal
        portscan module, we can safely ignore flipped flows.
        """
        state_hist = flow.state_hist if hasattr(flow, "state_hist") else ""
        return "^" in state_hist

    def add_port(
        self,
        profileid: ProfileID,
        twid: TimeWindow,
        flow,
        role: Role,
    ):
        """
        Store info about the dst port of this flow.

        The flow can go out of the IP (we are acting as Client aka the
        profile is the srcip of this flow) or into the IP
        (we are acting as Server aka the profile is the dstip of this  flow)
        """
        if self._was_flow_flipped(flow):
            return False

        pkts = int(flow.pkts)
        starttime = str(flow.starttime)
        ip = str(flow.daddr)
        summary_state = self.get_final_state_from_flags(flow.state, pkts)
        state: State = self.convert_str_to_state(summary_state)
        proto: Protocol = self.convert_str_to_proto(flow.proto)

        if self.is_negligible_flow(ip, role, proto, state):
            self.mark_profile_tw_as_modified(
                str(profileid), str(twid), starttime
            )
            return

        # depends on my role, i will gather info about the other ip of the
        # flow, so if i'm the server i will gather info about the client and
        # vice versa
        if role == Role.CLIENT:
            # if the profile (me) is a client, then i want to gather info
            # about the server ips that i connected to (aka dst servers)
            ip = flow.daddr
        else:
            # if the profile (me) is a server, then i want to gather info
            # about the client ips that connected to me (aka src ips)
            ip = flow.saddr

        # hash profile_tw:TCP:Not_estab:<port>:dstips <ip> <pkts>
        if self.is_info_needed_by_the_portscan_detector_modules(
            role, proto, state
        ):
            # needed info for horizontal portscans
            # hash e.g. profile_tw:TCP:Not_estab:<ip>:dstports <port>
            # <tot_pkts>
            key = (
                f"{profileid}_{twid}:"
                f"{proto.name.lower()}:not_estab:{ip}:dstports"
            )
            self.r.hincrby(key, flow.dport, pkts)

        self.mark_profile_tw_as_modified(str(profileid), str(twid), starttime)

    def is_info_needed_by_the_portscan_detector_modules(
        self,
        role: Role,
        proto: Protocol,
        state: State,
    ) -> bool:
        """
        Check if the given flow info is needed by any of the network
        discovery modules (horizontal or vertical portscan)
        """
        if (
            role == Role.CLIENT
            and proto in (Protocol.TCP, Protocol.UDP)
            and state == State.NOT_EST
        ):
            return True
        return False

    def is_info_needed_by_the_icmp_scan_detector_module(
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
