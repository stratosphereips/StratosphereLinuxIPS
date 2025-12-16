# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import sys
import traceback
from typing import Generator, Dict, Optional

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
    KeyType,
    Request,
)


class FlowAttrHandler:
    """
    Helper class for the Redis class in database.py
    Slips splits each flow into different attributes for categorizing them,
    and for easier pattern recognition.
    This class Contains all the logic related to flows attributes and
    categorizing
    """

    name = "DB"

    def get_specific_ip_info_from_profile_tw(
        self,
        query: FlowQuery,
        requested_ip: str,
    ) -> dict:
        """
        e.g looks up
        profile_1.1.1.1_timewindow2:server:udp:est:src:ips <ip>
        """
        key = str(query)
        return self.r.hget(key, requested_ip) or {}

    def get_specific_port_info_from_profile_tw(
        self,
        query: FlowQuery,
        requested_port: int,
    ) -> Optional[int]:
        # todo make sure ports are added as ints
        key = str(query)
        return self.r.hget(key, requested_port)

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

    def convert_str_to_proto(self, proto_as_str: str) -> Protocol:
        match proto_as_str.lower():
            case "tcp":
                return Protocol.TCP
            case "udp":
                return Protocol.UDP
            case "icmp":
                return Protocol.ICMP
            case "icmp6":
                return Protocol.ICMP6
            case _:
                # match substr
                for proto in ("tcp", "udp", "icmp6", "icmp"):
                    if proto in proto_as_str.lower():
                        return self.convert_str_to_proto(proto)

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
        totbytes = int(flow.totbytes)
        if role == Role.CLIENT:
            direction = Direction.DST
            ip = flow.daddr
            port = flow.dport
            request = Request.DST_PORTS
            pkts = int(flow.spkts)
        else:
            direction = Direction.SRC
            ip = flow.saddr
            port = flow.sport
            request = Request.SRC_PORTS
            pkts = int(flow.pkts) - int(flow.spkts)

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
        ######################################################################
        query = FlowQuery(
            profileid=profileid,
            timewindow=twid,
            direction=direction,
            state=state,
            protocol=proto,
            role=role,
            key_type=KeyType.IP,
            request=None,
        )
        old_info: Dict[str, int] = self.get_specific_ip_info_from_profile_tw(
            query, ip
        )

        if old_info:
            # ip exists as a part of this tw, update the port
            query = FlowQuery(
                profileid=profileid,
                timewindow=twid,
                direction=direction,
                state=state,
                protocol=proto,
                role=role,
                key_type=KeyType.IP,
                request=request,
                ip=ip,
            )
            # check if this port already exists or not
            old_spkts: int = self.get_specific_port_info_from_profile_tw(
                query, port
            )

            if old_spkts:
                # Add to this port's pkts
                pkts = old_spkts + pkts
        else:
            # First time seeing this ip
            ip_data = {
                "totalflows": 1,
                "totalpkt": pkts,
                "totalbytes": totbytes,
                "stime": flow.starttime,
            }
            query = FlowQuery(
                profileid=profileid,
                timewindow=twid,
                direction=direction,
                state=state,
                protocol=proto,
                role=role,
                key_type=KeyType.IP,
                request=None,
            )
            key = str(query)
            self.r.hset(key, ip, json.dumps(ip_data))

        # update the port info
        query = FlowQuery(
            profileid=profileid,
            timewindow=twid,
            direction=direction,
            state=state,
            protocol=proto,
            role=role,
            key_type=KeyType.IP,
            request=request,
            ip=ip,
        )
        key = str(query)
        self.r.hset(key, port, pkts)
        return True

    def add_port(
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
        if self._was_flow_flipped(flow):
            return False

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

        # Choose which port to use based on if we were asked Dst or Src
        port = str(sport) if port_type == "Src" else str(dport)

        # If we are the Client, we want to store the dstips only
        # If we are the Server, we want to store the srcips only
        ip_key = "srcips" if role == "Server" else "dstips"

        # Get the state. Established, NotEstablished
        summary_state = self.get_final_state_from_flags(state, pkts)

        old_profileid_twid_data = self.get_data_from_profile_tw(
            profileid, twid, port_type, summary_state, proto, role, "Ports"
        )

        try:
            # we already have info about this dport, update it
            port_data = old_profileid_twid_data[port]
            port_data["totalflows"] += 1
            port_data["totalpkt"] += pkts
            port_data["totalbytes"] += totbytes

            # if there's a conn from this ip on this port, update the pkts
            # of this conn
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
        self.mark_profile_tw_as_modified(profileid, twid, starttime)

        if key_name == "DstPortsClientTCPNot Established":
            # this key is used in horizontal ps module only
            # to avoid unnecessary storing and filtering of data, we store
            # only unresolved non multicast non broadcast ips.
            # if this key is ever needed for another module, we'll need to
            # workaround this
            ip_resolved = self.get_dns_resolution(ip)
            if ip_resolved or self._is_multicast_or_broadcast(ip):
                return

        self.r.hset(hash_key, key_name, str(data))

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
