# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import sys
import traceback
from typing import Generator

from slips_files.core.structures.evidence import (
    ProfileID,
    TimeWindow,
)
from slips_files.core.structures.flow_attributes import FlowQuery


class FlowAttrHandler:
    """
    Helper class for the Redis class in database.py
    Slips splits each flow into different attributes for categorizing them,
    and for easier pattern recognition.
    This class Contains all the logic related to flows attributes and
    categorizing
    """

    name = "DB"

    def _construct_query_key(
        self, profileid: ProfileID, twid: TimeWindow, query: FlowQuery
    ) -> str:
        """
        All queries done by this class (insertions and lookups)
        will be using the same format of key

        the format of the key in redis is
        profile_{ip}_{tw}:{role}:{proto}:{state}:{dir}:{type}:{request}
        e.g
        profile_1.1.1.1_timewindow2:client:tcp:not_est:dst:ports:dst_ips
        or
        profile_1.1.1.1_timewindow2:server:udp:est:src:ips:dst_ports
        """
        role = query.role.name.lower()
        protocol = query.protocol.name.lower()
        state = query.state.name.lower()
        direction = query.direction.name.lower()
        key_type = query.type_data.name.lower()  # PORT or IP
        # request example:
        # if key_type=PORT: request will be IP
        # if key_type=IP: request will be PORT
        request = query.request.name.lower()

        key = (
            f"{str(profileid)}_{str(twid)}"
            f":{role}:{protocol}:{state}:{direction}:{key_type}:{request}"
        )
        return key

    def get_data_from_profile_tw(
        self,
        profileid: ProfileID,
        twid: TimeWindow,
        query: FlowQuery,
    ) -> Generator:
        """
        Retrieves information for a given profile and time window
        based on flow characteristics (role, protocol, state, direction).


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
            key: str = self._construct_query_key(profileid, twid, query)
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

    def add_ips(self, profileid, twid, flow, role):
        """
        Function to add information about an IP address
        The flow can go out of the IP (we are acting as Client) or into the IP
        (we are acting as Server)
        ip_as_obj: IP to add. It can be a dstIP or srcIP depending on the role
        role: 'Client' or 'Server'
        This function does two things:
            1- Add the ip to this tw in this profile, counting how many times
            it was contacted, and storing it in the key 'DstIPs' or 'SrcIPs'
            in the hash of the profile
            2- Use the ip as a key to count how many times that IP was
            contacted on each port. We store it like this because its the
               pefect structure to detect vertical port scans later on
            3- Check if this IP has any detection in the threat intelligence
            module. The information is added by the module directly in the DB.
        """

        uid = flow.uid
        starttime = str(flow.starttime)
        ip = flow.daddr if role == "Client" else flow.saddr

        """
        Depending if the traffic is going out or not, we are Client or Server
        Client role means:
            The profile corresponds to the src ip that received this flow
            The dstip is here the one receiving data from your profile
            So check the dst ip
        Server role means:
            The profile corresponds to the dst ip that received this flow
            The srcip is here the one sending data to your profile
            So check the src ip
        """
        direction = "Dst" if role == "Client" else "Src"

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
        summary_state = self.get_final_state_from_flags(flow.state, flow.pkts)
        key_name = f"{direction}IPs{role}{flow.proto.upper()}{summary_state}"
        # Get the previous data about this key
        old_profileid_twid_data = self.get_data_from_profile_tw(
            profileid,
            twid,
            direction,
            summary_state,
            flow.proto,
            role,
            "IPs",
        )
        profileid_twid_data: dict = self.update_ip_info(
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
        self.r.hset(
            f"{profileid}{self.separator}{twid}",
            key_name,
            json.dumps(profileid_twid_data),
        )
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

    def update_ip_info(
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
        #  Updates how many times each individual DstPort was contacted,
        the total flows sent by this ip and their uids,
        the total packets sent by this ip,
        and total bytes sent by this ip
        """
        dport = str(dport)
        spkts = int(spkts)
        pkts = int(pkts)
        totbytes = int(totbytes)
        if ip in old_profileid_twid_data:
            # update info about an existing ip
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
            # First time seeing this ip
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
