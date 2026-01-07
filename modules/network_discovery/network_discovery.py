# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from typing import List, Dict

from modules.network_discovery.icmp_scan_ports import ICMP_SCAN_PORTS
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.imodule import IModule
from modules.network_discovery.horizontal_portscan import HorizontalPortscan
from modules.network_discovery.vertical_portscan import VerticalPortscan
from slips_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    TimeWindow,
    Victim,
    Attacker,
    Proto,
    ThreatLevel,
    EvidenceType,
    IoCType,
    Direction,
)

# TODO update the ports stored in the db in
#  is_info_needed_by_the_icmp_scan_detector_module() if changed here
ICMP_SCAN_PORT_MAP = {
    8: EvidenceType.ICMP_ADDRESS_SCAN,
    19: EvidenceType.ICMP_TIMESTAMP_SCAN,
    20: EvidenceType.ICMP_TIMESTAMP_SCAN,
    23: EvidenceType.ICMP_ADDRESS_MASK_SCAN,
    24: EvidenceType.ICMP_ADDRESS_MASK_SCAN,
}


class NetworkDiscovery(IModule):
    """
    A class process to find port scans
    This should be converted into a module that wakesup alone when a new alert arrives
    """

    name = "Network Discovery"
    description = "Detect Horizonal, Vertical, ICMP and DHCP Scans."
    authors = ["Sebastian Garcia", "Alya Gomaa"]

    def init(self):
        self.horizontal_ps = HorizontalPortscan(self.db)
        self.vertical_ps = VerticalPortscan(self.db)
        self.c1 = self.db.subscribe("tw_modified")
        self.c2 = self.db.subscribe("new_notice")
        self.c3 = self.db.subscribe("new_dhcp")
        self.channels = {
            "tw_modified": self.c1,
            "new_notice": self.c2,
            "new_dhcp": self.c3,
        }
        # We need to know that after a detection, if we receive another flow
        # that does not modify the count for the detection, we are not
        # re-detecting again only because the threshold was overcomed last time.
        self.cache_det_thresholds = {}
        self.separator = "_"
        # The minimum amount of ports to scan in vertical scan
        self.port_scan_minimum_dports = 5
        self.pingscan_minimum_pkts = 5
        self.pingscan_minimum_scanned_ips = 5
        # time in seconds to wait before alerting port scan
        self.time_to_wait_before_generating_new_alert = 25
        # when a client is seen requesting this minimum addresses in 1 tw,
        # slips sets dhcp scan evidence
        self.minimum_requested_addrs = 4
        self.classifier = FlowClassifier()

    def check_icmp_sweep(self, twid, flow):
        """
        Use our own Zeek scripts to detect ICMP scans.
        Threshold is on the scripts and it is 25 ICMP flows
        """
        scan_mapping = {
            "TimestampScan": EvidenceType.ICMP_TIMESTAMP_SCAN,
            "ICMPAddressScan": EvidenceType.ICMP_ADDRESS_SCAN,
            "AddressMaskScan": EvidenceType.ICMP_ADDRESS_MASK_SCAN,
        }

        evidence_type: EvidenceType = next(
            (scan_mapping[key] for key in scan_mapping if key in flow.note),
            False,
        )
        if not evidence_type:
            # unsupported notice type
            return

        hosts_scanned = int(flow.msg.split("on ")[1].split(" hosts")[0])
        # get the confidence from 0 to 1 based on the number of hosts scanned
        confidence = 1 / (255 - 5) * (hosts_scanned - 255) + 1
        twid = int(twid.replace("timewindow", ""))
        # this one is detected by Zeek, so we can't track the UIDs causing it
        evidence = Evidence(
            evidence_type=evidence_type,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            ),
            threat_level=ThreatLevel.MEDIUM,
            confidence=confidence,
            description=flow.msg,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=twid),
            uid=[flow.uid],
            timestamp=flow.starttime,
        )

        self.db.set_evidence(evidence)

    def _handle_icmp_scanning_several_hosts(
        self,
        profileid: ProfileID,
        twid: TimeWindow,
        attack,
        sport: int,
        amount_of_scanned_ips: int,
    ):

        # to avoid reporting so many evidence
        cache_key = f"{profileid}:{twid}:{attack}"
        prev_scanned_ips = self.cache_det_thresholds.get(cache_key, 0)
        # detect every 5, 10, 15, etc. scanned IPs
        if (
            amount_of_scanned_ips % self.pingscan_minimum_scanned_ips == 0
            and prev_scanned_ips < amount_of_scanned_ips
        ):
            attack_info: Dict[str, int]
            attack_info = self.db.get_icmp_attack_info_to_several_hosts(
                profileid, twid, sport
            )
            print(
                f"@@@@@@@@@@@@@@@@ here!!! amount_of_scanned_ips: "
                f"{amount_of_scanned_ips} {profileid} {twid}"
            )
            uids = []
            self.set_evidence_icmp_scan(
                amount_of_scanned_ips,
                attack_info["starttime"],
                int(attack_info["total_pkts_sent"]),
                profileid,
                twid,
                uids,
                attack,
            )
            self.cache_det_thresholds[cache_key] = amount_of_scanned_ips

    def check_icmp_scan(self, profileid: ProfileID, twid: TimeWindow):
        for sport in ICMP_SCAN_PORTS:
            sport: int
            # get the name of the attack that we can detect on this port
            attack: EvidenceType = ICMP_SCAN_PORT_MAP.get(sport)
            if not attack:
                return

            # get the number IPs attacked to answer:
            # are we pinging a single IP or ping scanning several IPs?
            amount_of_scanned_ips, number_of_flows = (
                self.db.get_info_about_icmp_flows_using_sport(
                    profileid, twid, sport
                )
            )
            # is the attacker pinging a single host for reachability or the
            # entire network?
            if amount_of_scanned_ips == 1:
                self._handle_icmp_scanning_one_host(profileid, twid, sport)
            elif amount_of_scanned_ips > 1:
                # this srcip is scanning several IPs (a network maybe)
                self._handle_icmp_scanning_several_hosts(
                    profileid, twid, attack, sport, amount_of_scanned_ips
                )

    def _handle_icmp_scanning_one_host(
        self, profileid: ProfileID, twid: TimeWindow, sport: int | str
    ):
        # how many flows are responsible for this attack
        attack_info = self.db.get_icmp_attack_info_to_single_host(
            profileid, twid, sport
        )
        scanned_ip = attack_info["scanned_ip"]
        pkts_sent = attack_info["pkts_sent"]

        attack = ICMP_SCAN_PORT_MAP.get(sport)
        cache_key = (
            f"{profileid}:{twid}:dstip:" f"{scanned_ip}:{sport}:{attack}"
        )
        prev_pkts = self.cache_det_thresholds.get(cache_key, 0)

        # We detect a scan every Threshold. So we detect when there
        # is 5,10,15 etc. scan to the same dstip on the same port
        # The idea is that after X dips we detect a connection.
        # And then we 'reset' the counter
        # until we see again X more.
        if (
            pkts_sent % self.pingscan_minimum_pkts == 0
            and prev_pkts < pkts_sent
        ):
            self.cache_det_thresholds[cache_key] = pkts_sent
            amount_of_scanned_ips = 1
            self.set_evidence_icmp_scan(
                amount_of_scanned_ips,
                attack_info["attack_ts"],
                pkts_sent,
                profileid,
                twid,
                [],
                attack,
                scanned_ip=scanned_ip,
            )

    def set_evidence_icmp_scan(
        self,
        number_of_scanned_ips: int,
        timestamp: str,
        pkts_sent: int,
        profileid: ProfileID,
        twid: TimeWindow,
        icmp_flows_uids: List[str],
        attack: EvidenceType,
        scanned_ip: str = False,
    ):
        confidence = utils.calculate_confidence(pkts_sent)
        threat_level = ThreatLevel.MEDIUM
        srcip = profileid.ip

        victim = None
        if number_of_scanned_ips == 1:
            description = (
                f"ICMP scanning {scanned_ip} ICMP scan type: {attack}. "
                f"Total packets sent: {pkts_sent}. "
                f"Confidence: {confidence}. by Slips"
            )
            if scanned_ip:
                victim = Victim(
                    value=scanned_ip,
                    direction=Direction.DST,
                    ioc_type=IoCType.IP,
                )
        else:
            # not Victim here bc there's not a single victim, there are many
            description = (
                f"ICMP scanning {number_of_scanned_ips} different IPs."
                f" ICMP scan type: {attack}. "
                f"Total packets sent: {pkts_sent}. "
                f"Confidence: {confidence}. by Slips"
            )

        attacker = Attacker(
            direction=Direction.SRC, ioc_type=IoCType.IP, value=srcip
        )

        evidence = Evidence(
            evidence_type=attack,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=profileid,
            timewindow=twid,
            uid=icmp_flows_uids,
            timestamp=timestamp,
            proto=Proto("icmp"),
            victim=victim,
        )

        self.db.set_evidence(evidence)

    def set_evidence_dhcp_scan(
        self, profileid, twid, flow, number_of_requested_addrs
    ):
        srcip = profileid.split("_")[-1]
        confidence = 0.8
        description = (
            f"Performing a DHCP scan by requesting "
            f"{number_of_requested_addrs} different IP addresses. "
            f"Confidence: {confidence}. by Slips"
        )
        twid_number = int(twid.replace("timewindow", ""))
        evidence = Evidence(
            evidence_type=EvidenceType.DHCP_SCAN,
            attacker=Attacker(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=srcip
            ),
            threat_level=ThreatLevel.MEDIUM,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=srcip),
            timewindow=TimeWindow(number=twid_number),
            uid=flow.uids,
            timestamp=flow.starttime,
        )

        self.db.set_evidence(evidence)

    def check_dhcp_scan(self, profileid, twid, flow):
        """
        Detects DHCP scans, when a client requests 4+ different IPs in the
        same tw
        """
        if not flow.requested_addr:
            # we are only interested in DHCPREQUEST flows,
            # where a client is requesting an IP
            return
        # dhcp_flows format is
        #       { requested_addr: uid,
        #         requested_addr2: uid2... }

        dhcp_flows: dict = self.db.get_dhcp_flows(profileid, twid)

        if dhcp_flows:
            # client was seen requesting an addr before in this tw
            # was it requesting the same addr?
            if flow.requested_addr in dhcp_flows:
                # a client requesting the same addr twice isn't a scan
                return

            # it was requesting a different addr, keep track of it and its uid
            self.db.set_dhcp_flow(
                profileid, twid, flow.requested_addr, flow.uids
            )
        else:
            # first time for this client to make a dhcp request in this tw
            self.db.set_dhcp_flow(
                profileid, twid, flow.requested_addr, flow.uids
            )
            return

        # TODO if we are not going to use the requested addr, no need to store it
        # TODO just store the uids
        dhcp_flows: dict = self.db.get_dhcp_flows(profileid, twid)

        # we alert every 4,8,12, etc. requested IPs
        number_of_requested_addrs = len(dhcp_flows)
        if number_of_requested_addrs % self.minimum_requested_addrs == 0:
            # get the uids of all the flows where this client
            # was requesting an addr in this tw

            for uids_list in dhcp_flows.values():
                flow.uids.append(uids_list[0])

            self.set_evidence_dhcp_scan(
                profileid, twid, flow, number_of_requested_addrs
            )

    def pre_main(self):
        utils.drop_root_privs_permanently()

    def main(self):
        if msg := self.get_msg("tw_modified"):
            msg = json.loads(msg["data"])
            profileid = msg["profileid"]
            twid = msg["twid"]

            self.print(
                f"Running the detection of portscans in profile "
                f"{profileid} TW {twid}",
                3,
                0,
            )
            try:
                profileid = ProfileID(ip=profileid.split("_")[-1])
            except ValueError:
                return

            twid = TimeWindow(number=int(twid.replace("timewindow", "")))
            # For port scan detection, we will measure different things:

            # 1. Vertical port scan:
            # (single IP being scanned for multiple ports)
            # - 1 srcip sends not established flows to > 3 dst ports in the
            # same dst ip. Any number of packets
            # 2. Horizontal port scan:
            #  (scan against a group of IPs for a single port)
            # - 1 srcip sends not established flows to the same dst ports in
            # > 3 dst ip.
            # 3. Too many connections???:
            # - 1 srcip sends not established flows to the same dst ports,
            # > 3 pkts, to the same dst ip
            # 4. Slow port scan. Same as the others but distributed in
            # multiple time windows

            # Remember that in slips all these port scans can happen
            # for traffic going IN to an IP or going OUT from the IP.

            self.horizontal_ps.check(profileid, twid)
            self.vertical_ps.check(profileid, twid)
            self.check_icmp_scan(profileid, twid)

        if msg := self.get_msg("new_notice"):
            data = json.loads(msg["data"])
            twid = data["twid"]
            flow = self.classifier.convert_to_flow_obj(data["flow"])
            self.check_icmp_sweep(twid, flow)

        if msg := self.get_msg("new_dhcp"):
            msg = json.loads(msg["data"])
            profileid = msg["profileid"]
            twid = msg["twid"]
            flow = self.classifier.convert_to_flow_obj(msg["flow"])
            self.check_dhcp_scan(profileid, twid, flow)
