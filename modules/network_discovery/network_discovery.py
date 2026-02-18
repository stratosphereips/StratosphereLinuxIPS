# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from typing import List

from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.imodule import IModule
from modules.network_discovery.horizontal_portscan import HorizontalPortscan
from modules.network_discovery.vertical_portscan import VerticalPortscan
from slips_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    TimeWindow,
    Attacker,
    ThreatLevel,
    EvidenceType,
    IoCType,
    Direction,
)


class NetworkDiscovery(IModule):
    """
    A class process to find port scans
    This should be converted into a module that wakesup alone when a new alert arrives
    """

    name = "Network Discovery"
    description = "Detect Horizonal, Vertical, and DHCP Scans."
    authors = ["Sebastian Garcia", "Alya Gomaa"]

    def init(self):
        self.horizontal_ps = HorizontalPortscan(self.db)
        self.vertical_ps = VerticalPortscan(self.db)
        self.c1 = self.db.subscribe("tw_modified")
        self.c2 = self.db.subscribe("new_notice")
        self.c3 = self.db.subscribe("new_dhcp")
        self.c4 = self.db.subscribe("tw_closed")
        self.channels = {
            "tw_modified": self.c1,
            "new_notice": self.c2,
            "new_dhcp": self.c3,
            "tw_closed": self.c4,
        }
        # To make sure each evidence has more pkts than the last one
        self.cached_thresholds_per_tw = {}
        self.separator = "_"
        self.pingscan_minimum_scanned_ips = 5
        # when a client is seen requesting this minimum addresses in 1 tw,
        # slips sets dhcp scan evidence
        self.minimum_requested_addrs = 4
        self.classifier = FlowClassifier()

    def check_icmp_sweep(self, twid, flow):
        """
        Use our own Zeek scripts to detect ICMP scans.
        Threshold is defined in the scripts and it is 25 ICMP flows
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
        # dhcp_flows format is a set of requested_addr

        dhcp_flows = self.db.get_dhcp_requested_addrs(profileid, twid)

        if dhcp_flows:
            # client was seen requesting an addr before in this tw
            # was it requesting the same addr?
            if flow.requested_addr in dhcp_flows:
                # a client requesting the same addr twice isn't a scan
                return

            # it was requesting a different addr, keep track of it and its uid
            self.db.add_dhcp_requested_addr(
                profileid, twid, flow.requested_addr
            )
        else:
            # first time for this client to make a dhcp request in this tw
            self.db.add_dhcp_requested_addr(
                profileid, twid, flow.requested_addr
            )
            return

        # TODO if we are not going to use the requested addr, no need to store it
        # TODO just store the uids
        dhcp_flows = self.db.get_dhcp_requested_addrs(profileid, twid)

        # we alert every 4,8,12, etc. requested IPs
        number_of_requested_addrs = len(dhcp_flows)
        if number_of_requested_addrs % self.minimum_requested_addrs == 0:
            flow.uids = []
            self.set_evidence_dhcp_scan(
                profileid, twid, flow, number_of_requested_addrs
            )

    def cleanup_cache_dicts(self, profile_tw: List[str]):
        """
        removes closed timewindows from cache dicts to
        avoid storing useless info in mem
        """
        profile_tw: str = "_".join(profile_tw)

        for cache_dict in (
            self.cached_thresholds_per_tw,
            self.horizontal_ps.cached_thresholds_per_tw,
            self.vertical_ps.cached_thresholds_per_tw,
        ):
            new_cache = {}
            for key, threshold in cache_dict.items():
                if profile_tw in key:
                    continue
                new_cache[key] = threshold

            cache_dict.clear()
            cache_dict.update(new_cache)

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

        if msg := self.get_msg("tw_closed"):
            profileid_tw: List[str] = msg["data"].split("_")
            self.cleanup_cache_dicts(profileid_tw)
