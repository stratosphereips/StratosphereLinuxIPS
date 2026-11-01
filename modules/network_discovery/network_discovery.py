# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import time
import math
import ipaddress
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import List
from slips_files.common.scan_progress import ConfirmedScan, scan_confidence

from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.imodule import IModule
from modules.network_discovery.horizontal_portscan import HorizontalPortscan
from modules.network_discovery.vertical_portscan import VerticalPortscan
from modules.network_discovery.scan_settings import ScanSettings
from modules.supported_module_names import Modules
from slips_files.common.input_type import InputType
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


@dataclass(slots=True)
class AddressRequests:
    """Bound DHCP address observations until a compact counter replaces them."""

    started: float
    last: float
    addresses: OrderedDict[str, str] = field(default_factory=OrderedDict)
    confidence: float = 0
    progress: ConfirmedScan | None = None


class NetworkDiscovery(IModule):
    """
    A class process to find port scans
    This should be converted into a module that wakesup alone when a new alert arrives
    """

    name = Modules.NETWORK_DISCOVERY.value
    description = "Detects Horizonal, Vertical, and DHCP Scans."
    authors = ["Sebastian Garcia", "Alya Gomaa"]

    def init(self) -> None:
        """Initialize bounded horizontal analysis and the existing scan checks."""
        self.horizontal_ps = HorizontalPortscan(
            self.db,
            ScanSettings.from_config(self.conf),
            live=self.db.get_input_type() == InputType.INTERFACE
            or bool(self.args.growing),
            interfaces=(
                (self.args.interface,)
                if isinstance(self.args.interface, str)
                else tuple(self.args.interface or [])
            ),
        )
        self.vertical_ps = VerticalPortscan(
            self.db, self.horizontal_ps.settings, self.horizontal_ps.scope
        )
        self.horizontal_capacity_reported = 0
        self.horizontal_next_warning = 0.0
        self.vertical_capacity_reported = 0
        self.vertical_next_warning = 0.0
        # To make sure each evidence has more pkts than the last one
        self.cached_thresholds_per_tw = {}
        self.separator = "_"
        self.pingscan_minimum_scanned_ips = 5
        # when a client is seen requesting this minimum addresses in 1 tw,
        # slips sets dhcp scan evidence
        self.minimum_requested_addrs = (
            self.horizontal_ps.settings.dhcp_min_addresses
        )
        self.dhcp_groups: OrderedDict[tuple, AddressRequests] = OrderedDict()
        self.notice_groups: OrderedDict[tuple, tuple] = OrderedDict()
        self.classifier = FlowClassifier()

    def subscribe_to_channels(self):
        self.c1 = self.db.subscribe("new_flow")
        self.c2 = self.db.subscribe("new_notice")
        self.c3 = self.db.subscribe("new_dhcp")
        self.c4 = self.db.subscribe("tw_closed")
        self.channels = {
            "new_flow": self.c1,
            "new_notice": self.c2,
            "new_dhcp": self.c3,
            "tw_closed": self.c4,
        }

    def check_icmp_sweep(self, twid: str, flow: object) -> None:
        """Report Zeek's distinct-host counts at confidence/growth milestones.

        Parameters:
            twid: Evidence attribution time window.
            flow: Parsed scan notice containing Zeek's observed host count.
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

        try:
            hosts_scanned = int(flow.msg.split("on ")[1].split(" hosts")[0])
            ts = float(flow.starttime)
        except (ValueError, TypeError, IndexError):
            return
        if (
            hosts_scanned < self.pingscan_minimum_scanned_ips
            or not math.isfinite(ts)
            or ts < 0
        ):
            return
        # get the confidence from 0 to 1 based on the number of hosts scanned
        confidence = scan_confidence(
            0.65, hosts_scanned, self.pingscan_minimum_scanned_ips
        )
        settings = self.horizontal_ps.settings
        key = (
            getattr(flow, "interface", "default"),
            flow.saddr,
            evidence_type,
        )
        previous = self.notice_groups.get(key)
        if (
            previous
            and ts - previous[0] < settings.other_scan_quiet_seconds
            and hosts_scanned >= previous[2]
        ):
            next_count = 10 ** (int(math.log10(max(1, previous[2]))) + 1)
            if confidence <= previous[1] and hosts_scanned < next_count:
                self.notice_groups[key] = (
                    max(ts, previous[0]),
                    previous[1],
                    previous[2],
                )
                self.notice_groups.move_to_end(key)
                return
        self.notice_groups[key] = (ts, confidence, hosts_scanned)
        self.notice_groups.move_to_end(key)
        while len(self.notice_groups) > settings.other_scan_max_groups:
            self.notice_groups.popitem(last=False)
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
        self,
        profileid: str,
        twid: str,
        flow: object,
        number_of_requested_addrs: int,
        confidence: float = 0.8,
        approximate: bool = False,
        uids: list[str] | None = None,
    ) -> None:
        """Store a distinct-address DHCP finding with bounded representative IDs.

        Parameters:
            profileid: Requesting client's profile.
            twid: Evidence attribution window.
            flow: Triggering DHCP record.
            number_of_requested_addrs: Exact initial or estimated ongoing count.
            confidence: Support for the observed multi-address request pattern.
            approximate: Whether compact continuation counting was used.
            uids: Sample IDs, or the triggering record's IDs when omitted.
        """
        srcip = profileid.split("_")[-1]
        description = (
            f"{'Continuing a confirmed DHCP scan: approximately ' if approximate else 'Performing a DHCP scan by requesting '}"
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
            uid=flow.uids if uids is None else uids,
            timestamp=flow.starttime,
        )

        self.db.set_evidence(evidence)

    def check_dhcp_scan(self, profileid: str, twid: str, flow: object) -> None:
        """Count requested addresses locally and compact confirmed broad requests.

        Parameters:
            profileid: Source client profile, isolated further by client MAC.
            twid: DHCP request time window.
            flow: Parsed DHCP request with its original supporting IDs.
        """
        try:
            address = ipaddress.ip_address(flow.requested_addr)
            ts = float(flow.starttime)
            uid = str(flow.uids[0])
            if (
                not math.isfinite(ts)
                or ts < 0
                or address.is_multicast
                or address.is_unspecified
                or str(address) == "255.255.255.255"
            ):
                return
        except (ValueError, TypeError, IndexError):
            return
        settings = self.horizontal_ps.settings
        key = (
            getattr(flow, "interface", "default"),
            profileid,
            getattr(flow, "smac", ""),
            twid,
        )
        group = self.dhcp_groups.get(key)
        if (
            group is None
            or ts - group.last >= settings.other_scan_quiet_seconds
        ):
            group = AddressRequests(ts, ts)
            self.dhcp_groups[key] = group
        if ts < group.started:
            return
        group.last = max(group.last, ts)
        self.dhcp_groups.move_to_end(key)
        while len(self.dhcp_groups) > settings.other_scan_max_groups:
            self.dhcp_groups.popitem(last=False)
        if group.progress:
            group.progress.observe(str(address), uid, ts)
            if group.progress.due():
                self.set_evidence_dhcp_scan(
                    profileid,
                    twid,
                    flow,
                    group.progress.counter.estimate(),
                    1.0,
                    True,
                    list(group.progress.samples.values()),
                )
                group.progress.reported()
            return
        group.addresses[str(address)] = uid
        count = len(group.addresses)
        if count < self.minimum_requested_addrs:
            return
        confidence = scan_confidence(0.8, count, self.minimum_requested_addrs)
        if confidence <= group.confidence:
            return
        group.confidence = confidence
        self.set_evidence_dhcp_scan(
            profileid,
            twid,
            flow,
            count,
            confidence,
            False,
            list(group.addresses.values())[-20:],
        )
        if confidence == 1.0:
            group.progress = ConfirmedScan.seed(
                group.addresses.items(),
                group.started,
                ts,
                "requested addresses",
            )
            group.addresses.clear()

    def cleanup_cache_dicts(self, profile_tw: List[str]):
        """
        removes closed timewindows from cache dicts to
        avoid storing useless info in mem
        """
        profile_tw: str = "_".join(profile_tw)

        for cache_dict in (
            self.cached_thresholds_per_tw,
            self.vertical_ps.cached_thresholds_per_tw,
        ):
            new_cache = {}
            for key, threshold in cache_dict.items():
                if profile_tw in key:
                    continue
                new_cache[key] = threshold

            cache_dict.clear()
            cache_dict.update(new_cache)
        for key in tuple(self.dhcp_groups):
            if f"{key[1]}_{key[3]}" == profile_tw:
                del self.dhcp_groups[key]

    def pre_main(self):
        utils.drop_root_privs_permanently()

    def main(self) -> None:
        """Consume scan events and report bounded-context capacity pressure."""
        if msg := self.get_msg("new_flow"):
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
            self.horizontal_ps.check(
                profileid,
                twid,
                msg.get("flow"),
                msg.get("interpreted_state", ""),
            )
            evictions = self.horizontal_ps.detector.capacity_evictions
            if evictions > self.horizontal_capacity_reported:
                now = time.monotonic()
                if now >= self.horizontal_next_warning:
                    self.print(
                        f"Horizontal scan context reached its memory limit: "
                        f"{evictions} group/target evictions so far. "
                        "Older context was forgotten; see network_discovery "
                        "horizontal_max_groups and horizontal_max_targets.",
                        1,
                        0,
                    )
                    self.horizontal_capacity_reported = evictions
                    self.horizontal_next_warning = now + 60
            self.vertical_ps.check(
                profileid,
                twid,
                msg.get("flow"),
                msg.get("interpreted_state", ""),
            )

            evictions = self.vertical_ps.detector.evictions
            if (
                evictions > self.vertical_capacity_reported
                and time.monotonic() >= self.vertical_next_warning
            ):
                self.print(
                    "Vertical scan candidate memory limit reached; older multi-port context was discarded. Review network_discovery vertical_max_groups and vertical_max_ports.",
                    1,
                    0,
                )
                self.vertical_capacity_reported = evictions
                self.vertical_next_warning = time.monotonic() + 60

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
            profileid_tw: List[str] = utils.get_msg_payload(msg).split("_")
            self.cleanup_cache_dicts(profileid_tw)
