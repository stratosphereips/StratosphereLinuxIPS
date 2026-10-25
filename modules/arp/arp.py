# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import ipaddress
import os
import time
import sqlite3
import math
from collections import OrderedDict
from pathlib import Path
from typing import Any

from modules.arp.filter import ARPEvidenceFilter
from modules.arp.scan_detector import ARPFinding, ARPScanDetector, unicast_mac
from modules.arp.scan_history import ARPHistoryStore
from modules.arp.scan_settings import ARPScanSettings
from modules.supported_module_names import Modules
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.ips import BROADCAST_MAC, IPV4_ANY, NULL_MAC
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.imodule import IModule
from slips_files.common.input_type import InputType
from slips_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    TimeWindow,
    Victim,
    Attacker,
    ThreatLevel,
    EvidenceType,
    IoCType,
    Direction,
)


class ARP(IModule):

    name = Modules.ARP.value
    description = "Detects ARP attacks"
    authors = ["Alya Gomaa"]

    def init(self) -> None:
        """Initialize bounded packet-time analysis without opening a checkpoint."""
        self.read_configuration()
        self.classifier = FlowClassifier()
        self.scan_detector = ARPScanDetector(self.scan_settings)
        self.history_store: ARPHistoryStore | None = None
        self.live = (
            self.db.get_input_type() == InputType.INTERFACE
            or getattr(self.args, "growing", False) is True
        )
        interfaces = getattr(self.args, "interface", [])
        self.scan_interfaces = (
            [interfaces]
            if isinstance(interfaces, str)
            else (
                list(interfaces)
                if isinstance(interfaces, (list, tuple))
                else []
            )
        )
        self.scan_networks: OrderedDict[str, tuple[float, dict]] = (
            OrderedDict()
        )
        self.scan_run_scope = f"run:{self.parent_output_dir}:{self.ppid}"
        self.next_scan_flush = self.next_scan_checkpoint = (
            self.next_scan_warning
        ) = 0.0
        self.last_arp_received = time.monotonic()
        self.delete_arp_periodically = (
            self.delete_zeek_files and not self.store_zeek_files_copy
        )
        self.arp_log_creation_time = (
            time.time() if self.delete_arp_periodically else 0
        )
        self.period_before_deleting = (
            3600 if self.delete_arp_periodically else 0
        )
        self.is_zeek_running = self.is_running_zeek()
        self.evidence_filter = ARPEvidenceFilter(self.conf, self.args, self.db)

    def subscribe_to_channels(self) -> None:
        """Consume ARP and successful connection context without a timer thread."""
        self.channels = {
            name: self.db.subscribe(name) for name in ("new_arp", "new_flow")
        }

    def read_configuration(self):
        conf = ConfigParser()
        self.home_network = conf.home_network_ranges
        self.delete_zeek_files = conf.delete_zeek_files()
        if self.delete_zeek_files:
            self.print(
                "Warning: Slips will delete Zeek log files after "
                "the analysis is done. and will delete arp.log every 1h. "
                "You can modify this by changing "
                "delete_zeek_files in the config file."
            )
        self.store_zeek_files_copy = conf.store_zeek_files_copy()
        self.scan_settings = ARPScanSettings.from_config(conf)

    def is_running_zeek(self) -> bool:
        return (
            self.db.get_input_type() == InputType.PCAP
            or self.db.is_running_non_stop()
        )

    def _scan_context(
        self, interface: str, timestamp: float
    ) -> tuple[str, str, str]:
        """Resolve packet-time network identity using a bounded five-second cache.

        Parameters:
            interface: Captured interface, including legacy default names.
            timestamp: Packet timestamp used to handle delayed records.

        Returns:
            Network scope, local subnet and gateway IP. Unverified networks and
            imported logs use an isolated run/interface scope.
        """
        if interface == "default" and len(self.scan_interfaces) == 1:
            interface = self.scan_interfaces[0]
        fallback = f"{self.scan_run_scope}:{interface}"
        if not self.live:
            return fallback, "", ""
        now = time.monotonic()
        cached = self.scan_networks.get(interface)
        if cached is None or now >= cached[0]:
            state = self.db.get_network_state(interface)
            state = state if isinstance(state, dict) else {}
            self.scan_networks[interface] = now + 5, state
            self.scan_networks.move_to_end(interface)
            if len(self.scan_networks) > 16:
                self.scan_networks.popitem(last=False)
        else:
            state = cached[1]
        if timestamp < float(state.get("changed_at") or 0):
            state = max(
                (
                    item
                    for item in state.get("history", [])
                    if isinstance(item, dict)
                    and float(item.get("changed_at") or 0) <= timestamp
                ),
                key=lambda item: float(item.get("changed_at") or 0),
                default={},
            )
        gateway_mac = unicast_mac(state.get("gateway_mac"))
        network = str(state.get("local_network") or "")
        fallback = f"{fallback}:epoch:{state.get('changed_at') or 0}"
        scope = (
            f"gateway:{gateway_mac}:{network}"
            if gateway_mac and network
            else fallback
        )
        return scope, network, str(state.get("gateway_ip") or "")

    def check_arp_scan(self, profileid: str, twid: str, flow: Any) -> bool:
        """Evaluate requests using history from before the current burst.

        Parameters:
            profileid: Requesting host profile.
            twid: Slips time window used for attribution only.
            flow: Parsed ARP record.

        Returns:
            Whether this call emitted scan or informational discovery evidence.
        """
        try:
            timestamp = float(flow.starttime)
        except (ValueError, TypeError):
            return False
        if not math.isfinite(timestamp) or timestamp < 0:
            return False
        self.scan_detector.clock = max(self.scan_detector.clock, timestamp)
        self.last_arp_received = time.monotonic()
        if profileid.removeprefix("profile_") != flow.saddr:
            return False
        scope, network, gateway = self._scan_context(flow.interface, timestamp)
        if gateway and gateway == flow.saddr:
            return False
        findings = self.scan_detector.request(
            flow, scope, profileid, twid, network
        )
        self.last_arp_received = time.monotonic()
        for finding in findings:
            self.set_evidence_arp_scan(finding)
        return bool(findings)

    def set_evidence_arp_scan(self, finding: ARPFinding) -> None:
        """Persist the actual decision, counts and representative triggering flows.

        Parameters:
            finding: Explained scan or broad neighbour-discovery observation.
        """
        source = finding.profileid.removeprefix("profile_")
        self.set_evidence(
            Evidence(
                evidence_type=(
                    EvidenceType.ARP_SCAN
                    if finding.scan
                    else EvidenceType.ARP_DISCOVERY
                ),
                attacker=Attacker(
                    direction=Direction.SRC, ioc_type=IoCType.IP, value=source
                ),
                threat_level=(
                    ThreatLevel.LOW if finding.scan else ThreatLevel.INFO
                ),
                confidence=finding.confidence,
                description=finding.description,
                profile=ProfileID(ip=source),
                timewindow=TimeWindow(
                    number=int(finding.twid.replace("timewindow", ""))
                ),
                uid=list(finding.uids),
                timestamp=finding.timestamp,
                interface=finding.interface,
                detection_details={"arp_scan": finding.facts},
            )
        )

    def _scan_maintenance(self, force: bool = False) -> None:
        """Finish quiet candidates and periodically checkpoint outside profiling.

        Parameters:
            force: Flush immediately while the module releases resources.
        """
        now = time.monotonic()
        if force or now >= self.next_scan_flush:
            self.next_scan_flush = now + 1
            timestamp = self.scan_detector.clock + max(
                0, now - self.last_arp_received
            )
            if force:
                timestamp += self.scan_settings.scan_context_wait_seconds
            for finding in self.scan_detector.flush(timestamp):
                self.set_evidence_arp_scan(finding)
        if self.history_store is not None and (
            force or now >= self.next_scan_checkpoint
        ):
            self.next_scan_checkpoint = (
                now + self.scan_settings.scan_checkpoint_seconds
            )
            try:
                self.history_store.save(
                    self.scan_detector,
                    time.time() if self.live else self.scan_detector.clock,
                )
            except sqlite3.OperationalError as error:
                code = getattr(error, "sqlite_errorcode", None)
                if not (code is not None and code & 255 in (5, 6)) and str(
                    error
                ).lower() not in {"database is locked", "database is busy"}:
                    raise
                if now >= self.next_scan_warning:
                    self.print(
                        "ARP contact checkpoint busy; will retry without blocking flow processing.",
                        0,
                        1,
                    )
                    self.next_scan_warning = now + 60
        if self.scan_detector.evictions and now >= self.next_scan_warning:
            self.print(
                "ARP history/window capacity reached; old context was discarded. Review arp.scan_max_* limits if unfamiliar-target findings increase.",
                0,
                1,
            )
            self.next_scan_warning = now + 60

    def check_dstip_outside_localnet(self, twid, flow):
        """Function to setEvidence when daddr is outside the local network"""

        if IPV4_ANY in flow.saddr or IPV4_ANY in flow.daddr:
            # this is the case of arp probe, not an
            # arp outside of local network, don't alert
            return False

        daddr_as_obj = ipaddress.IPv4Address(flow.daddr)
        if daddr_as_obj.is_multicast or daddr_as_obj.is_link_local:
            # The arp to ‘outside’ the network should
            # not detect multicast or link-local addresses.
            return False

        for network in self.home_network:
            if daddr_as_obj in network:
                # IP is in this local network, don't alert
                return False

        # to prevent arp alerts from one IP to itself
        first_octet = flow.saddr.split(".")[0]
        if not flow.daddr.startswith(first_octet):
            # comes here if the IP isn't in any of the local networks
            confidence: float = 0.6
            threat_level: ThreatLevel = ThreatLevel.LOW
            description: str = (
                f"sending ARP packet to a destination "
                f"address outside of local network: {flow.daddr}. "
            )

            attacker: Attacker = Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            )
            victim = Victim(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=flow.daddr,
            )

            evidence: Evidence = Evidence(
                evidence_type=EvidenceType.ARP_OUTSIDE_LOCALNET,
                attacker=attacker,
                threat_level=threat_level,
                confidence=confidence,
                description=description,
                profile=ProfileID(ip=flow.saddr),
                timewindow=TimeWindow(
                    number=int(twid.replace("timewindow", ""))
                ),
                uid=[flow.uid],
                timestamp=flow.starttime,
                victim=victim,
            )
            # no need to go through the arp filter here, so use
            # self.db.set_evidence instead of self.set_evidence
            # because the filter is only to filter attacks that can be done
            # using the arp_poisoner, but this one isnt done there.
            self.db.set_evidence(evidence)
            return True

        return False

    def detect_unsolicited_arp(self, twid: str, flow):
        """
        Unsolicited arp is used to update the neighbours'
        arp caches but can also be used in arp spoofing
        """
        if (
            flow.dmac == BROADCAST_MAC
            and flow.dst_hw == BROADCAST_MAC
            and flow.smac != NULL_MAC
            and flow.src_hw != NULL_MAC
        ):
            # We're sure this is unsolicited arp
            # it may be arp spoofing
            confidence: float = 0.8
            threat_level: ThreatLevel = ThreatLevel.LOW
            description: str = "broadcasting unsolicited ARP"

            attacker = Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            )

            evidence: Evidence = Evidence(
                evidence_type=EvidenceType.UNSOLICITED_ARP,
                attacker=attacker,
                threat_level=threat_level,
                confidence=confidence,
                description=description,
                profile=ProfileID(ip=flow.saddr),
                timewindow=TimeWindow(
                    number=int(twid.replace("timewindow", ""))
                ),
                uid=[flow.uid],
                timestamp=flow.starttime,
            )

            self.set_evidence(evidence)
            return True

    def detect_mitm_arp_attack(self, twid: str, flow):
        """
        Detects when a MAC with IP A, is trying to tell others that
        now that MAC is also for IP B (arp cache attack)
        """
        # Todo in rare cases, the vendor and IP of this mac is known AFTER
        #  returning from this function so detection is missed

        # to test this add these 2 flows to arp.log
        # {"ts":1636305825.755132,"operation":"reply",
        # "src_mac":"2e:a4:18:f8:3d:02", "dst_mac":"ff:ff:ff:ff:ff:ff",
        # "orig_h":"172.20.7.40","resp_h":"172.20.7.40",
        # "orig_hw":"2e:a4:18:f8:3d:02", "resp_hw":"00:00:00:00:00:00"}
        # {"ts":1636305825.755132,"operation":"reply",
        # "src_mac":"2e:a4:18:f8:3d:02", "dst_mac":"ff:ff:ff:ff:ff:ff",
        # "orig_h":"172.20.7.41","resp_h":"172.20.7.41",
        # "orig_hw":"2e:a4:18:f8:3d:02", "resp_hw":"00:00:00:00:00:00"}

        # todo will we get FPs when an ip changes?
        # todo what if the ip of the attacker came to us
        #  first and we stored it in the db?
        #  the original IP of this src mac is now the IP of the attacker?

        # get the original IP of the src mac from the database
        original_ip: str = self.db.get_ip_of_mac(flow.smac)
        if original_ip is None:
            return

        # original_IP is a serialized list
        original_ip: str = json.loads(original_ip)[0]
        original_ip = original_ip.replace("profile_", "")

        # is this saddr trying to tell everyone that this
        # it owns this flow.smac even though we know this
        # src_mac is associated
        # with another IP (original_IP)?
        if flow.saddr != original_ip:
            # From our db we know that:
            # original_IP has flow.smac
            # now saddr has flow.smac and saddr isn't the same as original_IP
            # so this is either a MITM arp attack or the IP
            # address of this flow.smac has simply changed
            # todo how to find out which one is it??

            confidence: float = 0.2  # low confidence for now
            threat_level: ThreatLevel = ThreatLevel.CRITICAL

            attackers_ip = original_ip
            victims_ip = flow.saddr

            gateway_ip = self.db.get_gateway_ip(flow.interface)
            gateway_mac = self.db.get_gateway_mac(flow.interface)

            if flow.smac == gateway_mac:
                src_mac = f"of the gateway {flow.smac}"
            else:
                src_mac = flow.smac

            original_ip = f"IP {original_ip}"
            if original_ip == gateway_ip:
                original_ip = f"the gateway IP {original_ip}"

            attacker: Attacker = Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=attackers_ip,
            )

            victim = Victim(
                direction=Direction.DST,  #  TODO not really dst
                ioc_type=IoCType.IP,
                value=victims_ip,
            )
            if flow.saddr == gateway_ip:
                saddr = f"The gateway {flow.saddr}"
            else:
                saddr = flow.saddr
            description = (
                f"{attackers_ip} performing a MITM ARP attack. "
                f"The MAC {src_mac}, now belonging to "
                f"{saddr}, was seen before for {original_ip}."
            )

            evidence: Evidence = Evidence(
                evidence_type=EvidenceType.MITM_ARP_ATTACK,
                attacker=attacker,
                threat_level=threat_level,
                confidence=confidence,
                description=description,
                profile=ProfileID(ip=attackers_ip),
                timewindow=TimeWindow(
                    number=int(twid.replace("timewindow", ""))
                ),
                uid=[flow.uid],
                timestamp=flow.starttime,
                victim=victim,
            )

            self.set_evidence(evidence)
            return True

    def check_if_gratutitous_arp(self, flow):
        """
        Check if an ARP packet is gratuitous

        The Gratuitous arp is sent as a broadcast, as a way for a
        node to announce or update
        its IP to MAC mapping to the entire network.
        Gratuitous ARP shouldn't be marked as an arp scan
        Check https://www.practicalnetworking.net/series/arp/gratuitous-arp/
        dst_mac is the real MAC used to deliver the packet
        src_mac is the real MAC used to deliver the packet
        dst_hw is the MAC in the headers of the ARP packet
        src_hw is the MAC in the headers of the ARP packet
        saddr is the IP in the headers of the ARP packet
        daddr is the IP in the headers of the ARP packet

        Gratuitous ARP can be used for (1) Updating ARP Mapping,
        (2) Announcing a Node’s Existence,
        (3) Redundancy, (4) MITM. Which is similar to an
        'unrequested' load balancing
         The saddr and daddr are the ones being avertised.
         The supposed purpose of the Gratuitous ARP
        """
        # It should be a reply
        # The dst_mac should be ff:ff:ff:ff:ff:ff or 00:00:00:00:00:00
        return "reply" in flow.operation and flow.dst_hw in [
            BROADCAST_MAC,
            NULL_MAC,
        ]

    def clear_arp_logfile(self):
        if not self.delete_arp_periodically:
            return

        if not self.is_zeek_running:
            # we only clear arp.log if it's growing, aka zeek is running in
            # real time and generating logs constantly. like
            # interfaces/pcaps and growing zeek dirs
            return

        if (
            time.time()
            >= self.arp_log_creation_time + self.period_before_deleting
        ):
            arp_log_file_path = os.path.join(
                self.db.get_output_dir(), "zeek_files/arp.log"
            )
            open(arp_log_file_path, "w").close()
            # update ts of the new arp.log
            self.arp_log_creation_time = time.time()

    def set_evidence(self, evidence: Evidence):
        """the goal of this function is to discard evidence of other slips
        peers doing arp scans because that's slips attacking back attackers"""
        if self.evidence_filter.should_discard_evidence(evidence.profile.ip):
            return
        self.db.set_evidence(evidence)

    def pre_main(self) -> None:
        """Restore live contacts while keeping imported captures independent."""
        utils.drop_root_privs_permanently()
        root = (
            Path(self.conf.permanent_dir())
            if self.live
            else Path(self.parent_output_dir)
        )
        self.history_store = ARPHistoryStore(
            root / self.name / "contacts.sqlite"
        )
        if self.live:
            self.history_store.load(self.scan_detector, time.time())
        self.print(
            f"ARP scan context restored: {len(self.scan_detector.contacts)} contacts; request window {self.scan_settings.scan_window_seconds:g}s.",
            1,
            0,
        )

    def main(self) -> None:
        """Drain bounded message batches, then run nonblocking maintenance."""
        self.clear_arp_logfile()
        for _ in range(32):
            msg = self.get_msg("new_flow")
            if not msg:
                break
            try:
                payload = json.loads(msg["data"])
                if not isinstance(payload, dict):
                    continue
                flow = payload.get("flow")
                if (
                    not isinstance(flow, dict)
                    or payload.get("profileid")
                    != f"profile_{flow.get('saddr')}"
                ):
                    continue
                scope, network, _ = self._scan_context(
                    str(flow.get("interface") or "default"),
                    float(flow["starttime"]),
                )
                self.scan_detector.observe_connection(flow, scope, network)
            except (KeyError, ValueError, TypeError):
                continue
        for _ in range(32):
            msg = self.get_msg("new_arp")
            if not msg:
                break
            try:
                payload = json.loads(msg["data"])
                if not isinstance(payload, dict) or not isinstance(
                    payload.get("flow"), dict
                ):
                    continue
                flow = self.classifier.convert_to_flow_obj(payload["flow"])
                self.last_arp_received = time.monotonic()
                if "request" in flow.operation:
                    self.check_arp_scan(
                        payload["profileid"], payload["twid"], flow
                    )
                    self.check_dstip_outside_localnet(payload["twid"], flow)
                elif "reply" in flow.operation:
                    scope, _, _ = self._scan_context(
                        flow.interface, float(flow.starttime)
                    )
                    self.scan_detector.reply(flow, scope)
                    if self.check_if_gratutitous_arp(flow):
                        self.detect_mitm_arp_attack(payload["twid"], flow)
                    self.detect_unsolicited_arp(payload["twid"], flow)
            except (KeyError, ValueError, TypeError):
                continue
        self._scan_maintenance()

    def shutdown_gracefully(self) -> None:
        """Finish pending decisions and close the module's own history writer."""
        try:
            self._scan_maintenance(force=True)
        finally:
            if self.history_store is not None:
                self.history_store.close()
                self.history_store = None
