# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from slips_files.common.slips_utils import utils
from collections.abc import Callable
import time

from .scan_detector import ScanFlow
from .scan_settings import ScanSettings
from .vertical_detector import VerticalDetector
from slips_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    TimeWindow,
    Attacker,
    ThreatLevel,
    EvidenceType,
    IoCType,
    Direction,
    Victim,
    Proto,
)
from slips_files.core.structures.flow_attributes import (
    State,
    Protocol,
)


class VerticalPortscan:
    """
    Check distinct failed destination ports for the arriving flow's host.
    Report logarithmic port-count milestones to avoid repeated evidence.
    Counts are scoped to a source profile, destination and time window.
    """

    def __init__(
        self,
        db: object,
        settings: ScanSettings | None = None,
        scope: Callable | None = None,
    ) -> None:
        """Initialize bounded scan state and optional shared network resolution.

        Parameters:
            db: Existing database facade used only for evidence and P2P context.
            settings: Validated limits, or defaults.
            scope: Cached network identity resolver supplied by the module.
        """
        self.db = db
        self.settings = settings or ScanSettings()
        self.settings.validate()
        self.detector = VerticalDetector(self.settings)
        self.scope = scope
        self.p2p_tuples: set[tuple] = set()
        self.next_p2p_refresh = 0.0
        # to keep track of the max dports reported per timewindow
        self.cached_thresholds_per_tw = {}
        # The minimum amount of scanned ports to trigger an evidence
        # is increased exponentially every evidence, and is reset each timewindow
        self.minimum_dports_to_set_evidence = 5

    def set_evidence_vertical_portscan(self, evidence: dict):
        """Sets the vertical portscan evidence in the db"""
        threat_level = ThreatLevel.HIGH
        saddr = evidence["profileid"].split("_")[-1]
        confidence = utils.calculate_confidence(evidence["pkts_sent"])
        description = (
            f"new vertical port scan to IP {evidence['dstip']} from {saddr}. "
            f"Total {evidence['amount_of_dports']} "
            f"{evidence['protocol'].upper()} ports were scanned. "
            f"Total packets sent to all ports: {evidence['pkts_sent']}. "
            f"Confidence: {confidence}. by Slips"
        )

        attacker = Attacker(
            direction=Direction.SRC, ioc_type=IoCType.IP, value=saddr
        )
        victim = Victim(
            direction=Direction.DST,
            ioc_type=IoCType.IP,
            value=evidence["dstip"],
        )
        str_twid = evidence["twid"]
        twid = int(str_twid.replace("timewindow", ""))

        evidence = Evidence(
            evidence_type=EvidenceType.VERTICAL_PORT_SCAN,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid),
            uid=evidence["uid"],
            timestamp=evidence["timestamp"],
            proto=Proto(evidence["protocol"].lower()),
            victim=victim,
        )

        self.db.set_evidence(evidence)

    def check_if_enough_dports_to_trigger_an_evidence(
        self, profileid, twid, dstip, amount_of_dports: int
    ) -> bool:
        """
        checks if the dports scanned so far are enough to trigger a new
        evidence

        Returns True only when int(log10(dports)) exceeds the logarithmic
        bucket of the last reported evidence.

        The goal is to never get an evidence that's
         1 or 2 ports more than the previous one so we dont
         have so many portscan evidence
        """
        if not dstip:
            return False

        twid_identifier = f"{profileid}:{twid}:dstip:{dstip}"

        last_threshold = self.cached_thresholds_per_tw.get(twid_identifier, 0)
        current_threshold = utils.log10(amount_of_dports)

        if current_threshold > last_threshold:
            # keep track of the reported evidence's log(pkts)
            self.cached_thresholds_per_tw[twid_identifier] = current_threshold
            return True
        return False

    def should_set_evidence(
        self,
        amount_of_dports,
        profileid,
        twid,
        dstip,
    ) -> bool:
        return (
            amount_of_dports > self.minimum_dports_to_set_evidence
            and self.check_if_enough_dports_to_trigger_an_evidence(
                profileid, twid, dstip, amount_of_dports
            )
        )

    def check(
        self,
        profileid: ProfileID,
        twid: TimeWindow,
        flow: dict | None = None,
        summary_state: str = "",
    ) -> None:
        """Check the arriving flow's destination instead of rescanning all hosts.

        Parameters:
            profileid: Original source profile receiving the event.
            twid: Time window containing the failed-port counters.
            flow: Current connection metadata; omit for an explicit full check.
            summary_state: Profiler fallback for inputs without packet history.
        """
        protocols = (Protocol.TCP, Protocol.UDP)
        if flow is not None:
            self.check_flow(profileid, twid, flow, summary_state)
            return
        # When scanning an open port, the connection will appear as
        # ESTABLISHED.
        # Open ports are typically very few compared to the full port range.
        # Ignoring ESTABLISHED connections is theoretically inaccurate because
        # it misses scans hitting open ports, but in practice this is
        # negligible. Focusing on non-ESTABLISHED states significantly
        # reduces false positives while preserving the port-scan signal.
        for protocol in protocols:
            # For each dstip, see if the amount of ports
            # connections is over the threshold
            for (
                dstip,
                first_seen_ts,
            ) in (
                ((flow["daddr"], flow["starttime"]),)
                if flow is not None
                else self.db.get_dstips_with_not_established_flows(
                    profileid, twid, protocol
                )
            ):
                if not (
                    utils.are_detection_modules_interested_in_this_ip(dstip)
                ):
                    continue
                # Get the total amount of pkts sent to all
                # ports on the same host
                amount_of_dports, total_pkts_sent_to_all_dports = (
                    self.db.get_info_about_not_established_flows(
                        profileid, twid, protocol, dstip
                    )
                )
                amount_of_dports, total_pkts_sent_to_all_dports = (
                    int(amount_of_dports),
                    int(total_pkts_sent_to_all_dports),
                )

                # todo use this later
                # last_seen = self.db.get_ip_last_seen_ts(
                #     profileid, twid, dstip)

                if amount_of_dports > self.minimum_dports_to_set_evidence:
                    # to be able to avoid setting "unknown port" evidence for each
                    # scanned port from this attacker
                    self.db.mark_ip_as_port_scanner(profileid.ip, str(twid))

                if self.should_set_evidence(
                    amount_of_dports,
                    profileid,
                    twid,
                    dstip,
                ):
                    uids = self.db.get_uids_for_vertical_portscan(
                        profileid, twid, protocol, dstip
                    )
                    # ok why are we excluding p2p related flows here
                    # instead of excluding them early before storing them
                    # in the db? because the latter would require checking
                    # of p2p related flows in the hot path (the hot path is
                    # the path the flow takes from the minute it arrives to
                    # slips until its distributed to the modules)
                    # any heavy checking in this hot path causes severe
                    # latency in slips, it should be as fast as possible
                    # and has minimum checks as possible.
                    p2p_uids = utils.p2p_related_uids(uids, self.db)
                    uids = [uid for uid in uids if uid not in p2p_uids]
                    if not uids:
                        # every contributing flow is Slips's own
                        # P2P traffic, not an actual scan
                        continue
                    evidence_details = {
                        "timestamp": first_seen_ts,
                        "pkts_sent": total_pkts_sent_to_all_dports,
                        "protocol": protocol.name.lower(),
                        "profileid": str(profileid),
                        "twid": str(twid),
                        "uid": uids,
                        "amount_of_dports": amount_of_dports,
                        "dstip": dstip,
                        "state": State.NOT_EST.name.lower(),
                    }

                    self.set_evidence_vertical_portscan(evidence_details)

    def check_flow(
        self,
        profileid: ProfileID,
        twid: TimeWindow,
        raw: dict,
        summary_state: str = "",
    ) -> None:
        """Detect from the event without reading accumulated Redis scan totals.

        Parameters:
            profileid: Source profile of the event.
            twid: Evidence attribution time window.
            raw: Original-direction connection metadata.
            summary_state: Profiler fallback for incomplete legacy summaries.
        """
        if not isinstance(raw, dict) or raw.get("saddr") != profileid.ip:
            return
        flow = ScanFlow.from_flow(
            raw, summary_state or raw.get("interpreted_state", "")
        )
        if flow is None:
            return
        scope = self.scope(flow) if self.scope else flow.interface
        if scope is None:
            return
        now = time.monotonic()
        if flow.proto == "tcp" and now >= self.next_p2p_refresh:
            self.next_p2p_refresh = now + 5
            self.p2p_tuples.clear()
            for item in self.db.get_authenticated_p2p_connections():
                try:
                    entry = (
                        str(item["local_ip"]),
                        int(item["local_port"]),
                        str(item["remote_ip"]),
                        int(item["remote_port"]),
                    )
                except (KeyError, TypeError, ValueError):
                    continue
                self.p2p_tuples.add(entry)
                self.p2p_tuples.add((entry[2], entry[3], entry[0], entry[1]))
                if len(self.p2p_tuples) >= 8192:
                    break
        if (
            flow.proto == "tcp"
            and (flow.src, flow.sport, flow.dst, flow.port) in self.p2p_tuples
        ):
            return
        finding = self.detector.process(flow, scope)
        if finding is None:
            return
        count = finding.target_count or len(finding.flows)
        uids = list(
            finding.sample_uids or tuple(p.uid for p in finding.flows[-20:])
        )
        description = (
            f"Vertical port scan from {flow.src} to {flow.dst}: "
            f"{'approximately ' if finding.approximate else ''}{count} distinct {flow.proto.upper()} destination ports "
            f"{'over the continuing scan' if finding.approximate else 'within'} {finding.window:g} seconds. "
            f"{finding.reason}. Confidence: {finding.confidence:g}."
        )
        self.db.set_evidence(
            Evidence(
                evidence_type=EvidenceType.VERTICAL_PORT_SCAN,
                attacker=Attacker(Direction.SRC, IoCType.IP, flow.src),
                victim=Victim(Direction.DST, IoCType.IP, flow.dst),
                threat_level=ThreatLevel[finding.threat.upper()],
                confidence=finding.confidence,
                description=description,
                profile=profileid,
                timewindow=twid,
                uid=uids,
                timestamp=flow.start,
                proto=Proto(flow.proto),
            )
        )
        if finding.threat in {"medium", "high"}:
            self.db.mark_ip_as_port_scanner(flow.src, str(twid))
