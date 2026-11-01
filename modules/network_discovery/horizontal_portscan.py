"""Explain horizontal scan candidates without treating old sessions as probes."""

import json
import time
import ipaddress
from collections import OrderedDict
from typing import Any

from slips_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    TimeWindow,
    Attacker,
    Proto,
    ThreatLevel,
    EvidenceType,
    IoCType,
    Direction,
)

from .scan_detector import ProgressBatch, ScanDetector, ScanFlow
from .scan_settings import ScanSettings


class HorizontalPortscan:
    """Consume each original-direction flow once using bounded rolling state."""

    def __init__(
        self,
        db: Any,
        settings: ScanSettings | None = None,
        live: bool = False,
        interfaces: tuple[str, ...] = (),
    ) -> None:
        """Initialize detection without opening databases or creating threads.

        Parameters:
            db: Existing Slips database facade.
            settings: Validated scan thresholds, or built-in defaults.
            live: Whether gateway identity is available from live capture.
            interfaces: Capture interfaces used to resolve the default name.
        """
        self.db = db
        self.settings = settings or ScanSettings()
        self.settings.validate()
        self.detector = ScanDetector(self.settings)
        self.live = live
        self.interfaces = interfaces
        self.networks: OrderedDict[str, tuple[float, dict]] = OrderedDict()

    def scope(self, flow: ScanFlow) -> str | None:
        """Separate networks and exclude observed IPv4 subnet broadcasts.

        Parameters:
            flow: Validated flow with packet timestamp and interface.

        Returns:
            Network/interface scope, or None for subnet broadcast traffic.
        """
        interface = flow.interface
        if interface == "default" and len(self.interfaces) == 1:
            interface = self.interfaces[0]
        if not self.live:
            return interface
        now = time.monotonic()
        cached = self.networks.get(interface)
        if cached is None or now >= cached[0]:
            state = self.db.get_network_state(interface)
            state = state if isinstance(state, dict) else {}
            self.networks[interface] = (now + 5, state)
            self.networks.move_to_end(interface)
            if len(self.networks) > 16:
                self.networks.popitem(last=False)
        else:
            state = cached[1]
        if flow.start < float(state.get("changed_at") or 0):
            state = max(
                (
                    s
                    for s in state.get("history", [])
                    if isinstance(s, dict)
                    and float(s.get("changed_at") or 0) <= flow.start
                ),
                key=lambda s: float(s.get("changed_at") or 0),
                default={},
            )
        try:
            network = ipaddress.ip_network(
                state.get("local_network", ""), strict=False
            )
            if (
                network.version == 4
                and network.prefixlen < 31
                and any(
                    ipaddress.ip_address(ip)
                    in {network.broadcast_address, network.network_address}
                    for ip in (flow.src, flow.dst)
                )
            ):
                return None
        except ValueError:
            pass
        return json.dumps(
            [
                interface,
                state.get("gateway_mac", ""),
                state.get("local_network", ""),
            ]
        )

    def check(
        self,
        profileid: ProfileID,
        twid: TimeWindow,
        raw: dict[str, Any],
        summary_state: str = "",
    ) -> None:
        """Analyze a source profile's flow and emit evidence after P2P exclusions.

        Parameters:
            profileid: Profile receiving the event.
            twid: Current evidence attribution window, not the scan period.
            raw: Original connection summary, already included in the event.
            summary_state: Coarse profiler state for inputs without packet history.
        """
        if not isinstance(raw, dict) or profileid.ip != raw.get("saddr"):
            return
        flow = ScanFlow.from_flow(raw, summary_state)
        if flow is None:
            return
        scope = self.scope(flow)
        if scope is None:
            return
        result = self.detector.process(flow, scope)
        if result is None:
            return
        group, finding = result
        # Check actual tuples in one round trip only when a candidate exists.
        probes = (
            list(finding.flows)
            if isinstance(finding, ProgressBatch)
            else [t.probe for t in group.targets.values() if t.probe]
        )
        excluded = self.db.is_p2p_related_flow_batch(
            [(p.src, p.sport, p.dst, p.port, p.proto) for p in probes]
        )
        if isinstance(finding, ProgressBatch):
            finding = self.detector.progress_candidate(
                group,
                [p for p, own_p2p in zip(probes, excluded) if not own_p2p],
            )
            if finding is None:
                return
        else:
            dropped = False
            for probe, is_p2p in zip(probes, excluded):
                if is_p2p:
                    self.detector.forget(group, probe.dst)
                    dropped = True
            if dropped:
                finding = self.detector.candidate(group, scope, flow.src)
                if finding is None:
                    return
        self.set_evidence_horizontal_portscan(
            {
                "protocol": flow.proto,
                "profileid": str(profileid),
                "twid": str(twid),
                "uids": [p.uid for p in finding.flows[:20]],
                "dport": flow.port,
                "pkts_sent": sum(p.packets for p in finding.flows),
                "first_timestamp": max(p.start for p in finding.flows),
                "amount_of_dips": finding.target_count or len(finding.flows),
                "approximate": finding.approximate,
                "threat": finding.threat,
                "confidence": finding.confidence,
                "reason": finding.reason,
                "window": finding.window,
                "failure_ratio": finding.failure_ratio,
            }
        )
        self.detector.reported(group, finding)
        if finding.threat in {"medium", "high"}:
            self.db.mark_ip_as_port_scanner(profileid.ip, str(twid))

    def set_evidence_horizontal_portscan(
        self, evidence: dict[str, Any]
    ) -> None:
        """Store an explained finding with confidence independent of packet count.

        Parameters:
            evidence: Target counts, contributing UIDs and assessed uncertainty.
        """
        srcip = evidence["profileid"].split("_", 1)[-1]
        portproto = f"{evidence['dport']}/{evidence['protocol']}"
        port_info = self.db.get_port_info(portproto) or ""
        count_label = "approximately " if evidence.get("approximate") else ""
        period_label = (
            "over the continuing scan's"
            if evidence.get("approximate")
            else "within"
        )
        fraction = (
            f"Failed-target fraction: {evidence['failure_ratio']:.0%}. "
            if evidence.get("failure_ratio") is not None
            else ""
        )
        description = (
            f"Horizontal port scan to port {port_info} {portproto}. "
            f"From {srcip} to {count_label}{evidence['amount_of_dips']} unique destination IPs "
            f"{period_label} {evidence['window']:g} seconds. {evidence['reason']}. "
            f"{fraction}"
            f"Packets in contributing flows: {evidence['pkts_sent']}. "
            f"Confidence: {evidence['confidence']:g}."
        )
        self.db.set_evidence(
            Evidence(
                evidence_type=EvidenceType.HORIZONTAL_PORT_SCAN,
                attacker=Attacker(
                    direction=Direction.SRC, ioc_type=IoCType.IP, value=srcip
                ),
                threat_level=ThreatLevel[evidence["threat"].upper()],
                confidence=evidence["confidence"],
                description=description,
                profile=ProfileID(ip=srcip),
                timewindow=TimeWindow(
                    number=int(evidence["twid"].replace("timewindow", ""))
                ),
                uid=evidence["uids"],
                timestamp=evidence["first_timestamp"],
                proto=Proto(evidence["protocol"].lower()),
                dst_port=evidence["dport"],
            )
        )
