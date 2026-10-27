"""Detect SMB scanning, propagation, file abuse and authentication behaviors."""

import json
import time
from collections import OrderedDict
from datetime import datetime
from typing import Any

from modules.supported_module_names import Modules
from slips_files.common.abstracts.imodule import IModule
from slips_files.common.input_type import InputType
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
    Attacker,
    Direction,
    Evidence,
    EvidenceType,
    IoCType,
    ProfileID,
    Proto,
    ThreatLevel,
    TimeWindow,
    Victim,
)
from .detector import Detector, Finding
from .settings import Settings


class SMBAnalyzer(IModule):
    """Analyze metadata without opening another capture, database or worker pool."""

    name = Modules.SMB_ANALYZER.value
    description = "Detects suspicious SMB behaviors"
    authors = ["Sebastian Garcia"]

    def init(self) -> None:
        """Initialize validated settings and resource-bounded correlation state."""
        self.settings = Settings.from_config(self.conf)
        self.detector = Detector(self.settings)
        self.live = self.db.get_input_type() == InputType.INTERFACE
        self.networks: OrderedDict = OrderedDict()
        self.next_warning = 0.0
        self.reported_evictions = 0
        self.pending: dict[str, tuple[float, dict]] = {}

    def subscribe_to_channels(self) -> None:
        """Receive normalized connections and persisted SMB-related events."""
        self.channels = {
            name: self.db.subscribe(name) for name in ("new_flow", "new_smb")
        }

    def pre_main(self) -> None:
        """Release capture privileges before analyzing metadata."""
        utils.drop_root_privs_permanently()

    def scope(self, flow: dict) -> str:
        """Separate reused private addresses when the capture network changes.

        :param flow: Normalized flow with capture timestamp and interface.
        :return: Interface/network scope local to this module's run.
        """
        interface = flow.get("interface") or "default"
        interfaces = getattr(self.args, "interface", []) or []
        if interface == "default" and len(interfaces) == 1:
            interface = interfaces[0]
        if not self.live:
            return str(interface)
        now = time.monotonic()
        cached = self.networks.get(interface)
        if cached is None or now > cached[0]:
            network = self.db.get_network_state(interface)
            network = network if isinstance(network, dict) else {}
            self.networks[interface] = (now + 5, network)
            self.networks.move_to_end(interface)
            while len(self.networks) > 16:
                self.networks.popitem(last=False)
        else:
            network = cached[1]
        ts = float(flow["starttime"])
        if ts < float(network.get("changed_at") or 0):
            network = max(
                (
                    v
                    for v in network.get("history", [])
                    if float(v.get("changed_at") or 0) <= ts
                ),
                key=lambda v: float(v.get("changed_at") or 0),
                default={},
            )
        return json.dumps(
            [
                interface,
                network.get("gateway_mac", ""),
                network.get("local_network", ""),
                network.get("changed_at", ""),
            ]
        )

    def handle(self, payload: dict[str, Any]) -> None:
        """Process only the original source profile, then publish explained evidence.

        :param payload: Decoded Redis flow notification.
        """
        flow = payload.get("flow")
        if (
            not isinstance(flow, dict)
            or payload.get("profileid") != f"profile_{flow.get('saddr')}"
        ):
            return
        if flow.get("type_") == "conn":
            try:
                port = int(flow.get("dport") or 0)
            except (TypeError, ValueError):
                return
            if (
                port not in self.settings.ports
                or str(flow.get("proto", "")).lower() != "tcp"
            ):
                return
        flow = flow.copy()
        timestamp = flow.get("starttime")
        if isinstance(timestamp, datetime):
            timestamp = timestamp.timestamp()
        try:
            flow["starttime"] = float(timestamp)
        except (ValueError, TypeError):
            flow["starttime"] = float(
                utils.convert_ts_format(timestamp, "unixtimestamp")
            )
        window = int(str(payload["twid"]).replace("timewindow", ""))
        for finding in self.detector.process(flow, self.scope(flow)):
            self.emit(finding, window)
        if (
            self.detector.evictions > self.reported_evictions
            and time.monotonic() >= self.next_warning
        ):
            self.print(
                "SMB correlation capacity reached; older context was discarded. Increase SMB state limits if needed.",
                0,
                1,
            )
            self.next_warning = time.monotonic() + 60
            self.reported_evictions = self.detector.evictions

    def emit(self, finding: Finding, window: int) -> None:
        """Attribute a finding to the initiating client and describe uncertainty.

        :param finding: Observed behavior and bounded supporting UIDs.
        :param window: Slips time window for the triggering event.
        """
        flow = finding.flow
        _, threat, confidence = self.settings.rule(finding.kind)
        confidence = finding.details.get("scan_confidence", confidence)
        self.db.set_evidence(
            Evidence(
                evidence_type=EvidenceType[finding.kind],
                attacker=Attacker(Direction.SRC, IoCType.IP, flow["saddr"]),
                victim=Victim(Direction.DST, IoCType.IP, flow["daddr"]),
                threat_level=ThreatLevel[threat.upper()],
                confidence=confidence,
                description=finding.description,
                profile=ProfileID(flow["saddr"]),
                timewindow=TimeWindow(window),
                timestamp=flow["starttime"],
                uid=finding.uids,
                src_port=flow.get("sport") or None,
                dst_port=flow.get("dport") or None,
                proto=Proto.TCP,
                interface=flow.get("interface", "default"),
                detection_details={
                    "smb": finding.details,
                    "confidence_meaning": "Confidence in the recorded behavior, not the probability of malware or successful exploitation.",
                },
            )
        )

    def main(self) -> None:
        """Merge bounded batches by capture time with one lookahead per channel."""
        empty: set[str] = set()
        for _ in range(64):
            for channel in ("new_smb", "new_flow"):
                if channel in self.pending or channel in empty:
                    continue
                message = self.get_msg(channel)
                if not message:
                    empty.add(channel)
                    continue
                try:
                    payload = json.loads(message["data"])
                    timestamp = float(payload["flow"]["starttime"])
                    self.pending[channel] = (timestamp, payload)
                except (ValueError, TypeError, KeyError) as error:
                    if time.monotonic() >= self.next_warning:
                        self.print(
                            f"Invalid SMB metadata skipped: {error}", 0, 1
                        )
                        self.next_warning = time.monotonic() + 60
            if not self.pending:
                break
            channel = min(self.pending, key=lambda key: self.pending[key][0])
            _, payload = self.pending.pop(channel)
            try:
                self.handle(payload)
            except (ValueError, TypeError, KeyError) as error:
                if time.monotonic() >= self.next_warning:
                    self.print(f"Invalid SMB metadata skipped: {error}", 0, 1)
                    self.next_warning = time.monotonic() + 60

    def shutdown_gracefully(self) -> None:
        """Finish at most two cached records before releasing this worker."""
        for _, payload in sorted(
            self.pending.values(), key=lambda item: item[0]
        ):
            try:
                self.handle(payload)
            except (ValueError, TypeError, KeyError) as error:
                self.print(
                    f"Invalid pending SMB metadata skipped: {error}", 0, 1
                )
        self.pending.clear()
