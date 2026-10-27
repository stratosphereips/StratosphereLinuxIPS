"""Bounded ARP scan decisions using packet time and prior successful contacts."""

import ipaddress
import json
import math
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from typing import Any

from slips_files.common.mac import classify_mac, normalize_mac
from slips_files.common.scan_progress import ConfirmedScan, scan_confidence

from .scan_settings import ARPScanSettings


def unicast_mac(value: Any) -> str:
    """Return a normalized individual MAC, or an empty string.

    Parameters:
        value: Candidate link-layer address.

    Returns:
        Valid unicast MAC, including locally administered addresses.
    """
    return (
        normalize_mac(value)
        if classify_mac(value)
        in {"universally_administered", "locally_administered"}
        else ""
    )


def unicast_ip(value: Any) -> str:
    """Validate an IPv4 endpoint without treating ARP type/code fields as ports.

    Parameters:
        value: Candidate IP address.

    Returns:
        IPv4 unicast address, or an empty string.
    """
    try:
        address = ipaddress.ip_address(value)
        return (
            str(address)
            if address.version == 4
            and not (
                address.is_multicast
                or address.is_unspecified
                or address.is_loopback
                or str(address) == "255.255.255.255"
            )
            else ""
        )
    except (ValueError, TypeError):
        return ""


@dataclass(slots=True)
class Contact:
    """Two successful uses separated in time establish a familiar neighbour."""

    scope: str
    source_mac: str
    source_ip: str
    peer_ip: str
    peer_mac: str
    first: float
    seen: float
    confirmed: float = 0


@dataclass(slots=True)
class Target:
    """Keep one representative request per target, not every retry."""

    first: float
    seen: float
    uid: str
    familiar: bool
    known: bool
    replied: float = -math.inf
    used: float = -math.inf


@dataclass(slots=True)
class RequestGroup:
    """A rolling window for one source device/address in one network."""

    scope: str
    source_mac: str
    source_ip: str
    profileid: str
    twid: str
    interface: str
    seen: float
    started: float
    targets: OrderedDict[str, Target] = field(default_factory=OrderedDict)
    candidate_at: float | None = None
    reported: float = -math.inf
    report_level: int = -1
    evaluated: float = -math.inf
    truncated: bool = False
    expire_at: float = math.inf
    report_confidence: float = 0
    progress: ConfirmedScan | None = None


@dataclass(frozen=True, slots=True)
class ARPFinding:
    """One explained discovery episode attributed to its latest source profile."""

    profileid: str
    twid: str
    interface: str
    timestamp: float
    uids: tuple[str, ...]
    scan: bool
    confidence: float
    description: str
    facts: dict[str, Any]


class ARPScanDetector:
    """Analyze ARP requests with bounded state and no per-packet disk access."""

    def __init__(self, settings: ARPScanSettings) -> None:
        """Initialize empty scan windows and relationship history.

        Parameters:
            settings: Validated decision and memory limits.
        """
        settings.validate()
        self.settings = settings
        self.groups: OrderedDict[tuple[str, str, str], RequestGroup] = (
            OrderedDict()
        )
        self.contacts: OrderedDict[str, Contact] = OrderedDict()
        self.nodes: OrderedDict[tuple[str, str], tuple[float, str, float]] = (
            OrderedDict()
        )
        self.flow_uids: OrderedDict[str, None] = OrderedDict()
        self.source_history: OrderedDict[
            tuple[str, str], tuple[float, float]
        ] = OrderedDict()
        self.pending: set[tuple[str, str, str]] = set()
        self.clock = 0.0
        self.dirty = False
        self.evictions = 0

    def _node(self, scope: str, ip: str, mac: str, timestamp: float) -> None:
        """Remember an observed sender, never merely an ARP question's target.

        Parameters:
            scope: Network identity.
            ip: Sender address.
            mac: Confirmed link-layer sender address.
            timestamp: Observation time.
        """
        key = (scope, ip)
        previous = self.nodes.get(key)
        if not mac:
            return
        if previous and previous[0] > timestamp and previous[1] != mac:
            return
        first = (
            min(previous[2], timestamp)
            if previous and previous[1] == mac
            else timestamp
        )
        latest = max(previous[0], timestamp) if previous else timestamp
        self.nodes[key] = latest, mac, first
        self.nodes.move_to_end(key)
        while len(self.nodes) > self.settings.scan_max_relationships:
            self.nodes.popitem(last=False)

    def _familiar(
        self, scope: str, source_mac: str, peer: str, before: float
    ) -> bool:
        """Check source-specific history that existed before this burst.

        Parameters:
            scope: Network identity.
            source_mac: Requesting device.
            peer: Target IP.
            before: First packet time in this episode.

        Returns:
            Whether prior successful use is mature, recent and identity-consistent.
        """
        saved = self.contacts.get(json.dumps([scope, source_mac, peer]))
        if saved is None or not saved.confirmed or saved.confirmed >= before:
            return False
        if (
            saved.seen
            < before - self.settings.scan_familiar_retention_days * 86400
        ):
            return False
        node = self.nodes.get((scope, peer))
        return not node or node[1] == saved.peer_mac

    def _contact(
        self,
        scope: str,
        src: str,
        smac: str,
        dst: str,
        dmac: str,
        timestamp: float,
    ) -> None:
        """Learn an actual two-way contact, requiring separated successful uses.

        Parameters:
            scope: Network identity.
            src: Source IP.
            smac: Source MAC.
            dst: Peer IP.
            dmac: Peer MAC.
            timestamp: Completed flow time.
        """
        key = json.dumps([scope, smac, dst])
        saved = self.contacts.get(key)
        if (
            saved is not None
            and saved.peer_mac != dmac
            and timestamp < saved.seen
        ):
            return
        if saved is None or saved.peer_mac != dmac:
            self.contacts[key] = Contact(
                scope, smac, src, dst, dmac, timestamp, timestamp
            )
        else:
            saved.source_ip = src
            saved.first = min(saved.first, timestamp)
            saved.seen = max(saved.seen, timestamp)
            if (
                not saved.confirmed
                and saved.seen - saved.first
                >= self.settings.scan_familiar_min_interval_seconds
            ):
                saved.confirmed = saved.seen
        self.contacts.move_to_end(key)
        learned = self.contacts[key]
        if learned.confirmed:
            source = (scope, smac)
            old = self.source_history.get(
                source, (learned.confirmed, learned.seen)
            )
            self.source_history[source] = min(old[0], learned.confirmed), max(
                old[1], learned.seen
            )
            self.source_history.move_to_end(source)
            while (
                len(self.source_history) > self.settings.scan_max_relationships
            ):
                self.source_history.popitem(last=False)
        while len(self.contacts) > self.settings.scan_max_relationships:
            self.contacts.popitem(last=False)
            self.evictions += 1
        self.dirty = True

    def observe_connection(
        self, flow: dict[str, Any], scope: str, network: str = ""
    ) -> None:
        """Learn from local TCP/UDP application traffic answered in both directions.

        Parameters:
            flow: Original connection record from new_flow.
            scope: Verified network or isolated run/interface.
            network: Local IPv4 subnet, if known. Otherwise both endpoints must
                already have been observed sending ARP on this link.
        """
        try:
            if flow.get("type_") != "conn" or str(
                flow.get("proto", "")
            ).lower() not in {"tcp", "udp"}:
                return
            if any(
                int(flow.get(key, 0)) <= 0
                for key in ("spkts", "dpkts", "sbytes", "dbytes")
            ):
                return
            if any(
                classify_mac(flow.get(key))
                in {"broadcast", "multicast", "invalid"}
                for key in ("smac", "dmac")
            ):
                return
            src, dst = unicast_ip(flow.get("saddr")), unicast_ip(
                flow.get("daddr")
            )
            start, duration = float(flow["starttime"]), float(
                flow.get("dur", 0)
            )
            end = start + duration
            uid = flow["uid"]
            if (
                not src
                or not dst
                or src == dst
                or not isinstance(uid, str)
                or not uid
                or len(uid) > 256
                or not all(
                    math.isfinite(t) and t >= 0 for t in (start, duration, end)
                )
            ):
                return
            if uid in self.flow_uids:
                return
            if network:
                subnet = ipaddress.ip_network(network, strict=False)
                if subnet.version != 4 or any(
                    ipaddress.ip_address(ip) not in subnet
                    or subnet.prefixlen < 31
                    and ip
                    in {
                        str(subnet.network_address),
                        str(subnet.broadcast_address),
                    }
                    for ip in (src, dst)
                ):
                    return
            elif any((scope, ip) not in self.nodes for ip in (src, dst)):
                return
            smac = (
                unicast_mac(flow.get("smac"))
                or self.nodes.get((scope, src), (0, ""))[1]
            )
            dmac = (
                unicast_mac(flow.get("dmac"))
                or self.nodes.get((scope, dst), (0, ""))[1]
            )
            if not smac or not dmac or smac == dmac:
                return
        except (KeyError, TypeError, ValueError, OverflowError):
            return
        self.flow_uids[uid] = None
        while len(self.flow_uids) > self.settings.scan_max_relationships:
            self.flow_uids.popitem(last=False)
        self._node(scope, src, smac, end)
        self._node(scope, dst, dmac, end)
        for source, mac, peer, peer_mac in (
            (src, smac, dst, dmac),
            (dst, dmac, src, smac),
        ):
            group = self.groups.get((scope, mac, source))
            target = group.targets.get(peer) if group else None
            if (
                target
                and target.first
                <= end
                <= group.seen + self.settings.scan_window_seconds
            ):
                target.used = max(target.used, end)
                previous = self.contacts.get(json.dumps([scope, mac, peer]))
                if previous and previous.peer_mac != peer_mac:
                    target.familiar = False
            self._contact(scope, source, mac, peer, peer_mac, end)

    def request(
        self,
        flow: Any,
        scope: str,
        profileid: str,
        twid: str,
        network: str = "",
    ) -> list[ARPFinding]:
        """Add one real request, expiring every target by its own timestamp.

        Parameters:
            flow: Parsed ARP flow.
            scope: Network identity.
            profileid: Source profile used for evidence attribution.
            twid: Current Slips time window, independent of the rolling check.
            network: Observed local subnet, used to exclude its broadcast address.

        Returns:
            Explained findings, if the candidate is ready for a decision.
        """
        try:
            timestamp = float(flow.starttime)
            src, dst = unicast_ip(flow.saddr), unicast_ip(flow.daddr)
            mac = unicast_mac(flow.src_hw) or unicast_mac(flow.smac)
            if (
                "request" not in flow.operation
                or not src
                or not dst
                or src == dst
                or not math.isfinite(timestamp)
                or timestamp < 0
                or not isinstance(flow.uid, str)
                or not flow.uid
                or len(flow.uid) > 256
            ):
                return []
            if network:
                subnet = ipaddress.ip_network(network, strict=False)
                if (
                    subnet.version == 4
                    and subnet.prefixlen < 31
                    and dst
                    in {
                        str(subnet.network_address),
                        str(subnet.broadcast_address),
                    }
                ):
                    return []
        except (TypeError, ValueError, AttributeError):
            return []
        key = scope, mac or f"ip:{src}", src
        group = self.groups.get(key)
        findings = []
        if group is not None and group.progress:
            progress = group.progress
            if timestamp < progress.started:
                return []
            if (
                timestamp - progress.last
                < self.settings.scan_alert_cooldown_seconds
            ):
                group.seen = max(group.seen, timestamp)
                group.profileid, group.twid = profileid, twid
                self.groups.move_to_end(key)
                self.clock = max(self.clock, timestamp)
                if not self._familiar(scope, mac, dst, progress.started):
                    progress.observe(dst, flow.uid, timestamp)
                if progress.due():
                    count = progress.counter.estimate()
                    progress.reported()
                    return [
                        ARPFinding(
                            profileid,
                            twid,
                            flow.interface,
                            timestamp,
                            tuple(progress.samples.values()),
                            True,
                            1.0,
                            f"Continuing previously confirmed ARP scan: approximately {count} distinct unfamiliar target IPs over {timestamp - progress.started:g} seconds. Familiar neighbours are excluded; representative request IDs are sampled. Missing replies remain unknown.",
                            {
                                "version": 1,
                                "continuation": True,
                                "approximate": True,
                                "targets": count,
                                "window_seconds": timestamp - progress.started,
                                "source_mac": mac,
                                "network_scope": scope,
                            },
                        )
                    ]
                return []
            group.progress = None
            group.reported, group.report_level, group.report_confidence = (
                -math.inf,
                -1,
                0,
            )
            group.candidate_at = None
        if group is not None:
            if timestamp < group.seen - self.settings.scan_window_seconds:
                return []
            if (
                timestamp - group.seen
                > self.settings.scan_context_wait_seconds
            ):
                finding = self._evaluate(key, group, timestamp)
                if finding:
                    findings.append(finding)
            if max(group.seen, timestamp) > group.expire_at:
                for peer in list(group.targets):
                    if (
                        group.targets[peer].seen
                        < max(group.seen, timestamp)
                        - self.settings.scan_window_seconds
                    ):
                        del group.targets[peer]
                group.expire_at = min(
                    (
                        target.seen + self.settings.scan_window_seconds
                        for target in group.targets.values()
                    ),
                    default=math.inf,
                )
            if not group.targets:
                group.started = timestamp
                group.candidate_at = None
                group.truncated = False
        else:
            group = RequestGroup(
                scope,
                mac,
                src,
                profileid,
                twid,
                flow.interface,
                timestamp,
                timestamp,
            )
            self.groups[key] = group
        group.seen = max(timestamp, group.seen)
        group.profileid, group.twid = profileid, twid
        self.groups.move_to_end(key)
        self.clock = max(self.clock, timestamp)
        self._node(scope, src, mac, timestamp)
        previous = group.targets.get(dst)
        before = max(
            group.started, group.seen - self.settings.scan_window_seconds
        )
        if previous is None:
            known = self.nodes.get((scope, dst))
            group.targets[dst] = Target(
                timestamp,
                timestamp,
                flow.uid,
                self._familiar(scope, mac, dst, before),
                bool(
                    known
                    and known[0]
                    >= before
                    - self.settings.scan_familiar_retention_days * 86400
                    and known[2] < before
                ),
            )
        elif timestamp >= previous.seen:
            previous.seen, previous.uid = timestamp, flow.uid
            group.targets.move_to_end(dst)
        while len(group.targets) > self.settings.scan_max_targets:
            group.targets.popitem(last=False)
            group.truncated = True
        group.expire_at = min(
            group.expire_at, timestamp + self.settings.scan_window_seconds
        )
        while len(self.groups) > self.settings.scan_max_sources:
            dropped, _ = self.groups.popitem(last=False)
            self.pending.discard(dropped)
            self.evictions += 1
        if len(group.targets) >= self.settings.scan_min_targets:
            if group.candidate_at is None:
                group.candidate_at = group.seen
            self.pending.add(key)
            if (
                group.seen - group.evaluated >= 1
                or len(group.targets) % self.settings.scan_min_targets == 0
            ):
                finding = self._evaluate(key, group, group.seen)
                if finding:
                    findings.append(finding)
        return findings

    def reply(self, flow: Any, scope: str) -> None:
        """Record positive reply support; a missing reply is never a failure.

        Parameters:
            flow: Parsed ARP reply.
            scope: Network identity at packet time.
        """
        try:
            timestamp = float(flow.starttime)
            src, dst = unicast_ip(flow.saddr), unicast_ip(flow.daddr)
            smac = unicast_mac(flow.src_hw) or unicast_mac(flow.smac)
            dmac = unicast_mac(flow.dst_hw) or unicast_mac(flow.dmac)
            if not src or not math.isfinite(timestamp) or timestamp < 0:
                return
            self.clock = max(self.clock, timestamp)
            self._node(scope, src, smac, timestamp)
            group = self.groups.get((scope, dmac, dst))
            target = group.targets.get(src) if group else None
            if (
                target
                and target.first
                <= timestamp
                <= target.seen + self.settings.scan_window_seconds
            ):
                target.replied = max(target.replied, timestamp)
                previous = self.contacts.get(
                    json.dumps([scope, group.source_mac, src])
                )
                if previous and smac and previous.peer_mac != smac:
                    target.familiar = False
        except (ValueError, TypeError, AttributeError):
            return

    def _evaluate(
        self, key: tuple, group: RequestGroup, timestamp: float
    ) -> ARPFinding | None:
        """Classify a candidate with independent novelty and search-pattern checks.

        Parameters:
            key: Source group key.
            group: Rolling requests and prior-history snapshots.
            timestamp: Packet or idle-flush time used only for the short wait.

        Returns:
            Scan evidence or informational broad discovery, or no finding.
        """
        if (
            group.candidate_at is None
            or timestamp
            < group.candidate_at + self.settings.scan_context_wait_seconds
        ):
            return None
        group.evaluated = group.seen
        before = max(
            group.started, group.seen - self.settings.scan_window_seconds
        )
        for peer, target in group.targets.items():
            if target.first < before:
                target.first = target.seen
                target.familiar = self._familiar(
                    group.scope, group.source_mac, peer, before
                )
                node = self.nodes.get((group.scope, peer))
                target.known = bool(
                    node
                    and node[0]
                    >= before
                    - self.settings.scan_familiar_retention_days * 86400
                    and node[2] < before
                )
        targets = list(group.targets.values())
        count = len(targets)
        unfamiliar = sum(not target.familiar for target in targets)
        addresses = [
            int(ipaddress.IPv4Address(ip))
            for ip, _ in sorted(
                group.targets.items(), key=lambda item: item[1].seen
            )
        ]
        ordered = sum(
            abs(a - b) == 1 for a, b in zip(addresses, addresses[1:])
        ) / max(1, count - 1)
        broad = count >= self.settings.scan_broad_targets
        known = sum(target.known for target in targets)
        prior = self.source_history.get((group.scope, group.source_mac))
        has_history = bool(
            prior
            and prior[0] < before
            and prior[1]
            >= before - self.settings.scan_familiar_retention_days * 86400
        )
        history_supports_novelty = (
            has_history
            or count - known >= self.settings.scan_min_unfamiliar_targets
        )
        scan = (
            history_supports_novelty
            and unfamiliar >= self.settings.scan_min_unfamiliar_targets
            and unfamiliar / max(1, count)
            >= self.settings.scan_min_unfamiliar_ratio
            and (
                ordered >= self.settings.scan_ordered_ratio
                or unfamiliar >= self.settings.scan_broad_targets
            )
        )
        level = 1 if scan else 0
        if not scan and not broad:
            self.pending.discard(key)
            return None
        familiar = count - unfamiliar
        replied = sum(target.replied >= before for target in targets)
        used = sum(target.used >= before for target in targets)
        confidence = (
            min(
                0.95,
                0.7
                + 0.1 * (unfamiliar >= self.settings.scan_broad_targets)
                + 0.1 * (ordered >= self.settings.scan_ordered_ratio),
            )
            if scan
            else 0.3
        )
        if scan and used / count >= 0.8:
            confidence -= 0.1
        if scan:
            confidence = scan_confidence(
                confidence,
                unfamiliar,
                self.settings.scan_min_unfamiliar_targets,
                unfamiliar / max(1, count),
                strong=bool(group.source_mac)
                and not group.truncated
                and used / count < 0.8,
            )
        if (
            group.seen
            < group.reported + self.settings.scan_alert_cooldown_seconds
            and level <= group.report_level
            and confidence <= group.report_confidence
        ):
            self.pending.discard(key)
            return None
        facts = {
            "version": 1,
            "window_seconds": self.settings.scan_window_seconds,
            "targets": count,
            "sampled_flows": count > 20,
            "familiar_targets": familiar,
            "unfamiliar_targets": unfamiliar,
            "known_on_network": known,
            "source_has_prior_contacts": has_history,
            "replied_targets": replied,
            "used_targets": used,
            "ordered_ratio": round(ordered, 3),
            "source_mac": group.source_mac,
            "network_scope": group.scope,
            "truncated": group.truncated,
            "min_unfamiliar_targets": self.settings.scan_min_unfamiliar_targets,
            "min_unfamiliar_ratio": self.settings.scan_min_unfamiliar_ratio,
            "broad_targets": self.settings.scan_broad_targets,
            "ordered_min_ratio": self.settings.scan_ordered_ratio,
        }
        title = (
            (
                "ARP scan pattern confirmed"
                if confidence == 1.0
                else "Possible ARP scan"
            )
            if scan
            else "Broad ARP neighbour discovery (informational)"
        )
        reason = (
            "unfamiliar targets and "
            + (
                "an ordered address sweep"
                if ordered >= self.settings.scan_ordered_ratio
                else "a large search"
            )
            if scan
            else "the count is large, but there is insufficient evidence of scanning"
        )
        description = (
            f"{title}: {count} distinct target IPs within {self.settings.scan_window_seconds:g} seconds. "
            f"{familiar} familiar and {unfamiliar} unfamiliar to this source before the burst; "
            f"{known} previously observed on this network; prior source communication history {'available' if has_history else 'unavailable'}; "
            f"{replied} observed replying, {used} with observed two-way application traffic; "
            f"{ordered:.0%} adjacent address steps. Reason: {reason}. "
            "Missing replies or later traffic are unknown, not failed connections."
        )
        group.reported, group.report_level, group.report_confidence = (
            group.seen,
            level,
            confidence,
        )
        if scan and confidence == 1.0:
            group.progress = ConfirmedScan.seed(
                (
                    (ip, target.uid)
                    for ip, target in group.targets.items()
                    if not target.familiar
                ),
                before,
                group.seen,
                "unfamiliar ARP targets",
            )
            group.targets.clear()
            group.candidate_at = None
        self.pending.discard(key)
        return ARPFinding(
            group.profileid,
            group.twid,
            group.interface,
            group.seen,
            tuple(target.uid for target in targets[-20:]),
            scan,
            round(confidence, 2),
            description,
            facts,
        )

    def flush(self, timestamp: float) -> list[ARPFinding]:
        """Finish ready candidates without needing another ARP packet.

        Parameters:
            timestamp: Packet-time watermark plus elapsed idle time.

        Returns:
            New findings for ready pending groups.
        """
        findings = []
        for key in tuple(self.pending):
            group = self.groups.get(key)
            if group:
                finding = self._evaluate(key, group, timestamp)
                if finding:
                    findings.append(finding)
        for key, group in list(self.groups.items()):
            if timestamp - group.seen > max(
                self.settings.scan_window_seconds,
                self.settings.scan_alert_cooldown_seconds,
            ):
                del self.groups[key]
                self.pending.discard(key)
        return findings

    def history(self, timestamp: float) -> list[dict[str, Any]]:
        """Export only bounded, recent contacts, excluding transient scan windows.

        Parameters:
            timestamp: Event clock, or wall time for a live checkpoint.

        Returns:
            Contact records for the module's private checkpoint.
        """
        cutoff = timestamp - self.settings.scan_familiar_retention_days * 86400
        for key in list(self.contacts):
            if self.contacts[key].seen < cutoff:
                del self.contacts[key]
                self.dirty = True
        return [asdict(contact) for contact in self.contacts.values()]

    def restore(self, records: list[dict[str, Any]], timestamp: float) -> None:
        """Restore validated contacts without importing another run's requests.

        Parameters:
            records: Bounded checkpoint records in oldest-first order.
            timestamp: Current live time for age validation.
        """
        for record in records[-self.settings.scan_max_relationships :]:
            try:
                contact = Contact(**record)
                if (
                    not isinstance(contact.scope, str)
                    or not 0 < len(contact.scope) <= 512
                    or not unicast_mac(contact.source_mac)
                    or not unicast_mac(contact.peer_mac)
                    or not unicast_ip(contact.peer_ip)
                    or not unicast_ip(contact.source_ip)
                ):
                    continue
                if (
                    not all(
                        isinstance(t, (int, float))
                        and math.isfinite(t)
                        and t >= 0
                        for t in (
                            contact.first,
                            contact.seen,
                            contact.confirmed,
                        )
                    )
                    or contact.first > contact.seen
                    or contact.confirmed > contact.seen
                    or contact.seen > timestamp
                    or contact.seen
                    < timestamp
                    - self.settings.scan_familiar_retention_days * 86400
                ):
                    continue
                if (
                    contact.confirmed
                    and contact.confirmed - contact.first
                    < self.settings.scan_familiar_min_interval_seconds
                ):
                    contact.confirmed = 0
                key = json.dumps(
                    [contact.scope, contact.source_mac, contact.peer_ip]
                )
                self.contacts[key] = contact
                if contact.confirmed:
                    source = contact.scope, contact.source_mac
                    old = self.source_history.get(
                        source, (contact.confirmed, contact.seen)
                    )
                    self.source_history[source] = min(
                        old[0], contact.confirmed
                    ), max(old[1], contact.seen)
                self._node(
                    contact.scope,
                    contact.source_ip,
                    contact.source_mac,
                    contact.seen,
                )
                self._node(
                    contact.scope,
                    contact.peer_ip,
                    contact.peer_mac,
                    contact.seen,
                )
            except (TypeError, ValueError, KeyError):
                continue
        self.dirty = False
