"""Check ARP discovery decisions with packet timestamps and isolated history."""

from dataclasses import asdict
from types import SimpleNamespace
import random

import pytest

from modules.arp.scan_detector import unicast_ip, unicast_mac
from tests.module_factory import ModuleFactory

SOURCE = "192.168.1.100"
MAC = "02:00:00:00:00:64"
SCOPE = "gateway:02:00:00:00:00:01:192.168.1.0/24"


def request(target: int, timestamp: float, **changes: object) -> SimpleNamespace:
    """Build a request independent of a live profiler.

    Parameters:
        target: Last target IP octet.
        timestamp: Packet time.
        changes: Endpoint or record overrides.

    Returns:
        Parsed-flow-compatible request.
    """
    return SimpleNamespace(**{**dict(saddr=SOURCE, daddr=f"192.168.1.{target}",
        smac=MAC, src_hw=MAC, dmac="ff:ff:ff:ff:ff:ff", dst_hw="00:00:00:00:00:00",
        starttime=timestamp, uid=f"arp-{target}-{timestamp}", operation="request", interface="eth0"), **changes})


def connection(target: int, timestamp: float, **changes: object) -> dict:
    """Build completed local application traffic.

    Parameters:
        target: Peer IP octet.
        timestamp: Flow start time.
        changes: Overrides for unsuccessful or malformed cases.

    Returns:
        New-flow connection record.
    """
    return {**dict(type_="conn", proto="tcp", saddr=SOURCE, daddr=f"192.168.1.{target}",
        smac=MAC, dmac=f"02:00:00:00:01:{target:02x}", starttime=timestamp, dur=1,
        spkts=10, dpkts=10, sbytes=500, dbytes=1000, uid=f"conn-{target}-{timestamp}"), **changes}


def train(detector: object, targets: list[int], scope: str = SCOPE) -> None:
    """Establish separated successful contacts before test requests.

    Parameters:
        detector: Isolated detector.
        targets: Neighbours used by the source.
        scope: Network identity.
    """
    for target in targets:
        for timestamp in (100.0, 500.0):
            detector.observe_connection(connection(target, timestamp), scope, "192.168.1.0/24")


def burst(detector: object, targets: list[int], start: float = 1000, scope: str = SCOPE, **changes: object) -> list:
    """Submit a fast burst and finish its short context wait.

    Parameters:
        detector: Isolated detector.
        targets: Target sequence.
        start: First packet time.
        scope: Network identity.
        changes: Request endpoint overrides.

    Returns:
        Findings, including a final idle flush.
    """
    findings = []
    for offset, target in enumerate(targets):
        findings.extend(detector.request(request(target, start + offset * .01, **changes), scope, f"profile_{changes.get('saddr', SOURCE)}", "timewindow1"))
    return findings + detector.flush(start + 4)


def test_seven_requests_with_retries_and_self_announcement_do_not_scan() -> None:
    """Reject the legacy pattern even before familiarity is available."""
    arp = ModuleFactory().create_arp_obj()
    targets = [1, 120, 100, 163, 230, 120, 163]
    assert len(targets) == 7
    assert burst(arp.scan_detector, targets) == []


@pytest.mark.parametrize("count", [5, 15, 40])
def test_usual_neighbours_do_not_become_scans(count: int) -> None:
    """Keep reconnect bursts benign, retaining only broad info when appropriate.

    Parameters:
        count: Number of familiar neighbours queried.
    """
    detector = ModuleFactory().create_arp_scan_detector()
    train(detector, list(range(1, count + 1)))
    findings = burst(detector, list(range(1, count + 1)))
    assert all(not finding.scan for finding in findings)
    assert len(findings) == int(count >= 32)
    if findings:
        assert findings[0].facts["familiar_targets"] == count


@pytest.mark.parametrize("randomized,count,expected", [(False, 12, True), (True, 12, False), (True, 40, True)])
def test_ordered_and_random_sweeps(randomized: bool, count: int, expected: bool) -> None:
    """Detect ordered small sweeps and large randomized ones without training.

    Parameters:
        randomized: Shuffle target order.
        count: Distinct targets.
        expected: Whether a scan should be reported.
    """
    detector = ModuleFactory().create_arp_scan_detector()
    targets = list(range(1, count + 1))
    if randomized:
        random.Random(49).shuffle(targets)
    findings = burst(detector, targets)
    assert any(item.scan for item in findings) is expected
    if expected:
        assert len(findings) == 1
        assert len(set(findings[0].uids)) == min(count, 20)
        assert "Missing replies" in findings[0].description


@pytest.mark.parametrize("scope,source_mac,expected", [(SCOPE, MAC, False), ("other-network", MAC, True), (SCOPE, "02:00:00:00:02:01", True)])
def test_familiarity_is_per_device_and_network(scope: str, source_mac: str, expected: bool) -> None:
    """Do not transfer source relationships between devices or networks.

    Parameters:
        scope: Scope of the later request.
        source_mac: Requesting device identity.
        expected: Whether the unfamiliar ordered sweep is detected.
    """
    detector = ModuleFactory().create_arp_scan_detector()
    train(detector, list(range(1, 16)))
    # A different device still has prior history, but not these neighbours.
    if source_mac != MAC:
        for timestamp in (100, 500):
            detector.observe_connection(connection(90, timestamp, smac=source_mac), SCOPE, "192.168.1.0/24")
    findings = burst(detector, list(range(1, 16)), scope=scope, src_hw=source_mac, smac=source_mac)
    assert any(item.scan for item in findings) is expected


def test_known_network_without_source_visibility_remains_ambiguous() -> None:
    """Do not call a known-neighbour refresh a scan just because flows are unseen."""
    detector = ModuleFactory().create_arp_scan_detector()
    for target in range(1, 41):
        detector.reply(request(100, 100, saddr=f"192.168.1.{target}", daddr=SOURCE,
            operation="reply", src_hw=f"02:00:00:00:01:{target:02x}"), SCOPE)
    findings = burst(detector, list(range(1, 41)))
    assert len(findings) == 1 and not findings[0].scan
    assert findings[0].facts["known_on_network"] == 40
    assert not findings[0].facts["source_has_prior_contacts"]


@pytest.mark.parametrize("spacing,expected", [(1, True), (10, False)])
def test_real_rolling_window_expires_each_target(spacing: float, expected: bool) -> None:
    """Old middle requests and an updated first target cannot inflate a burst.

    Parameters:
        spacing: Seconds between distinct targets.
        expected: Whether enough targets really fit inside 30 seconds.
    """
    detector = ModuleFactory().create_arp_scan_detector()
    findings = []
    for index in range(12):
        findings.extend(detector.request(request(index + 1, 1000 + index * spacing), SCOPE, f"profile_{SOURCE}", "timewindow1"))
    findings += detector.request(request(1, 1000 + 12 * spacing), SCOPE, f"profile_{SOURCE}", "timewindow2")
    findings += detector.flush(1000 + 12 * spacing + 4)
    assert any(item.scan for item in findings) is expected
    if not expected:
        assert len(next(iter(detector.groups.values())).targets) <= 4


def test_duplicate_requests_and_stale_out_of_order_packets() -> None:
    """Retries and old packets neither grow state nor fabricate targets."""
    detector = ModuleFactory().create_arp_scan_detector()
    assert burst(detector, [1] * 200) == []
    for target in range(2, 15):
        assert detector.request(request(target, 900), SCOPE, f"profile_{SOURCE}", "timewindow1") == []
    group = next(iter(detector.groups.values()))
    assert len(group.targets) == 1
    assert isinstance(group.targets["192.168.1.1"].uid, str)


@pytest.mark.parametrize("changes", [{"saddr": "0.0.0.0"}, {"daddr": SOURCE}, {"daddr": "224.0.0.1"},
    {"daddr": "255.255.255.255"}, {"starttime": float("nan")}, {"starttime": -1}, {"operation": "reply"}])
def test_invalid_requests_and_address_announcements_are_not_scans(changes: dict) -> None:
    """Ignore address probes, announcements and unsupported records.

    Parameters:
        changes: Invalid or non-scan request fields.
    """
    detector = ModuleFactory().create_arp_scan_detector()
    assert burst(detector, list(range(1, 41)), **changes) == []
    assert not detector.groups


@pytest.mark.parametrize("changes", [{"dbytes": 0}, {"dpkts": 0}, {"sbytes": 0}, {"proto": "icmp"},
    {"type_": "dns"}, {"daddr": "8.8.8.8"}, {"smac": "ff:ff:ff:ff:ff:ff"}, {"dur": float("nan")}])
def test_failed_remote_or_empty_contacts_do_not_train(changes: dict) -> None:
    """Require local two-way application bytes and individual identities.

    Parameters:
        changes: Nonqualifying connection fields.
    """
    detector = ModuleFactory().create_arp_scan_detector()
    for timestamp in (100, 500):
        detector.observe_connection(connection(1, timestamp, **changes), SCOPE, "192.168.1.0/24")
    assert not detector.contacts


def test_request_burst_cannot_teach_itself_to_be_benign() -> None:
    """ARP replies and one successful contact do not excuse the current scan."""
    detector = ModuleFactory().create_arp_scan_detector()
    for target in range(1, 16):
        detector.request(request(target, 1000), SCOPE, f"profile_{SOURCE}", "timewindow1")
        detector.reply(request(100, 1001, saddr=f"192.168.1.{target}", daddr=SOURCE,
            operation="reply", src_hw=f"02:00:00:00:01:{target:02x}", dst_hw=MAC), SCOPE)
        detector.observe_connection(connection(target, 1001), SCOPE, "192.168.1.0/24")
    findings = detector.flush(1004)
    assert len(findings) == 1 and findings[0].scan
    assert findings[0].facts["familiar_targets"] == 0
    assert findings[0].facts["replied_targets"] == 15
    assert findings[0].facts["used_targets"] == 15
    assert all(not contact.confirmed for contact in detector.contacts.values())


def test_repeated_uid_cannot_establish_a_contact() -> None:
    """The same connection received again later is still only one observation."""
    detector = ModuleFactory().create_arp_scan_detector()
    for timestamp in (100, 500):
        detector.observe_connection(connection(1, timestamp, uid="same-flow"), SCOPE, "192.168.1.0/24")
    assert all(not contact.confirmed for contact in detector.contacts.values())


def test_old_contacts_and_changed_destination_mac_do_not_transfer_trust() -> None:
    """Expire old history and recognize a neighbour's observed address reassignment."""
    detector = ModuleFactory().create_arp_scan_detector(scan_familiar_retention_days=1)
    train(detector, list(range(1, 16)))
    for target in range(1, 16):
        detector.reply(request(100, 900, saddr=f"192.168.1.{target}", operation="reply",
            src_hw=f"02:00:00:00:02:{target:02x}"), SCOPE)
    # Establish other source history so already-alive targets remain eligible.
    train(detector, [90])
    assert any(item.scan for item in burst(detector, list(range(1, 16))))
    assert detector.history(90000) == []


def test_cooldown_spans_slips_windows_and_stronger_scan_can_supersede_info() -> None:
    """One familiar burst cannot flood scores, but new scan activity still appears."""
    detector = ModuleFactory().create_arp_scan_detector()
    train(detector, list(range(1, 41)))
    first = burst(detector, list(range(1, 41)))
    assert len(first) == 1 and not first[0].scan
    assert burst(detector, list(range(1, 41)), start=1040) == []
    strong = burst(detector, list(range(110, 151)), start=1080)
    assert len(strong) == 1 and strong[0].scan
    assert burst(detector, list(range(110, 151)), start=1120) == []


def test_memory_limits_and_uid_caps_are_enforced() -> None:
    """Keep source, request, sender, contact and duplicate caches bounded."""
    detector = ModuleFactory().create_arp_scan_detector(scan_max_sources=2, scan_max_targets=32,
        scan_broad_targets=32, scan_max_relationships=8)
    train(detector, list(range(1, 16)))
    for source in range(100, 104):
        burst(detector, list(range(1, 41)), saddr=f"192.168.1.{source}", src_hw=f"02:00:00:00:00:{source:02x}")
    assert len(detector.groups) <= 2
    assert len(detector.pending) <= 2
    assert all(len(group.targets) <= 32 for group in detector.groups.values())
    assert max(len(detector.contacts), len(detector.nodes), len(detector.flow_uids), len(detector.source_history)) <= 8
    assert detector.evictions


def test_history_restore_preserves_familiarity_and_validates_records() -> None:
    """Restore contacts, but never restore scan windows or malformed identities."""
    detector = ModuleFactory().create_arp_scan_detector()
    train(detector, list(range(1, 16)))
    records = detector.history(1000)
    other = ModuleFactory().create_arp_scan_detector()
    other.restore(records + [{"invalid": True}, {**records[0], "seen": float("nan")}, {**records[0], "source_mac": "ff:ff:ff:ff:ff:ff"}], 1000)
    assert len(other.contacts) == len(detector.contacts)
    assert not other.groups
    assert burst(other, list(range(1, 16))) == []
    assert asdict(next(iter(other.contacts.values()))) in records


@pytest.mark.parametrize("value,expected", [("02:00:00:00:00:01", "02:00:00:00:00:01"),
    ("ff:ff:ff:ff:ff:ff", ""), ("00:00:00:00:00:00", ""), (None, "")])
def test_individual_mac_validation(value: object, expected: str) -> None:
    """Separate actual device MACs from delivery broadcasts.

    Parameters:
        value: MAC field.
        expected: Normalized individual address, if any.
    """
    _factory = ModuleFactory()
    assert unicast_mac(value) == expected


@pytest.mark.parametrize("value,expected", [("192.168.1.1", "192.168.1.1"), ("0.0.0.0", ""),
    ("255.255.255.255", ""), ("::1", ""), (None, "")])
def test_individual_ipv4_validation(value: object, expected: str) -> None:
    """Exclude non-IPv4 and nonindividual endpoints.

    Parameters:
        value: IP field.
        expected: Canonical IPv4 unicast address, if any.
    """
    _factory = ModuleFactory()
    assert unicast_ip(value) == expected


def test_continuous_requests_can_use_contacts_from_before_the_current_window() -> None:
    """A busy device must not retain its first-capture unfamiliar flags forever."""
    detector = ModuleFactory().create_arp_scan_detector()
    assert any(item.scan for item in burst(detector, list(range(1, 16))))
    for timestamp in (1100, 1500):
        for target in range(1, 16):
            detector.observe_connection(connection(target, timestamp), SCOPE, "192.168.1.0/24")
    for timestamp in range(1020, 2020, 20):
        burst(detector, list(range(1, 16)), start=timestamp)
    assert burst(detector, list(range(1, 16)), start=2020) == []
    assert all(target.familiar for group in detector.groups.values() for target in group.targets.values())


def test_old_reply_support_expires_while_requests_continue() -> None:
    """An old ARP reply must not support all later windows for a busy source."""
    detector = ModuleFactory().create_arp_scan_detector(scan_alert_cooldown_seconds=30)
    for target in range(1, 41):
        detector.request(request(target, 1000), SCOPE, f"profile_{SOURCE}", "timewindow1")
        detector.reply(request(100, 1001, saddr=f"192.168.1.{target}", operation="reply", src_hw=f"02:00:00:00:01:{target:02x}", dst_hw=MAC), SCOPE)
    first = detector.flush(1004)
    assert first[0].facts["replied_targets"] == 40
    for timestamp in (1020, 1040):
        findings = burst(detector, list(range(1, 41)), start=timestamp)
    assert findings[0].facts["replied_targets"] == 0


def test_rolling_state_expires_after_cooldown_without_new_packets() -> None:
    """Quiet sources free their request memory without waiting for a Slips TW."""
    detector = ModuleFactory().create_arp_scan_detector()
    burst(detector, list(range(1, 16)))
    detector.flush(2000)
    assert not detector.groups and not detector.pending


def test_large_arp_scan_compacts_and_reports_logarithmic_growth() -> None:
    """Proven unfamiliar sweeps release target records and keep small counters."""
    detector = ModuleFactory().create_arp_scan_detector()
    findings = []
    for i in range(1, 12001):
        flow = request(1, 1000+i*.1, saddr="10.0.0.10", daddr=f"10.0.{i//256}.{i%256}", uid=f"arp-{i}")
        findings += detector.request(flow, "large-lan", "profile_10.0.0.10", "timewindow1", "10.0.0.0/16")
    assert any(f.confidence == 1 and not f.facts.get("continuation") for f in findings)
    growth = [f for f in findings if f.facts.get("continuation")]
    assert len(growth) == 2
    assert all(f.scan and f.confidence == 1 and len(f.uids) <= 20 for f in growth)
    group = next(iter(detector.groups.values()))
    assert not group.targets
    assert len(group.progress.counter.registers) == 1024
    assert len(group.progress.samples) <= 20
    assert detector.evictions == 0


def test_many_known_neighbours_cannot_enter_confirmed_arp_mode() -> None:
    """Without source history, many already-observed devices remain discovery."""
    detector = ModuleFactory().create_arp_scan_detector()
    targets = [i for i in range(1, 151) if i != 100]
    for i in targets:
        detector._node(SCOPE, f"192.168.1.{i}", f"02:00:00:00:01:{i:02x}", 100)
    findings = burst(detector, targets)
    assert findings and all(not f.scan and f.confidence == .3 for f in findings)
    assert all(g.progress is None for g in detector.groups.values())


def test_familiar_arp_discovery_remains_informational_at_large_counts() -> None:
    """Volume cannot promote established neighbour discovery to full confidence."""
    detector = ModuleFactory().create_arp_scan_detector()
    targets = [i for i in range(1, 151) if i != 100]
    train(detector, targets)
    findings = burst(detector, targets)
    assert findings and all(not f.scan for f in findings)
    assert all(g.progress is None for g in detector.groups.values())
