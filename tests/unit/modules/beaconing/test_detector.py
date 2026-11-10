"""Numeric rhythm regression tests independent of Redis and TensorFlow."""

import random
from dataclasses import replace

import pytest

from modules.beaconing.detector import Detector, Observation, features, rhythm
from tests.module_factory import ModuleFactory


def event(index: int, timestamp: float | None = None, **changes: object) -> Observation:
    """Build an original-direction connection.

    Parameters:
        index: Unique flow number.
        timestamp: Optional packet start time.
        changes: Observation field overrides.

    Returns:
        Independent numeric observation.
    """
    return replace(Observation(str(index), 1700000000 + index * 60 if timestamp is None else timestamp, 0.2, "192.168.1.2", "8.8.8.8", 443, "tcp", 386, 115, 5, 5, True), **changes)


@pytest.mark.parametrize("gaps,expected", [([60.0] * 15, True), ([60, 62, 59, 58, 61] * 3, True), ([60, 60, 120, 60, 180] * 3, True), ([0.0] * 15, False), ([1, 1, 10, 100, 1000] * 3, False)])
def test_rhythm(gaps: list[float], expected: bool) -> None:
    """Rhythm.

    Parameters:
        gaps: Observed interval test case.
        expected: Whether the intervals should form a recurring pattern.
    """
    module = ModuleFactory().create_beaconing_obj()
    result = rhythm(gaps, module.settings)
    assert bool(result) == expected
    if result:
        assert result["period"] == pytest.approx(60, abs=3)


@pytest.mark.parametrize("mode", ["regular", "after-reply", "bursts", "random", "too-short"])
def test_numeric_features(mode: str) -> None:
    """Numeric features.

    Parameters:
        mode: Traffic pattern being exercised.
    """
    module = ModuleFactory().create_beaconing_obj()
    rng = random.Random(73)
    if mode == "bursts":
        events = [event(3 * i + j, 1700000000 + 60 * i + j * 0.2) for i in range(16) for j in range(3)]
    elif mode == "random":
        times = sorted(rng.uniform(0, 2000) for _ in range(60))
        events = [event(i, 1700000000 + t) for i,t in enumerate(times)]
    elif mode == "after-reply":
        events = []
        clock = 1700000000.0
        for i in range(32):
            duration = rng.uniform(1, 180)
            events.append(event(i, clock, duration=duration))
            clock += duration + 30
    else:
        events = [event(i) for i in range(32 if mode == "regular" else 4)]
    result = features(events, module.settings)
    assert bool(result) == (mode not in {"random", "too-short"})
    if mode == "bursts":
        assert result["mode"] == "burst-to-burst"
        assert result["period"] == pytest.approx(60)
    if mode == "after-reply":
        assert result["mode"] == "after-reply"
        assert result["period"] == pytest.approx(30)


def test_pauses_resume_and_changed_behavior() -> None:
    """Pauses resume and changed behavior.
    """
    module = ModuleFactory().create_beaconing_obj(evaluate_interval_seconds=0.0)
    detector = module.detector
    results = []
    for i in range(32):
        if result := detector.process(event(i), "wifi", i):
            results.append(result)
    assert results
    key = results[-1][0]
    assert detector.should_alert(key, "periodic", event(31).timestamp)
    assert not detector.should_alert(key, "periodic", event(32).timestamp)
    assert detector.should_alert(key, "c2", event(32).timestamp)
    for i in range(32, 80):
        detector.process(event(i, 1700000000 + 86400 + i * 60), "wifi", i)
    assert features(list(detector.channels[key].events), module.settings)["period"] == pytest.approx(60)
    rng = random.Random(92)
    times = sorted(rng.uniform(0, 5000) for _ in range(128))
    for i, offset in enumerate(times, 100):
        detector.process(event(i, 1700000000 + 200000 + offset), "wifi", i)
    assert not features(list(detector.channels[key].events), module.settings)


def test_dedup_network_rollover_capacity_and_restore() -> None:
    """Dedup network rollover capacity and restore.
    """
    module = ModuleFactory().create_beaconing_obj(max_channels=16, max_candidates=16, window_connections=16, evaluate_interval_seconds=0.0)
    detector = module.detector
    for i in range(20):
        detector.process(event(i), "wifi", i)
        detector.process(event(i), "wifi", i)
    key = next(iter(detector.channels))
    assert len(detector.channels[key].events) == 16
    detector.process(event(20), "phone", 21)
    assert len(detector.channels) == 1
    assert len(detector.candidates) == 1
    detector.process(event(200, event(18).timestamp + 1), "wifi", 22)
    assert len(detector.channels[key].events) == 16
    assert detector.late_flows == 1
    detector.should_alert(key, "periodic", event(20).timestamp)
    records = [(k, detector.snapshot(k)) for k in reversed([*detector.channels, *detector.candidates])]
    restored = Detector(module.settings)
    restored.restore(records)
    assert restored.snapshot(key) == detector.snapshot(key)
    restored.process(event(19), "wifi", 23)
    assert len(restored.channels[key].events) == 16
    for i in range(1000):
        detector.process(event(i + 1000, dst=f"10.0.{i // 250}.{i % 250 + 1}"), "wifi", i)
    assert len(detector.channels) <= 16
    assert len(detector.candidates) <= 16
    assert len(detector.deleted) <= 32
    assert len(detector.dirty) <= 32
    assert len(detector.seen) <= 16 * 16


@pytest.mark.parametrize("changes", [{"proto": "icmp"}, {"daddr": "224.0.0.1"}, {"dport": 0}, {"dur": float("nan")}, {"smac": "ff:ff:ff:ff:ff:ff"}, {"uid": ""}])
def test_reject_invalid_flow(changes: dict) -> None:
    """Reject invalid flow.

    Parameters:
        changes: Invalid values or field overrides being tested.
    """
    module = ModuleFactory().create_beaconing_obj()
    flow = {"type_": "conn", "uid": "x", "starttime": 1700000000, "dur": 1, "saddr": "192.168.1.2", "daddr": "8.8.8.8", "dport": 443, "proto": "tcp", **changes}
    assert Observation.from_flow(flow) is None
    assert not module.detector.channels


@pytest.mark.parametrize("changes", [{"min_connections": 1}, {"jitter_tolerance": True}, {"max_channels": 16.5}, {"max_period_seconds": float("inf")}, {"window_connections": 16, "min_connections": 20}, {"max_period_seconds": 86400, "retention_hours": 1}, {"max_candidates": 0}, {"report_growth_factor": 1}, {"stable_evaluate_every": 0}, {"stable_evaluate_interval_seconds": -1}])
def test_reject_invalid_settings(changes: dict) -> None:
    """Reject invalid settings.

    Parameters:
        changes: Invalid values or field overrides being tested.
    """
    factory = ModuleFactory()
    with pytest.raises(ValueError):
        factory.create_beaconing_obj(**changes)


def test_runtime_cadence_and_constant_epochs() -> None:
    """Runtime cadence and constant epochs.
    """
    module = ModuleFactory().create_beaconing_obj()
    detector = module.detector
    result = None
    for i in range(20):
        result = detector.process(event(i, 1700000000 + i * 0.001), "scope", 0) or result
    assert result is None
    key = next(iter(detector.channels))
    assert len({e.timestamp for e in detector.channels[key].events}) == 20
    assert not rhythm([0] * 30, module.settings)


def test_short_connection_flood_preserves_mature_channels() -> None:
    """One-off destinations and short retry bursts cannot evict a mature window."""
    module = ModuleFactory().create_beaconing_obj(max_channels=16, max_candidates=16)
    detector = module.detector
    for i in range(20):
        detector.process(event(i), "network", i)
    key = next(iter(detector.channels))
    for i in range(100):
        for retry in range(4):
            detector.process(event(1000 + i * 4 + retry, timestamp=1700002000 + i, dst=f"10.0.0.{i + 1}"), "network", 100 + i)
    assert key in detector.channels
    assert len(detector.channels) == 1
    assert detector.evictions == 0
    assert detector.candidate_evictions == 84
    assert len(detector.candidates) == 16
    assert all(len(channel.events) == 4 for channel in detector.candidates.values())
    assert all(channel.events.maxlen == 12 for channel in detector.candidates.values())


def test_long_silence_requires_new_observations() -> None:
    """A resumed channel earns a new finding from fresh connections."""
    module = ModuleFactory().create_beaconing_obj()
    detector = module.detector
    for i in range(12):
        result = detector.process(event(i), "network", i * 60)
    key, stats = result
    assert detector.should_alert(key, "periodic", event(11).timestamp, stats)
    for i in range(11):
        assert detector.process(event(i + 100, timestamp=1700010000 + i * 60), "network", 10000 + i * 60) is None
    result = detector.process(event(111, timestamp=1700010660), "network", 10660)
    assert result
    key, stats = result
    assert detector.should_alert(key, "periodic", 1700010660, stats)
    assert detector.channels[key].reports["periodic"]["count"] == 12
    assert not detector.channels[key].reports["periodic"]["continuation"]


def test_mature_capacity_still_bounds_retained_windows() -> None:
    """Promotion at a full mature pool discards one window and records the loss."""
    module = ModuleFactory().create_beaconing_obj(max_channels=16, max_candidates=16)
    for destination in range(17):
        for i in range(12):
            module.detector.process(event(destination * 100 + i, timestamp=1700000000 + destination * 1000 + i * 60, dst=f"10.0.0.{destination+1}"), "network", destination * 1000 + i * 60)
    assert len(module.detector.channels) == 16
    assert not module.detector.candidates
    assert module.detector.evictions == 1
    assert len(module.detector.deleted) == 1


@pytest.mark.parametrize("change", ["period", "mode", "interrupted"])
def test_changed_rhythm_and_interrupted_progress(change: str) -> None:
    """Changed timing bypasses old progress; a recovered same pattern uses cooldown.

    Parameters:
        change: New period, new timing method, or recovery after a failed check.
    """
    module = ModuleFactory().create_beaconing_obj()
    detector = module.detector
    for i in range(12):
        result = detector.process(event(i), "network", i * 60)
    key, stats = result
    assert detector.should_alert(key, "periodic", event(11).timestamp, stats)
    channel = detector.channels[key]
    if change == "period":
        stats = {**stats, "period": stats["period"] * 2}
    elif change == "mode":
        stats = {**stats, "mode": "after-reply"}
    else:
        channel.reports["periodic"]["interrupted"] = True
    assert detector.should_alert(key, "periodic", event(12).timestamp, stats) is (change != "interrupted")
    if change == "interrupted":
        assert detector.should_alert(key, "periodic", event(12).timestamp + 3600, stats)
    assert not channel.reports["periodic"]["continuation"]
