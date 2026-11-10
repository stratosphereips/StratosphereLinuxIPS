"""Checkpoint ownership, retention and recovery without production databases."""

import json
import sqlite3
from pathlib import Path

import pytest

from modules.beaconing.detector import Detector
from modules.beaconing.store import Store
from tests.module_factory import ModuleFactory
from tests.unit.modules.beaconing.test_detector import event


def test_checkpoint_restore_and_writer_ownership(tmp_path: Path) -> None:
    """Checkpoint restore and writer ownership.

    Parameters:
        tmp_path: Isolated test directory.
    """
    module = ModuleFactory().create_beaconing_obj()
    path = tmp_path / "channels.sqlite"
    store = Store(path)
    try:
        for i in range(20):
            module.detector.process(event(i), "network", i)
        key = next(iter(module.detector.channels))
        module.detector.should_alert(key, "periodic", event(19).timestamp)
        store.save(module.detector)
        assert not module.detector.dirty
        with pytest.raises(BlockingIOError):
            Store(path)
        restored = Detector(module.settings)
        store.load(restored, event(19).timestamp)
        assert restored.snapshot(key) == module.detector.snapshot(key)
        assert not restored.should_alert(key, "periodic", event(20).timestamp)
    finally:
        store.close()
    assert path.stat().st_mode & 0o777 == 0o600
    store = Store(path)
    store.close()


def test_expiration_capacity_and_busy_retry(tmp_path: Path) -> None:
    """Expiration capacity and busy retry.

    Parameters:
        tmp_path: Isolated test directory.
    """
    module = ModuleFactory().create_beaconing_obj(max_channels=16, max_candidates=16)
    store = Store(tmp_path / "channels.sqlite")
    try:
        for i in range(30):
            module.detector.process(event(i, dst=f"10.0.0.{i + 1}"), "network", i)
        store.save(module.detector)
        assert store.connection.execute("SELECT count(*) FROM channels").fetchone()[0] == 16
        module.detector.process(event(100, timestamp=1800000000), "network", 100)
        store.save(module.detector)
        assert len(module.detector.channels) + len(module.detector.candidates) == 1
        assert store.connection.execute("SELECT count(*) FROM channels").fetchone()[0] == 1
        writer = sqlite3.connect(tmp_path / "channels.sqlite", timeout=0)
        writer.execute("BEGIN IMMEDIATE")
        module.detector.process(event(101, timestamp=1800000060), "network", 101)
        with pytest.raises(sqlite3.OperationalError):
            store.save(module.detector)
        assert module.detector.dirty
        writer.rollback()
        writer.close()
        store.save(module.detector)
        assert not module.detector.dirty
    finally:
        store.close()


def test_evicted_channel_returning_before_checkpoint(tmp_path: Path) -> None:
    """Retain a returning channel even if its earlier window was evicted.

    Parameters:
        tmp_path: Isolated checkpoint directory.
    """
    module = ModuleFactory().create_beaconing_obj(max_channels=16, max_candidates=16)
    store = Store(tmp_path / "channels.sqlite")
    try:
        module.detector.process(event(0), "network", 0)
        original = next(iter(module.detector.candidates))
        store.save(module.detector)
        for index in range(20):
            module.detector.process(event(index + 1, dst=f"10.0.0.{index + 1}"), "network", index)
        assert original in module.detector.deleted
        module.detector.process(event(100), "network", 100)
        store.save(module.detector)
        assert store.connection.execute("SELECT count(*) FROM channels WHERE key=?", (original,)).fetchone()[0] == 1
    finally:
        store.close()


def test_progress_restore_and_unchanged_checkpoint_avoids_writes(tmp_path: Path) -> None:
    """Preserve cumulative milestones through restarts and skip idle transactions.

    Parameters:
        tmp_path: Isolated checkpoint directory.
    """
    module = ModuleFactory().create_beaconing_obj(stable_evaluate_every=4, stable_evaluate_interval_seconds=0)
    detector = module.detector
    with_store = Store(tmp_path / "channels.sqlite")
    try:
        for i in range(90):
            result = detector.process(event(i), "network", i * 60)
            if result:
                detector.should_alert(result[0], "periodic", event(i).timestamp, result[1])
        key = next(iter(detector.channels))
        with_store.save(detector)
        statements = []
        with_store.connection.set_trace_callback(statements.append)
        with_store.save(detector)
        assert statements == []
        restored = Detector(module.settings)
        with_store.load(restored, event(89).timestamp)
        assert restored.channels[key].count == 90
        assert restored.channels[key].reports["periodic"]["next_count"] == 100
        reports = []
        for i in range(90, 108):
            result = restored.process(event(i), "network", i * 60)
            if result and restored.should_alert(key, "periodic", event(i).timestamp, result[1]):
                reports.append(restored.channels[key].reports["periodic"]["count"])
        assert len(reports) == 1 and 100 <= reports[0] <= 104
    finally:
        with_store.close()


def test_legacy_checkpoint_restores_candidates_and_mature_channels(tmp_path: Path) -> None:
    """Read old snapshots without growth fields and separate their short sequences.

    Parameters:
        tmp_path: Isolated checkpoint directory.
    """
    module = ModuleFactory().create_beaconing_obj()
    for i in range(20):
        module.detector.process(event(i), "network", i)
    module.detector.process(event(100, dst="10.0.0.1"), "network", 100)
    store = Store(tmp_path / "channels.sqlite")
    try:
        for key in [*module.detector.channels, *module.detector.candidates]:
            snapshot = module.detector.snapshot(key)
            snapshot.pop("count")
            snapshot.pop("reports")
            store.connection.execute("INSERT INTO channels VALUES (?,?,?)", (key, event(100).timestamp, json.dumps(snapshot)))
        store.connection.commit()
        restored = Detector(module.settings)
        store.load(restored, event(100).timestamp)
        assert len(restored.channels) == 1
        assert len(restored.candidates) == 1
        assert next(iter(restored.channels.values())).count == 20
    finally:
        store.close()


def test_candidate_churn_cannot_restore_stale_saved_windows(tmp_path: Path) -> None:
    """Reconcile saved keys even when more evictions occur than queued deletions.

    Parameters:
        tmp_path: Isolated checkpoint directory.
    """
    module = ModuleFactory().create_beaconing_obj(max_channels=16, max_candidates=16)
    store = Store(tmp_path / "channels.sqlite")
    try:
        for i in range(16):
            module.detector.process(event(i, dst=f"10.0.0.{i+1}"), "network", i)
        store.save(module.detector)
        for i in range(16, 150):
            module.detector.process(event(i, dst=f"10.0.0.{i+1}"), "network", i)
        store.save(module.detector)
        saved = {row[0] for row in store.connection.execute("SELECT key FROM channels")}
        assert saved == set(module.detector.candidates)
        assert len(saved) == 16
    finally:
        store.close()
