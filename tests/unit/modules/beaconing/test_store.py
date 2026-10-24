"""Checkpoint ownership, retention and recovery without production databases."""

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
    module = ModuleFactory().create_beaconing_obj(max_channels=16)
    store = Store(tmp_path / "channels.sqlite")
    try:
        for i in range(30):
            module.detector.process(event(i, dst=f"10.0.0.{i + 1}"), "network", i)
        store.save(module.detector)
        assert store.connection.execute("SELECT count(*) FROM channels").fetchone()[0] == 16
        module.detector.process(event(100, timestamp=1800000000), "network", 100)
        store.save(module.detector)
        assert len(module.detector.channels) == 1
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
    module = ModuleFactory().create_beaconing_obj(max_channels=16)
    store = Store(tmp_path / "channels.sqlite")
    try:
        module.detector.process(event(0), "network", 0)
        original = next(iter(module.detector.channels))
        store.save(module.detector)
        for index in range(20):
            module.detector.process(event(index + 1, dst=f"10.0.0.{index + 1}"), "network", index)
        assert original in module.detector.deleted
        module.detector.process(event(100), "network", 100)
        store.save(module.detector)
        assert store.connection.execute("SELECT count(*) FROM channels WHERE key=?", (original,)).fetchone()[0] == 1
    finally:
        store.close()
