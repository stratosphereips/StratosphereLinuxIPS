"""Exercise private ARP history persistence and single-writer safety."""

import json
import sqlite3
from pathlib import Path
import pytest

from modules.arp.scan_history import ARPHistoryStore
from tests.module_factory import ModuleFactory
from tests.unit.modules.arp.test_scan_detector import train, burst


def test_private_history_survives_restart_and_expires(tmp_path: Path) -> None:
    """Restore live familiarity, then expire it without touching other history.

    Parameters:
        tmp_path: Isolated module directory.
    """
    factory = ModuleFactory()
    detector = factory.create_arp_scan_detector(scan_familiar_retention_days=1)
    train(detector, list(range(1, 16)))
    path = tmp_path / "contacts.sqlite"
    store = ARPHistoryStore(path)
    store.save(detector, 1000)
    assert not detector.dirty
    store.close()
    restored = factory.create_arp_scan_detector(scan_familiar_retention_days=1)
    store = ARPHistoryStore(path)
    try:
        store.load(restored, 1000)
        assert burst(restored, list(range(1, 16))) == []
        assert not restored.groups or len(restored.groups) == 1
        store.save(restored, 90000)
        assert store.connection.execute("SELECT COUNT(*) FROM contacts").fetchone()[0] == 0
    finally:
        store.close()
    assert store.connection is None and store.lock.closed


def test_busy_checkpoint_preserves_previous_snapshot_and_dirty_state(tmp_path: Path) -> None:
    """Never lose learning or partially replace a checkpoint during contention.

    Parameters:
        tmp_path: Isolated module database.
    """
    detector = ModuleFactory().create_arp_scan_detector()
    train(detector, [1])
    path = tmp_path / "contacts.sqlite"
    store = ARPHistoryStore(path)
    store.save(detector, 1000)
    lock = sqlite3.connect(path, timeout=0)
    try:
        train(detector, [2])
        lock.execute("BEGIN IMMEDIATE")
        with pytest.raises(sqlite3.OperationalError):
            store.save(detector, 1000)
        assert detector.dirty
        lock.rollback()
        store.save(detector, 1000)
        assert not detector.dirty
        assert store.connection.execute("SELECT COUNT(*) FROM contacts").fetchone()[0] == 4
    finally:
        lock.close()
        store.close()


def test_second_writer_fails_without_harming_first(tmp_path: Path) -> None:
    """A second live writer must not corrupt the first worker's state.

    Parameters:
        tmp_path: Isolated history directory.
    """
    _factory = ModuleFactory()
    path = tmp_path / "contacts.sqlite"
    first = ARPHistoryStore(path)
    try:
        with pytest.raises(BlockingIOError):
            ARPHistoryStore(path)
        assert first.connection.execute("SELECT COUNT(*) FROM contacts").fetchone()[0] == 0
    finally:
        first.close()


def test_load_is_bounded_and_skips_malformed_or_future_contacts(tmp_path: Path) -> None:
    """Treat corrupted, oversized and future records conservatively.

    Parameters:
        tmp_path: Isolated private checkpoint.
    """
    factory = ModuleFactory()
    detector = factory.create_arp_scan_detector(scan_max_relationships=4)
    train(detector, list(range(1, 10)))
    store = ARPHistoryStore(tmp_path / "contacts.sqlite")
    try:
        store.save(detector, 1000)
        store.connection.executemany("INSERT INTO contacts(updated,data) VALUES (?,?)", [(500, "not-json"), (500, json.dumps({"invalid": True})), (99999, "{}")])
        store.connection.commit()
        restored = factory.create_arp_scan_detector(scan_max_relationships=4)
        store.load(restored, 1000)
        assert len(restored.contacts) <= 4
        assert all(contact.seen <= 1000 for contact in restored.contacts.values())
    finally:
        store.close()


def test_expired_disk_rows_are_removed_even_when_not_loaded(tmp_path: Path) -> None:
    """Startup filtering must not leave expired records on disk indefinitely.

    Parameters:
        tmp_path: Isolated checkpoint directory.
    """
    factory = ModuleFactory()
    detector = factory.create_arp_scan_detector(scan_familiar_retention_days=1)
    train(detector, [1, 2])
    store = ARPHistoryStore(tmp_path / "contacts.sqlite")
    try:
        store.save(detector, 1000)
        restored = factory.create_arp_scan_detector(scan_familiar_retention_days=1)
        store.load(restored, 90000)
        assert not restored.contacts and restored.dirty
        store.save(restored, 90000)
        assert store.connection.execute("SELECT COUNT(*) FROM contacts").fetchone()[0] == 0
    finally:
        store.close()
