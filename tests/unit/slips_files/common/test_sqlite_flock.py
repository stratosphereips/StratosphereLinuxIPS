"""Unit tests for SQLite flock handling."""

import os

import pytest

from slips_files.common import sqlite_flock
from tests.module_factory import ModuleFactory


def test_sqlite_flock_creates_owner_only_lockfile(tmp_path):
    """The SQLite flock helper should create an owner-only writable lock file."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    locks_dir = tmp_path / "locks"
    locks_dir.mkdir()
    current_user_uid = os.getuid()

    original_locks_dir = sqlite_flock.SLIPS_LOCKS_DIR
    sqlite_flock.SLIPS_LOCKS_DIR = str(locks_dir)
    try:
        flock = sqlite_flock.SQLiteFlock("sqlite_db", 12345, current_user_uid)
    finally:
        sqlite_flock.SLIPS_LOCKS_DIR = original_locks_dir

    assert flock.lockfile_path.endswith("sqlite_db.lock")
    assert oct(os.stat(flock.lockfile_path).st_mode & 0o777) == "0o600"


def test_sqlite_flock_prepare_locks_dir_sets_sticky_permissions(tmp_path):
    """The SQLite flock helper should create the shared locks directory."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    locks_dir = tmp_path / "slips-locks"

    original_locks_dir = sqlite_flock.SLIPS_LOCKS_DIR
    sqlite_flock.SLIPS_LOCKS_DIR = str(locks_dir)
    try:
        sqlite_flock.SQLiteFlock.prepare_locks_dir()
    finally:
        sqlite_flock.SLIPS_LOCKS_DIR = original_locks_dir

    assert locks_dir.exists()
    assert oct(locks_dir.stat().st_mode & 0o1777) == "0o1777"


@pytest.mark.parametrize("nest_context", [True, False])
def test_sqlite_flock_acquire_supports_reentrant_usage(tmp_path, nest_context):
    """The SQLite flock helper should support direct and nested acquisition."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    locks_dir = tmp_path / "locks"
    locks_dir.mkdir()
    current_user_uid = os.getuid()

    original_locks_dir = sqlite_flock.SLIPS_LOCKS_DIR
    sqlite_flock.SLIPS_LOCKS_DIR = str(locks_dir)
    try:
        flock = sqlite_flock.SQLiteFlock("sqlite_db", 12345, current_user_uid)
    finally:
        sqlite_flock.SLIPS_LOCKS_DIR = original_locks_dir

    with flock.acquire():
        assert flock._lock_acquired is True
        if nest_context:
            with flock.acquire():
                assert flock._lock_acquired is True

    assert flock._lock_acquired is False
