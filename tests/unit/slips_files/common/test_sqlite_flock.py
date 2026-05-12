"""Unit tests for SQLite flock handling."""

import os

import pytest

from slips_files.common.sqlite_flock import SQLiteFlock
from slips_files.common.slips_utils import utils
from tests.module_factory import ModuleFactory


def test_sqlite_flock_creates_owner_only_lockfile(tmp_path):
    """The SQLite flock helper should create an owner-only writable lock file."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    locks_dir = tmp_path / "locks"
    locks_dir.mkdir()
    current_user_uid = os.getuid()

    original_locks_dir = utils.slips_locks_dir
    utils.slips_locks_dir = str(locks_dir)
    try:
        sqlite_flock = SQLiteFlock("sqlite_db", 12345, current_user_uid)
    finally:
        utils.slips_locks_dir = original_locks_dir

    assert sqlite_flock.lockfile_path.endswith("sqlite_db.lock")
    assert oct(os.stat(sqlite_flock.lockfile_path).st_mode & 0o777) == "0o600"


def test_sqlite_flock_prepare_locks_dir_sets_sticky_permissions(tmp_path):
    """The SQLite flock helper should create the shared locks directory."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    locks_dir = tmp_path / "slips-locks"

    original_locks_dir = utils.slips_locks_dir
    utils.slips_locks_dir = str(locks_dir)
    try:
        SQLiteFlock.prepare_locks_dir()
    finally:
        utils.slips_locks_dir = original_locks_dir

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

    original_locks_dir = utils.slips_locks_dir
    utils.slips_locks_dir = str(locks_dir)
    try:
        sqlite_flock = SQLiteFlock("sqlite_db", 12345, current_user_uid)
    finally:
        utils.slips_locks_dir = original_locks_dir

    with sqlite_flock.acquire():
        assert sqlite_flock._lock_acquired is True
        if nest_context:
            with sqlite_flock.acquire():
                assert sqlite_flock._lock_acquired is True

    assert sqlite_flock._lock_acquired is False
