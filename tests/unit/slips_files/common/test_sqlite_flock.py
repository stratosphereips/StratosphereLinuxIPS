"""Unit tests for SQLite flock handling."""

import os
from unittest.mock import patch

import pytest

from slips_files.common import sqlite_flock
from tests.module_factory import ModuleFactory


def test_sqlite_flock_creates_world_writable_lockfile(tmp_path):
    """The SQLite flock helper should create a world read/write lock file
    so both root and non-root Slips processes/modules can open it,
    regardless of which one created it."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    locks_dir = tmp_path / "locks"
    locks_dir.mkdir()

    original_locks_dir = sqlite_flock.SLIPS_LOCKS_DIR
    sqlite_flock.SLIPS_LOCKS_DIR = str(locks_dir)
    try:
        flock = sqlite_flock.SQLiteFlock("sqlite_db", 12345)
    finally:
        sqlite_flock.SLIPS_LOCKS_DIR = original_locks_dir

    assert flock.lockfile_path.endswith("sqlite_db.lock")
    assert oct(os.stat(flock.lockfile_path).st_mode & 0o777) == "0o666"


def test_sqlite_flock_leaves_lockfile_ownership_unchanged(tmp_path):
    """The lock file's ownership must be left as whoever created it (e.g.
    root, when running under sudo) - chowning it to another uid has been
    observed to make root unable to reopen its own lock file later on
    some systems, even though the file is 0666. This isn't needed for
    cleanup either: each lock file name is namespaced by the main pid, so
    a stale lock from a crashed run never blocks a future run."""
    locks_dir = tmp_path / "locks"
    locks_dir.mkdir()

    original_locks_dir = sqlite_flock.SLIPS_LOCKS_DIR
    sqlite_flock.SLIPS_LOCKS_DIR = str(locks_dir)
    try:
        with patch("slips_files.common.sqlite_flock.os.fchown") as mock_fchown:
            sqlite_flock.SQLiteFlock("sqlite_db", 12345)
    finally:
        sqlite_flock.SLIPS_LOCKS_DIR = original_locks_dir

    mock_fchown.assert_not_called()


def test_sqlite_flock_recovers_from_unopenable_stale_lockfile(tmp_path):
    """A stale lock file left behind with restrictive (e.g. old 0600)
    permissions - unopenable by the current process/user - must be removed
    and recreated rather than causing SQLiteFlock() to raise."""
    locks_dir = tmp_path / "locks"
    locks_dir.mkdir()

    original_locks_dir = sqlite_flock.SLIPS_LOCKS_DIR
    sqlite_flock.SLIPS_LOCKS_DIR = str(locks_dir)
    try:
        lockfile_path = sqlite_flock.SQLiteFlock._build_lockfile_path(
            "sqlite_db", 12345
        )
        # simulate a stale lock file this process can't open at all
        os.close(os.open(lockfile_path, os.O_WRONLY | os.O_CREAT, 0o600))

        real_os_open = os.open
        call_count = 0

        def deny_first_open(path, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if path == lockfile_path and call_count == 1:
                raise PermissionError("simulated stale-file EACCES")
            return real_os_open(path, *args, **kwargs)

        with patch(
            "slips_files.common.sqlite_flock.os.open",
            side_effect=deny_first_open,
        ):
            flock = sqlite_flock.SQLiteFlock("sqlite_db", 12345)
    finally:
        sqlite_flock.SLIPS_LOCKS_DIR = original_locks_dir

    assert flock.lockfile_path == lockfile_path
    assert oct(os.stat(lockfile_path).st_mode & 0o777) == "0o666"


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


def test_sqlite_flock_survives_lockfile_deleted_by_another_process(tmp_path):
    """Another process's close() (see delete_lockfile()) can unlink the
    shared lock file at any time - even between our own existence check
    and chmod. Since _ensure_lockfile() now chmods the fd it just opened
    instead of the path, a concurrent unlink of that path must not raise.
    """
    module_factory = ModuleFactory()
    assert module_factory is not None

    locks_dir = tmp_path / "locks"
    locks_dir.mkdir()

    original_locks_dir = sqlite_flock.SLIPS_LOCKS_DIR
    sqlite_flock.SLIPS_LOCKS_DIR = str(locks_dir)
    try:
        lockfile_path = sqlite_flock.SQLiteFlock._build_lockfile_path(
            "sqlite_db", 12345
        )

        real_os_open = os.open

        def unlink_right_after_open(path, *args, **kwargs):
            fd = real_os_open(path, *args, **kwargs)
            if path == lockfile_path:
                os.unlink(path)
            return fd

        with patch(
            "slips_files.common.sqlite_flock.os.open",
            side_effect=unlink_right_after_open,
        ):
            flock = sqlite_flock.SQLiteFlock("sqlite_db", 12345)
    finally:
        sqlite_flock.SLIPS_LOCKS_DIR = original_locks_dir

    assert flock.lockfile_path == lockfile_path
    assert not os.path.exists(lockfile_path)


@pytest.mark.parametrize("nest_context", [True, False])
def test_sqlite_flock_acquire_supports_reentrant_usage(tmp_path, nest_context):
    """The SQLite flock helper should support direct and nested acquisition."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    locks_dir = tmp_path / "locks"
    locks_dir.mkdir()

    original_locks_dir = sqlite_flock.SLIPS_LOCKS_DIR
    sqlite_flock.SLIPS_LOCKS_DIR = str(locks_dir)
    try:
        flock = sqlite_flock.SQLiteFlock("sqlite_db", 12345)
    finally:
        sqlite_flock.SLIPS_LOCKS_DIR = original_locks_dir

    with flock.acquire():
        assert flock._lock_acquired is True
        if nest_context:
            with flock.acquire():
                assert flock._lock_acquired is True

    assert flock._lock_acquired is False


def test_sqlite_flock_delete_lockfile_tolerates_permission_error(tmp_path):
    """A module that has permanently dropped root privileges (-p) can't
    unlink a lock file it doesn't own from the sticky SLIPS_LOCKS_DIR.
    delete_lockfile() must not propagate that PermissionError - cleanup
    isn't required for correctness since lock file names are namespaced
    by main_pid."""
    locks_dir = tmp_path / "locks"
    locks_dir.mkdir()

    original_locks_dir = sqlite_flock.SLIPS_LOCKS_DIR
    sqlite_flock.SLIPS_LOCKS_DIR = str(locks_dir)
    try:
        flock = sqlite_flock.SQLiteFlock("sqlite_db", 12345)
        with patch(
            "slips_files.common.sqlite_flock.Path.unlink",
            side_effect=PermissionError("simulated sticky-dir EPERM"),
        ):
            flock.delete_lockfile()
    finally:
        sqlite_flock.SLIPS_LOCKS_DIR = original_locks_dir

    assert os.path.exists(flock.lockfile_path)
