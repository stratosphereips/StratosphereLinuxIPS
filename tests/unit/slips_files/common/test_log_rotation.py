"""Check file rotation, retention limits and persistent web log streams."""

import os
from pathlib import Path

import pytest

from tests.module_factory import ModuleFactory
from slips_files.common.log_rotation import (
    RotatingTextLog,
    expire_rotated_logs,
    rotate_log,
)


@pytest.mark.parametrize(
    "enabled,size,rotated",
    [
        (True, 1024 * 1024, True),
        (True, 20, False),
        (False, 1024 * 1024, False),
    ],
)
def test_rotation_preserves_full_log_and_active_permissions(
    tmp_path: Path, enabled: bool, size: int, rotated: bool
) -> None:
    """Keep the full old file and reopen a new active log with matching permissions.

    Parameters:
        tmp_path: Isolated output directory.
        enabled: Whether rotation is enabled.
        size: Active file size.
        rotated: Expected rotation decision.
    """
    _factory = ModuleFactory()
    path = tmp_path / "slips.log"
    path.write_bytes(b"x" * size)
    path.chmod(0o640)
    policy = {
        "enabled": enabled,
        "log_max_size_mb": 1,
        "archive_retention_days": 30,
        "log_backup_count": 2,
    }
    assert rotate_log(path, policy) is rotated
    assert path.stat().st_mode & 0o777 == 0o640
    segments = list((tmp_path / "rotated").glob("slips.log.*"))
    assert len(segments) == int(rotated)
    if rotated:
        assert segments[0].read_bytes() == b"x" * size
        assert path.read_bytes() == b""


@pytest.mark.parametrize("enabled,expected", [(True, 2), (False, 0)])
def test_quiet_segments_expire_by_age_and_count(
    tmp_path: Path, enabled: bool, expected: int
) -> None:
    """Enforce retention even without another write to the active log.

    Parameters:
        tmp_path: Isolated output directory.
        enabled: Whether retention is enabled.
        expected: Number of expired files.
    """
    _factory = ModuleFactory()
    directory = tmp_path / "alerts" / "rotated"
    directory.mkdir(parents=True)
    now = 2_000_000_000.0
    for index, days in enumerate((1, 2, 31)):
        path = directory / f"alerts.json.{index}"
        path.write_text("record\n")
        os.utime(path, (now - days * 86400, now - days * 86400))
    policy = {
        "enabled": enabled,
        "archive_retention_days": 30,
        "log_backup_count": 1,
    }
    assert expire_rotated_logs(tmp_path, policy, now) == expected


def test_web_stream_keeps_writing_after_rotation(tmp_path: Path) -> None:
    """Keep web access records and tracebacks in the active file after rotation.

    Parameters:
        tmp_path: Isolated web log directory.
    """
    _factory = ModuleFactory()
    policy = {
        "enabled": True,
        "log_max_size_mb": 1,
        "archive_retention_days": 30,
        "log_backup_count": 2,
    }
    path = tmp_path / "web_interface" / "server.log"
    stream = RotatingTextLog(path, policy)
    assert stream.writable()
    assert stream.write("x" * 1024 * 1024) == 1024 * 1024
    stream.flush()
    print("traceback continuation", file=stream, flush=True)
    assert path.read_text() == "traceback continuation\n"
    assert len(list((path.parent / "rotated").iterdir())) == 1
