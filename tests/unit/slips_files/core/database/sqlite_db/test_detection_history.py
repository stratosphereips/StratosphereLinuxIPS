"""Exercise durable, restartable detection rotation and exact hourly summaries."""

import os
import sqlite3
from pathlib import Path
from unittest.mock import Mock

import pytest

from tests.module_factory import ModuleFactory
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.core.database.sqlite_db.database import SQLiteDB
from slips_files.core.database.sqlite_db.detection_history import (
    DetectionHistory,
)
from slips_files.core.database.sqlite_db.detection_queries import (
    detection_total,
    hourly_evidence_source,
)


def test_maintenance_writer_contention_leaves_connection_reusable(
    tmp_path: Path,
) -> None:
    """Recover the writer connection after early archive maintenance fails.

    Parameters:
        tmp_path: Isolated run database.
    """
    factory = ModuleFactory()
    db = SQLiteDB(factory.logger, str(tmp_path), 12345)
    policy = ConfigParser().detection_history_policy()
    competing_writer = sqlite3.connect(db._flows_db)
    competing_writer.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            db.maintain_detection_history(policy, 2_000_000_000.0)
        assert not db.conn.in_transaction
        assert db.conn.execute("PRAGMA busy_timeout").fetchone() == (20000,)
    finally:
        competing_writer.rollback()
        competing_writer.close()
    status = db.maintain_detection_history(policy, 2_000_000_000.0)
    assert not status["interrupted"]
    db.execute("INSERT INTO flows(uid,flow) VALUES ('after-contention','{}')")
    assert db.conn.execute(
        "SELECT uid FROM flows WHERE uid='after-contention'"
    ).fetchone() == ("after-contention",)
    db.close()


@pytest.mark.parametrize("disk_pressure", [False, True])
def test_maintenance_respects_disk_pressure_and_rotates_by_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, disk_pressure: bool
) -> None:
    """Archive older records under size pressure while protecting the last day.

    Parameters:
        tmp_path: Isolated database directory.
        monkeypatch: Supply predictable disk availability.
        disk_pressure: Pause archival when the disk reserve is unavailable.
    """
    factory = ModuleFactory()
    db = SQLiteDB(factory.logger, str(tmp_path), 12345)
    now = 2_000_000_000.0
    db.execute(
        "INSERT INTO evidence(evidence_id,evidence_time,data) VALUES ('old',?,?)",
        (now - 2 * 86400, "x" * 2 * 1024 * 1024),
    )
    db.execute(
        "INSERT INTO evidence(evidence_id,evidence_time) VALUES ('recent',?)",
        (now,),
    )
    policy = ConfigParser().detection_history_policy(
        {"max_active_size_mb": 1, "work_budget_ms": 1000}
    )
    monkeypatch.setattr(
        "slips_files.core.database.sqlite_db.detection_history.shutil.disk_usage",
        lambda _: Mock(free=0 if disk_pressure else 10 * 1024**3),
    )
    status = db.maintain_detection_history(policy, now)
    assert status["size_pressure"] is True
    assert status["disk_pressure"] is disk_pressure
    assert detection_total(db.conn, "evidence") == (2 if disk_pressure else 1)
    assert db.conn.execute(
        "SELECT 1 FROM evidence WHERE evidence_id='recent'"
    ).fetchone()
    db.close()


def test_archive_size_rotation_and_cap(tmp_path: Path) -> None:
    """Split large monthly archives and expire the oldest completed segment.

    Parameters:
        tmp_path: Isolated database directory.
    """
    factory = ModuleFactory()
    db = SQLiteDB(factory.logger, str(tmp_path), 12345)
    now = 2_000_000_000.0
    for identifier in ("first", "second"):
        db.execute(
            "INSERT INTO evidence(evidence_id,evidence_time,data) VALUES (?,1,?)",
            (identifier, "x" * 2 * 1024 * 1024),
        )
    history = DetectionHistory(db.conn, str(tmp_path))
    for _ in range(20):
        if not history.archive_step("evidence", 100, 1, now, file_size_mb=1):
            break
    files = sorted(history.directory.glob("*.sqlite"))
    assert len(files) == 2
    assert history.expire_archives(now, 30, max_size_mb=3) == 1
    assert len(list(history.directory.glob("*.sqlite"))) == 1
    assert detection_total(db.conn, "evidence") == 0
    db.close()


def test_nullable_summary_keys_are_aggregated(tmp_path: Path) -> None:
    """Combine nullable legacy rows without converting nulls to empty strings.

    Parameters:
        tmp_path: Isolated database directory.
    """
    factory = ModuleFactory()
    db = SQLiteDB(factory.logger, str(tmp_path), 12345)
    db.execute(
        "INSERT INTO evidence(evidence_id,evidence_time) VALUES ('a',3700),('b',3800)"
    )
    history = DetectionHistory(db.conn, str(tmp_path))
    for _ in range(20):
        if not history.summary_step(1):
            break
    assert db.conn.execute(
        "SELECT profile_ip,record_count FROM evidence_hourly"
    ).fetchall() == [(None, 2)]
    db.close()


def test_active_alert_protects_older_supporting_evidence(
    tmp_path: Path,
) -> None:
    """Keep older evidence queryable while a recent alert still cites it.

    Parameters:
        tmp_path: Isolated database directory.
    """
    factory = ModuleFactory()
    db = SQLiteDB(factory.logger, str(tmp_path), 12345)
    db.execute(
        "INSERT INTO evidence(evidence_id,evidence_time) VALUES ('old',1)"
    )
    db.execute(
        "INSERT INTO alerts(alert_id,alert_time) VALUES ('recent',1000)"
    )
    db.execute("INSERT INTO alert_evidence VALUES ('recent','old')")
    history = DetectionHistory(db.conn, str(tmp_path))
    assert history.archive_step("evidence", 100, 10, 2000) == 0
    assert detection_total(db.conn, "evidence") == 1
    for _ in range(5):
        history.archive_step("alerts", 1100, 10, 2000)
    for _ in range(5):
        history.archive_step("evidence", 1100, 10, 2000)
    assert detection_total(db.conn, "evidence") == 0
    db.close()


@pytest.mark.parametrize("batch", [1, 2, 20])
def test_rotation_preserves_records_reviews_and_every_relationship(
    tmp_path: Path, batch: int
) -> None:
    """Rotate a detection graph without expiring its raw flow separately.

    Parameters:
        tmp_path: Isolated run directory.
        batch: Maximum relationships handled in a maintenance step.
    """
    factory = ModuleFactory()
    db = SQLiteDB(factory.logger, str(tmp_path), 12345)
    now = 2_000_000_000.0
    old = now - 100 * 86400
    db.execute(
        "INSERT INTO evidence(evidence_id,evidence_time) VALUES ('old',?)",
        (old,),
    )
    db.execute(
        "INSERT INTO evidence(evidence_id,evidence_time) VALUES ('recent',?)",
        (now,),
    )
    db.execute(
        "INSERT INTO alerts(alert_id,alert_time) VALUES ('alert',?)", (old,)
    )
    db.execute("INSERT INTO alert_evidence VALUES ('alert','old')")
    db.execute(
        "INSERT INTO evidence_reviews VALUES ('old','true_positive','verified',1)"
    )
    db.execute(
        "INSERT INTO alert_reviews VALUES ('alert','resolved','done',1,'true_positive')"
    )
    for index in range(7):
        db.execute(
            "INSERT INTO evidence_flows VALUES ('old',?)", (f"uid-{index}",)
        )
    db.execute(
        "INSERT INTO flows(uid,flow,event_time) VALUES ('uid-0','{}',?)",
        (old,),
    )
    history = DetectionHistory(db.conn, str(tmp_path))
    for _ in range(50):
        progress = sum(
            history.archive_step(entity, now - 90 * 86400, batch, now)
            for entity in ("evidence", "alerts")
        )
        if not progress:
            break
    assert db.conn.execute("SELECT evidence_id FROM evidence").fetchall() == [
        ("recent",)
    ]
    assert db.conn.execute("SELECT * FROM evidence_flows").fetchall() == []
    assert db.conn.execute("SELECT * FROM alert_evidence").fetchall() == []
    assert (
        db.conn.execute("SELECT * FROM history_archive_queue").fetchall() == []
    )
    assert db.conn.execute("SELECT uid FROM flows").fetchall() == [("uid-0",)]
    assert detection_total(db.conn, "evidence") == 1
    with sqlite3.connect(next(history.directory.glob("*.sqlite"))) as archive:
        assert archive.execute(
            "SELECT evidence_id FROM evidence"
        ).fetchall() == [("old",)]
        assert (
            archive.execute("SELECT COUNT(*) FROM evidence_flows").fetchone()[
                0
            ]
            == 7
        )
        assert archive.execute("SELECT * FROM alert_evidence").fetchall() == [
            ("alert", "old")
        ]
        assert (
            archive.execute("SELECT note FROM evidence_reviews").fetchone()[0]
            == "verified"
        )
        assert (
            archive.execute("SELECT verdict FROM alert_reviews").fetchone()[0]
            == "true_positive"
        )
    db.close()


def test_copy_failure_keeps_active_detection_and_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep the source intact if the durable destination cannot be written.

    Parameters:
        tmp_path: Isolated run directory.
        monkeypatch: Inject an archive write failure.
    """
    factory = ModuleFactory()
    db = SQLiteDB(factory.logger, str(tmp_path), 12345)
    db.execute(
        "INSERT INTO evidence(evidence_id,evidence_time) VALUES ('old',1)"
    )
    db.execute("INSERT INTO evidence_flows VALUES ('old','flow')")
    history = DetectionHistory(db.conn, str(tmp_path))
    monkeypatch.setattr(
        history,
        "_copy_row",
        Mock(side_effect=sqlite3.OperationalError("disk full")),
    )
    with pytest.raises(sqlite3.OperationalError, match="disk full"):
        history.archive_step("evidence", 100, 10, 200)
    db.conn.rollback()
    assert db.conn.execute("SELECT evidence_id FROM evidence").fetchall() == [
        ("old",)
    ]
    assert db.conn.execute("SELECT * FROM evidence_flows").fetchall() == [
        ("old", "flow")
    ]
    db.close()


def test_links_added_behind_copy_cursor_are_preserved(tmp_path: Path) -> None:
    """Restart an incomplete copy when a concurrent writer changes its links.

    Parameters:
        tmp_path: Isolated run directory.
    """
    factory = ModuleFactory()
    db = SQLiteDB(factory.logger, str(tmp_path), 12345)
    db.execute(
        "INSERT INTO evidence(evidence_id,evidence_time) VALUES ('old',1)"
    )
    for uid in ("b", "c", "d"):
        db.execute("INSERT INTO evidence_flows VALUES ('old',?)", (uid,))
    history = DetectionHistory(db.conn, str(tmp_path))
    history.archive_step("evidence", 100, 1, 200)
    db.execute("INSERT INTO evidence_flows VALUES ('old','a')")
    for _ in range(30):
        if not history.archive_step("evidence", 100, 1, 200):
            break
    with sqlite3.connect(next(history.directory.glob("*.sqlite"))) as archive:
        assert archive.execute(
            "SELECT uid FROM evidence_flows ORDER BY uid"
        ).fetchall() == [("a",), ("b",), ("c",), ("d",)]
    db.close()


@pytest.mark.parametrize(
    "age_days,queued,expected", [(29, False, 0), (31, False, 1), (31, True, 0)]
)
def test_archive_expiration_respects_age_and_incomplete_copies(
    tmp_path: Path,
    age_days: int,
    queued: bool,
    expected: int,
) -> None:
    """Expire complete rotated files only after the configured archive age.

    Parameters:
        tmp_path: Isolated run directory.
        age_days: Time since the archive's last write.
        queued: Whether a transfer still uses the archive.
        expected: Number of files eligible for expiration.
    """
    factory = ModuleFactory()
    db = SQLiteDB(factory.logger, str(tmp_path), 12345)
    history = DetectionHistory(db.conn, str(tmp_path))
    history.directory.mkdir()
    path = history.directory / "detections-2020-01.sqlite"
    path.touch()
    now = 2_000_000_000.0
    os.utime(path, (now - age_days * 86400, now - age_days * 86400))
    if queued:
        db.execute(
            "INSERT INTO history_archive_queue(entity,record_id,filename) VALUES ('evidence','old',?)",
            (path.name,),
        )
    assert history.expire_archives(now, 30) == expected
    assert path.exists() is (expected == 0)
    db.close()


def test_hourly_summary_handles_partial_hours_and_invalidates_updates(
    tmp_path: Path,
) -> None:
    """Use exact boundary rows and rebuild summaries after evidence changes.

    Parameters:
        tmp_path: Isolated run directory.
    """
    factory = ModuleFactory()
    db = SQLiteDB(factory.logger, str(tmp_path), 12345)
    for identifier, timestamp in (
        ("first", 3500),
        ("inside", 3700),
        ("last", 7300),
    ):
        db.execute(
            "INSERT INTO evidence(evidence_id,evidence_time,profile_ip,threat_level,accumulated_ratl) "
            "VALUES (?,?,'192.0.2.1','low',0.5)",
            (identifier, timestamp),
        )
    db.execute("INSERT INTO alert_evidence VALUES ('alert','inside')")
    history = DetectionHistory(db.conn, str(tmp_path))
    for _ in range(50):
        if not history.summary_step(1):
            break
    source = hourly_evidence_source(db.conn, 3550, 7350)
    assert source is not None
    assert db.conn.execute(
        f"SELECT SUM(weight),SUM(summarized_alerts) FROM {source}"
    ).fetchone() == (2, 1)
    db.execute("UPDATE evidence SET whitelisted=1 WHERE evidence_id='inside'")
    assert hourly_evidence_source(db.conn, 3550, 7350) is None
    for _ in range(50):
        if not history.summary_step(1):
            break
    source = hourly_evidence_source(db.conn, 3550, 7350)
    assert (
        db.conn.execute(
            f"SELECT SUM(weight) FROM {source} WHERE COALESCE(whitelisted,0)=0"
        ).fetchone()[0]
        == 1
    )
    assert detection_total(db.conn, "evidence") == 3
    db.close()
