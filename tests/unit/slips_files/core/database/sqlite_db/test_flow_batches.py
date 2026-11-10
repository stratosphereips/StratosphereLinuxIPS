"""Durable batched flow writes and concurrent WAL reads under scan load."""

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from slips_files.core.database.database_manager import DBManager
from slips_files.core.database.sqlite_db.database import SQLiteDB
from tests.module_factory import ModuleFactory


@dataclass
class StoredFlow:
    """Minimal parsed record used by the real flow storage methods."""

    uid: str
    starttime: float = 100.0
    aid: str = "hash"


@pytest.mark.parametrize("count", [0, 1, 64, 65])
def test_flow_batch_commits_once_and_preserves_publication(tmp_path: Path, count: int) -> None:
    """Publish committed tasks once and reject oversized batches before writing.

    Parameters:
        tmp_path: Isolated output database.
        count: Number of records in the batch.
    """
    factory = ModuleFactory()
    db = DBManager.__new__(DBManager)
    db.sqlite = SQLiteDB(factory.logger, str(tmp_path), 12345)
    db.rdb = Mock()
    tasks = [{"flow": StoredFlow(f"flow-{n}"), "profileid": "profile_1",
              "twid": "timewindow1", "label": "malicious"} for n in range(count)]
    queries = []
    db.sqlite.conn.set_trace_callback(queries.append)
    if count > 64:
        with pytest.raises(ValueError):
            db.add_flows(tasks)
        db.rdb.add_flow.assert_not_called()
    else:
        def published(**task: object) -> None:
            """Assert the whole batch is durable before any subscriber is notified."""
            with sqlite3.connect(db.sqlite._flows_db) as observer:
                assert observer.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == count

        db.rdb.add_flow.side_effect = published
        db.add_flows(tasks)
        assert [call.kwargs for call in db.rdb.add_flow.call_args_list] == tasks
        assert queries.count("COMMIT") == int(count > 0)
    db.sqlite.close()


def test_failed_flow_batch_rolls_back_without_publication(tmp_path: Path) -> None:
    """A failed transaction leaves neither partial records nor published events.

    Parameters:
        tmp_path: Isolated output database.
    """
    factory = ModuleFactory()
    db = DBManager.__new__(DBManager)
    db.sqlite = SQLiteDB(factory.logger, str(tmp_path), 12345)
    db.rdb = Mock()
    db.sqlite.execute("CREATE TRIGGER reject_bad BEFORE INSERT ON flows WHEN NEW.uid='bad' BEGIN SELECT RAISE(ABORT,'rejected'); END")
    tasks = [{"flow": StoredFlow(uid), "profileid": "profile_1", "twid": "timewindow1", "label": "benign"} for uid in ("good", "bad")]
    with pytest.raises(sqlite3.IntegrityError):
        db.add_flows(tasks)
    assert db.sqlite.get_flows_count() == 0
    assert not db.sqlite.conn.in_transaction
    db.rdb.add_flow.assert_not_called()
    db.sqlite.close()


def test_wal_reads_do_not_acquire_the_shared_writer_lock(tmp_path: Path) -> None:
    """Read committed flows while another connection has an uncommitted write.

    Parameters:
        tmp_path: Isolated output database.
    """
    factory = ModuleFactory()
    db = SQLiteDB(factory.logger, str(tmp_path), 12345)
    db.execute("INSERT INTO flows(uid,flow) VALUES ('committed','{}')")
    with sqlite3.connect(db._flows_db) as writer:
        writer.execute("INSERT INTO flows(uid,flow) VALUES ('pending','{}')")
        with patch.object(db, "_acquire_flock", side_effect=AssertionError("Reader requested exclusive writer lock")):
            assert db.get_flows_count() == 1
        writer.rollback()
    db.close()
