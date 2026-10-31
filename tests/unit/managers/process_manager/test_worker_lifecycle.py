"""Check worker ownership without touching live Redis or capture processes."""

import multiprocessing
import os
import time
from contextlib import nullcontext
from unittest.mock import Mock, patch

import psutil
import pytest

from managers.process_manager.worker_lifecycle import (
    start_parent_watchdog,
    watch_parent,
)
from slips_files.core.database.database_manager import DBManager
from slips_files.core.database.redis_db.database import RedisDB
from tests.module_factory import ModuleFactory
from slips_files.core.aid_manager import AIDManager


@pytest.mark.parametrize("alive", [False, True])
def test_watch_parent_exits_only_after_parent_death(alive: bool) -> None:
    """Stop orphan work while allowing normal completion and cleanup.

    Parameters:
        alive: Whether the spawning parent still exists.
    """
    factory = ModuleFactory()
    parent = Mock()
    parent.is_alive.return_value = alive
    finished = Mock()
    finished.wait.side_effect = [False, True]
    exit_process = Mock()
    watch_parent(parent, finished, exit_process)
    assert exit_process.call_count == int(not alive)
    assert factory.logger is not None


def test_watchdog_does_not_start_inside_main_process() -> None:
    """Keep test and management commands free of child watchdog threads."""
    factory = ModuleFactory()
    with patch('managers.process_manager.worker_lifecycle.parent_process', return_value=None):
        with patch('managers.process_manager.worker_lifecycle.utils.start_thread') as start:
            finished = start_parent_watchdog(factory.logger)
    assert not finished.is_set()
    start.assert_not_called()


def orphan_probe(results: object) -> None:
    """Run a guarded worker after reporting its identity.

    Parameters:
        results: Pipe through which the test receives the worker PID.
    """
    start_parent_watchdog(Mock())
    results.send(os.getpid())
    time.sleep(30)


def parent_probe(results: object) -> None:
    """Start a child whose immediate parent the test can safely terminate.

    Parameters:
        results: Pipe shared with the guarded child.
    """
    child = multiprocessing.Process(target=orphan_probe, args=(results,))
    child.start()
    time.sleep(30)


@pytest.mark.parametrize("method", ["spawn", "forkserver"])
def test_abrupt_parent_death_reaps_guarded_worker(method: str) -> None:
    """Verify real OS parent death cannot leave another subscribed worker.

    Parameters:
        method: Worker startup mechanism to exercise.
    """
    factory = ModuleFactory()
    context = multiprocessing.get_context(method)
    receiver, sender = context.Pipe(duplex=False)
    parent = context.Process(target=parent_probe, args=(sender,))
    child = None
    try:
        parent.start()
        assert receiver.poll(15)
        child = psutil.Process(receiver.recv())
        parent.kill()
        parent.join(5)
        deadline = time.monotonic() + 5
        while child.is_running() and child.status() != psutil.STATUS_ZOMBIE:
            assert time.monotonic() < deadline, 'orphan worker kept running'
            time.sleep(.1)
        assert factory.logger is not None
    except psutil.NoSuchProcess:
        pass
    finally:
        if parent.is_alive():
            parent.kill()
            parent.join(5)
        if child is not None:
            try:
                if child.is_running() and child.status() != psutil.STATUS_ZOMBIE:
                    child.kill()
            except psutil.NoSuchProcess:
                pass
        parent.close()
        receiver.close()
        sender.close()


@pytest.mark.parametrize("owner,caller,expected", [(100,100,True),(100,99,False),(None,100,False)])
def test_reused_output_directory_requires_same_coordinator(owner: int | None, caller: int, expected: bool) -> None:
    """Reject a previous run even when its output directory is reused.

    Parameters:
        owner: Current coordinator recorded in Redis.
        caller: Coordinator that created the writing worker.
        expected: Whether evidence may be committed.
    """
    factory = ModuleFactory()
    redis_db = object.__new__(RedisDB)
    redis_db.get_output_dir = Mock(return_value='output/same-run')
    redis_db.r = factory.logger
    redis_db.r.hget.return_value = str(owner) if owner else None
    assert redis_db.belongs_to_run('output/same-run/', caller) is expected


def test_evidence_writer_supplies_original_coordinator() -> None:
    """Check ownership before any Redis or SQLite evidence mutation."""
    factory = ModuleFactory()
    database = object.__new__(DBManager)
    database.output_dir = 'output/same-run'
    database.main_pid = 99
    database.rdb = factory.logger
    database.rdb.belongs_to_run.return_value = False
    database.sqlite = Mock()
    assert database.set_evidence(Mock()) is False
    database.rdb.belongs_to_run.assert_called_once_with('output/same-run', 99)
    database.rdb.set_evidence.assert_not_called()
    database.sqlite.add_evidence.assert_not_called()


@pytest.mark.parametrize("fails", [False, True])
def test_flow_writer_finishes_its_watchdog(fails: bool) -> None:
    """Protect the separate AID writer and release its guard after cleanup.

    Parameters:
        fails: Whether the writer exits through an exception.
    """
    factory = ModuleFactory()
    finished = Mock()
    with (
        patch('slips_files.core.aid_manager.DBManager', return_value=factory.logger),
        patch('managers.process_manager.worker_lifecycle.start_parent_watchdog', return_value=finished) as start,
        patch.object(AIDManager, '_worker_loop', side_effect=RuntimeError('stop') if fails else None),
        pytest.raises(RuntimeError) if fails else nullcontext(),
    ):
        AIDManager._run_worker(Mock(), {})
    start.assert_called_once_with(factory.logger)
    finished.set.assert_called_once()
