"""Check baseline recovery, isolation, ownership and transient contention."""

import sqlite3
import json
import multiprocessing
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import pytest

from modules.anomaly_detection_services.store import BaselineStore
from modules.anomaly_detection_services.models import Observation
from tests.module_factory import ModuleFactory
from tests.unit.modules.anomaly_detection_services.test_baseline import train
from tests.unit.modules.anomaly_detection_services.test_models import flow


def spawn_replay(output_dir: str) -> None:
    """Run the real module lifecycle in a fresh interpreter with isolated IO.

    Parameters:
        output_dir: Child-owned temporary model directory.
    """
    module = ModuleFactory().create_service_anomaly_obj(
        output_dir, mode="train"
    )
    messages = [
        {
            "data": json.dumps(
                {
                    "twid": "timewindow1",
                    "flow": flow(day, uid=f"spawn-{day}-{index}"),
                }
            )
        }
        for day in range(3)
        for index in range(20)
    ]
    module.get_msg = lambda channel: messages.pop(0) if messages else None
    module.should_stop = lambda: not messages
    with patch(
        "modules.anomaly_detection_services.anomaly_detection_services.utils.drop_root_privs_permanently"
    ):
        module.run()
    assert module.store is None


def test_spawned_module_lifecycle_checkpoints_its_last_batch(
    tmp_path: Path,
) -> None:
    """Verify native spawn import, bounded draining and final persistence.

    Parameters:
        tmp_path: Child-owned temporary model directory.
    """
    module = ModuleFactory().create_service_anomaly_obj(str(tmp_path))
    child = multiprocessing.get_context("spawn").Process(
        target=spawn_replay, args=(str(tmp_path),)
    )
    child.start()
    child.join(15)
    try:
        assert child.exitcode == 0
    finally:
        if child.is_alive():
            child.terminate()
            child.join(3)
        child.close()
    path = tmp_path / "permanent" / module.name / "baseline.sqlite"
    with closing(BaselineStore(path, module.settings)) as store:
        restored = store.load()
    assert len(restored) == 1
    assert next(iter(restored.values())).summary.count == 60


def test_checkpoint_restores_models_and_alert_cooldowns(
    tmp_path: Path,
) -> None:
    """Resume learned clients and rate limits without erasing prior detections.

    Parameters:
        tmp_path: Isolated model directory.
    """
    module = ModuleFactory().create_service_anomaly_obj(training_hours=24)
    train(module)
    observation = Observation.from_zeek(flow(4, uid="first-b"))
    assert module.detector.process(observation, "service", "b")
    path = tmp_path / "baseline.sqlite"
    with closing(BaselineStore(path, module.settings)) as store:
        store.save(module.detector)
    restored = ModuleFactory().create_service_anomaly_obj(training_hours=24)
    with closing(BaselineStore(path, restored.settings)) as store:
        restored.detector.restore(store.load())
    assert restored.detector.services["service"].summary.count == 60
    assert len(restored.detector.services["service"].summary.durations) == 60
    duplicate = Observation.from_zeek(flow(4, uid="restart-b"))
    assert not restored.detector.process(duplicate, "service", "b")
    new = Observation.from_zeek(flow(4, uid="restart-c"))
    assert restored.detector.process(new, "service", "c")


def test_single_writer_ownership(tmp_path: Path) -> None:
    """Reject a second writer without damaging the first owner's database.

    Parameters:
        tmp_path: Isolated model directory.
    """
    module = ModuleFactory().create_service_anomaly_obj()
    path = tmp_path / "baseline.sqlite"
    with closing(BaselineStore(path, module.settings)) as store:
        with pytest.raises(BlockingIOError):
            BaselineStore(path, module.settings)
        train(module)
        store.save(module.detector)
    with closing(BaselineStore(path, module.settings)) as store:
        assert "service" in store.load()


def test_checkpoint_busy_is_deferred_and_retried(tmp_path: Path) -> None:
    """Preserve pending state and bound warnings during a real SQLite lock.

    Parameters:
        tmp_path: Isolated model directory.
    """
    module = ModuleFactory().create_service_anomaly_obj()
    train(module)
    path = tmp_path / "baseline.sqlite"
    with closing(BaselineStore(path, module.settings)) as store:
        module.store = store
        with sqlite3.connect(path) as writer:
            writer.execute("BEGIN IMMEDIATE")
            module._checkpoint(force=True)
            module._checkpoint(force=True)
            assert module.detector.dirty
            assert module.print.call_count == 1
            writer.rollback()
        module._checkpoint(force=True)
        assert not module.detector.dirty
        assert "service" in store.load()
        module.store = None


def test_timezone_change_preserves_clients_and_relearns_only_timing(
    tmp_path: Path,
) -> None:
    """Do not interpret historical clock bins in a different timezone.

    Parameters:
        tmp_path: Isolated model directory.
    """
    module = ModuleFactory().create_service_anomaly_obj()
    train(module)
    path = tmp_path / "baseline.sqlite"
    with closing(BaselineStore(path, module.settings)) as store:
        store.save(module.detector)
    changed = ModuleFactory().create_service_anomaly_obj(
        timezone="Europe/Prague"
    )
    with closing(BaselineStore(path, changed.settings)) as store:
        service = store.load()["service"]
    assert service.clients["client-a"].count == 60
    assert len(service.clients["client-a"].durations) == 60
    assert not service.clients["client-a"].activity
    assert service.training_days


def test_lowered_client_limit_is_persisted_conservatively(
    tmp_path: Path,
) -> None:
    """Remember saturation after truncating restored client models.

    Parameters:
        tmp_path: Isolated model directory.
    """
    module = ModuleFactory().create_service_anomaly_obj(mode="train")
    train(module)
    other = Observation.from_zeek(flow(4, uid="client-b"))
    module.detector.process(other, "service", "client-b")
    path = tmp_path / "baseline.sqlite"
    with closing(BaselineStore(path, module.settings)) as store:
        store.save(module.detector)
    smaller = ModuleFactory().create_service_anomaly_obj(max_clients=1)
    with closing(BaselineStore(path, smaller.settings)) as store:
        smaller.detector.restore(store.load())
        store.save(smaller.detector)
        service = store.load()["service"]
    assert len(service.clients) == 1
    assert not service.clients_complete


def test_live_and_offline_baselines_are_isolated(tmp_path: Path) -> None:
    """Keep offline analysis out of the live permanent baseline.

    Parameters:
        tmp_path: Isolated run directory.
    """
    module = ModuleFactory().create_service_anomaly_obj(str(tmp_path))
    with patch(
        "modules.anomaly_detection_services.anomaly_detection_services.utils.drop_root_privs_permanently"
    ):
        module.pre_main()
        assert (
            module.store.path
            == tmp_path / "permanent" / module.name / "baseline.sqlite"
        )
        module.shutdown_gracefully()
        module.live = False
        module.pre_main()
        assert module.store.path == tmp_path / module.name / "baseline.sqlite"
        module.shutdown_gracefully()


def test_corrupt_saved_state_is_reported_without_resetting_it(
    tmp_path: Path,
) -> None:
    """Do not silently overwrite an unreadable baseline with a fresh model.

    Parameters:
        tmp_path: Isolated model directory.
    """
    module = ModuleFactory().create_service_anomaly_obj()
    path = tmp_path / "baseline.sqlite"
    with closing(BaselineStore(path, module.settings)) as store:
        store.connection.execute("INSERT INTO services VALUES ('bad', 1, '{')")
        store.connection.commit()
        with pytest.raises(ValueError):
            store.load()
        assert (
            store.connection.execute("SELECT data FROM services").fetchone()[0]
            == "{"
        )
