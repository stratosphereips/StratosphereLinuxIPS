"""Check that modules cross a spawn boundary holding only configuration.

Exercise real spawn/forkserver boundaries without external services.
"""

import multiprocessing
import os
import pickle
import time
from queue import Empty
from unittest.mock import Mock, patch

import pytest

from modules.template.template import Template
from slips_files.core.aid_manager import AIDManager
from tests.module_factory import ModuleFactory


def wait_for_cleanup(ready: object) -> None:
    """Keep an isolated child alive until the process manager reaps it.

    Parameters:
        ready: Queue reporting that the child has started.
    """
    ready.put(os.getpid())
    time.sleep(30)


def make_module(**kwargs):
    """Build an unstarted Template module with picklable arguments."""
    return Template(
        "logger",
        "output",
        6379,
        None,
        "args",
        "conf",
        1,
        "bloom",
        **kwargs,
    )


def test_constructor_defers_resources_to_the_child() -> None:
    """The parent must not build the database or run init()."""
    module = make_module(startup_total=3)

    assert not hasattr(module, "db")
    assert module.startup_total == 3
    assert module.name == "template"
    assert module.description == "Template module"


def test_deferred_module_state_is_picklable() -> None:
    """Spawn pickles the module, so its stored state must pickle."""
    module = make_module()
    state = {k: v for k, v in vars(module).items() if k != "_config"}

    assert pickle.loads(pickle.dumps(state))["redis_port"] == 6379


def test_spawn_is_the_default_start_method() -> None:
    """Slips relies on spawn on every OS."""
    assert multiprocessing.get_start_method() == "spawn"


def test_run_prepares_child_then_executes() -> None:
    """run() builds resources, tracks sockets and stops them on exit."""
    module = make_module(startup_total=2)
    module._setup = Mock(
        side_effect=lambda: setattr(module, "db", Mock(name="db"))
    )
    module._execute = Mock()
    module._announce_startup = Mock()
    tracker = Mock()
    with patch(
        "slips_files.common.abstracts.imodule.parent_process",
        return_value=Mock(),
    ), patch(
        "slips_files.common.slips_own_traffic.SlipsTrafficTracker",
        return_value=tracker,
    ), patch(
        "managers.process_manager.worker_lifecycle.start_parent_watchdog"
    ) as watchdog, patch("signal.signal"):
        module.run()

    tracker.install.assert_called_once_with()
    tracker.attach.assert_called_once_with(module.db)
    module._announce_startup.assert_called_once_with()
    module._execute.assert_called_once_with()
    watchdog.return_value.set.assert_called_once_with()
    tracker.stop.assert_called_once_with()


@pytest.mark.parametrize("recorded_stopped", [False, True])
def test_owned_child_is_reaped_without_redis(recorded_stopped: bool) -> None:
    """Prevent a restarted analysis from retaining an old consumer process.

    Parameters:
        recorded_stopped: Whether the child reported completion prematurely.
    """
    factory = ModuleFactory()
    manager = factory.create_process_manager_obj()
    context = multiprocessing.get_context("spawn")
    ready = context.Queue()
    process = context.Process(target=wait_for_cleanup, args=(ready,), name="flow_alerts")
    try:
        process.start()
        assert ready.get(timeout=20) == process.pid
        manager.children = [process]
        manager.main.db.get_name_of_module_at.side_effect = RuntimeError("Redis unavailable")
        manager.stopped_modules = {"flow_alerts"} if recorded_stopped else set()
        manager.deferred_stopped_modules = set()
        manager._should_defer_web_interface_stopped_message = Mock(return_value=False)
        manager.print_stopped_module = Mock()
        manager.kill_all_children(force=True)
        assert not process.is_alive()
        assert process.exitcode is not None
    finally:
        if process.is_alive():
            process.kill()
            process.join(timeout=5)
        process.close()
        ready.close()
        ready.join_thread()


def test_aid_worker_owns_database_and_drains_tasks() -> None:
    """Create the AID database in the consumer and store queued flows."""
    factory = ModuleFactory()

    flow = Mock()
    queue = Mock()
    queue.get_nowait.side_effect = Empty
    queue.get.side_effect = [
        {
            "flow": flow,
            "profileid": "profile_1",
            "twid": "tw1",
            "label": "benign",
        },
        "stop",
    ]
    options = {
        "logger": factory.logger,
        "start_redis_server": False,
        "flush_db": False,
    }
    with patch(
        "slips_files.core.aid_manager.DBManager"
    ) as database_class, patch(
        "slips_files.core.aid_manager.utils.get_aid", return_value="aid-value"
    ):
        AIDManager._run_worker(queue, options)
        database_class.assert_called_once_with(**options)
        database_class.return_value.add_flows.assert_called_once_with(
            [{"flow": flow, "profileid": "profile_1", "twid": "tw1", "label": "benign"}]
        )
        assert flow.aid == "aid-value"


def test_aid_shutdown_waits_for_storage() -> None:
    """Wait for AID storage before the profiler can exit."""
    factory = ModuleFactory()

    manager = AIDManager.for_queue(factory.profiler_queue)
    manager._process = Mock()
    manager.shutdown()
    assert factory.profiler_queue.get(timeout=2) == "stop"
    manager._process.join.assert_called_once_with()
